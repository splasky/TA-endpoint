/*
 * Copyright (C) 2019-2020 BiiLabs Co., Ltd. and Contributors
 * All Rights Reserved.
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the MIT license. A copy of the license can be found in the file
 * "LICENSE" at the root of this distribution.
 */

#include "impl.h"
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include "device.h"

#define MAXLINE 1024
#define IMSI_LEN 15
#define CBC_IV_SIZE 16
#define READ_BUFFER_SIZE 32
#define DEFAULT_PORT "/dev/ttyHSO0"

static inline void register_wp7702(void);
static inline void unregister_wp7702(void);

extern struct device_type wp7702_device_type;

static int wp7702_init(void) {
  register_wp7702();
  return DEVICE_OK;
}

static void wp7702_release(void) { unregister_wp7702(); }

// Get AES key with hashchain in legato originated app form.
static int wp7702_get_key(uint8_t *key) {
  char hash_chain_res[MAXLINE];
  char cmd[] = "cm sim info";  // TODO Use the right command
  FILE *fp;

  fp = popen(cmd, "r");

  if (NULL == fp) {
    perror("popen open error");
    return -DEVICE_ERROR;
  }

  if (fgets(hash_chain_res, sizeof(hash_chain_res), fp) != NULL) {
    hash_chain_res[strlen(hash_chain_res) - 2] = '\0';
  }

  memcpy(key, hash_chain_res, CBC_IV_SIZE);

  if (pclose(fp) == -1) {
    perror("close FILE pointer");
    return -DEVICE_ERROR;
  }

  return DEVICE_OK;
}

static int wp7702_get_device_id(char *device_id) {
  char result_buf[MAXLINE], *imsi;
  char cmd[] = "cm sim info";
  FILE *fp;

  fp = popen(cmd, "r");
  if (NULL == fp) {
    perror("popen open error");
    return -DEVICE_ERROR;
  }

  while (fgets(result_buf, sizeof(result_buf), fp) != NULL) {
    if (strstr(result_buf, "IMSI")) {
      result_buf[strlen(result_buf) - 1] = '\0';
      imsi = strtok(result_buf + 5, " ");
    }
  }

  strncpy(device_id, imsi, IMSI_LEN);

  if (pclose(fp) == -1) {
    perror("close FILE pointer");
    return -DEVICE_ERROR;
  }

  return DEVICE_OK;
}

static void write_log(char *path, char *msg, size_t msg_len) {
  FILE *fp;
  // Append the next address to the address log file
  fp = fopen(path, "a");
  if (!fp) {
    perror("logging to file failed:");
    fclose(fp);
  }
  fputs(msg, fp);
  fclose(fp);
}

static inline void register_wp7702(void) {
  int err = register_device(&wp7702_device_type);
  if (err) fprintf(stderr, "register wp7702 device error:%d", err);
}

static inline void unregister_wp7702(void) {
  int err = unregister_device(&wp7702_device_type);
  if (err) fprintf(stderr, "unregister device wp7702 error:%d", err);
}

static int set_interface_attribs(int fd, int speed) {
  struct termios tty;

  if (tcgetattr(fd, &tty) < 0) {
    printf("Error from tcgetattr: %s\n", strerror(errno));
    return -1;
  }

  cfsetospeed(&tty, (speed_t)speed);
  cfsetispeed(&tty, (speed_t)speed);

  tty.c_cflag |= (CLOCAL | CREAD); /* ignore modem controls */
  tty.c_cflag &= ~CSIZE;
  tty.c_cflag |= CS8;      /* 8-bit characters */
  tty.c_cflag &= ~PARENB;  /* no parity bit */
  tty.c_cflag &= ~CSTOPB;  /* only need 1 stop bit */
  tty.c_cflag &= ~CRTSCTS; /* no hardware flowcontrol */

  /* setup for non-canonical mode */
  tty.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
  tty.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
  tty.c_oflag &= ~OPOST;

  /* fetch bytes as they become available */
  tty.c_cc[VMIN] = 1;
  tty.c_cc[VTIME] = 1;

  if (tcsetattr(fd, TCSANOW, &tty) != 0) {
    printf("Error from tcsetattr: %s\n", strerror(errno));
    return -1;
  }
  return 0;
}

static int uart_init(const char *device) {
  if (device == NULL) device = DEFAULT_PORT;
  int fd;

  fd = open(device, O_RDWR | O_NOCTTY | O_SYNC);
  if (fd < 0) {
    printf("Error opening %s: %s\n", device, strerror(errno));
    return -1;
  }
  /*baudrate 115200, 8 bits, no parity, 1 stop bit */
  set_interface_attribs(fd, B115200);
  return fd;
}

static void uart_write(const int fd, const char *cmd) {
  /* simple output */
  ssize_t cmd_len = strlen(cmd);
  ssize_t wlen = write(fd, cmd, cmd_len);
  if (wlen != cmd_len) {
    printf("Error from write: %ld, %d\n", wlen, errno);
  }
  tcdrain(fd); /* delay for output */
}

static char *uart_read(const int fd) {
  unsigned char buf[READ_BUFFER_SIZE];
  char *response = NULL;

  ssize_t rdlen = read(fd, buf, sizeof(buf) - 1);
  if (rdlen > 0) {
    // printf("buf = %s\n", buf);
    response = (char *)malloc(sizeof(char) * rdlen);
    strncpy(response, (char *)buf, READ_BUFFER_SIZE);
  } else if (rdlen < 0) {
    printf("Error from read: %ld: %s\n", rdlen, strerror(errno));
  }

  return response;
}

static void uart_clean(const int fd) {
  if (tcflush(fd, TCIOFLUSH) != 0) {
    perror("tcflush error");
  }
}

static const struct device_operations wp7702_ops = {
    .init = wp7702_init, .fini = wp7702_release, .get_key = wp7702_get_key, .get_device_id = wp7702_get_device_id};

static const struct logging_operations wp7702_logger = {.write_log = write_log};

static const struct uart_operations wp7702_uart = {
    .init = uart_init, .write = uart_write, .read = uart_read, .clean = uart_clean};

struct device_type wp7702_device_type = {
    .name = "wp7702", .op = &wp7702_ops, .uart = &wp7702_uart, .logger = &wp7702_logger};

DECLARE_DEVICE(wp7702);
