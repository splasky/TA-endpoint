/*
 * Copyright (C) 2019 BiiLabs Co., Ltd. and Contributors
 * All Rights Reserved.
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the MIT license. A copy of the license can be found in the file
 * "LICENSE" at the root of this distribution.
 */

#include "uart_utils.h"

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
  tty.c_iflag &=
      ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
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

static void set_mincount(int fd, int mcount) {
  struct termios tty;

  if (tcgetattr(fd, &tty) < 0) {
    printf("Error tcgetattr: %s\n", strerror(errno));
    return;
  }

  tty.c_cc[VMIN] = mcount ? 1 : 0;
  tty.c_cc[VTIME] = 5; /* half second timer */

  if (tcsetattr(fd, TCSANOW, &tty) < 0)
    printf("Error tcsetattr: %s\n", strerror(errno));
}

int uart_init() {
  char *portname = "/dev/ttyHS0";
  int fd;
  int wlen;

  fd = open(portname, O_RDWR | O_NOCTTY | O_SYNC);
  if (fd < 0) {
    printf("Error opening %s: %s\n", portname, strerror(errno));
    return -1;
  }
  /*baudrate 115200, 8 bits, no parity, 1 stop bit */
  set_interface_attribs(fd, B115200);
  // set_mincount(fd, 0);                /* set to pure timed read */

  return fd;
}

void uart_write(const int fd, char cmd) {
  /* simple output */
  ssize_t cmd_len = strlen(cmd);
  ssize_t wlen = write(fd, cmd, cmd_len);
  if (wlen != cmd_len) {
    printf("Error from write: %d, %d\n", wlen, errno);
  }
  tcdrain(fd); /* delay for output */
}

char *uart_read(const int fd) {
  unsigned char buf[READ_BUFFER_SIZE];
  char *response = NULL;

  ssize_t rdlen = read(fd, buf, sizeof(buf) - 1);
  if (rdlen > 0) {
    // printf("buf = %s\n", buf);
    response = (char *)malloc(sizeof(char) * rdlen);
    strncpy(response, buf, READ_BUFFER_SIZE);
  } else if (rdlen < 0) {
    printf("Error from read: %d: %s\n", rdlen, strerror(errno));
  }

  return response;
}