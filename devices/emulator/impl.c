/*
 * Copyright (C) 2019-2020 BiiLabs Co., Ltd. and Contributors
 * All Rights Reserved.
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the MIT license. A copy of the license can be found in the file
 * "LICENSE" at the root of this distribution.
 */

#include "impl.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAXLINE 1024
#define IMSI_LEN 15
#define CBC_IV_SIZE 16
#define UART_BUFFER_SIZE 1024

/* Setting data to produce predictable results for emulator */
// device id
static const char *device_id = "470010171566423";
// private key
static const uint8_t private_key[32] = {82,  142, 184, 64,  74, 105, 126, 65,  154, 116, 14,  193, 208, 41,  8,  115,
                                        158, 252, 228, 160, 79, 5,   167, 185, 13,  159, 135, 113, 49,  209, 58, 68};
static char UART_BUFFER[UART_BUFFER_SIZE];

extern struct device_type emulator_device_type;

static inline void register_emulator(void) {
  int err = register_device(&emulator_device_type);
  if (err) LOG_ERROR("register emulator device error:%d", err);
}

static inline void unregister_emulator(void) {
  int err = unregister_device(&emulator_device_type);
  if (err) LOG_ERROR("unregister device emulator error:%d", err);
}

static int emulator_init(void) {
  register_emulator();
  return DEVICE_OK;
}

static void emulator_release(void) { unregister_emulator(); }

// Get AES key with hashchain in legato originated app form.
static int emulator_get_key(uint8_t *key) {
  memcpy(key, private_key, 16);
  LOG_INFO("Get device key success");
  return DEVICE_OK;
}

static int emulator_get_device_id(char *id) {
  memcpy(id, device_id, 16);
  LOG_INFO("Get device id success");
  return DEVICE_OK;
}

static void write_log(char *path, char *msg, size_t msg_len) {
  FILE *fp = fopen(path, "a");
  if (!fp) {
    LOG_ERROR("logging to file failed");
    fclose(fp);
    return;
  }
  fputs(msg, fp);
  fclose(fp);
}

static int uart_init(const char *device) {
  int fd = 0;
  LOG_INFO("UART init device %s success", device);
  return fd;
}

static void uart_write(const int fd, const char *cmd) {
  /* simple output */
  size_t cmd_len = strlen(cmd);
  if (cmd_len > UART_BUFFER_SIZE) {
    LOG_ERROR("command too long");
    return;
  }
  snprintf(UART_BUFFER, cmd_len, "%s", cmd);
  LOG_INFO("UART write success");
}

static char *uart_read(const int fd) {
  char *response = strdup("This is a test");
  LOG_INFO("UART read success");
  return response;
}

static void uart_clean(const int fd) { LOG_INFO("UART clean success"); }

static const struct device_operations emulator_ops = {.init = emulator_init,
                                                      .fini = emulator_release,
                                                      .get_key = emulator_get_key,
                                                      .get_device_id = emulator_get_device_id};

static const struct logging_operations emulator_logger = {.write_log = write_log};

static const struct uart_operations emulator_uart = {
    .init = uart_init, .write = uart_write, .read = uart_read, .clean = uart_clean};

struct device_type emulator_device_type = {
    .name = "emulator", .op = &emulator_ops, .uart = &emulator_uart, .logger = &emulator_logger};

DECLARE_DEVICE(emulator);
