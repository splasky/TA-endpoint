/*
 * Copyright (C) 2019 BiiLabs Co., Ltd. and Contributors
 * All Rights Reserved.
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the MIT license. A copy of the license can be found in the file
 * "LICENSE" at the root of this distribution.
 */

#include "serializer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IV_LEN 16
#define UINT32_LEN 32

int serialize_msg(uint8_t *iv, uint32_t ciphertext_len, uint8_t *ciphertext,
                  char *out_msg) {
  char str_ciphertext[1025] = {}, str_iv[IV_LEN + 1] = {}, str_ciphertext_len[UINT32_LEN + 1] = {};
  memcpy(str_ciphertext, ciphertext, 1024);
  memcpy(str_iv, iv, 16);
  sprintf(str_ciphertext_len, "%032d", ciphertext_len);
  sprintf(out_msg, "%s%s%s", str_iv, str_ciphertext_len, str_ciphertext);
  return 0;
}

int deserialize_msg(char *msg, uint8_t *iv, uint32_t *ciphertext_len,
                    uint8_t *ciphertext) {
  char str_ciphertext[1025] = {}, str_iv[IV_LEN + 1] = {}, str_ciphertext_len[UINT32_LEN + 1] = {};
  strncpy(iv, msg, IV_LEN);
  strncpy(str_ciphertext_len, msg + IV_LEN, IV_LEN);
  strncpy(ciphertext, msg + IV_LEN + UINT32_LEN, strlen(msg) - IV_LEN - UINT32_LEN);
  ciphertext_len = atoi(str_ciphertext_len);
  return 0;
}