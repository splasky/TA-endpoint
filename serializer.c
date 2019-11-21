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

int serialize_msg(uint8_t *ciphertext, uint32_t ciphertext_len, uint8_t *iv,
                  char *out_msg) {
  char str_ciphertext[1025] = {}, str_iv[17] = {};
  memcpy(str_ciphertext, ciphertext, 1024);
  memcpy(str_iv, iv, 16);
  sprintf(out_msg, "%s:%d:%s", str_ciphertext, ciphertext_len, str_iv);
  return 0;
}

int deserialize_msg(char *msg, uint8_t *ciphertext, uint32_t *ciphertext_len,
                    uint8_t *iv) {
  char str_ciphertext[1025] = {}, str_iv[17] = {};
  const char s[2] = ":";
  char *token;
  token = strtok(msg, s);
  memcpy(ciphertext, token, 1024);
  int i = 0;
  while (token != NULL) {
    token = strtok(NULL, s);

    if (i == 0) {
      *ciphertext_len = atoi(token);
    } else if (i == 1) {
      memcpy(iv, token, 16);
      break;
    }
    i++;
  }

  return 0;
}