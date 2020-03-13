/*
 * Copyright (C) 2019-2020 BiiLabs Co., Ltd. and Contributors
 * All Rights Reserved.
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the MIT license. A copy of the license can be found in the file
 * "LICENSE" at the root of this distribution.
 */

#include "stdio.h"
#include "string.h"
#include "tryte_byte_conv.h"

int main() {
  const char test_str[1024] = {48, 48, 48, 48, 48, 0,  48, 48, 48, 48, 48, 48, 48, 48,
                               48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48};
  const int str_len = 28;
  char enc_msg[1024] = {0}, dec_msg[1024] = {0};

  bytes_to_trytes(test_str, str_len, enc_msg);
  trytes_to_bytes(enc_msg, strlen(enc_msg), dec_msg);

  if (!memcmp(test_str, dec_msg, str_len)) {
    printf("SUCCESS\n");
    return 0;
  } else {
    printf("FAILED\n");
    return 1;
  }
  return 0;
}
