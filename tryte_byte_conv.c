/*
 * Copyright (C) 2019 BiiLabs Co., Ltd. and Contributors
 * All Rights Reserved.
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the MIT license. A copy of the license can be found in the file
 * "LICENSE" at the root of this distribution.
 */

#include "tryte_byte_conv.h"
#include <stdint.h>

void ascii_to_trytes(unsigned char const *const input, char *const output) {
  const char tryte_alphabet[] = "9ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  unsigned int j = 0, dec = 0, lower = 0, upper = 0;

  for (uint16_t i = 0; input[i]; i++) {
    dec = input[i];
    upper = (dec >> 4) & 15;
    lower = dec & 15;
    output[j++] = tryte_alphabet[upper];
    output[j++] = tryte_alphabet[lower];
  }
}

void trytes_to_ascii(unsigned char const *const input, char *const output) {
  const char tryte_alphabet[] = "9ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  unsigned int upper = 0, lower = 0;

  for (uint16_t i = 0; input[i]; i += 2) {
    if (input[i] == '9') {
      upper = 0;
    } else {
      upper = input[i] - 64;
    }
    if (input[i + 1] == '9') {
      lower = 0;
    } else {
      lower = input[i + 1] - 64;
    }

    output[i / 2] = (upper << 4) + lower;
  }
}