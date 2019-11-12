/*
 * Copyright (C) 2018-2019 BiiLabs Co., Ltd. and Contributors
 * All Rights Reserved.
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the MIT license. A copy of the license can be found in the file
 * "LICENSE" at the root of this distribution.
 */

#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int encrypt(unsigned char *plaintext, int plaintext_len,
            unsigned char *ciphertext, uint32_t *ciphertext_len, uint8_t *iv);
int decrypt(unsigned char *ciphertext, int ciphertext_len, uint8_t *iv,
            unsigned char *plaintext);

#ifdef __cplusplus
}
#endif

#endif  // CRYPTO_UTILS_H
