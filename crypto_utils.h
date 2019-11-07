/*
 * Copyright (C) 2018-2019 BiiLabs Co., Ltd. and Contributors
 * All Rights Reserved.
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the MIT license. A copy of the license can be found in the file
 * "LICENSE" at the root of this distribution.
 */

#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

int encrypt(unsigned char *plaintext, int plaintext_len,
            unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);

#ifdef __cplusplus
}
#endif

#endif  // CRYPTO_UTILS_H
