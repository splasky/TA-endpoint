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

#define AES_BLOCK_SIZE 16
#define MAXLINE 1024
#define IMSI_LEN 15

int get_device_id(const char *device_id);
int get_aes_key(const uint8_t *key);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext, int ciphertext_len, uint8_t iv[16],
            uint8_t key[AES_BLOCK_SIZE * 2], uint8_t device_id[IMSI_LEN + 1]);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext, int plaintext_len, uint8_t iv[16],
            uint8_t key[AES_BLOCK_SIZE * 2]);
int aes_encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, unsigned int keybits,
                unsigned char iv[16], unsigned char *ciphertext, int ciphertext_len);
int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, unsigned int keybits,
                unsigned char iv[16], unsigned char *plaintext, int plaintext_len);

#ifdef __cplusplus
}
#endif

#endif  // CRYPTO_UTILS_H
