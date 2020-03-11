/*
 * Copyright (C) 2019-2020 BiiLabs Co., Ltd. and Contributors
 * All Rights Reserved.
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the MIT license. A copy of the license can be found in the file
 * "LICENSE" at the root of this distribution.
 */

#ifndef SERIALIZER_H
#define SERIALIZER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int serialize_msg(const uint8_t *iv, uint32_t ciphertext_len, const uint8_t *ciphertext, char *out_msg,
                  uint32_t *out_msg_len);
int deserialize_msg(char *msg, const uint8_t *iv, uint32_t *ciphertext_len, uint8_t *ciphertext);

#ifdef __cplusplus
}
#endif

#endif  // SERIALIZER_H
