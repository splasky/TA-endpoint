/*
 * Copyright (C) 2019 BiiLabs Co., Ltd. and Contributors
 * All Rights Reserved.
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the MIT license. A copy of the license can be found in the file
 * "LICENSE" at the root of this distribution.
 */

#ifndef TRYTE_BYTE_CONV_H
#define TRYTE_BYTE_CONV_H

#ifdef __cplusplus
extern "C" {
#endif

void ascii_to_trytes(unsigned char const *const input, char *const output);
void trytes_to_ascii(unsigned char const *const input, char *const output);

#ifdef __cplusplus
}
#endif

#endif  // TRYTE_BYTE_CONV_H