/*
 * Copyright (C) 2019-2020 BiiLabs Co., Ltd. and Contributors
 * All Rights Reserved.
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the MIT license. A copy of the license can be found in the file
 * "LICENSE" at the root of this distribution.
 */

#ifndef UTILS_PROTOCOL_H
#define UTILS_PROTOCOL_H

#include "defined_error.h"

/**
 * @brief Send message via http protocol
 *
 * @param[in] host Https host
 * @param[in] port Https port
 * @param[in] api API for post request to https server, example: transaction/. Must be
 * string.
 * @param[in] msg Message to send
 * @param[in] msg_len Length of message
 * @param[in] ssl_seed Seed for ssl connection
 *
 * @return #retcode_t
 */
retcode_t send_https_msg(char const *host, char const *port, char const *api, const char *msg, const int msg_len,
                         const char *ssl_seed);
#endif  // UTILS_PROTOCOL_H
