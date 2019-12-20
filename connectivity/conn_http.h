/*
 * Copyright (C) 2019 BiiLabs Co., Ltd. and Contributors
 * All Rights Reserved.
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the MIT license. A copy of the license can be found in the file
 * "LICENSE" at the root of this distribution.
 */

#ifndef CONN_HTTP_H
#define CONN_HTTP_H

#ifdef __cplusplus
extern "C" {
#endif

#include "http_parser.h"
#include "mbedtls/certs.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include <stdbool.h>
#include "defined_error.h"

#define HTTP_OK 200

char *http_res_body;

typedef struct {
  bool https;

  mbedtls_net_context *net_ctx;
  mbedtls_entropy_context *entropy;
  mbedtls_ctr_drbg_context *ctr_drbg;
  mbedtls_ssl_context *ssl_ctx;
  mbedtls_ssl_config *ssl_config;
  mbedtls_x509_crt *cacert;
} connect_info_t;

http_retcode_t http_open(connect_info_t *const info,
                         char const *const seed_nonce, char const *const host,
                         char const *const port);
http_retcode_t http_send_request(connect_info_t *const info,
                                 const char const *req);
http_retcode_t http_read_response(connect_info_t *const info, char *res,
                                  size_t res_len);
http_retcode_t http_close(connect_info_t *const info);

http_retcode_t set_post_request(char const *const api, char const *const host,
                                const uint32_t port, char const *const req_body,
                                char **out);
http_retcode_t set_get_request(char const *const api, char const *const host,
                               const uint32_t port, char **out);

int parser_body_callback(http_parser *parser, const char *at, size_t length);

#ifdef __cplusplus
}
#endif

#endif // CONN_HTTP_H
