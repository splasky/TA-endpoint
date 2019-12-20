/*
 * Copyright (C) 2019 BiiLabs Co., Ltd. and Contributors
 * All Rights Reserved.
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the MIT license. A copy of the license can be found in the file
 * "LICENSE" at the root of this distribution.
 */

#ifndef ERROR_H
#define ERROR_H

#ifdef __cplusplus
extern "C" {
#endif

#define HTTP_OK 200

typedef enum {
  RET_OK,
  RET_WRITE_ERROR,
  RET_OOM,
  RET_HTTP_INIT,
  RET_HTTP_CERT,
  RET_HTTP_CONNECT,
  RET_HTTP_SSL,
} http_retcode_t;

#ifdef __cplusplus
}
#endif

#endif // ERROR_H
