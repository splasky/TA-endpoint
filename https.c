//
// Created by HISONA on 2016. 2. 29..
//

#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ca_cert.h"
#include "https.h"

static int _error;

char *strtoken(char *src, char *dst, int size) {
  char *p, *st, *ed;
  int len = 0;

  // l-trim
  p = src;

  while (true) {
    if ((*p == '\n') || (*p == 0)) {
      return NULL;
    } /* value is not exists */
    if ((*p != ' ') && (*p != '\t')) {
      break;
    }
    p++;
  }

  st = p;
  while (true) {
    ed = p;
    if (*p == ' ') {
      p++;
      break;
    }
    if ((*p == '\n') || (*p == 0)) {
      break;
    }
    p++;
  }

  while (true) {
    ed--;
    if (st == ed) {
      break;
    }
    if ((*ed != ' ') && (*ed != '\t')) {
      break;
    }
  }

  len = (int)(ed - st + 1);
  if ((size > 0) && (len >= size)) {
    len = size - 1;
  }

  strncpy(dst, st, len);
  dst[len] = 0;

  return p;
}

static int parse_url(char *src_url, int *https, char *host, char *port,
                     char *url) {
  char *p1, *p2;
  char str[1024];

  memset(str, 0, 1024);

  if (strncmp(src_url, "http://", 7) == 0) {
    p1 = &src_url[7];
    *https = 0;
  } else if (strncmp(src_url, "https://", 8) == 0) {
    p1 = &src_url[8];
    *https = 1;
  } else {
    p1 = &src_url[0];
    *https = 0;
  }

  if ((p2 = strstr(p1, "/")) == NULL) {
    sprintf(str, "%s", p1);
    sprintf(url, "/");
  } else {
    strncpy(str, p1, p2 - p1);
    snprintf(url, 256, "%s", p2);
  }

  if ((p1 = strstr(str, ":")) != NULL) {
    *p1 = 0;
    snprintf(host, 256, "%s", str);
    snprintf(port, 5, "%s", p1 + 1);
  } else {
    snprintf(host, 256, "%s", str);

    if (*https == 0)
      snprintf(port, 5, "80");
    else
      snprintf(port, 5, "443");
  }

  return 0;
}

static int http_header(HTTP_INFO *hi, char *param) {
  char *token;
  char t1[256], t2[256];
  int len;

  token = param;

  if ((token = strtoken(token, t1, 256)) == 0) {
    return error;
  }
  if ((token = strtoken(token, t2, 256)) == 0) {
    return error;
  }

  if (strncasecmp(t1, "HTTP", 4) == 0) {
    hi->response.status = atoi(t2);
  } else if (strncasecmp(t1, "set-cookie:", 11) == 0) {
    snprintf(hi->response.cookie, 512, "%s", t2);
  } else if (strncasecmp(t1, "location:", 9) == 0) {
    len = (int)strlen(t2);
    strncpy(hi->response.location, t2, len);
    hi->response.location[len] = 0;
  } else if (strncasecmp(t1, "content-length:", 15) == 0) {
    hi->response.content_length = atoi(t2);
  } else if (strncasecmp(t1, "transfer-encoding:", 18) == 0) {
    if (strncasecmp(t2, "chunked", 7) == 0) {
      hi->response.chunked = true;
    }
  } else if (strncasecmp(t1, "connection:", 11) == 0) {
    if (strncasecmp(t2, "close", 5) == 0) {
      hi->response.close = true;
    }
  }

  return 1;
}

static int http_parse(HTTP_INFO *hi) {
  char *p1, *p2;
  long len;

  if (hi->r_len <= 0) {
    return error;
  }

  p1 = hi->r_buf;

  while (true) {
    if (hi->header_end == false)  // header parser
    {
      if ((p2 = strstr(p1, "\r\n")) != NULL) {
        len = (long)(p2 - p1);
        *p2 = 0;

        if (len > 0) {
          http_header(hi, p1);
          p1 = p2 + 2;  // skip CR+LF
        } else {
          hi->header_end = true;  // reach the header-end.
          p1 = p2 + 2;            // skip CR+LF

          if (hi->response.chunked == true) {
            len = hi->r_len - (p1 - hi->r_buf);
            if (len > 0) {
              if ((p2 = strstr(p1, "\r\n")) != NULL) {
                *p2 = 0;
                if ((hi->length = strtol(p1, NULL, 16)) == 0) {
                  hi->response.chunked = false;
                } else {
                  hi->response.content_length += hi->length;
                }
                p1 = p2 + 2;  // skip CR+LF
              } else {
                // copy the data as chunked size ...
                strncpy(hi->r_buf, p1, len);
                hi->r_buf[len] = 0;
                hi->r_len = len;
                hi->length = -1;

                break;
              }
            } else {
              hi->r_len = 0;
              hi->length = -1;

              break;
            }
          } else {
            hi->length = hi->response.content_length;
          }
        }

      } else {
        len = hi->r_len - (p1 - hi->r_buf);
        if (len > 0) {
          // keep the partial header data ...
          strncpy(hi->r_buf, p1, len);
          hi->r_buf[len] = 0;
          hi->r_len = len;
        } else {
          hi->r_len = 0;
        }

        break;
      }
    } else  // body parser
    {
      if (hi->response.chunked == true && hi->length == -1) {
        len = hi->r_len - (p1 - hi->r_buf);
        if (len > 0) {
          if ((p2 = strstr(p1, "\r\n")) != NULL) {
            *p2 = 0;

            if ((hi->length = strtol(p1, NULL, 16)) == 0) {
              hi->response.chunked = false;
            } else {
              hi->response.content_length += hi->length;
            }

            p1 = p2 + 2;  // skip CR+LF
          } else {
            // copy the remain data as chunked size
            strncpy(hi->r_buf, p1, len);
            hi->r_buf[len] = 0;
            hi->r_len = len;
            hi->length = -1;

            break;
          }
        } else {
          hi->r_len = 0;

          break;
        }
      } else {
        if (hi->length > 0) {
          len = hi->r_len - (p1 - hi->r_buf);

          if (len > hi->length) {
            // copy the data for response ..
            if (hi->body_len < hi->body_size - 1) {
              if (hi->body_size > (hi->body_len + hi->length)) {
                strncpy(&(hi->body[hi->body_len]), p1, hi->length);
                hi->body_len += hi->length;
                hi->body[hi->body_len] = 0;
              } else {
                strncpy(&(hi->body[hi->body_len]), p1,
                        hi->body_size - hi->body_len - 1);
                hi->body_len = hi->body_size - 1;
                hi->body[hi->body_len] = 0;
              }
            }

            p1 += hi->length;
            len -= hi->length;

            if (hi->response.chunked == true && len >= 2) {
              p1 += 2;  // skip CR+LF
              hi->length = -1;
            } else {
              return error;
            }
          } else {
            // copy the data for response ..
            if (hi->body_len < hi->body_size - 1) {
              if (hi->body_size > (hi->body_len + len)) {
                strncpy(&(hi->body[hi->body_len]), p1, len);
                hi->body_len += len;
                hi->body[hi->body_len] = 0;
              } else {
                strncpy(&(hi->body[hi->body_len]), p1,
                        hi->body_size - hi->body_len - 1);
                hi->body_len = hi->body_size - 1;
                hi->body[hi->body_len] = 0;
              }
            }

            hi->length -= len;
            hi->r_len = 0;

            if (hi->response.chunked == false && hi->length <= 0) {
              return 1;
            }

            break;
          }
        } else {
          if (hi->response.chunked == false) {
            return 1;
          }

          // chunked size check ..
          if ((hi->r_len > 2) && (memcmp(p1, "\r\n", 2) == 0)) {
            p1 += 2;
            hi->length = -1;
          } else {
            hi->length = -1;
            hi->r_len = 0;
          }
        }
      }
    }
  }

  return 0;
}

int https_init(HTTP_INFO *hi, bool https, bool verify) {
  memset(hi, 0, sizeof(HTTP_INFO));

  if (https == true) {
    mbedtls_ssl_init(&hi->tls.ssl);
    mbedtls_ssl_config_init(&hi->tls.conf);
    mbedtls_x509_crt_init(&hi->tls.cacert);
    mbedtls_ctr_drbg_init(&hi->tls.ctr_drbg);
  }

  mbedtls_net_init(&hi->tls.ssl_fd);

  // verify: check the server CA cert
  hi->tls.verify = verify;
  hi->url.https = https;
  return 0;
}

static int https_close(HTTP_INFO *hi) {
  if (hi->url.https == true) {
    mbedtls_ssl_close_notify(&hi->tls.ssl);
  }

  mbedtls_net_free(&hi->tls.ssl_fd);

  if (hi->url.https == true) {
    mbedtls_x509_crt_free(&hi->tls.cacert);
    mbedtls_ssl_free(&hi->tls.ssl);
    mbedtls_ssl_config_free(&hi->tls.conf);
    mbedtls_ctr_drbg_free(&hi->tls.ctr_drbg);
    mbedtls_entropy_free(&hi->tls.entropy);
  }
  return 0;
}

/*
 * Initiate a TCP connection with host:port and the given protocol
 * waiting for timeout (ms)
 */
static int mbedtls_net_connect_timeout(mbedtls_net_context *ctx,
                                       const char *host, const char *port,
                                       int proto, uint32_t timeout) {
  http_retcode_t ret;
  struct addrinfo hints, *addr_list, *cur;

  signal(SIGPIPE, SIG_IGN);

  /* Do name resolution with both IPv6 and IPv4 */
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = proto == MBEDTLS_NET_PROTO_UDP ? SOCK_DGRAM : SOCK_STREAM;
  hints.ai_protocol =
      proto == MBEDTLS_NET_PROTO_UDP ? IPPROTO_UDP : IPPROTO_TCP;

  if (getaddrinfo(host, port, &hints, &addr_list) != 0)
    return (MBEDTLS_ERR_NET_UNKNOWN_HOST);

  /* Try the sockaddrs until a connection succeeds */
  ret = MBEDTLS_ERR_NET_UNKNOWN_HOST;
  for (cur = addr_list; cur != NULL; cur = cur->ai_next) {
    ctx->fd = (int)socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
    if (ctx->fd < 0) {
      ret = MBEDTLS_ERR_NET_SOCKET_FAILED;
      continue;
    }

    if (mbedtls_net_set_nonblock(ctx) < 0) {
      close(ctx->fd);
      ctx->fd = -1;
      ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
      break;
    }

    if (connect(ctx->fd, cur->ai_addr, cur->ai_addrlen) == 0) {
      ret = 0;
      break;
    } else if (errno == EINPROGRESS) {
      int fd = (int)ctx->fd;
      int opt;
      socklen_t slen;
      struct timeval tv;
      fd_set fds;

      while (true) {
        FD_ZERO(&fds);
        FD_SET(fd, &fds);

        tv.tv_sec = timeout / 1000;
        tv.tv_usec = (timeout % 1000) * 1000;

        ret = select(fd + 1, NULL, &fds, NULL, timeout == 0 ? NULL : &tv);
        if (ret == -1) {
          if (errno == EINTR) continue;
        } else if (ret == 0) {
          close(fd);
          ctx->fd = -1;
          ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
        } else {
          ret = 0;

          slen = sizeof(int);
          if ((getsockopt(fd, SOL_SOCKET, SO_ERROR, (void *)&opt, &slen) ==
               0) &&
              (opt > 0)) {
            close(fd);
            ctx->fd = -1;
            ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
          }
        }

        break;
      }

      break;
    }

    close(ctx->fd);
    ctx->fd = -1;
    ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
  }

  freeaddrinfo(addr_list);

  if ((ret == 0) && (mbedtls_net_set_block(ctx) < 0)) {
    close(ctx->fd);
    ctx->fd = -1;
    ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
  }

  return ret;
}

static int https_connect(HTTP_INFO *hi, char *host, char *port) {
  http_retcode_t ret;
  bool https = hi->url.https;

  if (https == true) {
    mbedtls_entropy_init(&hi->tls.entropy);

    ret = mbedtls_ctr_drbg_seed(&hi->tls.ctr_drbg, mbedtls_entropy_func,
                                &hi->tls.entropy, NULL, 0);
    if (ret != success) {
      return ret;
    }

    ca_crt_rsa[ca_crt_rsa_size - 1] = 0;
    ret = mbedtls_x509_crt_parse(&hi->tls.cacert, (uint8_t *)ca_crt_rsa,
                                 ca_crt_rsa_size);
    if (ret != success) {
      return ret;
    }

    ret = mbedtls_ssl_config_defaults(&hi->tls.conf, MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != success) {
      return ret;
    }

    /* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
    mbedtls_ssl_conf_authmode(&hi->tls.conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&hi->tls.conf, &hi->tls.cacert, NULL);
    mbedtls_ssl_conf_rng(&hi->tls.conf, mbedtls_ctr_drbg_random,
                         &hi->tls.ctr_drbg);
    mbedtls_ssl_conf_read_timeout(&hi->tls.conf, 5000);

    ret = mbedtls_ssl_setup(&hi->tls.ssl, &hi->tls.conf);
    if (ret != success) {
      return ret;
    }

    ret = mbedtls_ssl_set_hostname(&hi->tls.ssl, host);
    if (ret != success) {
      return ret;
    }
  }

  ret = mbedtls_net_connect_timeout(&hi->tls.ssl_fd, host, port,
                                    MBEDTLS_NET_PROTO_TCP, 5000);
  if (ret != success) {
    return ret;
  }

  if (https == true) {
    mbedtls_ssl_set_bio(&hi->tls.ssl, &hi->tls.ssl_fd, mbedtls_net_send,
                        mbedtls_net_recv, mbedtls_net_recv_timeout);

    while ((ret = mbedtls_ssl_handshake(&hi->tls.ssl)) != 0) {
      if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
          ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
        return ret;
      }
    }

    /* In real life, we probably want to bail out when ret != 0 */
    if (hi->tls.verify && (mbedtls_ssl_get_verify_result(&hi->tls.ssl) != 0)) {
      return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
    }
  }

  return 0;
}

static int https_write(HTTP_INFO *hi, char *buffer, int len) {
  http_retcode_t ret;
  int slen = 0;

  while (true) {
    if (hi->url.https == true) {
      ret = mbedtls_ssl_write(&hi->tls.ssl, (unsigned char *)&buffer[slen],
                              (size_t)(len - slen));
    } else {
      ret = mbedtls_net_send(&hi->tls.ssl_fd, (unsigned char *)&buffer[slen],
                             (size_t)(len - slen));
    }

    if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
      continue;
    } else if (ret <= 0) {
      return ret;
    }
  }
    slen += ret;

    if (slen >= len) {
      break;
    }
  }

  return slen;
}

static int https_read(HTTP_INFO *hi, char *buffer, int len) {
  if (hi->url.https == true) {
    return mbedtls_ssl_read(&hi->tls.ssl, (unsigned char *)buffer, (size_t)len);
  } else {
    return mbedtls_net_recv_timeout(&hi->tls.ssl_fd, (unsigned char *)buffer,
                                    (size_t)len, 5000);
  }
}

http_retcode_t http_close(HTTP_INFO *hi) { return https_close(hi); }

void http_strerror(char *buf, int len) { mbedtls_strerror(_error, buf, len); }

http_retcode_t http_open(HTTP_INFO *hi, char *url) {
  char host[256], port[10], dir[1024];
  int sock_fd, verify;
  bool https;
  http_retcode_t ret;
  int opt;
  socklen_t slen;

  if (NULL == hi) {
    return error;
  }

  verify = hi->tls.verify;

  parse_url(url, &https, host, port, dir);

  if ((hi->tls.ssl_fd.fd == -1) || (hi->url.https != https) ||
      (strcmp(hi->url.host, host) != 0) || (strcmp(hi->url.port, port) != 0)) {
    if (hi->tls.ssl_fd.fd != -1) {
      https_close(hi);
    }

    https_init(hi, https, verify);

    if ((ret = https_connect(hi, host, port)) < 0) {
      https_close(hi);

      _error = ret;

      return error;
    }
  } else {
    sock_fd = hi->tls.ssl_fd.fd;

    slen = sizeof(int);

    if ((getsockopt(sock_fd, SOL_SOCKET, SO_ERROR, (void *)&opt, &slen) < 0) ||
        (opt > 0)) {
      https_close(hi);

      https_init(hi, https, verify);

      if ((ret = https_connect(hi, host, port)) < 0) {
        https_close(hi);

        _error = ret;

        return error;
      }
    }
  }

  strncpy(hi->url.host, host, strlen(host));
  strncpy(hi->url.port, port, strlen(port));
  strncpy(hi->url.path, dir, strlen(dir));

  return 0;
}

http_retcode_t http_write_header(HTTP_INFO *hi) {
  char request[4096], buf[H_FIELD_SIZE];
  http_retcode_t ret;
  int len, l;

  if (NULL == hi) {
    return error;
  }

  /* Send HTTP request. */
  len = snprintf(request, 1024,
                 "%s %s HTTP/1.1\r\n"
                 "Host: %s:%s\r\n"
                 "Content-Type: %s\r\n",
                 hi->request.method, hi->url.path, hi->url.host, hi->url.port,
                 hi->request.content_type);

  if (hi->request.referrer[0] != 0) {
    len += snprintf(&request[len], H_FIELD_SIZE, "Referer: %s\r\n",
                    hi->request.referrer);
  }
  if (hi->request.chunked == true) {
    len +=
        snprintf(&request[len], H_FIELD_SIZE, "Transfer-Encoding: chunked\r\n");
  } else {
    len += snprintf(&request[len], H_FIELD_SIZE, "Content-Length: %ld\r\n",
                    hi->request.content_length);
  }

  if (hi->request.close == true) {
    len += snprintf(&request[len], H_FIELD_SIZE, "Connection: close\r\n");
  } else {
    len += snprintf(&request[len], H_FIELD_SIZE, "Connection: Keep-Alive\r\n");
  }

  if (hi->request.cookie[0] != 0) {
    len += snprintf(&request[len], H_FIELD_SIZE, "Cookie: %s\r\n",
                    hi->request.cookie);
  }

  len += snprintf(&request[len], H_FIELD_SIZE, "\r\n");

  printf("%s", request);

  if ((ret = https_write(hi, request, len)) != len) {
    https_close(hi);

    _error = ret;

    return error;
  }

  return 0;
}

http_retcode_t http_write(HTTP_INFO *hi, char *data, int len) {
  char str[10];
  http_retcode_t ret;
  int l;

  if (NULL == hi || len <= 0) {
    return error;
  }

  if (hi->request.chunked == true) {
    l = snprintf(str, 10, "%x\r\n", len);

    if ((ret = https_write(hi, str, l)) != l) {
      https_close(hi);
      _error = ret;

      return error;
    }
  }

  if ((ret = https_write(hi, data, len)) != len) {
    https_close(hi);
    _error = ret;

    return error;
  }

  if (hi->request.chunked == true) {
    if ((ret = https_write(hi, "\r\n", 2)) != 2) {
      https_close(hi);
      _error = ret;

      return error;
    }
  }

  return len;
}

http_retcode_t http_write_end(HTTP_INFO *hi) {
  char str[10];
  http_retcode_t ret;
  int len;

  if (NULL == hi) {
    return error;
  }

  if (hi->request.chunked == true) {
    len = snprintf(str, 10, "0\r\n\r\n");
  } else {
    len = snprintf(str, 10, "\r\n\r\n");
  }

  if ((ret = https_write(hi, str, len)) != len) {
    https_close(hi);
    _error = ret;

    return error;
  }

  return len;
}

http_retcode_t http_read_chunked(HTTP_INFO *hi, char *response, int size) {
  http_retcode_t ret;
  if (NULL == hi) {
    return error;
  }

  hi->response.status = 0;
  hi->response.content_length = 0;
  hi->response.close = 0;

  hi->r_len = 0;
  hi->header_end = 0;

  hi->body = response;
  hi->body_size = size;
  hi->body_len = 0;

  hi->body[0] = 0;

  while (true) {
    ret = https_read(hi, &hi->r_buf[hi->r_len], (int)(H_READ_SIZE - hi->r_len));
    if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
      continue;
    } else if (ret < 0) {
      https_close(hi);
      _error = ret;

      return error;
    } else if (ret == 0) {
      https_close(hi);
      break;
    }
    hi->r_len += ret;
    hi->r_buf[hi->r_len] = 0;

    if (http_parse(hi) != success) {
      break;
    }
  }

  if (hi->response.close == true) {
    https_close(hi);
  }

  return hi->response.status;
}
