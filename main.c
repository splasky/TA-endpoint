#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "https.h"

#define HOST "https://tangle-accel.biilabs.io/"
#define API "transaction/"

int main(int argc, char *argv[]) {
  char req_body[1024], response[4096];
  int ret, size;
  char url[] = HOST API;
  HTTP_INFO http_info;

  // Init http session. verify: check the server CA cert.
  https_init(&http_info, true, false);

  if (http_open(&http_info, url) < 0) {
    http_strerror(req_body, 1024);
    printf("socket error: %s \n", req_body);

    goto error;
  }

  http_info.request.close = false;
  http_info.request.chunked = false;
  snprintf(http_info.request.method, 8, "POST");
  snprintf(http_info.request.content_type, 256, "application/json");
  size = sprintf(
      req_body,
      "{\"value\": 0, \"tag\": \"POWEREDBYTANGLEACCELERATOR9\"}\r\n\r\n");

  http_info.request.content_length = size;

  if (http_write_header(&http_info) < 0) {
    http_strerror(req_body, 1024);
    printf("socket error: %s \n", req_body);

    goto error;
  }

  if (http_write(&http_info, req_body, size) != size) {
    http_strerror(req_body, 1024);
    printf("socket error: %s \n", req_body);

    goto error;
  }

  // Write end-chunked
  if (http_write_end(&http_info) < 0) {
    http_strerror(req_body, 1024);
    printf("socket error: %s \n", req_body);

    goto error;
  }

  ret = http_read_chunked(&http_info, response, sizeof(response));

  printf("return code: %d \n", ret);
  printf("return body: %s \n", response);

error:
  http_close(&http_info);

  return 0;
}
