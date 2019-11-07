#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto_utils.h"
#include "https.h"

#define HOST "https://tangle-accel.biilabs.io/"
#define API "transaction/"
#define REQ_BODY                                                           \
  "{\"value\": 0, \"tag\": \"POWEREDBYTANGLEACCELERATOR9\", \"message\": " \
  "\"%s\"}\r\n\r\n"
#define MSG "THISISMSG9THISISMSG9THISISMSG"
void ascii_to_trytes(unsigned char const *const input, char *const output) {
  const char tryte_alphabet[] = "9ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  int j = 0, dec = 0, first = 0, second = 0;

  for (size_t i = 0; input[i]; i++) {
    dec = input[i];
    first = dec & 15;
    second = (dec >> 4) & 15;
    output[j++] = tryte_alphabet[first];
    output[j++] = tryte_alphabet[second];
  }
}

int main(int argc, char *argv[]) {
  char req_body[1024], response[4096], msg[1024], tryte_msg[1024];
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

  encrypt(MSG, strlen(MSG), msg);
  ascii_to_trytes(msg, tryte_msg);
  sprintf(req_body, REQ_BODY, tryte_msg);
  http_info.request.close = false;
  http_info.request.chunked = false;
  snprintf(http_info.request.method, 8, "POST");
  snprintf(http_info.request.content_type, 256, "application/json");
  http_info.request.content_length = strlen(req_body);
  size = http_info.request.content_length;

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
