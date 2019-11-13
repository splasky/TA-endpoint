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
  unsigned int j = 0, dec = 0, first = 0, second = 0;

  for (size_t i = 0; input[i]; i++) {
    dec = input[i];
    first = dec & 15;
    second = (dec >> 4) & 15;
    output[j++] = tryte_alphabet[first];
    output[j++] = tryte_alphabet[second];
  }
}

void trytes_to_ascii(unsigned char const *const input, char *const output) {
  const char tryte_alphabet[] = "9ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  unsigned int first = 0, second = 0;

  for (size_t i = 0; input[i]; i += 2) {
    if (input[i + 1] == '9') {
      first = 0;
    } else {
      first = input[i + 1] - 64;
    }
    if (input[i] == '9') {
      second = 0;
    } else {
      second = input[i] - 64;
    }

    output[i / 2] = (first << 4) + second;
  }
}

int serialize_msg(uint8_t *ciphertext, uint32_t ciphertext_len, uint8_t *iv,
                  char *out_msg) {
  char str_ciphertext[1025] = {}, str_iv[17] = {};
  memcpy(str_ciphertext, ciphertext, 1024);
  memcpy(str_iv, iv, 16);
  sprintf(out_msg, "%s:%d:%s", str_ciphertext, ciphertext_len, str_iv);
  return 0;
}

int deserialize_msg(char *msg, uint8_t *ciphertext, uint32_t *ciphertext_len,
                    uint8_t *iv) {
  char str_ciphertext[1025] = {}, str_iv[17] = {};
  const char s[2] = ":";
  char *token;
  token = strtok(msg, s);
  memcpy(ciphertext, token, 1024);
  int i = 0;
  while (token != NULL) {
    token = strtok(NULL, s);

    if (i == 0) {
      *ciphertext_len = atoi(token);
    } else if (i == 1) {
      memcpy(iv, token, 16);
      break;
    }
    i++;
  }

  return 0;
}

int main(int argc, char *argv[]) {
  char req_body[1024] = {}, response[4096] = {}, tryte_msg[1024] = {},
       msg[1024] = {};
  uint8_t ciphertext[1024] = {}, iv[16] = {};
  int ret, size;
  char url[] = HOST API;
  HTTP_INFO http_info;

  char msg_de[1024] = {}, plain[1024] = {};
  uint32_t ciphertext_len = 0;
  encrypt(MSG, strlen(MSG), ciphertext, &ciphertext_len, iv);
  serialize_msg(ciphertext, ciphertext_len, iv, msg);
  ascii_to_trytes(msg, tryte_msg);
#if 1
  printf("msg len = %d, tryte_msg = %d\n", strlen(msg), strlen(tryte_msg));
  trytes_to_ascii(tryte_msg, msg_de);
  uint32_t ciphertext_len_de;
  printf("msg = %s \n", msg);
  deserialize_msg(msg_de, ciphertext, &ciphertext_len_de, iv);
  // printf("ciphertext_len_de = ");
  // printf("%d \n", ciphertext_len_de);
  decrypt(ciphertext, ciphertext_len, iv, plain);
  printf("plain = %s \n", plain);
#endif

  // Init http session. verify: check the server CA cert.
  https_init(&http_info, true, false);

  if (http_open(&http_info, url) < 0) {
    http_strerror(req_body, 1024);
    printf("socket error: %s \n", req_body);

    goto error;
  }

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
