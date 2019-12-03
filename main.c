#include "crypto_utils.h"
#include "https.h"
#include "serializer.h"
#include "tryte_byte_conv.h"
#include "uart_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HTTP_OK 200
#define HOST "https://tangle-accel.biilabs.io/"
#define API "transaction/"
#define REQ_BODY                                                               \
  "{\"value\": 0, \"tag\": \"POWEREDBYTANGLEACCELERATOR9\", \"message\": "     \
  "\"%s\", \"address\":\"%s\"}\r\n\r\n"
#define ADDRESS                                                                \
  "POWEREDBYTANGLEACCELERATOR999999999999999999999999999999999999999999999999" \
  "999999A"
#define ADDR_LEN 81
//#define MSG "%s:THISISMSG9THISISMSG9THISISMSG"
#define MSG "%s:%s"

void gen_trytes(uint16_t len, char *out) {
  const char tryte_alphabet[] = "9ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  uint8_t rand_index;
  for (int i = 0; i < len; i++) {
    rand_index = rand() % 27;
    out[i] = tryte_alphabet[rand_index];
  }
}

int send_https_msg(HTTP_INFO *http_info, char const *const url,
                   char const *const tryte_msg, char const *const addr) {
  char req_body[1024] = {}, response[4096] = {};
  int ret = 0;
  long size;
  https_init(http_info, true, false);
  while (ret != HTTP_OK) {
    if (http_open(http_info, url) < 0) {
      http_strerror(req_body, 1024);
      printf("socket error: %s \n", req_body);

      goto error;
    }

    sprintf(req_body, REQ_BODY, tryte_msg, addr);
    printf("body = %s \n", req_body);
    http_info->request.close = false;
    http_info->request.chunked = false;
    snprintf(http_info->request.method, 8, "POST");
    snprintf(http_info->request.content_type, 256, "application/json");
    http_info->request.content_length = strlen(req_body);
    size = http_info->request.content_length;

    if (http_write_header(http_info) < 0) {
      http_strerror(req_body, 1024);
      printf("socket error: %s \n", req_body);

      goto error;
    }

    if (http_write(http_info, req_body, size) != size) {
      http_strerror(req_body, 1024);
      printf("socket error: %s \n", req_body);

      goto error;
    }

    // Write end-chunked
    if (http_write_end(http_info) < 0) {
      http_strerror(req_body, 1024);
      printf("socket error: %s \n", req_body);

      goto error;
    }

    ret = http_read_chunked(http_info, response, sizeof(response));

    printf("return code: %d \n", ret);
  }
  printf("return body: %s \n", response);

error:
  http_close(http_info);

  return ret;
}

int main(int argc, char *argv[]) {
  int ret, size;
  HTTP_INFO http_info;

  uint8_t ciphertext[1024] = {}, iv1[16] = {};
  uint32_t raw_msg_len = strlen(MSG) + ADDR_LEN + 8, ciphertext_len = 0,
           msg_len;
  char tryte_msg[1024] = {}, msg[1024] = {}, url[] = HOST API,
       raw_msg[raw_msg_len], next_addr[ADDR_LEN + 1] = {};
  srand(time(NULL));

  int fd = uart_init();
  if (fd < 0) {
    printf("Error opening UART\n");
    return -1;
  }
  char *response = NULL, *addr = ADDRESS;

  while (true) {
    while (response = uart_read(fd)) {
      gen_trytes(ADDR_LEN, next_addr);

      // int gen_value = rand() % 1000; // TODO this could be changed to the
      // real transmitted data
      snprintf(raw_msg, raw_msg_len, MSG, next_addr, response);

      encrypt(raw_msg, strlen(raw_msg), ciphertext, &ciphertext_len, iv1);
      serialize_msg(iv1, ciphertext_len, ciphertext, msg, &msg_len);
      bytes_to_trytes(msg, msg_len, tryte_msg);

      // Init http session. verify: check the server CA cert.
      send_https_msg(&http_info, url, tryte_msg, addr);

      strncpy(addr, next_addr, ADDR_LEN);
      free(response);
      response = NULL;
    }
  }

#if 0
  uint8_t ciphertext_de[1024] = {}, iv2[16] = {};
  char msg_de[1024] = {}, plain[1024] = {};
  uint32_t ciphertext_len_de;
  trytes_to_bytes(tryte_msg, strlen(tryte_msg), msg_de);
  printf("strlen(tryte_msg) = %d \n", strlen(tryte_msg));
  deserialize_msg(msg_de, iv2, &ciphertext_len_de, ciphertext_de);
  printf("tryte_msg = %s \n", tryte_msg);
  if (!memcmp(msg, msg_de, strlen(tryte_msg) / 2)) {
    printf("msg SUCCESS \n");
  } else {
    printf("msg Failed \n");
    for (int j = 0; j < strlen(tryte_msg) / 2; j++) {
      printf("j = %d, msg = %d, msg_de = %d \n", j, msg[j], msg_de[j]);
    }
    return 1;
  }
  if (ciphertext_len == ciphertext_len_de) {
    printf("ciphertext_len SUCCESS \n");
  } else {
    printf("ciphertext_len Failed \n");
    return 1;
  }

  if (!memcmp(iv1, iv2, 16)) {
    printf("iv SUCCESS \n");
  } else {
    printf("iv Failed \n");
    return 1;
  }
  if (ciphertext_len != ciphertext_len_de) {
    printf("ciphertext_len = %d, ciphertext_len_de = %d\n", ciphertext_len,
           ciphertext_len_de);
    return 1;
  }
  if (!memcmp(ciphertext, ciphertext_de, ciphertext_len)) {
    printf("ciphertext SUCCESS \n");
  } else {
    printf("ciphertext Failed \n");
    for (int j = 0; j < ciphertext_len; j++) {
      if (ciphertext[j] != ciphertext_de[j]) {
        printf("=======j = %d, ciphertext = %d, ciphertext_de = %d======= \n",
               j, ciphertext[j], ciphertext_de[j]);
      } else {
        printf("j = %d, ciphertext = %d, ciphertext_de = %d \n", j,
               ciphertext[j], ciphertext_de[j]);
      }
    }
    return 1;
  }

  decrypt(ciphertext, ciphertext_len_de, iv2, plain);

  printf("plain = %s \n", plain);
  sleep(1);
#endif

  return 0;
}