#include "conn_http.h"
#include "crypto_utils.h"
#include "http_parser.h"
#include "serializer.h"
#include "tryte_byte_conv.h"
#include "uart_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>

#define HOST "tangle-accel.puyuma.org"
#define PORT "443"
#define API "transaction/"
#define SSL_SEED "nonce"
#define REQ_BODY                                                               \
  "{\"value\": 0, \"tag\": \"POWEREDBYTANGLEACCELERATOR9\", \"message\": "     \
  "\"%s\", \"address\":\"%s\"}\r\n\r\n"
#define ADDRESS                                                                \
  "POWEREDBYTANGLEACCELERATOR999999999999999999999999999999999999999999999999" \
  "999999A"
#define ADDR_LEN 81

#ifndef DEBUG
#define MSG "%s:%s"
#else
#define MSG "%s:THISISMSG9THISISMSG9THISISMSG"
#define ADDR_LOG_PATH "addr_log.log"
#endif

void gen_trytes(uint16_t len, char *out) {
  const char tryte_alphabet[] = "9ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  uint8_t rand_index;
  for (int i = 0; i < len; i++) {
    rand_index = rand() % 27;
    out[i] = tryte_alphabet[rand_index];
  }
}

void send_https_msg(char const *const host, char const *const port,
                    char const *const api, char const *const tryte_msg,
                    char const *const addr) {
  char req_body[1024] = {}, res[4096] = {0};
  char *req = NULL;
  sprintf(req_body, REQ_BODY, tryte_msg, addr);
  set_post_request(api, host, atoi(port), req_body, &req);

#ifdef DEBUG
  printf("req packet = \n%s", req);
#endif

  http_parser_settings settings;
  settings.on_body = parser_body_callback;
  http_parser *parser = malloc(sizeof(http_parser));

  while (parser->status_code != HTTP_OK) {
    connect_info_t info = {.https = true};
    http_open(&info, SSL_SEED, host, port);
    http_send_request(&info, req);
    http_read_response(&info, res, sizeof(res) / sizeof(char));
    http_close(&info);
    http_parser_init(parser, HTTP_RESPONSE);
    size_t nparsed = http_parser_execute(parser, &settings, res, strlen(res));
    printf("HTTP Response: %s\n", http_res_body);
    free(http_res_body);
    http_res_body = NULL;
  }
  free(parser);
}

int main(int argc, char *argv[]) {
  int ret, size;

  uint8_t ciphertext[1024] = {0}, iv[16] = {0};
  uint32_t raw_msg_len = 1 + ADDR_LEN + 20, ciphertext_len = 0, msg_len;
  char tryte_msg[1024] = {0}, msg[1024] = {0}, url[] = HOST API,
       raw_msg[1000] = {0}, addr[ADDR_LEN + 1] = ADDRESS,
       next_addr[ADDR_LEN + 1] = {0}, addr_log_template[] = "\n%s\n",
       addr_log[ADDR_LEN + 3];
  srand(time(NULL));

#ifndef DEBUG
  int fd = uart_init();
  if (fd < 0) {
    printf("Error in initializing UART\n");
    return -1;
  }
#else
  FILE *fp = fopen(ADDR_LOG_PATH, "a");
  snprintf(addr_log, 83, addr_log_template, next_addr);
  fputs(addr_log, fp);
  fclose(fp);
#endif

  char *response = NULL;
  time_t timer;
  char time_str[26];
  struct tm *tm_info;

#ifndef DEBUG
  fd_set rset;
  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = 500;
  while (true) {
    // TODO add select
    FD_ZERO(&rset);
    FD_SET(fd, &rset);
    select(fd + 1, &rset, NULL, NULL, &tv);

    if (FD_ISSET(fd, &rset)) {
#endif
      time(&timer);
      tm_info = localtime(&timer);
      strftime(time_str, 26, "%Y-%m-%d %H:%M:%S", tm_info);
      printf("%s\n", time_str);

      gen_trytes(ADDR_LEN, next_addr);

#ifndef DEBUG
      response = uart_read(fd);
#else
  response = strdup("This is a test");
  printf("next_addr = %s \n", next_addr);

  // Append the next address to the address log file
  fp = fopen(ADDR_LOG_PATH, "a");
  snprintf(addr_log, 83, addr_log_template, next_addr);
  fputs(addr_log, fp);
  fclose(fp);
#endif
      // real transmitted data
      snprintf(raw_msg, raw_msg_len, MSG, next_addr, response);
      printf("Raw Message: %s\n", raw_msg);
      encrypt(raw_msg, strlen(raw_msg), ciphertext, &ciphertext_len, iv);

      serialize_msg(iv, ciphertext_len, ciphertext, msg, &msg_len);
      bytes_to_trytes(msg, msg_len, tryte_msg);

      // Init http session. verify: check the server CA cert.
      send_https_msg(HOST, PORT, API, tryte_msg, addr);

      strncpy(addr, next_addr, ADDR_LEN);
      free(response);
      response = NULL;
      printf("========================Finishing Sending "
             "Transaction========================\n\n");
#ifndef DEBUG
    }
    if (tcflush(fd, TCIOFLUSH) != 0) {
      perror("tcflush error");
    }
  }
#endif

  return 0;
}