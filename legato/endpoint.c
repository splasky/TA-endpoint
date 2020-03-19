#include "interfaces.h"
#include "legato.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include "connectivity/conn_http.h"
#include "utils/crypto_utils.h"
#include "utils/serializer.h"
#include "utils/tryte_byte_conv.h"
#include "utils/uart_utils.h"
#include "utils/url.h"

#define MSG "%s:%s"

#define SSL_SEED "nonce"
#define ADDRESS                                                                \
  "POWEREDBYTANGLEACCELERATOR999999999999999999999999999999999999999999999999" \
  "999999A"
#define ADDR_LEN 81
#define ADDR_LOG_PATH "ta-endpoint.log"

const char *HOST = STRINGIZE(TA_HOST);
const char *PORT = STRINGIZE(TA_PORT);
const char *API = STRINGIZE(TA_API);

/**
 * Prints the on-line help and exits.  This function is called when "-h" or "--help" appears on
 * the command-line or when the help command is invoked.
 **/
static void PrintHelp(void) {
  puts(
      "NAME\n"
      "        ta-enpoint - Transcation information with Tangle-accerlator.\n"
      "\n"
      "SYNOPSIS\n"
      "        ta-endpoint [OPTION]...\n"
      "        ta-endpoint -h\n"
      "        ta-endpoint --help\n"
      "\n"
      "COMMANDS\n"
      "       help\n"
      "               Print a help message and exit. Ignore all other arguments.\n"
      "\n"
      "OPTIONS\n"
      "       -h\n"
      "       --host=<host ip or name>\n"
      "               Setting host ip or name for connect ta accerlator.\n"
      "               If not setting, would connect default host.\n"
      "\n"
      "       -p N\n"
      "       --port=<port>\n"
      "               Setting host port for connect ta accerlator\n"
      "               If not setting, would connect default port\n");

  exit(EXIT_SUCCESS);
}

COMPONENT_INIT {
  uint8_t addr[ADDR_LEN] = ADDRESS, next_addr[ADDR_LEN] = {0}, iv[16] = {0};
  char raw_msg[1000] = {0}, ciphertext[1024] = {0};
  char tryte_msg[1024] = {0}, msg[1024] = {0};
  uint32_t raw_msg_len = 1 + ADDR_LEN + 20, ciphertext_len = 0, msg_len = 0;

  srand(time(NULL));

  // Register a function to be called if -h or --help appears on the command-line.
  le_arg_SetFlagCallback(PrintHelp, NULL, "help");
  // Set host to the value HOST given by "-h <string>" or "--host=<string>"
  le_arg_SetStringVar(&HOST, "h", "host");
  // Set port to the value PORT given by "-p N" or "--port=N"
  le_arg_SetStringVar(&PORT, "p", "port");

  // Perform command-line argument processing.
  le_arg_Scan();

  // init uart for modem
  int fd = uart_init();
  if (fd < 0) {
    LE_ERROR("Error in initializing UART\n");
  }

  // create log file
  if (write_address(ADDR_LOG_PATH, next_addr, ADDR_LEN) != 0) {
    LE_ERROR("log address failed\n");
  }

  char *response = NULL;
  time_t timer;
  char time_str[26];
  struct tm *tm_info;

  fd_set rset;
  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = 500;
  // TODO:change to none blocking I/O descriptor
  while (true) {
    FD_ZERO(&rset);
    FD_SET(fd, &rset);
    select(fd + 1, &rset, NULL, NULL, &tv);

    if (FD_ISSET(fd, &rset)) {
      time(&timer);
      tm_info = localtime(&timer);
      strftime(time_str, 26, "%Y-%m-%d %H:%M:%S", tm_info);
      printf("%s\n", time_str);
      gen_rand_trytes(ADDR_LEN, next_addr);

      response = uart_read(fd);
      // real transmitted data
      snprintf(raw_msg, raw_msg_len, MSG, next_addr, response);
      LE_DEBUG("Raw_msg:%s\n", raw_msg);
      uint8_t private_key[AES_KEY_SIZE] = {0};
      uint8_t id[IMSI_LEN + 1] = {0};

      if (get_aes_key(private_key) != 0) {
        LE_ERROR("%s\n", "get aes key error");
      }
      // fetch Device_ID (IMSI, len <= 15)
      if (get_device_id(id) != 0) {
        LE_ERROR("%s\n", "get device id error");
      }

      ciphertext_len = ta_encrypt(raw_msg, strlen(raw_msg), ciphertext, 1024, iv, private_key, id);
      if (ciphertext_len == 0) {
        LE_ERROR("%s\n", "ta_encrypt msg error");
      }
      serialize_msg(iv, ciphertext_len, ciphertext, msg, &msg_len);
      bytes_to_trytes((const unsigned char *)msg, msg_len, tryte_msg);

      // Init http session. verify: check the server CA cert.
      char msg_body[1024];
      gen_tryte_msg(tryte_msg, addr, msg_body);
      if (send_https_msg(HOST, PORT, API, msg_body, 1024, SSL_SEED) != HTTP_OK) {
        LE_ERROR("Response from ta server failed\n");
      }

      memcpy(addr, next_addr, ADDR_LEN);

      free(response);
      response = NULL;
      printf(
          "========================Finishing Sending "
          "Transaction========================\n\n");
    }
    if (tcflush(fd, TCIOFLUSH) != 0) {
      perror("tcflush error");
    }
  }
}
