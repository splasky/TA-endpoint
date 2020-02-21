#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto_utils.h"

#define keybits 256

uint8_t test_payload1[] = "0123456789abcdef";
const uint16_t test_paylen1 = 16;

const uint8_t test_payload2[] = {
    99,  44,  121, 217, 149, 161, 127, 33,  133, 77,  125, 156, 53,  53,  248, 95,  57,  196, 141, 90,  121, 158,
    133, 218, 153, 153, 24,  84,  32,  245, 68,  131, 33,  189, 93,  182, 94,  220, 215, 227, 42,  85,  127, 95,
    138, 119, 190, 196, 60,  75,  30,  181, 233, 164, 143, 130, 61,  167, 214, 93,  156, 26,  225, 189, 216, 62,
    116, 54,  26,  75,  26,  68,  160, 153, 163, 43,  17,  97,  239, 77,  172, 13,  0,   149, 177, 145, 24,  239,
    57,  238, 76,  213, 9,   45,  147, 225, 107, 7,   23,  134, 82,  49,  202, 243, 203, 110, 30,  220, 207, 13,
    41,  124, 26,  43,  17,  204, 188, 41,  187, 245, 24,  7,   203, 33,  53,  94,  2,   160, 101, 25,  38,  183,
    75,  241, 170, 22,  95,  200, 242, 46,  213, 27,  170, 240, 70,  188, 188, 2,   229, 119, 248, 253, 126, 195,
    30,  179, 33,  32,  84,  134, 58,  122, 61,  133, 107, 232, 155, 202, 176, 141, 249, 134, 168, 163, 118, 238,
    95,  50,  240, 69,  169, 232, 66,  39,  171, 97,  219, 204, 129, 47,  82,  187, 169, 144, 64,  21,  120, 219,
    223, 40,  104, 216, 174, 16,  124, 36,  254, 219, 86,  239, 32,  255, 215, 99,  39,  131, 196, 2,   79,  69,
    49,  162, 1,   218, 50,  65,  239, 170, 29,  207, 210, 133, 167, 129, 150, 35,  165, 148, 255, 252, 131, 31,
    251, 91,  130, 34,  222, 70,  36,  45,  140, 85,  207, 141, 48,  1,   206, 31,  171, 235, 238, 126, 113};
const uint16_t test_paylen2 = 263;

const uint8_t iv_global[16] = {164, 3, 98, 193, 52, 162, 107, 252, 184, 42, 74, 225, 157, 26, 88, 72};
const char* device_id = "470010171566423";
const uint8_t key[32] = {82,  142, 184, 64,  74, 105, 126, 65,  154, 116, 14,  193, 208, 41,  8,  115,
                         158, 252, 228, 160, 79, 5,   167, 185, 13,  159, 135, 113, 49,  209, 58, 68};

int main(void) {
  // TODO:prefer to use c unittest framework
  uint8_t ciphertext[1024] = {0}, iv[16] = {0}, plain[1024] = {0};
  uint32_t ciphertext_len = 0;
  /* mbedtls_aes needs r/w iv[] */
  uint8_t iv_en[16], iv_dec[16];
  memcpy(iv_en, iv_global, 16);
  memcpy(iv_dec, iv_global, 16);

  printf("=============== AES Test1 =============== \n");
  ciphertext_len = aes_encrypt(test_payload1, test_paylen1, key, keybits, iv_en, ciphertext, 1024);
  aes_decrypt(ciphertext, ciphertext_len, key, keybits, iv_dec, plain, 1024);
  /* compare payload */
  if (!memcmp(test_payload1, plain, test_paylen1)) {
    printf("SUCCESS \n");
  } else {
    printf("FAILED \n");
  }

  printf("=============== AES Test2 =============== \n");
  ciphertext_len = aes_encrypt(test_payload2, test_paylen2, key, keybits, iv_en, ciphertext, 1024);
  aes_decrypt(ciphertext, ciphertext_len, key, keybits, iv_dec, plain, 1024);
  /* compare payload */
  if (!memcmp(test_payload2, plain, test_paylen2)) {
    printf("SUCCESS \n");
  } else {
    printf("FAILED \n");
  }

  /////////////////////////////////////////////////////////////////////
  printf("=============== Wrapper Test =============== \n");
  // TODO:request the hash of current order from hashchain and use it as
  // AES key hashchain would be another leagato original application
  uint8_t private_key[AES_BLOCK_SIZE * 2] = {0};
  char id[IMSI_LEN + 1] = {0};
#ifndef DEBUG
  if (get_aes_key(private_key) != 0) {
    fprintf(stderr, "%s\n", "get aes key error");
    return -1;
  }
  // fetch Device_ID (IMSI, len <= 15)
  if (get_device_id(id) != 0) {
    fprintf(stderr, "%s\n", "get device id error");
    return -1;
  }
#else
  memcpy(id, device_id, 16);
  memcpy(private_key, key, 16);
  memcpy(iv, iv_global, 16);
#endif

  memset(ciphertext, 0, 1024);
  memset(plain, 0, 1024);
  ciphertext_len = encrypt(test_payload2, test_paylen2, ciphertext, 1024, iv, private_key, id);
  decrypt(ciphertext, ciphertext_len, plain, 1024, iv, private_key);

  /* compare payload */
  if (!memcmp(test_payload2, plain, test_paylen2)) {
    printf("SUCCESS \n");
  } else {
    printf("FAILED \n");
  }
  return 0;
}
