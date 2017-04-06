/*
 * pbkdf2num.c --- generate pbkdf2 based prn
 *
 * Copyright (C) 2017 by Ivan Kelly
 *
 * This file may be distributed under the terms of the GNU Public
 * License.
 */

#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include "pwgen.h"


#define NUM_INTS 10000
#define BUFFER_SIZE (sizeof(int)*NUM_INTS)

unsigned char seed[BUFFER_SIZE];
int seed_idx = 0;

void pw_pbkdf2_setseed(char* input, int len);

void pw_pbkdf2_setseed(char* input, int len) {
  const EVP_MD *digest = EVP_sha512();
  int ret = 0;
  ret = PKCS5_PBKDF2_HMAC(input, len,
                          NULL, 0, 1000,
                          digest,
                          BUFFER_SIZE, seed);
  if (ret != 1) {
    fprintf(stderr, "Error generating data (%d)", ret);
    exit(-1);
  }
}

void pw_pbkdf2_askseed() {
  char input[BUFFER_SIZE];
  char input2[BUFFER_SIZE];

  struct termios ios, orig_ios;
  tcgetattr(0, &orig_ios);
  ios = orig_ios;

  memset(input, 0, BUFFER_SIZE);
  memset(input2, 0, BUFFER_SIZE);

  ios.c_lflag ^= ECHO | ISIG;
  tcsetattr(0, TCSADRAIN, &ios);

  fputs("Seed: ", stdout);
  fgets(input, BUFFER_SIZE, stdin);
  fputs("\nSeed(again): ", stdout);
  fgets(input2, BUFFER_SIZE, stdin);

  tcsetattr(0, TCSADRAIN, &orig_ios);
  fputs("\n", stdout);

  if (strcmp(input, input2) != 0) {
    fputs("Seeds do not match\n", stderr);
    exit(-1);
  }

  pw_pbkdf2_setseed(input, strlen(input));
}

int pw_pbkdf2_number(int max_num)
{
  int index = seed_idx++;
  int* seedi = (char*)seed;
  if (seed_idx >= NUM_INTS) {
    char tmp[BUFFER_SIZE];
    memcpy(tmp, seed, BUFFER_SIZE);
    pw_pbkdf2_setseed(tmp, BUFFER_SIZE);
    seed_idx = 0;
    return pw_pbkdf2_number(max_num);
  } else {
    return abs(seedi[index] % max_num);
  }
}
