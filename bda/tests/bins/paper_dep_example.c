// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file The example function from figure 2.12.
 * https://doi.org/10.25394/PGS.23542014.v1
 */

#include <stdint.h>
#include <stdlib.h>

char *foo(char p) {
  return malloc(p + (rand() % 100));
}

int input() {
  return rand();
}

char bar(char *p) {
  *p = 0;
  if (input()) {
    *p = 1;
    foo(*p);
  }
  if (input())
    return *p;
  else
    return ~(*p);
}

int main() {
  char x;
  return bar(&x);
}
