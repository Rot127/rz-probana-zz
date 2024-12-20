// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdint.h>
#include <stdlib.h>

int main() {
  uint8_t *x = malloc(5);
  for (size_t i = 0; i < 5; ++i) {
    x[i] = rand();
  }
  return x[0] | x[1] | x[2] | x[3] | x[4] | x[5];
}
