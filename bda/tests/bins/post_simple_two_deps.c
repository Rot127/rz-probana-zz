// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdlib.h>
#include <stdint.h>

int main() {
  uint8_t *x = malloc(10);
  if (rand()) {
    x = malloc(5);
  }
  return x[0];
}

