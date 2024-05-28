// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdint.h>
#include <stdio.h>

static const char *S = "Abstract interpreter stack var test - multiple arguments";

size_t f_mul(size_t i, const char *cp, uint8_t u8) {
  return i + S[0] + u8;
}

size_t stack_mul() {
  return f_mul(0xaaaaaaaaaa, S, 0xff);
}
