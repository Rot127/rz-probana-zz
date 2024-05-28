// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>

static const char *S = "Abstract interpreter stack var test - pointer argument";

void f_char_p(const char *p) {
  printf("%s\n", p);
}

void stack_ptr() {
  f_char_p(S);
}
