// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file This file calls various functions which access the stack is different ways.
 */

#include <stdio.h>

extern size_t stack_no_param();
extern const char *stack_ptr(void);
extern size_t stack_int();
extern size_t stack_mul();
extern size_t stack_mem_arg();

int main() {
  size_t i = stack_no_param();
  const char *r = stack_ptr();
  i += stack_int();
  i += stack_mul();
  i += stack_mem_arg();
  return 0;
}
