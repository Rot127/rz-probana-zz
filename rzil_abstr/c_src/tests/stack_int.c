// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>

size_t f_int(size_t i) {
  return i + 1;
}

size_t stack_int() {
  return f_int(0x00000001);
}
