// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>

size_t f_no_param() {
  return 0xaaaaaa0000;
}

size_t stack_no_param() {
  return f_no_param();
}
