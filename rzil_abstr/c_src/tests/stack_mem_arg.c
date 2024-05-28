// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdint.h>
#include <stdio.h>

size_t f_mem_arg(size_t a0, size_t a1, size_t a2, size_t a3, size_t a4,
                 size_t a5, size_t a6, size_t a7, size_t a8, size_t a9,
                 size_t a10, size_t a11, size_t a12, size_t a13, size_t a14,
                 size_t a15, size_t a16, size_t a17, size_t a18, size_t a19,
                 size_t a20, size_t a21, size_t a22, size_t a23, size_t a24,
                 size_t a25, size_t a26, size_t a27, size_t a28, size_t a29) {
  return a0 + a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8 + a9 + a10 + a11 + a12 +
         a13 + a14 + a15 + a16 + a17 + a18 + a19 + a20 + a21 + a22 + a23 + a24 +
         a25 + a26 + a27 + a28 + a29;
}

size_t stack_mem_arg() {
  return f_mem_arg(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
                   18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29);
}
