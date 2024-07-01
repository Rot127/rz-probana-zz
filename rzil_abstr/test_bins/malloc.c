// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void *dummy_malloc(size_t c) {
  return malloc(c);
}

struct obj0 {
  uint64_t field_a;
  uint32_t field_b;
};

struct obj1 {
  uint32_t field_c;
  uint16_t field_d;
};

int main() {
  struct obj0 *s0 = dummy_malloc(sizeof(struct obj0));
  struct obj1 *s1 = dummy_malloc(sizeof(struct obj1));
  s0->field_a = 0xaaaaaaaaaaaaaaaa;
  s0->field_b = 0xbbbbbbbb;
  s1->field_c = 0xcccc;
  s1->field_d = 0xdd;
  return 0;
}
