// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdint.h>
#include <stdlib.h>

void level_1(size_t *map, size_t v) {
  map[1] = v;
}

void level_0(size_t *map, size_t v) {
  level_1(map, v + 2);
  map[0] = v;
}

int main() {
  size_t *p = malloc(2);
  level_0(p, rand());
  return p[0] & p[1];
}
