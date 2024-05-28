// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

static int function_0() { return 0; }
static int function_1() { return 1; }
static int function_2() { return 2; }

typedef int (*fcn)();

fcn fcn_arr[] = {
  function_0,
  function_1,
  function_2,
};

int run() {
  unsigned int x = 0;
  unsigned int i = 0;
  x += fcn_arr[i]();
  i++;
  x += fcn_arr[i]();
  i++;
  x += fcn_arr[i]();
  return x;
}
