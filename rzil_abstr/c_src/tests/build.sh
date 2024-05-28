# SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: LGPL-3.0-only

echo "Compile binaries"
clang -c -o icall.o icall.c
clang -c -o stack_int.o stack_int.c
clang -c -o stack_mem_arg.o stack_mem_arg.c
clang -c -o stack_multiple.o stack_multiple.c
clang -c -o stack_no_param.o stack_no_param.c
clang -c -o stack_ptr.o stack_ptr.c
clang -o all stack_*.o all.c
