# SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: LGPL-3.0-only

echo "Compile x86 binaries"
clang -c -o x86_icall.o icall.c
clang -c -o x86_stack_int.o stack_int.c
clang -c -o x86_stack_mem_arg.o stack_mem_arg.c
clang -c -o x86_stack_multiple.o stack_multiple.c
clang -c -o x86_stack_no_param.o stack_no_param.c
clang -c -o x86_stack_ptr.o stack_ptr.c

echo "Compile Hexagon binaries"
hexagon-unknown-linux-musl-clang -c -O1 -o hexagon_icall.o icall.c
hexagon-unknown-linux-musl-clang -c -O1 -o hexagon_stack_int.o stack_int.c
hexagon-unknown-linux-musl-clang -c -O1 -o hexagon_stack_mem_arg.o stack_mem_arg.c
hexagon-unknown-linux-musl-clang -c -O1 -o hexagon_stack_multiple.o stack_multiple.c
hexagon-unknown-linux-musl-clang -c -O1 -o hexagon_stack_no_param.o stack_no_param.c
hexagon-unknown-linux-musl-clang -c -O1 -o hexagon_stack_ptr.o stack_ptr.c

