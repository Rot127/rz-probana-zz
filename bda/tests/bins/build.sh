# SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: LGPL-3.0-only

echo "Compile x86 binaries"
clang -c -o x86_unmapped_fcn_in_loop.o unmapped_fcn_in_loop.c
clang -c -o x86_discover_recurse.o discover_recurse.c
clang -c -o x86_icall_malloc.o icall_malloc.c
clang -c -o x86_paper_dep_example.o paper_dep_example.c
clang -c -o x86_post_simple_two_deps.o post_simple_two_deps.c

echo "Compile Hexagon binaries"
hexagon-unknown-linux-musl-clang -c -O0 -o hexagon_unmapped_fcn_in_loop.o unmapped_fcn_in_loop.c
hexagon-unknown-linux-musl-clang -c -O0 -o hexagon_discover_recurse.o discover_recurse.c
hexagon-unknown-linux-musl-clang -c -O0 -o hexagon_icall_malloc.o icall_malloc.c
hexagon-unknown-linux-musl-clang -c -O0 -o hexagon_paper_dep_example.o paper_dep_example.c
hexagon-unknown-linux-musl-clang -c -O0 -o hexagon_post_simple_two_deps.o post_simple_two_deps.c
