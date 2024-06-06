# SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: LGPL-3.0-only

echo "Compile x86 binaries"
clang -c -o x86_icall.o icall.c

echo "Compile Hexagon binaries"
hexagon-unknown-linux-musl-clang -c -O1 -o hexagon_icall.o icall.c

