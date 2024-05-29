// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

fn main() {
    println!("cargo:rustc-link-arg=-Wl,--copy-dt-needed-entries");
    println!("cargo:rustc-link-arg=-lrz_core");
}
