// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#![allow(non_snake_case)]

use bda::bda_binding::rz_analysis_bda_handler;
use binding::{get_rz_test_bin_path, init_rizin_instance};

#[test]
fn test_aaaaPb_x86_cfg_test() {
    let test_bin = get_rz_test_bin_path()
        .join("elf")
        .join("analysis")
        .join("x86_cfg_test");
    let (core, _analysis) = init_rizin_instance(test_bin.into_os_string().to_str().unwrap());
    rz_analysis_bda_handler(core, 0, std::ptr::null_mut());
}

#[test]
fn test_aaaaPb_hexagon_test_jmp() {
    let test_bin = get_rz_test_bin_path()
        .join("elf")
        .join("hexagon")
        .join("rzil")
        .join("test_jmp");
    let (core, _analysis) = init_rizin_instance(test_bin.into_os_string().to_str().unwrap());
    rz_analysis_bda_handler(core, 0, std::ptr::null_mut());
}

#[test]
fn test_aaaaPb_hexagon_hello_loop() {
    let test_bin = get_rz_test_bin_path()
        .join("elf")
        .join("analysis")
        .join("hexagon_hello_loop");
    let (core, _analysis) = init_rizin_instance(test_bin.into_os_string().to_str().unwrap());
    rz_analysis_bda_handler(core, 0, std::ptr::null_mut());
}
