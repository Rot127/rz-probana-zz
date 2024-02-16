// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use core::panic;
use std::{env, path::PathBuf, ptr::null_mut, str::FromStr};

pub extern "C" fn get_rz_test_bin_path() -> PathBuf {
    let rz_repo: String = match env::var("RZ_REPO_PATH") {
        Ok(v) => v,
        Err(_e) => {
            println!("RZ_REPO_PATH must be set to Rizins repo path.");
            std::process::exit(1)
        }
    };
    let path = PathBuf::from_str(rz_repo.as_str());
    match path {
        Ok(p) => p.join("test/bins/"),
        Err(_p) => panic!("Could not build path to test bins"),
    }
}
