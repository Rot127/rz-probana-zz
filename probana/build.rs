// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#[macro_use]
mod bindgen_blocklist;

use std::env;
use std::path::PathBuf;

fn main() {
    let rz_repo: String = match env::var("RZ_REPO_PATH") {
        Ok(v) => v,
        Err(_e) => {
            println!("RZ_REPO_PATH must be set to Rizins repo path.");
            std::process::exit(1)
        }
    };
    let rz_install_root: String = match env::var("RZ_INSTALL_ROOT_PATH") {
        Ok(v) => v,
        Err(_e) => String::from(""), // Try root
    };
    println!("cargo:rustc-link-search=/usr/local/lib");
    println!("cargo:rustc-link-search={}/usr/local/lib", rz_install_root);
    println!("cargo:rerun-if-changed=wrapper.h");

    println!("RZ_INSTALL_ROOT_PATH={}", rz_install_root);

    let bindings_setup = bindgen::Builder::default()
        .header("wrapper.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Finish the builder and generate the bindings.
        .clang_arg(format!("-I{}/usr/local/include/librz", rz_install_root))
        .clang_arg(format!(
            "-I{}/usr/local/include/librz/rz_util",
            rz_install_root
        ))
        .clang_arg(format!("-I{}/usr/local/include/librz/sdb", rz_install_root))
        .clang_arg(format!(
            "-I{}/usr/local/include/librz/rz_crypto",
            rz_install_root
        ))
        .clang_arg(format!(
            "-I{}/usr/local/include/librz/rz_il",
            rz_install_root
        ))
        .clang_arg(format!(
            "-I{}/usr/local/include/librz/rz_il/definitions",
            rz_install_root
        ))
        .clang_arg(format!("-I{}/librz/util/sdb/src/", rz_repo));
    let bindings = block_list!(bindings_setup)
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
