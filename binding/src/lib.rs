// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use core::panic;
use std::{env, path::PathBuf, ptr::null_mut, str::FromStr};

#[macro_export]
macro_rules! log_rz {
    ($level:ident, $msg:expr) => {
        log_rizn_style($level, $msg, line!())
    };
}

pub const LOG_SILLY: u32 = rz_log_level_RZ_LOGLVL_SILLY;
pub const LOG_DEBUG: u32 = rz_log_level_RZ_LOGLVL_DEBUG;
pub const LOG_VERBOSE: u32 = rz_log_level_RZ_LOGLVL_VERBOSE;
pub const LOG_INFO: u32 = rz_log_level_RZ_LOGLVL_INFO;
pub const LOG_WARN: u32 = rz_log_level_RZ_LOGLVL_WARN;
pub const LOG_ERROR: u32 = rz_log_level_RZ_LOGLVL_ERROR;
pub const LOG_FATAL: u32 = rz_log_level_RZ_LOGLVL_FATAL;

fn get_rz_loglevel() -> u32 {
    unsafe { rz_log_get_level() as u32 }
}

/// Write a log message in Rizin style.
pub fn log_rizn_style(level: rz_log_level, msg: String, line: u32) {
    if level < get_rz_loglevel() {
        return;
    }
    print!(
        "{}",
        match level {
            LOG_SILLY => "SILLY: ",
            LOG_DEBUG => "DEBUG: ",
            LOG_VERBOSE => "VERBOSE: ",
            LOG_INFO => "INFO: ",
            LOG_WARN => "WARN: ",
            LOG_ERROR => "ERROR: ",
            LOG_FATAL => "FATAL: ",
            _ => "UNKNOWN: ",
        }
    );
    print!("{}:{} ", file!(), line);
    print!("{}", msg);
    println!(""); // to get a new line at the end
}

// We redefine this struct and don't use the auto-generated one.
// Because the .data member is otherwise defined a mutable.
// This is a problem, because we can define the RzAnalysisPlugin struct only
// as const. And hence the assignment fails.
#[doc = " \\brief Represent the content of a plugin\n\n This structure should be pointed by the 'rizin_plugin' symbol found in the\n loaded library (e.g. .so file)."]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rz_lib_struct_t {
    #[doc = "< type of the plugin to load"]
    pub type_: RzLibType,
    #[doc = "< pointer to data handled by plugin handler (e.g. RzBinPlugin, RzAsmPlugin, etc.)"]
    pub data: *const ::std::os::raw::c_void,
    #[doc = "< rizin version this plugin was compiled for"]
    pub version: *const ::std::os::raw::c_char,
    pub free: ::std::option::Option<unsafe extern "C" fn(data: *mut ::std::os::raw::c_void)>,
    pub is_plugin_owned: bool,
}

pub type RzLibStruct = rz_lib_struct_t;

pub fn get_rz_test_bin_path() -> PathBuf {
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
