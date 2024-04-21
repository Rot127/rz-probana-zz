// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use core::panic;
use std::{env, path::PathBuf, str::FromStr};

#[macro_export]
macro_rules! log_rz {
    ($level:ident, $msg:expr, $tag:expr) => {
        log_rizn($level, $msg, $tag, line!(), file!().to_string())
    };
}

pub const LOG_DEBUG: u32 = rz_log_level_RZ_LOGLVL_DEBUG;
pub const LOG_VERBOSE: u32 = rz_log_level_RZ_LOGLVL_VERBOSE;
pub const LOG_INFO: u32 = rz_log_level_RZ_LOGLVL_INFO;
pub const LOG_WARN: u32 = rz_log_level_RZ_LOGLVL_WARN;
pub const LOG_ERROR: u32 = rz_log_level_RZ_LOGLVL_ERROR;
pub const LOG_FATAL: u32 = rz_log_level_RZ_LOGLVL_FATAL;

pub fn get_rz_loglevel() -> u32 {
    unsafe { rz_log_get_level() as u32 }
}

/// Write a log message in Rizin style.
pub fn log_rizn(
    level: rz_log_level,
    tag: Option<String>,
    mut msg: String,
    line: u32,
    mut filename: String,
) {
    msg.push('\n');
    msg.push('\0');
    let mut tag_msg: String = match tag {
        Some(t) => t,
        None => "".to_string(),
    };
    tag_msg.push('\0');
    filename.push('\0');
    unsafe {
        rz_log_bind(
            "\0".as_ptr().cast(),
            filename.as_str().as_ptr().cast(),
            line,
            level,
            tag_msg.as_str().as_ptr().cast(),
            msg.as_str().as_ptr().cast(),
        );
    }
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

pub fn init_rizin_instance(binary: &str) -> *mut RzCore {
    let core: *mut RzCore;
    unsafe {
        core = rz_core_new();
        if core.is_null() {
            panic!("Could not init RzCore.");
        }
        let cf: *const RzCoreFile =
            rz_core_file_open(core, binary.as_ptr().cast(), RZ_PERM_R as i32, 0);
        if cf.is_null() {
            panic!("Could not open file {}", binary);
        }
        rz_core_bin_load(core, std::ptr::null(), 0);
        rz_core_perform_auto_analysis(core, RzCoreAnalysisType_RZ_CORE_ANALYSIS_DEEP);
    };
    core
}

pub fn rz_notify_begin(rz_core: *mut RzCore, mut msg: String) {
    msg.push('\0');
    unsafe { rz_core_notify_begin_bind(rz_core, msg.as_ptr().cast()) };
}

pub fn rz_notify_done(rz_core: *mut RzCore, mut msg: String) {
    msg.push('\0');
    unsafe { rz_core_notify_done_bind(rz_core, msg.as_ptr().cast()) };
}

pub fn rz_notify_error(rz_core: *mut RzCore, mut msg: String) {
    msg.push('\0');
    unsafe { rz_core_notify_error_bind(rz_core, msg.as_ptr().cast()) };
}
