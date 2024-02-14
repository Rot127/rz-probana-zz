// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

/// Write a log message in Rizin style.
pub fn log_rz(level: rz_log_level, msg: String) {
    print!(
        "{}",
        match level {
            rz_log_level_RZ_LOGLVL_SILLY => "SILLY: ",
            rz_log_level_RZ_LOGLVL_DEBUG => "DEBUG: ",
            rz_log_level_RZ_LOGLVL_VERBOSE => "VERBOSE: ",
            rz_log_level_RZ_LOGLVL_INFO => "INFO: ",
            rz_log_level_RZ_LOGLVL_WARN => "WARN: ",
            rz_log_level_RZ_LOGLVL_ERROR => "ERROR: ",
            rz_log_level_RZ_LOGLVL_FATAL => "FATAL: ",
            _ => "UNKNOWN: ",
        }
    );
    print!("{}:{} ", file!(), line!());
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
