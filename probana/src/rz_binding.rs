// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use cty::c_void;

use crate::{
    rz_cmd_desc_argv_new, rz_cmd_desc_group_new, rz_cmd_get_desc, rz_cmd_status_t_RZ_CMD_STATUS_OK,
    rz_core_cmd_help, RzCmdDesc, RzCmdDescHelp, RzCmdStatus, RzCore, RzCorePlugin, RzLibType,
    RzLibType_RZ_LIB_TYPE_CORE, RZ_VERSION,
};

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
}

pub const analysis_probana_help: RzCmdDescHelp = RzCmdDescHelp {
    summary: "Probabalistic binary analysis algorithms".as_ptr().cast(),
    description: "Probabalistic binary analysis algorithms BDA, OSPREY and StochFuzz"
        .as_ptr()
        .cast(),
    args_str: "".as_ptr().cast(),
    usage: "".as_ptr().cast(),
    options: "".as_ptr().cast(),
    sort_subcommands: false,
    details: "".as_ptr().cast(),
    details_cb: None,
    args: "".as_ptr().cast(),
};

pub const help_msg_aaaaP: *const i8 =
    "Usage:\0aaaaP\0[bof]\0aaaaPb\0Run BDA.\0aaaaPo\0Run Osprey\0aaaaPf\0Run StochFuzz\0"
        .as_ptr()
        .cast();

pub extern "C" fn rz_analysis_probana_handler(
    core: *mut RzCore,
    _argc: i32,
    _argv: *mut *const i8,
) -> RzCmdStatus {
    unsafe {
        #[allow(const_item_mutation)]
        rz_core_cmd_help(core, &mut help_msg_aaaaP as *mut *const i8)
    };
    return rz_cmd_status_t_RZ_CMD_STATUS_OK;
}

pub fn get_probana_cmd_desc(core: *mut RzCore) -> *mut RzCmdDesc {
    unsafe {
        rz_cmd_desc_group_new(
            (*core).rcmd,
            rz_cmd_get_desc((*core).rcmd, "aaaa".as_ptr().cast()),
            "aaaaP".as_ptr().cast(),
            Some(rz_analysis_probana_handler),
            &analysis_probana_help,
            &analysis_probana_help,
        )
    }
}

pub extern "C" fn rz_probana_init_core(core: *mut RzCore) -> bool {
    unsafe {
        let probana_cd: *mut RzCmdDesc = get_probana_cmd_desc(core);
        rz_cmd_desc_argv_new(
            (*core).rcmd,
            probana_cd,
            "aaaaPb".as_ptr().cast(),
            Some(rz_analysis_probana_handler),
            &analysis_probana_help,
        )
    };
    true
}

pub const rz_core_plugin_probana: RzCorePlugin = RzCorePlugin {
    name: "Probana".as_ptr().cast(),
    desc: "Probabalistic binary analysis algorithms designed by Zhuo Zhang."
        .as_ptr()
        .cast(),
    license: "LGPL-3.0-only".as_ptr().cast(),
    author: "Rot127".as_ptr().cast(),
    version: "0.1".as_ptr().cast(),
    init: Some(rz_probana_init_core),
    fini: None,
    analysis: None,
};

pub type RzLibStruct = rz_lib_struct_t;
#[allow(dead_code)]
pub const rizin_plugin: RzLibStruct = RzLibStruct {
    type_: RzLibType_RZ_LIB_TYPE_CORE, // Until RzArch is introduced, we leave this as a core plugin, so we can add the command.
    data: &rz_core_plugin_probana as *const _ as *const c_void,
    version: RZ_VERSION.as_ptr().cast(),
    free: None,
};

// CMD handler

// RzCmdDesc *analyze_everything_cd = rz_cmd_desc_argv_new(core->rcmd, aa_cd, "aaa", rz_analyze_everything_handler, &analyze_everything_help);
// rz_warn_if_fail(analyze_everything_cd);
