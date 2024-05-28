// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use helper::rz::{parse_bda_entry_list, parse_bda_range_conf_val, parse_bda_timeout};
use std::ffi::CString;
use std::ptr::null;

use bda::bda_binding::rz_analysis_bda_handler;
use binding::{
    c_to_str, log_rizin, log_rz, pderef, rz_cmd_desc_arg_t__bindgen_ty_1,
    rz_cmd_desc_arg_t__bindgen_ty_1__bindgen_ty_1, rz_cmd_desc_argv_new, rz_cmd_desc_group_new,
    rz_cmd_get_desc, rz_cmd_status_t_RZ_CMD_STATUS_OK, rz_config_lock, rz_config_node_desc,
    rz_config_set_cb, rz_config_set_i_cb, rz_core_cmd_help, str_to_c, RzCmdDesc, RzCmdDescArg,
    RzCmdDescHelp, RzCmdStatus, RzConfigNode, RzCore, RzCorePlugin, RzLibStruct,
    RzLibType_RZ_LIB_TYPE_CORE, LOG_ERROR, RZ_VERSION,
};
use cty::c_void;

pub enum HighestPluginFunction {
    Binding,
    Bda,
    Osprey,
    None,
}

pub const analysis_probana_help: RzCmdDescHelp = RzCmdDescHelp {
    summary: "Probabalistic binary analysis algorithms\0".as_ptr().cast(),
    description: "Probabalistic binary analysis algorithms BDA, OSPREY and StochFuzz\0"
        .as_ptr()
        .cast(),
    args_str: "\0".as_ptr().cast(),
    usage: null(),
    options: null(),
    sort_subcommands: false,
    details: null(),
    details_cb: None,
    args: null(),
};

pub const help_msg_aaaaP: *const i8 = "Usage:\0aaaaP\0".as_ptr().cast();

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
            rz_cmd_get_desc((*core).rcmd, "aa\0".as_ptr().cast()),
            "aaaaP\0".as_ptr().cast(),
            None,
            &analysis_probana_help,
            &analysis_probana_help,
        )
    }
}

pub extern "C" fn rz_probana_init_core(core: *mut RzCore) -> bool {
    // Just register the group
    get_probana_cmd_desc(core);
    true
}

pub const rz_core_plugin_probana: RzCorePlugin = RzCorePlugin {
    name: "Probana\0".as_ptr().cast(),
    desc: "Probabalistic binary analysis algorithms designed by Zhuo Zhang.\0"
        .as_ptr()
        .cast(),
    license: "LGPL-3.0-only\0".as_ptr().cast(),
    author: "Rot127\0".as_ptr().cast(),
    version: "0.1\0".as_ptr().cast(),
    init: Some(rz_probana_init_core),
    fini: None,
    analysis: None,
};

pub const rizin_plugin_probana: RzLibStruct = RzLibStruct {
    type_: RzLibType_RZ_LIB_TYPE_CORE, // Until RzArch is introduced, we leave this as a core plugin, so we can add the command.
    data: &rz_core_plugin_probana as *const _ as *const c_void,
    version: RZ_VERSION.as_ptr().cast(),
    free: None,
    is_plugin_owned: true,
};

pub const analysis_bda_help_args: RzCmdDescArg = RzCmdDescArg {
    name: null(),
    optional: false,
    no_space: false,
    type_: 0,
    flags: 0,
    default_value: null(),
    __bindgen_anon_1: rz_cmd_desc_arg_t__bindgen_ty_1 {
        choices: rz_cmd_desc_arg_t__bindgen_ty_1__bindgen_ty_1 {
            choices: "\0".as_ptr() as *mut *const i8,
            choices_cb: None,
        },
    },
};

pub const analysis_bda_help: RzCmdDescHelp = RzCmdDescHelp {
    summary: "Run bda dependency analysis (algorithm: BDA).\0"
        .as_ptr()
        .cast(),
    description: "Detect memory dependencies via abstract interpretation over sampled paths.\0"
        .as_ptr()
        .cast(),
    args_str: null(),
    usage: null(),
    options: null(),
    sort_subcommands: false,
    details: null(),
    details_cb: None,
    args: &analysis_bda_help_args,
};

pub extern "C" fn rz_set_bda_range(core: *mut c_void, node: *mut c_void) -> bool {
    let _ = core as *mut RzCore;
    let rz_node = node as *mut RzConfigNode;
    // Just perform a check on the given value.
    if parse_bda_range_conf_val(c_to_str(pderef!(rz_node).value)).is_none() {
        return false;
    }
    true
}

pub extern "C" fn rz_set_bda_entry(core: *mut c_void, node: *mut c_void) -> bool {
    let _ = core as *mut RzCore;
    let rz_node = node as *mut RzConfigNode;
    // Just perform a check on the given value.
    if parse_bda_entry_list(c_to_str(pderef!(rz_node).value)).is_none() {
        return false;
    }
    true
}

pub extern "C" fn rz_set_bda_iterations(core: *mut c_void, node: *mut c_void) -> bool {
    let _ = core as *mut RzCore;
    let rz_node = node as *mut RzConfigNode;
    // Just perform a check on the given value.
    if pderef!(rz_node).i_value > 64 {
        log_rz!(
            LOG_ERROR,
            None,
            "Maximum number of iterations capped at 64."
        );
        return false;
    }
    true
}

pub extern "C" fn rz_set_bda_node_dups(core: *mut c_void, node: *mut c_void) -> bool {
    let _ = core as *mut RzCore;
    let rz_node = node as *mut RzConfigNode;
    // Just perform a check on the given value.
    if pderef!(rz_node).i_value > 64 {
        log_rz!(
            LOG_ERROR,
            None,
            "Maximum number of node duplicates capped at 64."
        );
        return false;
    }
    true
}

pub extern "C" fn rz_set_bda_timeout(core: *mut c_void, node: *mut c_void) -> bool {
    let _ = core as *mut RzCore;
    let rz_node = node as *mut RzConfigNode;
    // Just perform a check on the given value.
    if parse_bda_timeout(c_to_str(pderef!(rz_node).value)).is_none() {
        return false;
    }
    true
}

pub extern "C" fn rz_bda_init_core(core: *mut RzCore) -> bool {
    unsafe {
        // Add bda commands
        let binding_cd: *mut RzCmdDesc = get_probana_cmd_desc(core);
        rz_cmd_desc_argv_new(
            (*core).rcmd,
            binding_cd,
            "aaaaPb\0".as_ptr().cast(),
            Some(rz_analysis_bda_handler),
            &analysis_bda_help,
        );
        rz_config_lock(pderef!(core).config, 0);
        // Add settings for BDA
        rz_config_node_desc(
            rz_config_set_cb(
                pderef!(core).config,
                str_to_c!("plugins.bda.range"),
                str_to_c!("0x0-0xffffffffffffffff"),
                Some(rz_set_bda_range),
            ),
            str_to_c!("Comma separated list of address ranges to analyse."),
        );
        rz_config_node_desc(
            rz_config_set_cb(
                pderef!(core).config,
                str_to_c!("plugins.bda.entries"),
                str_to_c!(""),
                Some(rz_set_bda_entry),
            ),
            str_to_c!(
                "Comma separated list of address to start path sampling from. Addresses must point to a function start. If empty, the binary entry points are used."
            ),
        );
        rz_config_node_desc(
            rz_config_set_cb(
                pderef!(core).config,
                str_to_c!("plugins.bda.timeout"),
                str_to_c!("10:00:00"),
                Some(rz_set_bda_timeout),
            ),
            str_to_c!("Maximum runtime. Allowed formats: DD:HH:MM:SS, HH:MM:SS, MM:SS, SS"),
        );
        rz_config_node_desc(
            rz_config_set_i_cb(
                pderef!(core).config,
                str_to_c!("plugins.bda.repeat_iterations"),
                32,
                Some(rz_set_bda_iterations),
            ),
            str_to_c!("Maximum number of iterations for non-static RzIL REPEAT operations."),
        );
        rz_config_node_desc(
            rz_config_set_i_cb(
                pderef!(core).config,
                str_to_c!("plugins.bda.node_duplicates"),
                3,
                Some(rz_set_bda_node_dups),
            ),
            str_to_c!(
                "Number of node duplications, when loops with unknown iterations are resolved within CFGs and iCFGs."
            ),
        );
        rz_config_lock(pderef!(core).config, 1);
    };
    true
}

pub const rz_core_plugin_bda: RzCorePlugin = RzCorePlugin {
    name: "BDA\0".as_ptr().cast(),
    desc: "Dependency detection algorithm by Zhuo Zhang.\0"
        .as_ptr()
        .cast(),
    license: "LGPL-3.0-only\0".as_ptr().cast(),
    author: "Rot127\0".as_ptr().cast(),
    version: "0.1\0".as_ptr().cast(),
    init: Some(rz_bda_init_core),
    fini: None,
    analysis: None,
};

pub const rizin_plugin_bda: RzLibStruct = RzLibStruct {
    type_: RzLibType_RZ_LIB_TYPE_CORE, // Until RzArch is introduced, we leave this as a core plugin, so we can add the command.
    data: &rz_core_plugin_bda as *const _ as *const c_void,
    version: RZ_VERSION.as_ptr().cast(),
    free: None,
    is_plugin_owned: true,
};

pub extern "C" fn rizin_plugin_function_bda() -> RzLibStruct {
    rizin_plugin_bda
}

pub extern "C" fn rizin_plugin_function_probana() -> RzLibStruct {
    rizin_plugin_probana
}

#[no_mangle]
pub extern "C" fn rizin_plugin_function() -> RzLibStruct {
    // TODO Check this during build
    let highest_defined_function = HighestPluginFunction::Bda;
    match highest_defined_function {
        // HighestPluginFunction::Osprey => rizin_plugin_function_osprey,
        HighestPluginFunction::Bda => rizin_plugin_function_bda(),
        HighestPluginFunction::Binding => rizin_plugin_function_probana(),
        _ => panic!("Cannot call rizin_plugin_function."),
    }
}
