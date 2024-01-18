// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use cty::c_void;

use crate::RzAnalysisPlugin;

pub const rz_analysis_plugin_probana: RzAnalysisPlugin = RzAnalysisPlugin {
    name: "rz_probana".as_ptr().cast(),
    desc: "Probabilistic Binary Analysis Algorithms".as_ptr().cast(),
    license: "LGPL-3.0-only".as_ptr().cast(),
    arch: "".as_ptr().cast(),
    author: "Rot127".as_ptr().cast(),
    version: "0.1".as_ptr().cast(),
    bits: 0,
    esil: 0,
    fileformat_type: 0,
    init: Some(rz_probana_init),
    fini: None,
    archinfo: None,
    analysis_mask: None,
    preludes: None,
    address_bits: None,
    op: None,
    get_reg_profile: None,
    esil_init: None,
    esil_post_loop: None,
    esil_trap: None,
    esil_fini: None,
    il_config: None,
};

pub extern "C" fn rz_probana_init(_user: *mut *mut c_void) -> bool {
    true
}
