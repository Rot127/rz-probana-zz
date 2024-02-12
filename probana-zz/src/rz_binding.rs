// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

pub enum HighestPluginFunction {
    Binding,
    Bda,
    Osprey,
    None,
}

#[no_mangle]
pub extern "C" fn rizin_plugin_function() -> ::binding::RzLibStruct {
    // TODO Check this during build
    let highest_defined_function = HighestPluginFunction::Bda;
    match highest_defined_function {
        // HighestPluginFunction::Osprey => rizin_plugin_function_osprey,
        HighestPluginFunction::Bda => ::bda::rz_binding::rizin_plugin_function_bda(),
        HighestPluginFunction::Binding => ::binding::rizin_plugin_function_probana(),
        _ => panic!("Cannot call rizin_plugin_function."),
    }
}
