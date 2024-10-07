// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#![allow(non_snake_case)]

mod test {
    use bda::bda_binding::rz_analysis_bda_handler;
    use binding::{
        get_rz_test_bin_path, init_rizin_instance, wait_for_exlusive_core, RzCoreWrapper,
    };

    /// General "run BDA from beginning to end" tests.
    /// Nothing should break or hang.

    #[test]
    fn test_x86_cfg_test() {
        wait_for_exlusive_core!();

        let test_bin = get_rz_test_bin_path()
            .join("elf")
            .join("analysis")
            .join("x86_cfg_test");
        let core = init_rizin_instance(test_bin.into_os_string().to_str().unwrap());
        let rz_core = RzCoreWrapper::new(core);
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.timeout", "5");
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.entries", "0x08000040");
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.skip_questions", "true");
        rz_analysis_bda_handler(core, 0, std::ptr::null_mut());
    }

    #[test]
    fn test_arm_ls() {
        wait_for_exlusive_core!();

        let test_bin = get_rz_test_bin_path()
            .join("elf")
            .join("analysis")
            .join("arm-ls");
        let core = init_rizin_instance(test_bin.into_os_string().to_str().unwrap());
        let rz_core = RzCoreWrapper::new(core);
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.timeout", "5");
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.entries", "0x00011e90");
        rz_analysis_bda_handler(core, 0, std::ptr::null_mut());
    }

    #[test]
    fn test_ppc_execstack() {
        wait_for_exlusive_core!();

        let test_bin = get_rz_test_bin_path()
            .join("elf")
            .join("analysis")
            .join("elf-ppc-execstack");
        let core = init_rizin_instance(test_bin.into_os_string().to_str().unwrap());
        let rz_core = RzCoreWrapper::new(core);
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.timeout", "5");
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.skip_questions", "true");
        rz_analysis_bda_handler(core, 0, std::ptr::null_mut());
    }

    #[test]
    fn test_hexagon_test_jmp() {
        wait_for_exlusive_core!();

        let test_bin = get_rz_test_bin_path()
            .join("elf")
            .join("hexagon")
            .join("rzil")
            .join("test_jmp");
        let core = init_rizin_instance(test_bin.into_os_string().to_str().unwrap());
        let rz_core = RzCoreWrapper::new(core);
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.timeout", "5");
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.skip_questions", "true");
        rz_analysis_bda_handler(core, 0, std::ptr::null_mut());
    }

    #[test]
    fn test_hexagon_hello_loop() {
        wait_for_exlusive_core!();

        let test_bin = get_rz_test_bin_path()
            .join("elf")
            .join("analysis")
            .join("hexagon-hello-loop");
        let core = init_rizin_instance(test_bin.into_os_string().to_str().unwrap());
        let rz_core = RzCoreWrapper::new(core);
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.timeout", "10");
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.entries", "0x5110");
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.skip_questions", "true");
        rz_analysis_bda_handler(core, 0, std::ptr::null_mut());
    }
}
