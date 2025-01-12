// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#![allow(non_snake_case)]

mod test {
    use bda::bda_binding::rz_analysis_bda_handler;
    use binding::{get_rz_test_bin_path, init_rizin_instance, RzCoreWrapper};

    #[test]
    fn test_call_target_loop() {
        let test_bin = get_rz_test_bin_path()
            .join("elf")
            .join("analysis")
            .join("hexagon-hello-loop");
        let core = init_rizin_instance(test_bin.into_os_string().to_str().unwrap());
        let rz_core = RzCoreWrapper::new(core);
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.timeout", "5");
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.threads", "1");
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.entries", "0x6000");
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.sampling.range", "0x6000-0x7000");
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.skip_questions", "true");
        rz_analysis_bda_handler(core, 0, std::ptr::null_mut());
    }
}
