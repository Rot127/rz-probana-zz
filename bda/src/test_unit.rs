// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#[cfg(test)]
mod tests {
    use binding::{init_rizin_instance, wait_for_exlusive_core, RzCoreWrapper};

    use crate::bda_binding::setup_procedure_at_addr;

    #[test]
    pub fn test_setup_unmapped_procedure() {
        wait_for_exlusive_core!();

        let rz_core = RzCoreWrapper::new(init_rizin_instance("="));
        let mut unk_procedure = setup_procedure_at_addr(&rz_core.lock().unwrap(), 0x0);
        assert!(
            unk_procedure.is_some(),
            "Procedure was not intiazlized. But should be."
        );
        assert!(
            rz_core.lock().unwrap().run_cmd("f+ malloc @ 0x2"),
            "Running command failed."
        );
        unk_procedure = setup_procedure_at_addr(&rz_core.lock().unwrap(), 0x2);
        assert!(unk_procedure.is_some(), "Procedure was not intiazlized.");
        assert!(
            unk_procedure.unwrap().is_malloc(),
            "Procedure was not markes as malloc although the flag name suggests it."
        );
    }
}
