// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#[cfg(test)]
mod tests {
    use binding::{
        get_test_bin_path, init_rizin_instance, rz_core_graph_icfg, wait_for_exlusive_core,
        GRzCore, RzCoreWrapper,
    };

    use crate::{
        bda::run_bda,
        bda_binding::{add_procedures_to_icfg, get_graph},
        icfg::ICFG,
        state::BDAState,
    };

    fn get_x86_paper_dep_example() -> (GRzCore, ICFG) {
        let discover_o = get_test_bin_path().join("x86_paper_dep_example.o");
        let rz_core = RzCoreWrapper::new(init_rizin_instance(
            discover_o.to_str().expect("Path wrong"),
        ));
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.entries", "0x08000090");
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.sampling.range", "0x08000090-0x080000f6");
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.skip_questions", "true");
        let rz_icfg = unsafe { rz_core_graph_icfg(rz_core.lock().unwrap().get_ptr()) };
        let mut icfg = ICFG::new_graph(get_graph(rz_icfg));
        add_procedures_to_icfg(rz_core.clone(), &mut icfg);
        (rz_core, icfg)
    }

    #[test]
    pub fn test_x86_dep_search_on_input() {
        wait_for_exlusive_core!();

        let (core, mut icfg) = get_x86_paper_dep_example();
        let mut state = BDAState::new(3, 5, 1, 1);
        run_bda(core, &mut icfg, &mut state);
    }
}
