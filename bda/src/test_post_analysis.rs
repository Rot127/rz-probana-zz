// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, VecDeque};

    use binding::{
        get_test_bin_path, init_rizin_instance, rz_core_graph_icfg, GRzCore, RzCoreWrapper,
    };

    use crate::{
        bda::{run_bda, testing_bda_on_paths},
        bda_binding::{add_procedures_to_icfg, get_graph},
        flow_graphs::Address,
        icfg::ICFG,
        state::BDAState,
    };

    fn print_dip(DIP: &BTreeSet<(Address, Address)>) {
        println!("DIP:");
        for (a0, a1) in DIP.iter() {
            println!("({a0:#x} <-> {a1:#x})");
        }
    }

    fn get_x86_post_simple_two_deps() -> (GRzCore, ICFG) {
        let discover_o = get_test_bin_path().join("x86_post_simple_two_deps.o");
        let rz_core = RzCoreWrapper::new(init_rizin_instance(
            discover_o.to_str().expect("Path wrong"),
        ));
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.entries", "0x08000040");
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
    pub fn test_post_x86_simple_two_deps() {
        let (core, mut icfg) = get_x86_post_simple_two_deps();
        let mut state = BDAState::new(3, 1, 1, 1);
        let result = run_bda(core, &mut icfg, &mut state, false);
        let Some(dip) = result else {
            panic!("Is none");
        };
        assert!(dip.contains(&(0x8000079, 0x8000059)));
        assert!(dip.contains(&(0x8000079, 0x8000075)));
        assert!(dip.contains(&(0x8000084, 0x8000040)));
        assert_eq!(dip.len(), 3);
    }

    fn get_x86_paper_dep_example() -> (GRzCore, ICFG) {
        let discover_o = get_test_bin_path().join("x86_paper_dep_example.o");
        let rz_core = RzCoreWrapper::new(init_rizin_instance(
            discover_o.to_str().expect("Path wrong"),
        ));
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.entries", "0x08000100");
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.sampling.range", "0x08000090-0x08000120");
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.skip_questions", "true");
        let rz_icfg = unsafe { rz_core_graph_icfg(rz_core.lock().unwrap().get_ptr()) };
        let mut icfg = ICFG::new_graph(get_graph(rz_icfg));
        add_procedures_to_icfg(rz_core.clone(), &mut icfg);
        (rz_core, icfg)
    }

    fn get_x86_post_loop_offsets() -> (GRzCore, ICFG) {
        let discover_o = get_test_bin_path().join("x86_post_loop_offsets.o");
        let rz_core = RzCoreWrapper::new(init_rizin_instance(
            discover_o.to_str().expect("Path wrong"),
        ));
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.entries", "0x08000040");
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.node_duplicates", "9");
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.skip_questions", "true");
        let rz_icfg = unsafe { rz_core_graph_icfg(rz_core.lock().unwrap().get_ptr()) };
        let mut icfg = ICFG::new_graph(get_graph(rz_icfg));
        add_procedures_to_icfg(rz_core.clone(), &mut icfg);
        (rz_core, icfg)
    }

    fn get_x86_post_pass_ref_across_proc() -> (GRzCore, ICFG) {
        let discover_o = get_test_bin_path().join("x86_post_pass_ref_across_proc.o");
        let rz_core = RzCoreWrapper::new(init_rizin_instance(
            discover_o.to_str().expect("Path wrong"),
        ));
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.entries", "0x080000a0");
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
    pub fn test_post_x86_dep_paper_example() {
        let (core, mut icfg) = get_x86_paper_dep_example();
        let mut state = BDAState::new(3, 2, 1, 1);
        let result = run_bda(core, &mut icfg, &mut state, false);
        let Some(dip) = result else {
            panic!("Is none");
        };
        print_dip(&dip);

        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        assert!(dip.get(&(0x800009c, 0x8000098)).is_some());
        assert!(dip.get(&(0x80000b1, 0x8000098)).is_some());
        assert!(dip.get(&(0x80000b8, 0x8000098)).is_some());
        assert!(dip.get(&(0x80000bc, 0x80000b5)).is_some());
        assert!(dip.get(&(0x80000d2, 0x8000098)).is_some());
        assert!(dip.get(&(0x80000d6, 0x80000b5)).is_some());
        assert!(dip.get(&(0x80000d6, 0x80000a0)).is_some());
        assert!(dip.get(&(0x80000e0, 0x8000098)).is_some());
        assert!(dip.get(&(0x80000e4, 0x80000b5)).is_some());
        assert!(dip.get(&(0x80000e4, 0x80000a0)).is_some());
        assert!(dip.get(&(0x80000ed, 0x80000d8)).is_some());
        assert!(dip.get(&(0x80000ed, 0x80000ea)).is_some());
        assert!(dip.get(&(0x80000f5, 0x8000090)).is_some());
        assert!(dip.get(&(0x80000f6, 0x8000113)).is_some());
        assert!(dip.get(&(0x800011f, 0x8000100)).is_some());
        assert_eq!(dip.len(), 15);
        }
    }

    #[test]
    /// Run only two paths, get products and check if the post analysis does the inference correctly.
    pub fn test_post_x86_dep_paper_example_inference() {
        let (core, mut icfg) = get_x86_paper_dep_example();
        let mut state = BDAState::new(3, 2, 1, 1);
        let paths = Vec::from([
            // *p = 1. Return ~(*p).
            VecDeque::from([
                0x08000100, 0x08000101, 0x08000104, 0x08000108, 0x0800010f, 0x08000113, 0x08000090,
                0x08000091, 0x08000094, 0x08000098, 0x0800009c, 0x080000a0, 0x080000a3, 0x080000a8,
                0x080000ab, 0x080000b1, 0x080000b5, 0x080000b8, 0x080000bc, 0x080000bf, 0x080000c4,
                0x080000c9, 0x080000cc, 0x080000e0, 0x080000e4, 0x080000e7, 0x080000ea, 0x080000ed,
                0x080000f1, 0x080000f5, 0x080000f6, 0x08000118, 0x0800011b, 0x0800011f, 0x08000120,
            ]),
            // *p = 0. Return *p.
            VecDeque::from([
                0x08000100, 0x08000101, 0x08000104, 0x08000108, 0x0800010f, 0x08000113, 0x08000090,
                0x08000091, 0x08000094, 0x08000098, 0x0800009c, 0x080000a0, 0x080000a3, 0x080000a8,
                0x080000ab, 0x080000c4, 0x080000c9, 0x080000cc, 0x080000d2, 0x080000d6, 0x080000d8,
                0x080000db, 0x080000ed, 0x080000f1, 0x080000f5, 0x080000f6, 0x08000118, 0x0800011b,
                0x0800011f, 0x08000120,
            ]),
        ]);
        let result = testing_bda_on_paths(core, &mut icfg, &mut state, paths);
        let Some(dip) = result else {
            panic!("Is none");
        };
        print_dip(&dip);

        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        assert!(dip.get(&(0x800009c, 0x8000098)).is_some());
        assert!(dip.get(&(0x80000b1, 0x8000098)).is_some());
        assert!(dip.get(&(0x80000b8, 0x8000098)).is_some());
        assert!(dip.get(&(0x80000bc, 0x80000b5)).is_some());
        assert!(dip.get(&(0x80000d2, 0x8000098)).is_some());
        assert!(dip.get(&(0x80000e0, 0x8000098)).is_some());
        assert!(dip.get(&(0x80000f5, 0x8000090)).is_some());
        assert!(dip.get(&(0x80000f6, 0x8000113)).is_some());
        assert!(dip.get(&(0x800011f, 0x8000100)).is_some());

        // Should be infered by different paths
        assert!(dip.get(&(0x80000d6, 0x80000a0)).is_some());
        assert!(dip.get(&(0x80000d6, 0x80000b5)).is_some());
        assert!(dip.get(&(0x80000e4, 0x80000a0)).is_some());
        assert!(dip.get(&(0x80000e4, 0x80000b5)).is_some());
        assert!(dip.get(&(0x80000ed, 0x80000d8)).is_some());
        assert!(dip.get(&(0x80000ed, 0x80000ea)).is_some());
        assert_eq!(dip.len(), 15);
        }
    }

    #[test]
    pub fn test_post_x86_post_loop_offsets() {
        let (core, mut icfg) = get_x86_post_loop_offsets();

        let mut state = BDAState::new(3, 3, 1, 1);
        let result = run_bda(core, &mut icfg, &mut state, false);
        let Some(dip) = result else {
            panic!("Is none");
        };
        print_dip(&dip);

        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        // Default loop limit is 3. So it should always detect those references.
        assert!(dip.get(&(0x8000072, 0x8000065)).is_some());
        assert!(dip.get(&(0x8000076, 0x8000065)).is_some());
        assert!(dip.get(&(0x800007b, 0x8000065)).is_some());
        assert!(dip.get(&(0x800007f, 0x8000065)).is_some());
        // These should be detected because BDA does a comparison
        // and jump based on a global value. So it should do all iterations.
        // Although they are more than the limit.
        assert!(dip.get(&(0x8000085, 0x8000065)).is_some());
        assert!(dip.get(&(0x800008d, 0x8000065)).is_some());

        // Stack push and pop
        assert!(dip.get(&(0x8000097, 0x8000042)).is_some());
        assert!(dip.get(&(0x8000098, 0x8000040)).is_some());

        assert_eq!(dip.len(), 8);
        }
    }

    #[test]
    pub fn test_post_x86_post_pass_ref_across_proc() {
        let (core, mut icfg) = get_x86_post_pass_ref_across_proc();

        let mut state = BDAState::new(1, 2, 1, 1);
        let result = run_bda(core, &mut icfg, &mut state, false);
        let Some(dip) = result else {
            panic!("Is none");
        };
        print_dip(&dip);

        // Stack push/pop in level_1
        assert!(dip.get(&(0x800004c, 0x8000048)).is_some());
        assert!(dip.get(&(0x8000050, 0x8000044)).is_some());
        // push/pop rbp
        assert!(dip.get(&(0x8000058, 0x8000040)).is_some());
        // return address from call level_1()
        assert!(dip.get(&(0x8000059, 0x800007c)).is_some());

        // Stack push/pop in level_0
        assert!(dip.get(&(0x8000070, 0x8000068)).is_some());
        assert!(dip.get(&(0x8000074, 0x800006c)).is_some());
        assert!(dip.get(&(0x8000081, 0x800006c)).is_some());
        assert!(dip.get(&(0x8000085, 0x8000068)).is_some());
        // push/pop rbp
        assert!(dip.get(&(0x8000090, 0x8000060)).is_some());
        // Retrurn address from call in main()
        assert!(dip.get(&(0x8000091, 0x80000d1)).is_some());

        // Stack push/pop in main
        assert!(dip.get(&(0x80000bd, 0x80000b9)).is_some());
        assert!(dip.get(&(0x80000ca, 0x80000c1)).is_some());
        // push/pop rbp
        assert!(dip.get(&(0x80000e9, 0x80000a0)).is_some());

        // Stack reads
        assert!(dip.get(&(0x80000d6, 0x80000b9)).is_some());
        assert!(dip.get(&(0x80000dd, 0x80000b9)).is_some());
        // p[0] = val + 2 in level_0()
        assert!(dip.get(&(0x80000da, 0x8000089)).is_some());
        // p[1] = val in level_1()
        assert!(dip.get(&(0x80000e1, 0x8000054)).is_some());
        assert_eq!(dip.len(), 17);
    }
}
