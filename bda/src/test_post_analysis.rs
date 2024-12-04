// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use binding::{
        get_test_bin_path, init_rizin_instance, rz_core_graph_icfg, wait_for_exlusive_core,
        GRzCore, RzCoreWrapper,
    };

    use crate::{
        bda::{run_bda, testing_bda_on_paths},
        bda_binding::{add_procedures_to_icfg, get_graph},
        icfg::ICFG,
        state::BDAState,
    };

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
    pub fn test_x86_post_simple_two_deps() {
        wait_for_exlusive_core!();

        let (core, mut icfg) = get_x86_post_simple_two_deps();
        let mut state = BDAState::new(3, 1, 1, 1);
        let result = run_bda(core, &mut icfg, &mut state);
        let Some(dep) = result else {
            panic!("Is none");
        };
        assert!(dep
            .get(&0x8000079)
            .is_some_and(|set| { set.contains(&0x8000059) && set.contains(&0x8000075) }));
        assert!(dep
            .get(&0x8000084)
            .is_some_and(|set| { set.contains(&0x8000040) }));
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

    #[test]
    pub fn test_x86_dep_paper_example() {
        wait_for_exlusive_core!();

        let (core, mut icfg) = get_x86_paper_dep_example();
        let mut state = BDAState::new(3, 2, 1, 1);
        let result = run_bda(core, &mut icfg, &mut state);
        let Some(dep) = result else {
            panic!("Is none");
        };

        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        assert!(dep.get(&0x800009c).is_some_and(|set| { set.len() == 1 && set.contains(&0x8000098) }));
        assert!(dep.get(&0x80000b1).is_some_and(|set| { set.len() == 1 && set.contains(&0x8000098) }));
        assert!(dep.get(&0x80000b8).is_some_and(|set| { set.len() == 1 && set.contains(&0x8000098) }));
        assert!(dep.get(&0x80000bc).is_some_and(|set| { set.len() == 1 && set.contains(&0x80000b5) }));
        assert!(dep.get(&0x80000d2).is_some_and(|set| { set.len() == 1 && set.contains(&0x8000098) }));
        assert!(dep.get(&0x80000d6).is_some_and(|set| { set.len() == 2 && set.contains(&0x80000a0) && set.contains(&0x80000b5) }));
        assert!(dep.get(&0x80000e0).is_some_and(|set| { set.len() == 1 && set.contains(&0x8000098) }));
        assert!(dep.get(&0x80000e4).is_some_and(|set| { set.len() == 2 && set.contains(&0x80000a0) && set.contains(&0x80000b5) }));
        assert!(dep.get(&0x80000ed).is_some_and(|set| { set.len() == 2 && set.contains(&0x80000d8) && set.contains(&0x80000ea) }));
        assert!(dep.get(&0x80000f5).is_some_and(|set| { set.len() == 1 && set.contains(&0x8000090) }));
        assert!(dep.get(&0x80000f6).is_some_and(|set| { set.len() == 2 && set.contains(&0x8000090) && set.contains(&0x8000113) }));
        assert!(dep.get(&0x8000120).is_some_and(|set| { set.len() == 1 && set.contains(&0x8000100) }));
        assert_eq!(dep.len(), 12, "DEP is:\n{dep:x}");
        }
    }

    #[test]
    /// Run only two paths, get products and check if the post analysis does the inference correctly.
    pub fn test_x86_dep_paper_example_inference() {
        wait_for_exlusive_core!();

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
        let Some(dep) = result else {
            panic!("Is none");
        };

        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        assert!(dep.get(&0x800009c).is_some_and(|set| { set.len() == 1 && set.contains(&0x8000098) }));
        assert!(dep.get(&0x80000b1).is_some_and(|set| { set.len() == 1 && set.contains(&0x8000098) }));
        assert!(dep.get(&0x80000b8).is_some_and(|set| { set.len() == 1 && set.contains(&0x8000098) }));
        assert!(dep.get(&0x80000bc).is_some_and(|set| { set.len() == 1 && set.contains(&0x80000b5) }));
        assert!(dep.get(&0x80000d2).is_some_and(|set| { set.len() == 1 && set.contains(&0x8000098) }));
        assert!(dep.get(&0x80000d6).is_some_and(|set| { set.len() == 2 && set.contains(&0x80000a0) && set.contains(&0x80000b5) }));
        assert!(dep.get(&0x80000e0).is_some_and(|set| { set.len() == 1 && set.contains(&0x8000098) }));
        assert!(dep.get(&0x80000e4).is_some_and(|set| { set.len() == 2 && set.contains(&0x80000a0) && set.contains(&0x80000b5) }));
        assert!(dep.get(&0x80000ed).is_some_and(|set| { set.len() == 2 && set.contains(&0x80000d8) && set.contains(&0x80000ea) }));
        assert!(dep.get(&0x80000f5).is_some_and(|set| { set.len() == 1 && set.contains(&0x8000090) }));
        assert!(dep.get(&0x80000f6).is_some_and(|set| { set.len() == 2 && set.contains(&0x8000090) && set.contains(&0x8000113) }));
        assert!(dep.get(&0x8000120).is_some_and(|set| { set.len() == 1 && set.contains(&0x8000100) }));
        assert_eq!(dep.len(), 12, "DEP is:\n{dep:x}");
        }
    }
}
