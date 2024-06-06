// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{
        cfg::Procedure,
        flow_graphs::{Address, FlowGraphOperations, NodeId},
        icfg::ICFG,
        path_sampler::{sample_path, Path},
        test_graphs::{
            get_A, get_B, get_C, get_cfg_linear, get_cfg_simple_loop, get_gee_cfg,
            get_unset_indirect_call_to_0_cfg, CFG_ENTRY_A, CFG_ENTRY_A_CALL, CFG_ENTRY_B,
            CFG_ENTRY_B_CALL_1, CFG_ENTRY_B_CALL_2, CFG_ENTRY_C, GEE_ADDR, LINEAR_CFG_ENTRY,
            SIMPLE_LOOP_ENTRY, UNSET_INDIRECT_CALL_TO_0_CALL, UNSET_INDIRECT_CALL_TO_0_ENTRY,
        },
        weight::WeightMap,
    };

    pub const TEST_SAMPLE_SIZE: usize = 20000;

    fn check_p_path(sample_cnt: usize, p: f32, err: f32) {
        let lower_bound = if p >= err { p - err } else { 0.0 };
        let upper_bound = if (p + err) <= 1.0 { p + err } else { 1.0 };
        let meassured_p = sample_cnt as f32 / TEST_SAMPLE_SIZE as f32;
        assert!(
            lower_bound <= meassured_p && meassured_p <= upper_bound,
            "meassured p = {} is not in range {}±{}",
            meassured_p,
            p,
            err
        );
    }

    #[test]
    #[should_panic = "meassured p = 1 is not in range 0.1±0.1"]
    fn test_check_p_path_fail() {
        check_p_path(TEST_SAMPLE_SIZE, 0.1, 0.1);
    }

    #[test]
    fn test_check_p_path_ok() {
        check_p_path(TEST_SAMPLE_SIZE / 2, 0.5, 0.0);
    }

    #[test]
    fn test_check_p_path_ok_bound() {
        check_p_path(TEST_SAMPLE_SIZE / 2 + 100, 0.5, 0.1);
    }

    #[test]
    #[should_panic = "meassured p = 0.505 is not in range 0.5±0"]
    fn test_check_p_path_err_bound() {
        check_p_path(TEST_SAMPLE_SIZE / 2 + 100, 0.5, 0.0);
    }

    fn sample(
        icfg: &ICFG,
        entry: Address,
        wmap: &std::sync::RwLock<WeightMap>,
    ) -> HashMap<Path, usize> {
        let mut path_stats = HashMap::<Path, usize>::new();
        for _ in 0..TEST_SAMPLE_SIZE {
            let path = sample_path(&icfg, entry, &wmap, &Vec::new());
            let cnt = path_stats.get(&path);
            path_stats.insert(path, if cnt.is_none() { 1 } else { *cnt.unwrap() + 1 });
        }
        path_stats
    }

    macro_rules! build_path {
        ($( $elem:expr ),* ) => {
            Path::from(vec![
                $(
                    NodeId::from($elem),
                )*
            ])
        };
    }

    #[test]
    /// Test a single path graph.
    fn test_unique_path() {
        let mut icfg = ICFG::new();
        icfg.add_procedure(
            NodeId::from(LINEAR_CFG_ENTRY),
            Procedure::new(Some(get_cfg_linear()), false, false),
        );
        let wmap = WeightMap::new();
        icfg.resolve_loops(1, &wmap);

        let mut path_stats = HashMap::<Path, usize>::new();
        // Over TEST_SAMPLE_SIZE iterations we should get the same path with a probability of 1.
        for _ in 0..TEST_SAMPLE_SIZE {
            let path = sample_path(&icfg, LINEAR_CFG_ENTRY, &wmap, &Vec::new());
            let cnt = path_stats.get(&path);
            path_stats.insert(path, if cnt.is_none() { 1 } else { *cnt.unwrap() + 1 });
        }
        assert_eq!(path_stats.len(), 1, "More then one path.");
        for (_, cnt) in path_stats.iter() {
            assert_eq!(
                1,
                (TEST_SAMPLE_SIZE / cnt),
                "Path not sample with correct probability"
            );
        }
    }

    #[test]
    fn test_simple_branch() {
        let mut icfg = ICFG::new();
        icfg.add_procedure(
            NodeId::from(GEE_ADDR),
            Procedure::new(Some(get_gee_cfg()), false, false),
        );
        let wmap = WeightMap::new();
        icfg.resolve_loops(1, &wmap);

        let path_stats = sample(&icfg, GEE_ADDR, &wmap);
        assert_eq!(path_stats.len(), 2, "Wrong path count.");
        assert!(path_stats.get(&build_path!(0, 1, 2, 4)).is_some());
        assert!(path_stats.get(&build_path!(0, 1, 3, 4)).is_some());
        check_p_path(
            *path_stats.get(&build_path!(0, 1, 2, 4)).unwrap(),
            0.5,
            0.02,
        );
        check_p_path(
            *path_stats.get(&build_path!(0, 1, 3, 4)).unwrap(),
            0.5,
            0.02,
        );
    }

    #[test]
    fn test_two_edges() {
        let mut icfg = ICFG::new();
        icfg.add_procedure(
            NodeId::from(CFG_ENTRY_C),
            Procedure::new(Some(get_C()), false, false),
        );
        let wmap = WeightMap::new();
        icfg.resolve_loops(1, &wmap);

        let path_stats = sample(&icfg, CFG_ENTRY_C, &wmap);
        assert_eq!(path_stats.len(), 2, "Wrong path count.");
        assert!(path_stats.get(&build_path!(0xcccccc0, 0xcccccc1)).is_some());
        assert!(path_stats.get(&build_path!(0xcccccc0, 0xcccccc2)).is_some());
        check_p_path(
            *path_stats.get(&build_path!(0xcccccc0, 0xcccccc1)).unwrap(),
            0.5,
            0.01,
        );
        check_p_path(
            *path_stats.get(&build_path!(0xcccccc0, 0xcccccc2)).unwrap(),
            0.5,
            0.01,
        );
    }

    #[test]
    fn test_sample_simple_loop() {
        let mut icfg = ICFG::new();
        icfg.add_procedure(
            NodeId::from(GEE_ADDR),
            Procedure::new(Some(get_cfg_simple_loop()), false, false),
        );
        let wmap = WeightMap::new();
        icfg.resolve_loops(1, &wmap);
        let path_stats = sample(&icfg, SIMPLE_LOOP_ENTRY, &wmap);

        let n00 = (0, 0, 0);
        let n01 = (0, 0, 1);
        let n02 = (0, 0, 2);
        let n03 = (0, 0, 3);
        let n11 = (0, 1, 1);
        let n12 = (0, 1, 2);
        let n21 = (0, 2, 1);
        let n22 = (0, 2, 2);
        let n31 = (0, 3, 1);
        let n32 = (0, 3, 2);

        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        assert_eq!(path_stats.len(), 10, "Wrong path count.");

        let p0 = &build_path!(n00, n01, n02, n03);
        assert!(path_stats.get(p0).is_some());
        let p1 = &build_path!(n00, n11, n12, n03);
        assert!(path_stats.get(p1).is_some());
        let p2 = &build_path!(n00, n21, n22, n03);
        assert!(path_stats.get(p2).is_some());
        let p3 = &build_path!(n00, n31, n32, n03);
        assert!(path_stats.get(p3).is_some());

        let p4 = &build_path!(n00, n01, n02, n11, n12, n03);
        assert!(path_stats.get(p4).is_some());
        let p5 = &build_path!(n00, n11, n12, n21, n22, n03);
        assert!(path_stats.get(p5).is_some());
        let p6 = &build_path!(n00, n21, n22, n31, n32, n03);
        assert!(path_stats.get(p6).is_some());

        let p7 = &build_path!(n00, n01, n02, n11, n12, n21, n22, n03);
        assert!(path_stats.get(p7).is_some());
        let p8 = &build_path!(n00, n11, n12, n21, n22, n31, n32, n03);
        assert!(path_stats.get(p8).is_some());

        let p9 = &build_path!(n00, n01, n02, n11, n12, n21, n22, n31, n32, n03);
        assert!(path_stats.get(p9).is_some());
        }

        for (p, c) in path_stats.iter() {
            println!("{:?} = {}", p, c);
        }

        for (_, c) in path_stats.iter() {
            check_p_path(*c, 0.1, 0.01);
        }
    }

    #[test]
    fn test_sample_undiscovered_indirect_call() {
        let mut icfg = ICFG::new();
        icfg.add_procedure(
            NodeId::from(UNSET_INDIRECT_CALL_TO_0_ENTRY),
            Procedure::new(Some(get_unset_indirect_call_to_0_cfg()), false, false),
        );
        let wmap = WeightMap::new();
        icfg.resolve_loops(1, &wmap);
        let path_stats = sample(&icfg, UNSET_INDIRECT_CALL_TO_0_ENTRY, &wmap);
        assert_eq!(path_stats.len(), 1, "Wrong path count.");
        for (_, c) in path_stats.iter() {
            check_p_path(*c, 1.0, 0.0);
        }

        // Exchange the procedures and check if the paths are sample uniform afterwards.

        // Call simple loop CFG
        let mut lcfg = get_cfg_simple_loop();
        icfg.add_procedure(
            NodeId::from(SIMPLE_LOOP_ENTRY),
            Procedure::new(Some(lcfg), false, false),
        );
        icfg.get_procedure(&NodeId::from(UNSET_INDIRECT_CALL_TO_0_ENTRY))
            .write()
            .unwrap()
            .update_call_target(
                &NodeId::from(UNSET_INDIRECT_CALL_TO_0_CALL),
                -1,
                &NodeId::from(SIMPLE_LOOP_ENTRY),
            );
        icfg.resolve_loops(1, &wmap);
        let path_stats = sample(&icfg, UNSET_INDIRECT_CALL_TO_0_ENTRY, &wmap);
        assert_eq!(path_stats.len(), 10, "Wrong path count.");
        for (_, c) in path_stats.iter() {
            check_p_path(*c, 1.0 / 10.0, 0.01);
        }

        lcfg = get_gee_cfg();
        lcfg.make_acyclic(&wmap, None);
        icfg.add_procedure(
            NodeId::from(GEE_ADDR),
            Procedure::new(Some(lcfg), false, false),
        );
        icfg.get_procedure(&NodeId::from(UNSET_INDIRECT_CALL_TO_0_ENTRY))
            .write()
            .unwrap()
            .update_call_target(
                &NodeId::from(UNSET_INDIRECT_CALL_TO_0_CALL),
                -1,
                &NodeId::from(GEE_ADDR),
            );
        let path_stats = sample(&icfg, UNSET_INDIRECT_CALL_TO_0_ENTRY, &wmap);
        assert_eq!(path_stats.len(), 2, "Wrong path count.");
        for (_, c) in path_stats.iter() {
            check_p_path(*c, 0.5, 0.01);
        }
    }

    #[test]
    fn test_second_level_cfg_update() {
        let mut icfg = ICFG::new();
        icfg.add_procedure(
            NodeId::from(CFG_ENTRY_A),
            Procedure::new(Some(get_A()), false, false),
        );
        let wmap = WeightMap::new();
        icfg.resolve_loops(1, &wmap);
        let mut path_stats = sample(&icfg, CFG_ENTRY_A, &wmap);
        assert_eq!(path_stats.len(), 1, "Wrong path count.");
        for (_, c) in path_stats.iter() {
            check_p_path(*c, 1.0, 0.0);
        }

        // Add two levels of calls and check weights again.
        icfg.add_procedure(
            NodeId::from(CFG_ENTRY_B),
            Procedure::new(Some(get_B()), false, false),
        );
        icfg.get_procedure(&NodeId::from(CFG_ENTRY_A))
            .write()
            .unwrap()
            .update_call_target(
                &NodeId::from(CFG_ENTRY_A_CALL),
                -1,
                &NodeId::from(CFG_ENTRY_B),
            );

        icfg.add_procedure(
            NodeId::from(CFG_ENTRY_C),
            Procedure::new(Some(get_C()), false, false),
        );
        icfg.get_procedure(&NodeId::from(CFG_ENTRY_B))
            .write()
            .unwrap()
            .update_call_target(
                &NodeId::from(CFG_ENTRY_B_CALL_1),
                -1,
                &NodeId::from(CFG_ENTRY_C),
            );
        icfg.resolve_loops(1, &wmap);
        path_stats = sample(&icfg, CFG_ENTRY_A, &wmap);
        assert_eq!(path_stats.len(), 3, "Wrong path count.");
        for (_, c) in path_stats.iter() {
            check_p_path(*c, 1.0 / 3.0, 0.01);
        }

        // Add another call to C and check the paths again.
        icfg.get_procedure(&NodeId::from(CFG_ENTRY_B))
            .write()
            .unwrap()
            .update_call_target(
                &NodeId::from(CFG_ENTRY_B_CALL_2),
                -1,
                &NodeId::from(CFG_ENTRY_C),
            );
        icfg.resolve_loops(1, &wmap);
        path_stats = sample(&icfg, CFG_ENTRY_A, &wmap);
        println!("{:?}", path_stats);
        assert_eq!(path_stats.len(), 4, "Wrong path count.");
        for (_, c) in path_stats.iter() {
            check_p_path(*c, 0.25, 0.01);
        }
    }
}
