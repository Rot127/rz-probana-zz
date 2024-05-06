// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{
        flow_graphs::{Address, NodeId},
        icfg::{Procedure, ICFG},
        path_sampler::{sample_path, Path},
        test_graphs::{
            get_cfg_linear, get_cfg_simple_loop, get_gee_cfg, GEE_ADDR, LINEAR_CFG_ENTRY,
            SIMPLE_LOOP_ENTRY,
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
        icfg: ICFG,
        entry: Address,
        wmap: std::sync::RwLock<WeightMap>,
    ) -> HashMap<Path, usize> {
        let mut path_stats = HashMap::<Path, usize>::new();
        for _ in 0..TEST_SAMPLE_SIZE {
            let path = sample_path(&icfg, entry, &wmap);
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
            Procedure::new(Some(get_cfg_linear()), false),
        );
        let wmap = WeightMap::new();
        icfg.resolve_loops(1, &wmap);

        let mut path_stats = HashMap::<Path, usize>::new();
        // Over TEST_SAMPLE_SIZE iterations we should get the same path with a probability of 1.
        for _ in 0..TEST_SAMPLE_SIZE {
            let path = sample_path(&icfg, LINEAR_CFG_ENTRY, &wmap);
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
            Procedure::new(Some(get_gee_cfg()), false),
        );
        let wmap = WeightMap::new();
        icfg.resolve_loops(1, &wmap);

        let path_stats = sample(icfg, GEE_ADDR, wmap);
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
    fn test_sample_simple_loop() {
        let mut icfg = ICFG::new();
        icfg.add_procedure(
            NodeId::from(GEE_ADDR),
            Procedure::new(Some(get_cfg_simple_loop()), false),
        );
        let wmap = WeightMap::new();
        icfg.resolve_loops(1, &wmap);
        let path_stats = sample(icfg, SIMPLE_LOOP_ENTRY, wmap);

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

    // Test for loops
    // Test for self reference
    // Test with call
    // Test with call in loop
    // Test updated call
    // Test for nodes with 3+ outgoing nodes
}
