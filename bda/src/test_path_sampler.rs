// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{
        flow_graphs::NodeId,
        icfg::{Procedure, ICFG},
        path_sampler::{sample_path, Path},
        test_graphs::{get_cfg_linear, get_gee_cfg, GEE_ADDR, LINEAR_CFG_ENTRY},
        weight::WeightMap,
    };

    pub const TEST_SAMPLE_SIZE: usize = 10000;

    fn check_p_path(sample_cnt: usize, p: f32, err: f32) {
        let lower_bound = if p >= err { p - err } else { 0.0 };
        let upper_bound = if (p + err) <= 1.0 { p + err } else { 1.0 };
        let meassured_p = sample_cnt as f32 / TEST_SAMPLE_SIZE as f32;
        println!(
            "meassured p = {} which is not in range {}±{}",
            meassured_p, p, err
        );
        assert!(
            lower_bound <= meassured_p && meassured_p <= upper_bound,
            "meassured p = {}, which is not in range {}±{}",
            meassured_p,
            p,
            err
        );
    }

    #[test]
    #[should_panic = "meassured p = 1, which is not in range 0.1±0.1"]
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
    #[should_panic = "meassured p = 0.51, which is not in range 0.5±0"]
    fn test_check_p_path_err_bound() {
        check_p_path(TEST_SAMPLE_SIZE / 2 + 100, 0.5, 0.0);
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

        let mut path_stats = HashMap::<Path, usize>::new();
        for _ in 0..TEST_SAMPLE_SIZE {
            let path = sample_path(&icfg, GEE_ADDR, &wmap);
            let cnt = path_stats.get(&path);
            path_stats.insert(path, if cnt.is_none() { 1 } else { *cnt.unwrap() + 1 });
        }
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
    fn test_simple_loop() {
        let mut icfg = ICFG::new();
        icfg.add_procedure(
            NodeId::from(GEE_ADDR),
            Procedure::new(Some(get_gee_cfg()), false),
        );
        let wmap = WeightMap::new();
        icfg.resolve_loops(1, &wmap);

        let mut path_stats = HashMap::<Path, usize>::new();
        for _ in 0..TEST_SAMPLE_SIZE {
            let path = sample_path(&icfg, GEE_ADDR, &wmap);
            let cnt = path_stats.get(&path);
            path_stats.insert(path, if cnt.is_none() { 1 } else { *cnt.unwrap() + 1 });
        }
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

    // Test for loops
    // Test for self reference
    // Test with call
    // Test with call in loop
    // Test updated call
    // Test for nodes with 3+ outgoing nodes
}
