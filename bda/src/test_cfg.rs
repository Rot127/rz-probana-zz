// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#[cfg(test)]
mod tests {

    use petgraph::dot::{Config, Dot};

    use crate::cfg::{
        Address, CFGNodeData, FlowGraphOperations, NodeType, Procedure, Weight, CFG, ICFG,
    };

    const GEE_ADDR: Address = 0;
    const FOO_ADDR: Address = 6;
    const MAIN_ADDR: Address = 11;
    const RANDOM_FCN_ADDR: Address = 0x5a5a5a5a5a5a5a5a;

    /// Returns the CFG of the gee() function
    /// of the BDA paper [^Figure 2.7.]
    /// [^Figure 2.7.] See: [Figure 2.7.](https://doi.org/10.25394/PGS.23542014.v1)
    fn get_gee_cfg() -> CFG {
        let mut cfg = CFG::new();

        // gee()
        cfg.add_edge(
            (0, CFGNodeData::new(NodeType::Entry)),
            (1, CFGNodeData::new(NodeType::Normal)),
        );
        // if (input()) ... else ...
        cfg.add_edge(
            (1, CFGNodeData::new(NodeType::Normal)),
            (2, CFGNodeData::new(NodeType::Normal)),
        );
        cfg.add_edge(
            (1, CFGNodeData::new(NodeType::Normal)),
            (3, CFGNodeData::new(NodeType::Normal)),
        );
        // *a = 0
        cfg.add_edge(
            (2, CFGNodeData::new(NodeType::Normal)),
            (4, CFGNodeData::new(NodeType::Return)),
        );
        // *a = 2
        cfg.add_edge(
            (3, CFGNodeData::new(NodeType::Normal)),
            (4, CFGNodeData::new(NodeType::Return)),
        );

        cfg
    }

    /// Returns the CFG of the foo() function
    /// in the BDA paper [^Figure 2.7.]
    /// [^Figure 2.7.] See: [Figure 2.7.](https://doi.org/10.25394/PGS.23542014.v1)
    fn get_foo_cfg() -> CFG {
        let mut cfg = CFG::new();

        // foo()
        cfg.add_edge(
            (6, CFGNodeData::new(NodeType::Entry)),
            (7, CFGNodeData::new_call(GEE_ADDR, false)),
        );

        // gee()
        cfg.add_edge(
            (7, CFGNodeData::new_call(GEE_ADDR, false)),
            (8, CFGNodeData::new(NodeType::Normal)),
        );

        // if (intput())
        cfg.add_edge(
            (8, CFGNodeData::new(NodeType::Normal)),
            (9, CFGNodeData::new(NodeType::Normal)),
        );
        cfg.add_edge(
            (8, CFGNodeData::new(NodeType::Normal)),
            (10, CFGNodeData::new(NodeType::Return)),
        );

        // *a += 1
        cfg.add_edge(
            (9, CFGNodeData::new(NodeType::Normal)),
            (10, CFGNodeData::new(NodeType::Return)),
        );

        cfg
    }

    /// Returns the CFG of the foo() function
    /// of the BDA paper [^Figure 2.7.]
    /// [^Figure 2.7.] See: [Figure 2.7.](https://doi.org/10.25394/PGS.23542014.v1)
    fn get_main_cfg() -> CFG {
        let mut cfg = CFG::new();

        // main()
        cfg.add_edge(
            (11, CFGNodeData::new(NodeType::Entry)),
            (12, CFGNodeData::new(NodeType::Normal)),
        );
        // if (input()) ... else ...
        cfg.add_edge(
            (12, CFGNodeData::new(NodeType::Normal)),
            (13, CFGNodeData::new_call(GEE_ADDR, false)),
        );
        cfg.add_edge(
            (12, CFGNodeData::new(NodeType::Normal)),
            (14, CFGNodeData::new_call(FOO_ADDR, false)),
        );
        // gee()
        cfg.add_edge(
            (13, CFGNodeData::new_call(GEE_ADDR, false)),
            (15, CFGNodeData::new(NodeType::Return)),
        );
        // foo()
        cfg.add_edge(
            (14, CFGNodeData::new_call(FOO_ADDR, false)),
            (15, CFGNodeData::new(NodeType::Return)),
        );

        cfg
    }

    fn get_paper_example_icfg() -> ICFG {
        let mut icfg = ICFG::new();

        icfg.add_edge(
            (
                MAIN_ADDR,
                Procedure {
                    cfg: get_main_cfg(),
                    is_malloc: false,
                },
            ),
            (
                FOO_ADDR,
                Procedure {
                    cfg: get_foo_cfg(),
                    is_malloc: false,
                },
            ),
        );

        icfg.add_edge(
            (
                MAIN_ADDR,
                Procedure {
                    cfg: get_main_cfg(),
                    is_malloc: false,
                },
            ),
            (
                GEE_ADDR,
                Procedure {
                    cfg: get_gee_cfg(),
                    is_malloc: false,
                },
            ),
        );

        icfg.add_edge(
            (
                FOO_ADDR,
                Procedure {
                    cfg: get_foo_cfg(),
                    is_malloc: false,
                },
            ),
            (
                GEE_ADDR,
                Procedure {
                    cfg: get_gee_cfg(),
                    is_malloc: false,
                },
            ),
        );

        icfg
    }

    fn get_cfg_no_loop_sub_routine() -> CFG {
        let mut cfg = CFG::new();
        cfg.add_edge(
            (10, CFGNodeData::new(NodeType::Entry)),
            (11, CFGNodeData::new(NodeType::Normal)),
        );
        cfg.add_edge(
            (11, CFGNodeData::new(NodeType::Normal)),
            (0, CFGNodeData::new(NodeType::Normal)),
        );
        cfg.add_edge(
            (0, CFGNodeData::new(NodeType::Normal)),
            (1, CFGNodeData::new(NodeType::Normal)),
        );
        cfg.add_edge(
            (1, CFGNodeData::new(NodeType::Normal)),
            (2, CFGNodeData::new(NodeType::Normal)),
        );
        cfg.add_edge(
            (2, CFGNodeData::new(NodeType::Normal)),
            (12, CFGNodeData::new(NodeType::Normal)),
        );
        cfg.add_edge(
            (12, CFGNodeData::new(NodeType::Normal)),
            (13, CFGNodeData::new(NodeType::Return)),
        );
        cfg
    }

    fn get_cfg_no_loop_sub_routine_loop_ret() -> CFG {
        let mut cfg = CFG::new();
        cfg.add_edge(
            (0, CFGNodeData::new(NodeType::Normal)),
            (1, CFGNodeData::new(NodeType::Normal)),
        );
        cfg.add_edge(
            (1, CFGNodeData::new(NodeType::Normal)),
            (0, CFGNodeData::new(NodeType::Normal)),
        );
        cfg.add_edge(
            (1, CFGNodeData::new(NodeType::Normal)),
            (2, CFGNodeData::new(NodeType::Return)),
        );
        cfg.add_edge(
            (10, CFGNodeData::new(NodeType::Entry)),
            (11, CFGNodeData::new(NodeType::Normal)),
        );
        cfg.add_edge(
            (11, CFGNodeData::new(NodeType::Normal)),
            (12, CFGNodeData::new(NodeType::Normal)),
        );
        cfg.add_edge(
            (12, CFGNodeData::new(NodeType::Normal)),
            (13, CFGNodeData::new(NodeType::Normal)),
        );
        cfg.add_edge(
            (13, CFGNodeData::new(NodeType::Normal)),
            (14, CFGNodeData::new(NodeType::Return)),
        );
        cfg.add_edge(
            (13, CFGNodeData::new(NodeType::Normal)),
            (11, CFGNodeData::new(NodeType::Normal)),
        );
        cfg.add_edge(
            (11, CFGNodeData::new(NodeType::Normal)),
            (1, CFGNodeData::new(NodeType::Normal)),
        );
        cfg
    }

    fn get_paper_example_cfg_loop() -> CFG {
        let mut cfg = CFG::new();
        cfg.add_edge(
            (0, CFGNodeData::new(NodeType::Entry)),
            (1, CFGNodeData::new(NodeType::Normal)),
        );
        cfg.add_edge(
            (1, CFGNodeData::new(NodeType::Normal)),
            (2, CFGNodeData::new(NodeType::Normal)),
        );
        // Back edge
        cfg.add_edge(
            (2, CFGNodeData::new(NodeType::Normal)),
            (1, CFGNodeData::new(NodeType::Normal)),
        );
        cfg.add_edge(
            (2, CFGNodeData::new(NodeType::Normal)),
            (3, CFGNodeData::new(NodeType::Normal)),
        );
        // Back edge
        cfg.add_edge(
            (3, CFGNodeData::new(NodeType::Normal)),
            (2, CFGNodeData::new(NodeType::Normal)),
        );
        cfg.add_edge(
            (3, CFGNodeData::new(NodeType::Normal)),
            (4, CFGNodeData::new(NodeType::Return)),
        );
        cfg
    }

    fn get_unset_indirect_call_cfg() -> CFG {
        let mut cfg = CFG::new();

        cfg.add_edge(
            (0, CFGNodeData::new(NodeType::Entry)),
            (1, CFGNodeData::new_call(RANDOM_FCN_ADDR, true)),
        );
        cfg.add_edge(
            (1, CFGNodeData::new_call(RANDOM_FCN_ADDR, true)),
            (2, CFGNodeData::new(NodeType::Return)),
        );

        cfg
    }

    fn assert_node_weight(node_data: Option<&CFGNodeData>, weight: Weight) {
        let w: Weight = match node_data {
            Some(node) => node.weight,
            None => panic!("Node is None"),
        };
        assert_eq!(w, weight);
    }

    #[test]
    fn test_cfg_weight_calc_no_call() {
        let mut gee_cfg = get_gee_cfg();
        gee_cfg.calc_weight();
        assert_node_weight(gee_cfg.nodes_meta.get(&0), 2);
        assert_node_weight(gee_cfg.nodes_meta.get(&1), 2);
        assert_node_weight(gee_cfg.nodes_meta.get(&2), 1);
        assert_node_weight(gee_cfg.nodes_meta.get(&3), 1);
        assert_node_weight(gee_cfg.nodes_meta.get(&4), 1);
        assert_eq!(gee_cfg.get_weight(), 2);
    }

    #[test]
    fn test_undiscovered_indirect_call() {
        let mut cfg = get_unset_indirect_call_cfg();
        cfg.calc_weight();
        assert_node_weight(cfg.nodes_meta.get(&0), 1);
        cfg.add_call_target_weights(&[&(RANDOM_FCN_ADDR, 10)]);
        cfg.calc_weight();
        assert_node_weight(cfg.nodes_meta.get(&0), 10);
    }

    #[test]
    fn test_icfg_weight_calc() {
        let mut icfg: ICFG = get_paper_example_icfg();
        icfg.calc_weight();
        assert_eq!(icfg.get_procedure_weight(MAIN_ADDR), 6);
        assert_eq!(icfg.get_procedure_weight(FOO_ADDR), 4);
        assert_eq!(icfg.get_procedure_weight(GEE_ADDR), 2);
    }

    #[test]
    fn test_cfg_untangle() {
        let mut cfg = get_paper_example_cfg_loop();
        println!(
            "{:?}",
            Dot::with_config(&cfg.graph, &[Config::EdgeNoLabel, Config::NodeIndexLabel])
        );
        cfg.make_acyclic();
        println!("{:?}", Dot::with_config(&cfg.graph, &[Config::EdgeNoLabel]));
        assert_eq!(cfg.graph.node_count(), 14);
        assert_eq!(cfg.graph.edge_count(), 22);
        assert!(cfg.graph.contains_edge(0, 1));
        assert!(cfg.graph.contains_edge(1, 2));
        assert!(cfg.graph.contains_edge(2, 3));
        assert!(cfg.graph.contains_edge(3, 4));

        // Loop 2 -> 1 -> 2 ...
        assert!(cfg.graph.contains_edge(2, 0x10000000000000001));
        assert!(cfg
            .graph
            .contains_edge(0x10000000000000001, 0x10000000000000002));
        assert!(cfg
            .graph
            .contains_edge(0x10000000000000002, 0x20000000000000001));
        assert!(cfg
            .graph
            .contains_edge(0x20000000000000002, 0x30000000000000001));
        assert!(cfg
            .graph
            .contains_edge(0x30000000000000001, 0x30000000000000002));
        // Loop 3 -> 2 -> 3 ...
        assert!(cfg.graph.contains_edge(3, 0x10000000000000002));
        assert!(cfg
            .graph
            .contains_edge(0x10000000000000002, 0x10000000000000003));
        assert!(cfg
            .graph
            .contains_edge(0x10000000000000003, 0x20000000000000002));
        assert!(cfg
            .graph
            .contains_edge(0x20000000000000003, 0x30000000000000002));
        assert!(cfg
            .graph
            .contains_edge(0x30000000000000002, 0x30000000000000003));

        // Into scc edges
        assert!(cfg.graph.contains_edge(0, 0x10000000000000001));
        assert!(cfg.graph.contains_edge(0, 0x20000000000000001));
        assert!(cfg.graph.contains_edge(0, 0x30000000000000001));

        // Out of scc edges
        assert!(cfg.graph.contains_edge(0x10000000000000003, 4));
        assert!(cfg.graph.contains_edge(0x20000000000000003, 4));
        assert!(cfg.graph.contains_edge(0x30000000000000003, 4));

        assert!(cfg
            .graph
            .contains_edge(0x10000000000000001, 0x10000000000000002));
        assert!(cfg
            .graph
            .contains_edge(0x10000000000000002, 0x10000000000000003));
        assert!(cfg
            .graph
            .contains_edge(0x20000000000000001, 0x20000000000000002));
        assert!(cfg
            .graph
            .contains_edge(0x20000000000000002, 0x20000000000000003));
        assert!(cfg
            .graph
            .contains_edge(0x30000000000000001, 0x30000000000000002));
        assert!(cfg
            .graph
            .contains_edge(0x30000000000000002, 0x30000000000000003));
    }

    fn n_clone(n: Address, clone_count: u128) -> Address {
        (clone_count << 64) | (n & 0xffffffffffffffff)
    }

    #[test]
    /// Test if the back-edge logic with jumps to lower addresses works.
    fn test_cfg_no_loop_backedge() {
        let mut cfg = get_cfg_no_loop_sub_routine();
        // println!(
        //     "{:?}",
        //     Dot::with_config(&cfg.graph, &[Config::EdgeNoLabel, Config::NodeIndexLabel])
        // );
        cfg.make_acyclic();
        // println!("{:?}", Dot::with_config(&cfg.graph, &[Config::EdgeNoLabel]));
        assert_eq!(cfg.graph.node_count(), 7);
        assert_eq!(cfg.graph.edge_count(), 6);
        assert!(cfg.graph.contains_edge(10, 11));
        assert!(cfg.graph.contains_edge(11, 0));
        assert!(cfg.graph.contains_edge(0, 1));
        assert!(cfg.graph.contains_edge(1, 2));
        assert!(cfg.graph.contains_edge(2, 12));
        assert!(cfg.graph.contains_edge(12, 13));
    }

    #[test]
    /// Test if the back-edge logic with jumps to lower addresses works.
    fn test_cfg_loop_subroutine_ret() {
        let mut cfg = get_cfg_no_loop_sub_routine_loop_ret();
        println!(
            "Graph:\n{:?}",
            Dot::with_config(&cfg.graph, &[Config::EdgeNoLabel, Config::NodeIndexLabel])
        );
        cfg.make_acyclic();
        println!(
            "Acyclic:\n{:?}",
            Dot::with_config(&cfg.graph, &[Config::EdgeNoLabel])
        );
        assert_eq!(cfg.graph.node_count(), 23);
        assert_eq!(cfg.graph.edge_count(), 37);

        assert!(cfg.graph.contains_edge(10, 11));
        assert!(cfg.graph.contains_edge(11, 12));
        assert!(cfg.graph.contains_edge(12, 13));
        assert!(cfg.graph.contains_edge(13, 14));

        assert!(cfg.graph.contains_edge(0, 1));
        assert!(cfg.graph.contains_edge(1, 2));
        assert!(cfg.graph.contains_edge(11, 1));
        assert!(cfg.graph.contains_edge(11, n_clone(1, 1)));
        assert!(cfg.graph.contains_edge(11, n_clone(1, 2)));
        assert!(cfg.graph.contains_edge(11, n_clone(1, 3)));
        assert!(cfg.graph.contains_edge(n_clone(11, 1), 1));
        assert!(cfg.graph.contains_edge(n_clone(11, 2), 1));
        assert!(cfg.graph.contains_edge(n_clone(11, 3), 1));

        assert!(cfg.graph.contains_edge(n_clone(10, 0), n_clone(11, 1)));
        assert!(cfg.graph.contains_edge(n_clone(10, 0), n_clone(11, 2)));
        assert!(cfg.graph.contains_edge(n_clone(10, 0), n_clone(11, 3)));
        assert!(cfg.graph.contains_edge(n_clone(13, 0), n_clone(11, 1)));
        assert!(cfg.graph.contains_edge(n_clone(13, 1), n_clone(11, 2)));
        assert!(cfg.graph.contains_edge(n_clone(13, 2), n_clone(11, 3)));

        assert!(cfg.graph.contains_edge(n_clone(11, 1), n_clone(12, 1)));
        assert!(cfg.graph.contains_edge(n_clone(12, 1), n_clone(13, 1)));
        assert!(cfg.graph.contains_edge(n_clone(11, 2), n_clone(12, 2)));
        assert!(cfg.graph.contains_edge(n_clone(12, 2), n_clone(13, 2)));
        assert!(cfg.graph.contains_edge(n_clone(11, 3), n_clone(12, 3)));
        assert!(cfg.graph.contains_edge(n_clone(12, 3), n_clone(13, 3)));

        assert!(cfg.graph.contains_edge(n_clone(13, 1), n_clone(14, 0)));
        assert!(cfg.graph.contains_edge(n_clone(13, 2), n_clone(14, 0)));
        assert!(cfg.graph.contains_edge(n_clone(13, 3), n_clone(14, 0)));

        assert!(cfg.graph.contains_edge(1, n_clone(0, 1)));
        assert!(cfg.graph.contains_edge(n_clone(0, 1), n_clone(1, 1)));
        assert!(cfg.graph.contains_edge(n_clone(1, 1), n_clone(0, 2)));
        assert!(cfg.graph.contains_edge(n_clone(0, 2), n_clone(1, 2)));
        assert!(cfg.graph.contains_edge(n_clone(1, 2), n_clone(0, 3)));
        assert!(cfg.graph.contains_edge(n_clone(0, 3), n_clone(1, 3)));
        assert!(cfg.graph.contains_edge(n_clone(1, 1), 2));
        assert!(cfg.graph.contains_edge(n_clone(1, 2), 2));
        assert!(cfg.graph.contains_edge(n_clone(1, 3), 2));
    }
}
