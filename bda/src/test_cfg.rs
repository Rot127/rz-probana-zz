// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#[cfg(test)]
mod tests {

    use crate::cfg::{Address, CFGNodeData, NodeType, Weight, CFG};

    const GEE_ADDR: Address = 0;
    const FOO_ADDR: Address = 6;

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
            (7, CFGNodeData::new_call(GEE_ADDR)),
        );

        // gee()
        cfg.add_edge(
            (7, CFGNodeData::new_call(GEE_ADDR)),
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
            (13, CFGNodeData::new_call(GEE_ADDR)),
        );
        cfg.add_edge(
            (12, CFGNodeData::new(NodeType::Normal)),
            (14, CFGNodeData::new_call(FOO_ADDR)),
        );
        // gee()
        cfg.add_edge(
            (13, CFGNodeData::new_call(0)),
            (15, CFGNodeData::new(NodeType::Return)),
        );
        // foo()
        cfg.add_edge(
            (14, CFGNodeData::new_call(6)),
            (15, CFGNodeData::new(NodeType::Return)),
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
        assert_node_weight(gee_cfg.nodes_meta.get(&1), 1);
        assert_node_weight(gee_cfg.nodes_meta.get(&2), 1);
        assert_node_weight(gee_cfg.nodes_meta.get(&3), 1);
    }
}
