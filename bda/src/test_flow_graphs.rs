// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#[cfg(test)]
mod tests {

    use petgraph::dot::Dot;

    use crate::{
        cfg::{CFGNodeData, InsnNodeType, InsnNodeWeightType, CFG},
        flow_graphs::{
            Address, FlowGraphOperations, NodeId, SamplingBias, Weight, INVALID_NODE_ID,
            INVALID_WEIGHT,
        },
        icfg::{Procedure, ICFG},
    };

    const A_ADDR: Address = 0xa0;
    const B_ADDR: Address = 0xb0;
    const C_ADDR: Address = 0xc0;
    const D_ADDR: Address = 0xd0;
    const GEE_ADDR: Address = 0;
    const FOO_ADDR: Address = 6;
    const MAIN_ADDR: Address = 11;
    const RANDOM_FCN_ADDR: Address = 0x5a5a5a5a5a5a5a5a;

    /// A -> B -> C -> A
    ///           \  
    ///            +--> C -> C ....
    fn get_endless_loop_icfg() -> ICFG {
        let mut icfg = ICFG::new();
        let mut cfg_a = CFG::new();
        let mut cfg_b = CFG::new();
        let mut cfg_c = CFG::new();

        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        cfg_a.add_edge(
            (NodeId::new(0, 0, 0xa0), CFGNodeData::new_test_single(0xa0, InsnNodeType::new(InsnNodeWeightType::Normal, true), NodeId::new(0, 0, 0xa1), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 0xa1), CFGNodeData::new_test_single_call(0xa1, NodeId::new(0, 0, B_ADDR), false, NodeId::new(0, 0, 0xa2))),
        );
        cfg_a.add_edge(
            (NodeId::new(0, 0, 0xa1), CFGNodeData::new_test_single_call(0xa1, NodeId::new(0, 0, B_ADDR), false, NodeId::new(0, 0, 0xa2))),
            (NodeId::new(0, 0, 0xa2), CFGNodeData::new_test_single(0xa2, InsnNodeType::new(InsnNodeWeightType::Return, false), INVALID_NODE_ID, INVALID_NODE_ID)),
        );

        cfg_b.add_edge(
            (NodeId::new(0, 0, 0xb0), CFGNodeData::new_test_single(0xb0, InsnNodeType::new(InsnNodeWeightType::Normal, true), NodeId::new(0, 0, 0xb1), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 0xb1), CFGNodeData::new_test_single_call(0xb1, NodeId::new(0, 0, C_ADDR), false, NodeId::new(0, 0, 0xb2))),
        );
        cfg_b.add_edge(
            (NodeId::new(0, 0, 0xb1), CFGNodeData::new_test_single_call(0xb1, NodeId::new(0, 0, C_ADDR), false, NodeId::new(0, 0, 0xb2))),
            (NodeId::new(0, 0, 0xb2), CFGNodeData::new_test_single(0xb2, InsnNodeType::new(InsnNodeWeightType::Return, false), INVALID_NODE_ID, INVALID_NODE_ID)),
        );

        cfg_c.add_edge(
            (NodeId::new(0, 0, 0xc0), CFGNodeData::new_test_single(0xc0, InsnNodeType::new(InsnNodeWeightType::Normal, true), NodeId::new(0, 0, 0xc1), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 0xc1), CFGNodeData::new_test_single_call(0xc1, NodeId::new(0, 0, A_ADDR), false, NodeId::new(0, 0, 0xc2))),
        );
        cfg_c.add_edge(
            (NodeId::new(0, 0, 0xc1), CFGNodeData::new_test_single_call(0xc1, NodeId::new(0, 0, A_ADDR), false, NodeId::new(0, 0, 0xc2))),
            (NodeId::new(0, 0, 0xc2), CFGNodeData::new_test_single_call(0xc2, NodeId::new(0, 0, C_ADDR), false, NodeId::new(0, 0, 0xc3))),
        );
        cfg_c.add_edge(
            (NodeId::new(0, 0, 0xc2), CFGNodeData::new_test_single_call(0xc2, NodeId::new(0, 0, C_ADDR), false, NodeId::new(0, 0, 0xc3))),
            (NodeId::new(0, 0, 0xc3), CFGNodeData::new_test_single(0xc3, InsnNodeType::new(InsnNodeWeightType::Return, false), INVALID_NODE_ID, INVALID_NODE_ID)),
        );

        icfg.add_edge(
            (NodeId::new(0, 0, A_ADDR), Procedure::new(Some(cfg_a), false)),
            (NodeId::new(0, 0, B_ADDR), Procedure::new(Some(cfg_b), false)),
        );
        icfg.add_edge(
            (NodeId::new(0, 0, B_ADDR), Procedure::new(None, false)),
            (NodeId::new(0, 0, C_ADDR), Procedure::new(Some(cfg_c), false)),
        );
        icfg.add_edge(
            (NodeId::new(0, 0, C_ADDR), Procedure::new(None, false)),
            (NodeId::new(0, 0, C_ADDR), Procedure::new(None, false)),
        );
        icfg.add_edge(
            (NodeId::new(0, 0, C_ADDR), Procedure::new(None, false)),
            (NodeId::new(0, 0, A_ADDR), Procedure::new(None, false)),
        );
        }
        icfg
    }

    fn get_endless_loop_icfg_branch() -> ICFG {
        let mut icfg = ICFG::new();
        let mut cfg_a = CFG::new();
        let mut cfg_b = CFG::new();
        let mut cfg_d = CFG::new();

        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        cfg_a.add_edge(
            (NodeId::new(0, 0, 0xa0), CFGNodeData::new_test_single(0xa0, InsnNodeType::new(InsnNodeWeightType::Normal, true), NodeId::new(0, 0, 0xa1), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 0xa1), CFGNodeData::new_test_single_call(0xa1, NodeId::new(0, 0, B_ADDR), false, NodeId::new(0, 0, 0xa2))),
        );
        cfg_a.add_edge(
            (NodeId::new(0, 0, 0xa1), CFGNodeData::new_test_single_call(0xa1, NodeId::new(0, 0, B_ADDR), false, NodeId::new(0, 0, 0xa2))),
            (NodeId::new(0, 0, 0xa2), CFGNodeData::new_test_single(0xa2, InsnNodeType::new(InsnNodeWeightType::Return, false), INVALID_NODE_ID, INVALID_NODE_ID)),
        );

        cfg_b.add_edge(
            (NodeId::new(0, 0, 0xb0), CFGNodeData::new_test_single(0xb0, InsnNodeType::new(InsnNodeWeightType::Normal, true), NodeId::new(0, 0, 0xb1), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 0xb1), CFGNodeData::new_test_single_call(0xb1, NodeId::new(0, 0, D_ADDR), false, NodeId::new(0, 0, 0xb2))),
        );
        cfg_b.add_edge(
            (NodeId::new(0, 0, 0xb1), CFGNodeData::new_test_single_call(0xb1, NodeId::new(0, 0, D_ADDR), false, NodeId::new(0, 0, 0xb2))),
            (NodeId::new(0, 0, 0xb2), CFGNodeData::new_test_single(0xb2, InsnNodeType::new(InsnNodeWeightType::Return, false), INVALID_NODE_ID, INVALID_NODE_ID)),
        );

        cfg_d.add_edge(
            (NodeId::new(0, 0, 0xd0), CFGNodeData::new_test_single(0xd0, InsnNodeType::new(InsnNodeWeightType::Normal, true), NodeId::new(0, 0, 0xd1), NodeId::new(0, 0, 0xd2))),
            (NodeId::new(0, 0, 0xd1), CFGNodeData::new_test_single_call(0xd1, NodeId::new(0, 0, A_ADDR), false, NodeId::new(0, 0, 0xd3))),
        );
        cfg_d.add_edge(
            (NodeId::new(0, 0, 0xd1), CFGNodeData::new_test_single_call(0xd1, NodeId::new(0, 0, A_ADDR), false, NodeId::new(0, 0, 0xd3))),
            (NodeId::new(0, 0, 0xd3), CFGNodeData::new_test_single(0xd3, InsnNodeType::new(InsnNodeWeightType::Return, false), INVALID_NODE_ID, INVALID_NODE_ID)),
        );
        cfg_d.add_edge(
            (NodeId::new(0, 0, 0xd0), CFGNodeData::new_test_single(0xd0, InsnNodeType::new(InsnNodeWeightType::Normal, true), NodeId::new(0, 0, 0xd1), NodeId::new(0, 0, 0xd2))),
            (NodeId::new(0, 0, 0xd2), CFGNodeData::new_test_single_call(0xd2, NodeId::new(0, 0, D_ADDR), false, NodeId::new(0, 0, 0xd3))),
        );
        cfg_d.add_edge(
            (NodeId::new(0, 0, 0xd2), CFGNodeData::new_test_single_call(0xd2, NodeId::new(0, 0, D_ADDR), false, NodeId::new(0, 0, 0xd3))),
            (NodeId::new(0, 0, 0xd3), CFGNodeData::new_test_single(0xd3, InsnNodeType::new(InsnNodeWeightType::Return, false), INVALID_NODE_ID, INVALID_NODE_ID)),
        );

        icfg.add_edge(
            (NodeId::new(0, 0, A_ADDR), Procedure::new(Some(cfg_a), false)),
            (NodeId::new(0, 0, B_ADDR), Procedure::new(Some(cfg_b), false)),
        );
        icfg.add_edge(
            (NodeId::new(0, 0, B_ADDR), Procedure::new(None, false)),
            (NodeId::new(0, 0, D_ADDR), Procedure::new(Some(cfg_d), false)),
        );
        icfg.add_edge(
            (NodeId::new(0, 0, D_ADDR), Procedure::new(None, false)),
            (NodeId::new(0, 0, D_ADDR), Procedure::new(None, false)),
        );
        icfg.add_edge(
            (NodeId::new(0, 0, D_ADDR), Procedure::new(None, false)),
            (NodeId::new(0, 0, A_ADDR), Procedure::new(None, false)),
        );
        }
        icfg
    }

    /// Returns the CFG of the gee() function
    /// of the BDA paper [^Figure 2.7.]
    /// [^Figure 2.7.] See: [Figure 2.7.](https://doi.org/10.25394/PGS.23542014.v1)
    fn get_gee_cfg() -> CFG {
        let mut cfg = CFG::new();

        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        // gee()
        cfg.add_edge(
            (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::new(InsnNodeWeightType::Normal, true), NodeId::new(0, 0, 1), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), NodeId::new(0, 0, 3))),
        );
        // if (input()) ... else ...
        cfg.add_edge(
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), NodeId::new(0, 0, 3))),
            (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 4), INVALID_NODE_ID)),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), NodeId::new(0, 0, 3))),
            (NodeId::new(0, 0, 3), CFGNodeData::new_test_single(3, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 4), INVALID_NODE_ID)),
        );
        // *a = 0
        cfg.add_edge(
            (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 4), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 4), CFGNodeData::new_test_single(4, InsnNodeType::new(InsnNodeWeightType::Return, false), INVALID_NODE_ID, INVALID_NODE_ID)),
        );
        // *a = 2
        cfg.add_edge(
            (NodeId::new(0, 0, 3), CFGNodeData::new_test_single(3, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 4), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 4), CFGNodeData::new_test_single(4, InsnNodeType::new(InsnNodeWeightType::Return, false), INVALID_NODE_ID, INVALID_NODE_ID)),
        );
        }
        cfg
    }

    /// Returns the CFG of the foo() function
    /// in the BDA paper [^Figure 2.7.]
    /// [^Figure 2.7.] See: [Figure 2.7.](https://doi.org/10.25394/PGS.23542014.v1)
    fn get_foo_cfg() -> CFG {
        let mut cfg = CFG::new();

        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        // foo()
        cfg.add_edge(
            (NodeId::new(0, 0, 6), CFGNodeData::new_test_single(6, InsnNodeType::new(InsnNodeWeightType::Normal, true), NodeId::new(0, 0, 7), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 7), CFGNodeData::new_test_single_call(7, NodeId::new(0, 0, GEE_ADDR), false, NodeId::new(0, 0, 8))),
        );

        // gee()
        cfg.add_edge(
            (NodeId::new(0, 0, 7), CFGNodeData::new_test_single_call(7, NodeId::new(0, 0, GEE_ADDR), false, NodeId::new(0, 0, 8))),
            (NodeId::new(0, 0, 8), CFGNodeData::new_test_single(8, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 9), NodeId::new(0, 0, 1))),
        );

        // if (intput())
        cfg.add_edge(
            (NodeId::new(0, 0, 8), CFGNodeData::new_test_single(8, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 9), NodeId::new(0, 0, 1))),
            (NodeId::new(0, 0, 9), CFGNodeData::new_test_single(9, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 1), INVALID_NODE_ID)),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 8), CFGNodeData::new_test_single(8, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 9), NodeId::new(0, 0, 1))),
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::new(InsnNodeWeightType::Return, false), INVALID_NODE_ID, INVALID_NODE_ID)),
        );

        // *a += 1
        cfg.add_edge(
            (NodeId::new(0, 0, 9), CFGNodeData::new_test_single(9, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 1), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::new(InsnNodeWeightType::Return, false), INVALID_NODE_ID, INVALID_NODE_ID)),
        );
        }

        cfg
    }

    /// Returns the CFG of the foo() function
    /// of the BDA paper [^Figure 2.7.]
    /// [^Figure 2.7.] See: [Figure 2.7.](https://doi.org/10.25394/PGS.23542014.v1)
    fn get_main_cfg() -> CFG {
        let mut cfg = CFG::new();

        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        // main()
        cfg.add_edge(
            (NodeId::new(0, 0, 11), CFGNodeData::new_test_single(11, InsnNodeType::new(InsnNodeWeightType::Normal, true), NodeId::new(0, 0, 12), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 12), CFGNodeData::new_test_single(12, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 13), NodeId::new(0, 0, 14))),
        );
        // if (input()) ... else ...
        cfg.add_edge(
            (NodeId::new(0, 0, 12), CFGNodeData::new_test_single(12, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 13), NodeId::new(0, 0, 14))),
            (NodeId::new(0, 0, 13), CFGNodeData::new_test_single_call(13, NodeId::new(0, 0, GEE_ADDR), false, NodeId::new(0, 0, 15))),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 12), CFGNodeData::new_test_single(12, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 13), NodeId::new(0, 0, 14))),
            (NodeId::new(0, 0, 14), CFGNodeData::new_test_single_call(14, NodeId::new(0, 0, FOO_ADDR), false, NodeId::new(0, 0, 15))),
        );
        // gee()
        cfg.add_edge(
            (NodeId::new(0, 0, 13), CFGNodeData::new_test_single_call(13, NodeId::new(0, 0, GEE_ADDR), false, NodeId::new(0, 0, 15))),
            (NodeId::new(0, 0, 15), CFGNodeData::new_test_single(15, InsnNodeType::new(InsnNodeWeightType::Return, false), INVALID_NODE_ID, INVALID_NODE_ID)),
        );
        // foo()
        cfg.add_edge(
            (NodeId::new(0, 0, 14), CFGNodeData::new_test_single_call(14, NodeId::new(0, 0, FOO_ADDR), false, NodeId::new(0, 0, 15))),
            (NodeId::new(0, 0, 15), CFGNodeData::new_test_single(15, InsnNodeType::new(InsnNodeWeightType::Return, false), INVALID_NODE_ID, INVALID_NODE_ID)),
        );
        }

        cfg
    }

    fn get_paper_example_icfg() -> ICFG {
        let mut icfg = ICFG::new();

        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        icfg.add_edge(
            (NodeId::new(0, 0, MAIN_ADDR), Procedure::new(Some(get_main_cfg()), false)),
            (NodeId::new(0, 0, FOO_ADDR), Procedure::new(Some(get_foo_cfg()), false))
        );
        icfg.add_edge(
            (NodeId::new(0, 0, MAIN_ADDR), Procedure::new(None, false)),
            (NodeId::new(0, 0, GEE_ADDR), Procedure::new(Some(get_gee_cfg()), false))
        );
        icfg.add_edge(
            (NodeId::new(0, 0, FOO_ADDR), Procedure::new(None, false)),
            (NodeId::new(0, 0, GEE_ADDR), Procedure::new(None, false))
        );
        }

        icfg
    }

    fn get_icfg_with_selfref_and_recurse_cfg() -> ICFG {
        let mut icfg = ICFG::new();
        let cfg_recurse_selfref = get_cfg_self_ref_call();

        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        icfg.add_edge(
            (cfg_recurse_selfref.get_entry(), Procedure::new(Some(cfg_recurse_selfref.to_owned()), false)),
            (cfg_recurse_selfref.get_entry(), Procedure::new(Some(cfg_recurse_selfref.to_owned()), false)),
        );
        }

        icfg
    }

    fn get_cfg_no_loop_sub_routine() -> CFG {
        let mut cfg = CFG::new();
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        cfg.add_edge(
            (NodeId::new(0, 0, 10), CFGNodeData::new_test_single(10, InsnNodeType::new(InsnNodeWeightType::Normal, true), NodeId::new(0, 0, 11), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 11), CFGNodeData::new_test_single(11, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 0), INVALID_NODE_ID)),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 11), CFGNodeData::new_test_single(11, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 0), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 1), INVALID_NODE_ID)),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 1), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), INVALID_NODE_ID)),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 12), INVALID_NODE_ID)),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 12), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 12), CFGNodeData::new_test_single(12, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 13), INVALID_NODE_ID)),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 12), CFGNodeData::new_test_single(12, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 13), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 13), CFGNodeData::new_test_single(13, InsnNodeType::new(InsnNodeWeightType::Return, false), INVALID_NODE_ID, INVALID_NODE_ID)),
        );
        }
        cfg
    }

    fn get_cfg_no_loop_sub_routine_loop_ret() -> CFG {
        let mut cfg = CFG::new();
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        cfg.add_edge(
            (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 1), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), NodeId::new(0, 0, 0))),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), NodeId::new(0, 0, 0))),
            (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 1), INVALID_NODE_ID)),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), NodeId::new(0, 0, 0))),
            (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::new(InsnNodeWeightType::Return, false), INVALID_NODE_ID, INVALID_NODE_ID)),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 10), CFGNodeData::new_test_single(10, InsnNodeType::new(InsnNodeWeightType::Normal, true), NodeId::new(0, 0, 11), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 11), CFGNodeData::new_test_single(11, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 12), INVALID_NODE_ID)),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 11), CFGNodeData::new_test_single(11, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 12), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 12), CFGNodeData::new_test_single(12, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 13), INVALID_NODE_ID)),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 12), CFGNodeData::new_test_single(12, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 13), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 13), CFGNodeData::new_test_single(13, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 14), NodeId::new(0, 0, 11))),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 13), CFGNodeData::new_test_single(13, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 14), NodeId::new(0, 0, 11))),
            (NodeId::new(0, 0, 14), CFGNodeData::new_test_single(14, InsnNodeType::new(InsnNodeWeightType::Return, false), INVALID_NODE_ID, INVALID_NODE_ID)),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 13), CFGNodeData::new_test_single(13, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 14), NodeId::new(0, 0, 11))),
            (NodeId::new(0, 0, 11), CFGNodeData::new_test_single(11, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 12), INVALID_NODE_ID)),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 11), CFGNodeData::new_test_single(11, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 12), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), NodeId::new(0, 0, 0))),
        );
        }
        cfg
    }

    fn get_cfg_empty() -> CFG {
        CFG::new()
    }

    fn get_cfg_single_node() -> CFG {
        let mut cfg = CFG::new();
        cfg.add_node((
            NodeId::new(0, 0, 0),
            CFGNodeData::new_test_single(
                0,
                InsnNodeType::new(InsnNodeWeightType::Return, false),
                INVALID_NODE_ID,
                INVALID_NODE_ID,
            ),
        ));
        cfg
    }

    fn get_cfg_single_self_ref() -> CFG {
        let mut cfg = CFG::new();
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        cfg.add_edge(
            (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::new(InsnNodeWeightType::Return, false), INVALID_NODE_ID, NodeId::new(0, 0, 0))),
            (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::new(InsnNodeWeightType::Return, false), INVALID_NODE_ID, NodeId::new(0, 0, 0))),
        );
        }
        cfg
    }

    ///        Call     self
    ///                 ref
    /// 0 ----> 1 -----> 2 -----> 3
    fn get_cfg_self_ref_call() -> CFG {
        let mut cfg = CFG::new();
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        cfg.add_edge(
            (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::new(InsnNodeWeightType::Normal, true), NodeId::new(0, 0, 1), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single_call(1, NodeId::from(0), false, NodeId::new(0, 0, 2))),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single_call(1, NodeId::from(0), false, NodeId::new(0, 0, 2))),
            (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), NodeId::new(0, 0, 3))),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), NodeId::new(0, 0, 3))),
            (NodeId::new(0, 0, 3), CFGNodeData::new_test_single(3, InsnNodeType::new(InsnNodeWeightType::Return, false), INVALID_NODE_ID, INVALID_NODE_ID)),
        );
        }
        cfg
    }

    fn get_cfg_linear() -> CFG {
        let mut cfg = CFG::new();
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        cfg.add_edge(
            (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::new(InsnNodeWeightType::Normal, true), NodeId::new(0, 0, 1), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), INVALID_NODE_ID)),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 3), INVALID_NODE_ID)),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 3), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 3), CFGNodeData::new_test_single(3, InsnNodeType::new(InsnNodeWeightType::Return, false), INVALID_NODE_ID, INVALID_NODE_ID)),
        );
        }
        cfg
    }

    fn get_cfg_simple_loop() -> CFG {
        let mut cfg = CFG::new();
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        cfg.add_edge(
            (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::new(InsnNodeWeightType::Normal, true), NodeId::new(0, 0, 1), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), INVALID_NODE_ID)),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 3), NodeId::new(0, 0, 1))),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 3), NodeId::new(0, 0, 1))),
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), INVALID_NODE_ID)),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 3), NodeId::new(0, 0, 1))),
            (NodeId::new(0, 0, 3), CFGNodeData::new_test_single(3, InsnNodeType::new(InsnNodeWeightType::Return, false), INVALID_NODE_ID, INVALID_NODE_ID)),
        );
        }
        cfg
    }

    fn get_cfg_simple_loop_extra_nodes() -> CFG {
        let mut cfg = CFG::new();
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        cfg.add_edge(
            (NodeId::new(0, 0, 10), CFGNodeData::new_test_single(10, InsnNodeType::new(InsnNodeWeightType::Normal, true), NodeId::new(0, 0, 0), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 1), INVALID_NODE_ID)),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 1), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), INVALID_NODE_ID)),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 3), NodeId::new(0, 0, 1))),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 3), NodeId::new(0, 0, 1))),
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), INVALID_NODE_ID)),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 3), NodeId::new(0, 0, 1))),
            (NodeId::new(0, 0, 3), CFGNodeData::new_test_single(3, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 13), INVALID_NODE_ID)),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 3), CFGNodeData::new_test_single(3, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 13), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 13), CFGNodeData::new_test_single(13, InsnNodeType::new(InsnNodeWeightType::Return, false), INVALID_NODE_ID, INVALID_NODE_ID)),
        );
        }
        cfg
    }

    fn get_cfg_self_ref_loop() -> CFG {
        let mut cfg = CFG::new();
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        cfg.add_edge(
            (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::new(InsnNodeWeightType::Normal, true), NodeId::new(0, 0, 1), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), NodeId::new(0, 0, 1))),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), NodeId::new(0, 0, 1))),
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), NodeId::new(0, 0, 1))),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), NodeId::new(0, 0, 1))),
            (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::new(InsnNodeWeightType::Return, false), INVALID_NODE_ID, INVALID_NODE_ID)),
        );
        }
        cfg
    }

    ///
    /// ```
    ///  0
    ///  |
    ///  1     +--+
    /// | \    |  |
    /// |  4 <-+-+
    /// | /
    /// 2
    /// |
    /// 3
    /// ```
    fn get_cfg_loop_self_ref() -> CFG {
        let mut cfg = CFG::new();
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        cfg.add_edge(
            (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::new(InsnNodeWeightType::Normal, true), NodeId::new(0, 0, 1), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), INVALID_NODE_ID)),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 3), NodeId::new(0, 0, 4))),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 3), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 3), CFGNodeData::new_test_single(3, InsnNodeType::new(InsnNodeWeightType::Return, false), INVALID_NODE_ID, INVALID_NODE_ID)),
        );

        cfg.add_edge(
            (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 3), NodeId::new(0, 0, 4))),
            (NodeId::new(0, 0, 4), CFGNodeData::new_test_single(4, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 1), NodeId::new(0, 0, 4))),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 4), CFGNodeData::new_test_single(4, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 1), NodeId::new(0, 0, 4))),
            (NodeId::new(0, 0, 4), CFGNodeData::new_test_single(4, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 1), NodeId::new(0, 0, 4))),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 4), CFGNodeData::new_test_single(4, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 1), NodeId::new(0, 0, 4))),
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), INVALID_NODE_ID)),
        );
        }
        cfg
    }

    fn get_paper_example_cfg_loop() -> CFG {
        let mut cfg = CFG::new();
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        cfg.add_edge(
            (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::new(InsnNodeWeightType::Normal, true), NodeId::new(0, 0, 1), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), INVALID_NODE_ID)),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 3), NodeId::new(0, 0, 1))),
        );
        // Back edge
        cfg.add_edge(
            (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 3), NodeId::new(0, 0, 1))),
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), INVALID_NODE_ID)),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 3), NodeId::new(0, 0, 1))),
            (NodeId::new(0, 0, 3), CFGNodeData::new_test_single(3, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 4), NodeId::new(0, 0, 2))),
        );
        // Back edge
        cfg.add_edge(
            (NodeId::new(0, 0, 3), CFGNodeData::new_test_single(3, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 4), NodeId::new(0, 0, 2))),
            (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 3), NodeId::new(0, 0, 1))),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 3), CFGNodeData::new_test_single(3, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 4), NodeId::new(0, 0, 2))),
            (NodeId::new(0, 0, 4), CFGNodeData::new_test_single(4, InsnNodeType::new(InsnNodeWeightType::Return, false), INVALID_NODE_ID, INVALID_NODE_ID)),
        );
        }
        cfg
    }

    fn get_unset_indirect_call_cfg() -> CFG {
        let mut cfg = CFG::new();

        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        cfg.add_edge(
            (NodeId::new(0, 0, 0), CFGNodeData::new_test_single( 0, InsnNodeType::new(InsnNodeWeightType::Normal, true), NodeId::new(0, 0, 1), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single_call( 1, NodeId::new(0, 0, RANDOM_FCN_ADDR), true, NodeId::new(0, 0, 2))),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single_call( 1, NodeId::new(0, 0, RANDOM_FCN_ADDR), true, NodeId::new(0, 0, 2))),
            (NodeId::new(0, 0, 2), CFGNodeData::new_test_single( 2, InsnNodeType::new(InsnNodeWeightType::Return, false), NodeId::new(0, 0, 3), INVALID_NODE_ID)),
        );
        }

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
        assert_node_weight(gee_cfg.nodes_meta.get(&NodeId::new(0, 0, 0)), 2);
        assert_node_weight(gee_cfg.nodes_meta.get(&NodeId::new(0, 0, 1)), 2);
        assert_node_weight(gee_cfg.nodes_meta.get(&NodeId::new(0, 0, 2)), 1);
        assert_node_weight(gee_cfg.nodes_meta.get(&NodeId::new(0, 0, 3)), 1);
        assert_node_weight(gee_cfg.nodes_meta.get(&NodeId::new(0, 0, 4)), 1);
        assert_eq!(gee_cfg.get_weight(), 2);
    }

    #[test]
    fn test_undiscovered_indirect_call() {
        let mut cfg = get_unset_indirect_call_cfg();
        cfg.calc_weight();
        assert_node_weight(cfg.nodes_meta.get(&NodeId::new(0, 0, 0)), 1);
        cfg.add_call_target_weights(&[&(NodeId::new(0, 0, RANDOM_FCN_ADDR), 10)]);
        cfg.calc_weight();
        assert_node_weight(cfg.nodes_meta.get(&NodeId::new(0, 0, 0)), 10);
    }

    #[test]
    fn test_icfg_weight_calc() {
        let mut icfg: ICFG = get_paper_example_icfg();
        icfg.calc_weight();
        assert_eq!(icfg.get_procedure_weight(NodeId::new(0, 0, MAIN_ADDR)), 6);
        assert_eq!(icfg.get_procedure_weight(NodeId::new(0, 0, FOO_ADDR)), 4);
        assert_eq!(icfg.get_procedure_weight(NodeId::new(0, 0, GEE_ADDR)), 2);
    }

    #[test]
    fn test_icfg_no_procedure_duplicates() {
        let mut icfg: ICFG = get_paper_example_icfg();
        // Add a cloned edge from main -> foo'()
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        icfg.add_edge(
            (NodeId::new(0, 0, MAIN_ADDR), Procedure::new(None, false)),
            (NodeId::new(0, 0, FOO_ADDR), Procedure::new(None, false)),
        );
        }
        assert_eq!(icfg.num_procedures(), 3);
        icfg.add_cloned_edge(NodeId::new(0, 0, MAIN_ADDR), NodeId::new(0, 0, GEE_ADDR));
        assert_eq!(icfg.num_procedures(), 3);
    }

    #[test]
    fn test_cfg_untangle() {
        let mut cfg = get_paper_example_cfg_loop();
        // println!(
        //     "{:?}",
        //     Dot::with_config(&cfg.graph, &[Config::EdgeNoLabel, Config::NodeIndexLabel])
        // );
        cfg.make_acyclic();
        // println!("{:?}", Dot::with_config(&cfg.graph, &[Config::EdgeNoLabel]));
        assert_eq!(cfg.graph.node_count(), 14);
        assert_eq!(cfg.graph.edge_count(), 22);
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        assert!(cfg.graph.contains_edge(NodeId::new(0, 0, 0), NodeId::new(0, 0, 1)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 0, 1), NodeId::new(0, 0, 2)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 0, 2), NodeId::new(0, 0, 3)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 0, 3), NodeId::new(0, 0, 4)));

        // Loop 2 -> 1 -> 2 ...
        assert!(cfg.graph.contains_edge(NodeId::new(0, 0, 2), NodeId::new(0, 1, 0x1)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 1, 0x1), NodeId::new(0, 1, 0x2)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 1, 0x2), NodeId::new(0, 2, 0x1)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 2, 0x2), NodeId::new(0, 3, 0x1)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 3, 0x1), NodeId::new(0, 3, 0x2)));

        // Loop 3 -> 2 -> 3 ...
        assert!(cfg.graph.contains_edge(NodeId::new(0, 0, 3), NodeId::new(0, 1, 0x2)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 1, 0x2), NodeId::new(0, 1, 0x3)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 1, 0x3), NodeId::new(0, 2, 0x2)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 2, 0x3), NodeId::new(0, 3, 0x2)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 3, 0x2), NodeId::new(0, 3, 0x3)));

        // Into scc edges
        assert!(cfg.graph.contains_edge(NodeId::new(0, 0, 0), NodeId::new(0, 1, 0x1)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 0, 0), NodeId::new(0, 2, 0x1)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 0, 0), NodeId::new(0, 3, 0x1)));

        // Out of scc edges
        assert!(cfg.graph.contains_edge(NodeId::new(0, 1, 0x3), NodeId::new(0, 0, 4)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 2, 0x3), NodeId::new(0, 0, 4)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 3, 0x3), NodeId::new(0, 0, 4)));

        assert!(cfg.graph.contains_edge(NodeId::new(0, 1, 1), NodeId::new(0, 1, 2)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 1, 2), NodeId::new(0, 1, 3)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 2, 1), NodeId::new(0, 2, 2)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 2, 2), NodeId::new(0, 2, 3)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 3, 1), NodeId::new(0, 3, 2)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 3, 2), NodeId::new(0, 3, 3)));
        }
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
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        assert!(cfg.graph.contains_edge(NodeId::new(0, 0, 10), NodeId::new(0, 0, 11)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 0, 11), NodeId::new(0, 0, 0)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 0, 0), NodeId::new(0, 0, 1)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 0, 1), NodeId::new(0, 0, 2)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 0, 2), NodeId::new(0, 0, 12)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 0, 12), NodeId::new(0, 0, 13)));
        }
    }

    #[test]
    /// Test if the back-edge logic with jumps to lower addresses works.
    fn test_cfg_loop_subroutine_ret() {
        let mut cfg = get_cfg_no_loop_sub_routine_loop_ret();
        // println!(
        //     "Graph:\n{:?}",
        //     Dot::with_config(&cfg.graph, &[Config::EdgeNoLabel, Config::NodeIndexLabel])
        // );
        cfg.make_acyclic();
        // println!(
        //     "Acyclic:\n{:?}",
        //     Dot::with_config(&cfg.graph, &[Config::EdgeNoLabel])
        // );
        assert_eq!(cfg.graph.node_count(), 23);
        assert_eq!(cfg.graph.edge_count(), 37);

        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        assert!(cfg.graph.contains_edge(NodeId::new(0, 0, 10), NodeId::new(0, 0, 11)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 0, 11), NodeId::new(0, 0, 12)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 0, 12), NodeId::new(0, 0, 13)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 0, 13), NodeId::new(0, 0, 14)));

        assert!(cfg.graph.contains_edge(NodeId::new(0, 0, 0),  NodeId::new(0, 0, 1)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 0, 1),  NodeId::new(0, 0, 2)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 0, 11), NodeId::new(0, 0, 1)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 0, 11), NodeId::new(0, 1, 1)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 0, 11), NodeId::new(0, 2, 1)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 0, 11), NodeId::new(0, 3, 1)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 1, 11), NodeId::new(0, 0, 1)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 2, 11), NodeId::new(0, 0, 1)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 3, 11), NodeId::new(0, 0, 1)));

        assert!(cfg.graph.contains_edge(NodeId::new(0, 0, 10), NodeId::new(0, 1, 11)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 0, 10), NodeId::new(0, 2, 11)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 0, 10), NodeId::new(0, 3, 11)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 0, 13), NodeId::new(0, 1, 11)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 1, 13), NodeId::new(0, 2, 11)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 2, 13), NodeId::new(0, 3, 11)));

        assert!(cfg.graph.contains_edge(NodeId::new(0, 1, 11), NodeId::new(0, 1, 12)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 1, 12), NodeId::new(0, 1, 13)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 2, 11), NodeId::new(0, 2, 12)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 2, 12), NodeId::new(0, 2, 13)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 3, 11), NodeId::new(0, 3, 12)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 3, 12), NodeId::new(0, 3, 13)));

        assert!(cfg.graph.contains_edge(NodeId::new(0, 1, 13), NodeId::new(0, 0, 14)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 2, 13), NodeId::new(0, 0, 14)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 3, 13), NodeId::new(0, 0, 14)));

        assert!(cfg.graph.contains_edge(NodeId::new(0, 0, 1), NodeId::new(0, 1, 0)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 1, 0), NodeId::new(0, 1, 1)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 1, 1), NodeId::new(0, 2, 0)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 2, 0), NodeId::new(0, 2, 1)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 2, 1), NodeId::new(0, 3, 0)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 3, 0), NodeId::new(0, 3, 1)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 1, 1), NodeId::new(0, 0, 2)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 2, 1), NodeId::new(0, 0, 2)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 3, 1), NodeId::new(0, 0, 2)));
        }
    }

    #[test]
    fn test_cfg_loop_empty() {
        let mut cfg = get_cfg_empty();
        cfg.make_acyclic();
        assert_eq!(cfg.graph.edge_count(), 0);
        assert_eq!(cfg.graph.node_count(), 0);
        assert_eq!(cfg.nodes_meta.len(), 0);
        cfg.calc_weight();
        assert_eq!(cfg.get_weight(), INVALID_WEIGHT);
    }

    #[test]
    fn test_cfg_add_duplicate_node() {
        let mut cfg: CFG = get_cfg_single_node();
        cfg.add_node((
            NodeId::new(0, 0, 0),
            CFGNodeData::new_test_single(
                0,
                InsnNodeType::new(InsnNodeWeightType::Return, false),
                INVALID_NODE_ID,
                INVALID_NODE_ID,
            ),
        ));
    }

    #[test]
    fn test_cfg_single_node() {
        let mut cfg: CFG = get_cfg_single_node();
        cfg.make_acyclic();
        assert_eq!(cfg.graph.edge_count(), 0);
        assert_eq!(cfg.graph.node_count(), 1);
        assert_eq!(cfg.nodes_meta.len(), 1);
        cfg.calc_weight();
        assert_eq!(cfg.get_weight(), 1);
    }

    #[test]
    #[should_panic(
        expected = "Generated weight of CFG has weight 0. Does a return or invalid instruction exists?"
    )]
    fn test_cfg_no_return_node() {
        let mut cfg = CFG::new();
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        cfg.add_edge(
            (
                NodeId::new(0, 0, 0),
                CFGNodeData::new_test_single(0, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 1), INVALID_NODE_ID),
            ),
            (
                NodeId::new(0, 0, 1),
                CFGNodeData::new_test_single(1, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), INVALID_NODE_ID),
            ),
        );
        }
        cfg.calc_weight();
    }

    #[test]
    #[should_panic(expected = "Graph contains cycles. Cannot sort it to topological order.")]
    fn test_cfg_calc_weight_before_acyclic() {
        let mut cfg: CFG = get_cfg_single_self_ref();
        cfg.calc_weight();
    }

    #[test]
    #[should_panic(
        expected = "If get_weight() is called on a CFG, the weights must have been calculated before."
    )]
    fn test_cfg_no_weight_before_acyclic() {
        let cfg: CFG = get_cfg_single_self_ref();
        cfg.get_weight();
    }

    #[test]
    #[should_panic(expected = "Edge (0:0:0x64) => (0:0:0xc8) does not exist.")]
    fn test_cfg_get_invalid_edge() {
        let cfg: CFG = get_cfg_single_self_ref();
        cfg.get_edge_weight(NodeId::new(0, 0, 100), NodeId::new(0, 0, 200));
    }

    #[test]
    fn test_cfg_single_self_ref() {
        let mut cfg: CFG = get_cfg_single_self_ref();
        assert_eq!(cfg.graph.edge_count(), 1);
        assert_eq!(cfg.graph.node_count(), 1);
        assert_eq!(cfg.nodes_meta.len(), 1);
        cfg.make_acyclic();
        assert_eq!(cfg.graph.edge_count(), 3);
        assert_eq!(cfg.graph.node_count(), 4);
        assert_eq!(cfg.nodes_meta.len(), 4);
        cfg.calc_weight();
        assert_eq!(cfg.get_weight(), 1);
    }

    #[test]
    fn test_cfg_linear() {
        let mut cfg: CFG = get_cfg_linear();
        assert_eq!(cfg.graph.edge_count(), 3);
        assert_eq!(cfg.graph.node_count(), 4);
        assert_eq!(cfg.nodes_meta.len(), 4);
        cfg.make_acyclic();
        assert_eq!(cfg.graph.edge_count(), 3);
        assert_eq!(cfg.graph.node_count(), 4);
        assert_eq!(cfg.nodes_meta.len(), 4);
        cfg.calc_weight();
        assert_eq!(cfg.get_weight(), 1);
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 0, 0)), 1);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 0, 1)), 1);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 0, 2)), 1);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 0, 3)), 1);
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 0, 0), NodeId::new(0, 0, 1)), &(1, 1));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 0, 1), NodeId::new(0, 0, 2)), &(1, 1));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 0, 2), NodeId::new(0, 0, 3)), &(1, 1));
        }
    }

    #[test]
    fn test_cfg_simple_loop_single_node_scc() {
        let mut cfg: CFG = get_cfg_simple_loop_extra_nodes();
        assert_eq!(cfg.graph.edge_count(), 6);
        assert_eq!(cfg.graph.node_count(), 6);
        assert_eq!(cfg.nodes_meta.len(), 6);
        cfg.make_acyclic();
        assert_eq!(cfg.graph.edge_count(), 17);
        assert_eq!(cfg.graph.node_count(), 12);
        assert_eq!(cfg.nodes_meta.len(), 12);
        cfg.calc_weight();
        assert_eq!(cfg.graph.edge_count(), 17);
        assert_eq!(cfg.graph.node_count(), 12);
        assert_eq!(cfg.nodes_meta.len(), 12);
        assert_eq!(cfg.get_weight(), 10);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 0, 10)), 10);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 0, 0)), 10);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 0, 1)), 4);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 0, 2)), 4);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 0, 3)), 1);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 0, 13)), 1);

        assert_eq!(cfg.get_node_weight(NodeId::new(0, 1, 1)), 3);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 1, 2)), 3);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 2, 1)), 2);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 2, 2)), 2);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 3, 1)), 1);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 3, 2)), 1);

        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 0, 0), NodeId::new(0, 0, 1)), &(4, 10));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 0, 0), NodeId::new(0, 1, 1)), &(3, 10));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 0, 0), NodeId::new(0, 2, 1)), &(2, 10));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 0, 0), NodeId::new(0, 3, 1)), &(1, 10));

        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 0, 1), NodeId::new(0, 0, 2)), &(4, 4));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 1, 1), NodeId::new(0, 1, 2)), &(3, 3));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 2, 1), NodeId::new(0, 2, 2)), &(2, 2));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 3, 1), NodeId::new(0, 3, 2)), &(1, 1));

        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 0, 2), NodeId::new(0, 1, 1)), &(3, 4));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 1, 2), NodeId::new(0, 2, 1)), &(2, 3));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 2, 2), NodeId::new(0, 3, 1)), &(1, 2));

        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 0, 2), NodeId::new(0, 0, 3)), &(1, 4));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 1, 2), NodeId::new(0, 0, 3)), &(1, 3));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 2, 2), NodeId::new(0, 0, 3)), &(1, 2));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 3, 2), NodeId::new(0, 0, 3)), &(1, 1));

        // Single node SCCs
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 0, 3), NodeId::new(0, 0, 13)), &(1, 1));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 0, 10), NodeId::new(0, 0, 0)), &(10, 10));
        }
    }

    #[test]
    fn test_cfg_simple_loop() {
        let mut cfg: CFG = get_cfg_simple_loop();
        assert_eq!(cfg.graph.edge_count(), 4);
        assert_eq!(cfg.graph.node_count(), 4);
        assert_eq!(cfg.nodes_meta.len(), 4);
        cfg.make_acyclic();
        assert_eq!(cfg.graph.edge_count(), 15);
        assert_eq!(cfg.graph.node_count(), 10);
        assert_eq!(cfg.nodes_meta.len(), 10);
        cfg.calc_weight();
        assert_eq!(cfg.graph.edge_count(), 15);
        assert_eq!(cfg.graph.node_count(), 10);
        assert_eq!(cfg.nodes_meta.len(), 10);
        assert_eq!(cfg.get_weight(), 10);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 0, 0)), 10);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 0, 1)), 4);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 0, 2)), 4);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 0, 3)), 1);

        assert_eq!(cfg.get_node_weight(NodeId::new(0, 1, 1)), 3);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 1, 2)), 3);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 2, 1)), 2);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 2, 2)), 2);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 3, 1)), 1);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 3, 2)), 1);

        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 0, 0), NodeId::new(0, 0, 1)), &(4, 10));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 0, 0), NodeId::new(0, 1, 1)), &(3, 10));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 0, 0), NodeId::new(0, 2, 1)), &(2, 10));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 0, 0), NodeId::new(0, 3, 1)), &(1, 10));

        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 0, 1), NodeId::new(0, 0, 2)), &(4, 4));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 1, 1), NodeId::new(0, 1, 2)), &(3, 3));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 2, 1), NodeId::new(0, 2, 2)), &(2, 2));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 3, 1), NodeId::new(0, 3, 2)), &(1, 1));

        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 0, 2), NodeId::new(0, 1, 1)), &(3, 4));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 1, 2), NodeId::new(0, 2, 1)), &(2, 3));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 2, 2), NodeId::new(0, 3, 1)), &(1, 2));

        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 0, 2), NodeId::new(0, 0, 3)), &(1, 4));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 1, 2), NodeId::new(0, 0, 3)), &(1, 3));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 2, 2), NodeId::new(0, 0, 3)), &(1, 2));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 3, 2), NodeId::new(0, 0, 3)), &(1, 1));
        }
    }

    #[test]
    fn test_cfg_self_ref() {
        let mut cfg: CFG = get_cfg_self_ref_loop();
        assert_eq!(cfg.graph.edge_count(), 3);
        assert_eq!(cfg.graph.node_count(), 3);
        assert_eq!(cfg.nodes_meta.len(), 3);
        cfg.make_acyclic();
        assert_eq!(cfg.graph.edge_count(), 11);
        assert_eq!(cfg.graph.node_count(), 6);
        assert_eq!(cfg.nodes_meta.len(), 6);
        cfg.calc_weight();
        assert_eq!(cfg.graph.edge_count(), 11);
        assert_eq!(cfg.graph.node_count(), 6);
        assert_eq!(cfg.nodes_meta.len(), 6);
        assert_eq!(cfg.get_weight(), 10);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 0, 0)), 10);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 0, 1)), 4);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 0, 2)), 1);

        assert_eq!(cfg.get_node_weight(NodeId::new(0, 1, 1)), 3);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 2, 1)), 2);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 3, 1)), 1);

        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 0, 0), NodeId::new(0, 0, 1)), &(4, 10));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 0, 0), NodeId::new(0, 1, 1)), &(3, 10));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 0, 0), NodeId::new(0, 2, 1)), &(2, 10));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 0, 0), NodeId::new(0, 3, 1)), &(1, 10));

        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 0, 1), NodeId::new(0, 1, 1)), &(3, 4));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 1, 1), NodeId::new(0, 2, 1)), &(2, 3));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 2, 1), NodeId::new(0, 3, 1)), &(1, 2));

        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 0, 1), NodeId::new(0, 0, 2)), &(1, 4));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 1, 1), NodeId::new(0, 0, 2)), &(1, 3));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 2, 1), NodeId::new(0, 0, 2)), &(1, 2));
        assert_eq!(cfg.get_edge_weight(NodeId::new(0, 3, 1), NodeId::new(0, 0, 2)), &(1, 1));
        }
    }

    #[test]
    fn test_cfg_looped_self_ref() {
        let mut cfg: CFG = get_cfg_loop_self_ref();
        assert_eq!(cfg.graph.edge_count(), 6);
        assert_eq!(cfg.graph.node_count(), 5);
        assert_eq!(cfg.nodes_meta.len(), 5);
        // println!(
        //     "{:?}",
        //     Dot::with_config(&cfg.graph, &[Config::EdgeNoLabel, Config::NodeIndexLabel])
        // );
        cfg.make_acyclic();
        // println!("{:?}", Dot::with_config(&cfg.graph, &[]));
        assert_eq!(cfg.graph.edge_count(), 22);
        assert_eq!(cfg.graph.node_count(), 14);
        assert_eq!(cfg.nodes_meta.len(), 14);
        cfg.calc_weight();
        assert_eq!(cfg.graph.edge_count(), 22);
        assert_eq!(cfg.graph.node_count(), 14);
        assert_eq!(cfg.nodes_meta.len(), 14);
        assert_eq!(cfg.get_weight(), 15);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 0, 0)), 15);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 0, 1)), 8);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 0, 2)), 8);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 0, 3)), 1);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 0, 4)), 7);

        assert_eq!(cfg.get_node_weight(NodeId::new(0, 1, 1)), 4);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 2, 1)), 2);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 3, 1)), 1);

        assert_eq!(cfg.get_node_weight(NodeId::new(0, 1, 2)), 4);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 2, 2)), 2);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 3, 2)), 1);

        assert_eq!(cfg.get_node_weight(NodeId::new(0, 1, 4)), 3);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 2, 4)), 1);
        assert_eq!(cfg.get_node_weight(NodeId::new(0, 3, 4)), 0);
    }

    #[test]
    fn test_sampling_bias_printing() {
        assert_eq!(
            SamplingBias::new(INVALID_WEIGHT, INVALID_WEIGHT).to_string(),
            "invalid/invalid"
        );
        assert_eq!(
            SamplingBias::new(1, INVALID_WEIGHT).to_string(),
            "0x1/invalid"
        );
        assert_eq!(
            SamplingBias::new(INVALID_WEIGHT, 0xfffffffffffffffe).to_string(),
            "invalid/0xfffffffffffffffe"
        );
        assert_eq!(
            SamplingBias::new(0xfffffffffffffffe, 0xfffffffffffffffe).to_string(),
            "0xfffffffffffffffe/0xfffffffffffffffe"
        );
    }

    #[test]
    fn test_icfg_endless_acyclic() {
        let mut icfg = get_endless_loop_icfg();
        icfg.make_acyclic();
        icfg.calc_weight();
        // In this edge case, we can resolve a loop, but each path has the weight of 1.
        // Sincen no CFG has a branch.
        assert_eq!(icfg.get_procedure_weight(NodeId::new(0, 0, 0xa0)), 1);
        assert_eq!(icfg.get_procedure_weight(NodeId::new(0, 0, 0xb0)), 1);
        assert_eq!(icfg.get_procedure_weight(NodeId::new(0, 0, 0xc0)), 1);

        assert_eq!(icfg.get_procedure_weight(NodeId::new(1, 0, 0xa0)), 1);
        assert_eq!(icfg.get_procedure_weight(NodeId::new(1, 0, 0xb0)), 1);
        assert_eq!(icfg.get_procedure_weight(NodeId::new(1, 0, 0xc0)), 1);

        assert_eq!(icfg.get_procedure_weight(NodeId::new(2, 0, 0xa0)), 1);
        assert_eq!(icfg.get_procedure_weight(NodeId::new(2, 0, 0xb0)), 1);
        assert_eq!(icfg.get_procedure_weight(NodeId::new(2, 0, 0xc0)), 1);

        assert_eq!(icfg.get_procedure_weight(NodeId::new(3, 0, 0xa0)), 1);
        assert_eq!(icfg.get_procedure_weight(NodeId::new(3, 0, 0xb0)), 1);
        assert_eq!(icfg.get_procedure_weight(NodeId::new(3, 0, 0xc0)), 1);
    }

    #[test]
    fn test_icfg_endless_with_branch_acyclic() {
        let mut icfg = get_endless_loop_icfg_branch();
        icfg.make_acyclic();
        icfg.calc_weight();
        println!(
            "{:?}",
            Dot::with_config(
                &icfg
                    .get_procedure(&NodeId::new(0, 0, 0xa0))
                    .read()
                    .unwrap()
                    .get_cfg()
                    .graph,
                &[]
            )
        );

        assert_eq!(icfg.get_procedure_weight(NodeId::new(3, 0, 0xa0)), 2);
        assert_eq!(icfg.get_procedure_weight(NodeId::new(3, 0, 0xb0)), 2);
        assert_eq!(icfg.get_procedure_weight(NodeId::new(3, 0, 0xd0)), 2);

        assert_eq!(icfg.get_procedure_weight(NodeId::new(2, 0, 0xa0)), 4);
        assert_eq!(icfg.get_procedure_weight(NodeId::new(2, 0, 0xb0)), 4);
        assert_eq!(icfg.get_procedure_weight(NodeId::new(2, 0, 0xd0)), 4);

        assert_eq!(icfg.get_procedure_weight(NodeId::new(1, 0, 0xa0)), 8);
        assert_eq!(icfg.get_procedure_weight(NodeId::new(1, 0, 0xb0)), 8);
        assert_eq!(icfg.get_procedure_weight(NodeId::new(1, 0, 0xd0)), 8);

        assert_eq!(icfg.get_procedure_weight(NodeId::new(0, 0, 0xa0)), 16);
        assert_eq!(icfg.get_procedure_weight(NodeId::new(0, 0, 0xb0)), 16);
        assert_eq!(icfg.get_procedure_weight(NodeId::new(0, 0, 0xd0)), 16);
    }

    #[test]
    fn test_icfg_resolve_cycles() {
        let mut icfg = get_icfg_with_selfref_and_recurse_cfg();
        icfg.resolve_loops(4);
        assert_eq!(icfg.num_procedures(), 4);
    }
}
