// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#[cfg(test)]
mod tests {

    use std::{collections::HashSet, sync::RwLock};

    use petgraph::dot::{Config, Dot};

    use crate::{
        cfg::{CFGNodeData, InsnNodeType, InsnNodeWeightType, CFG},
        flow_graphs::{Address, FlowGraphOperations, NodeId, ProcedureMap, INVALID_NODE_ID},
        icfg::{Procedure, ICFG},
        weight::{WeightID, WeightMap},
    };

    const A_ADDR: Address = 0xa0;
    const B_ADDR: Address = 0xb0;
    const C_ADDR: Address = 0xc0;
    const D_ADDR: Address = 0xd0;
    const GEE_ADDR: Address = 0;
    const FOO_ADDR: Address = 6;
    const MAIN_ADDR: Address = 11;
    const RANDOM_FCN_ADDR: Address = 0x5a5a5a5a5a5a5a5a;

    macro_rules! empty_proc_map {
        () => {
            &ProcedureMap::new()
        };
    }

    fn assert_p_weight(icfg: &ICFG, proc: &NodeId, val: usize, wmap: &RwLock<WeightMap>) {
        assert!(
            icfg.get_procedure(proc)
                .write()
                .unwrap()
                .get_cfg_mut()
                .weight_eq_usize(val, icfg.get_procedures(), wmap),
            "Proc weight {} != {}",
            icfg.get_procedure(proc)
                .read()
                .unwrap()
                .get_cfg()
                .get_node_weight_id(proc)
                .unwrap()
                .get_weight_const(wmap),
            val
        );
    }

    /// A -> B -> C -> A
    ///           \  
    ///            +--> C -> C ....
    fn get_endless_loop_icfg() -> (ICFG, RwLock<WeightMap>) {
        let mut icfg = ICFG::new();
        let wmapo = WeightMap::new();
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
        (icfg, wmapo)
    }

    fn get_endless_loop_icfg_branch() -> (ICFG, RwLock<WeightMap>) {
        let mut icfg = ICFG::new();
        let wmapo = WeightMap::new();
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
        (icfg, wmapo)
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

    fn get_paper_example_icfg() -> (ICFG, RwLock<WeightMap>) {
        let mut icfg = ICFG::new();
        let wmapo = WeightMap::new();

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

        (icfg, wmapo)
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

    fn get_cfg_single_node(wmap: &RwLock<WeightMap>) -> CFG {
        let mut cfg = CFG::new();
        cfg.add_node(
            (
                NodeId::new(0, 0, 0),
                CFGNodeData::new_test_single(
                    0,
                    InsnNodeType::new(InsnNodeWeightType::Return, false),
                    INVALID_NODE_ID,
                    INVALID_NODE_ID,
                ),
            ),
            wmap,
        );
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

    fn get_cfg_linear_call() -> CFG {
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
            (NodeId::new(0, 0, 3), CFGNodeData::new_test_single(3, InsnNodeType::new(InsnNodeWeightType::Call, false), INVALID_NODE_ID, INVALID_NODE_ID)),
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

    /// 0 ---> 1 <-----> 2
    fn get_endless_loop_cfg() -> CFG {
        let mut cfg = CFG::new();

        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        cfg.add_edge(
            (NodeId::new(0, 0, 0), CFGNodeData::new_test_single( 0, InsnNodeType::new(InsnNodeWeightType::Normal, true), NodeId::new(0, 0, 1), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single( 0, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), INVALID_NODE_ID)),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single( 0, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 2), CFGNodeData::new_test_single( 2, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 1), INVALID_NODE_ID)),
        );
        cfg.add_edge(
            (NodeId::new(0, 0, 2), CFGNodeData::new_test_single( 2, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 1), INVALID_NODE_ID)),
            (NodeId::new(0, 0, 1), CFGNodeData::new_test_single( 0, InsnNodeType::new(InsnNodeWeightType::Normal, false), NodeId::new(0, 0, 2), INVALID_NODE_ID)),
        );
        }

        cfg
    }

    fn assert_node_weight(wid: WeightID, weight: usize, wmap: &RwLock<WeightMap>) {
        assert!(
            wid.eq_usize(weight, wmap),
            "Node weight {} != {}",
            wid.get_weight_const(wmap),
            weight
        );
    }

    fn assert_weight(wid: Option<WeightID>, cmp_w: usize, wmap: &RwLock<WeightMap>) {
        assert!(wid.is_some(), "wid is not set");
        let wid = wid.unwrap();
        assert!(
            wid.eq_usize(cmp_w, wmap),
            "Node weight {} != {}",
            wid.get_weight_const(wmap),
            cmp_w
        );
    }

    #[test]
    fn test_cfg_weight_calc_no_call() {
        let wmap = &WeightMap::new();
        let mut gee_cfg = get_gee_cfg();
        gee_cfg.make_acyclic(wmap, None);
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        assert_node_weight(gee_cfg.calc_node_weight(&NodeId::new(0, 0, 0), empty_proc_map!(), wmap, false), 2, wmap);
        assert_node_weight(gee_cfg.calc_node_weight(&NodeId::new(0, 0, 1), empty_proc_map!(), wmap, false), 2, wmap);
        assert_node_weight(gee_cfg.calc_node_weight(&NodeId::new(0, 0, 2), empty_proc_map!(), wmap, false), 1, wmap);
        assert_node_weight(gee_cfg.calc_node_weight(&NodeId::new(0, 0, 3), empty_proc_map!(), wmap, false), 1, wmap);
        assert_node_weight(gee_cfg.calc_node_weight(&NodeId::new(0, 0, 4), empty_proc_map!(), wmap, false), 1, wmap);
        assert_weight(gee_cfg.get_entry_weight_id(empty_proc_map!(), wmap), 2, wmap);
        }
    }

    #[test]
    fn test_undiscovered_indirect_call() {
        let wmap = &WeightMap::new();
        let mut cfg = get_unset_indirect_call_cfg();
        cfg.make_acyclic(wmap, None);
        println!("{:?}", Dot::with_config(&cfg.graph, &[Config::EdgeNoLabel]));
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        assert_node_weight(cfg.calc_node_weight(&NodeId::new(0, 0, 0), empty_proc_map!(), wmap, false), 1, wmap);
        let mut proc_map = ProcedureMap::new();
        let mut lcfg = get_cfg_simple_loop();
        lcfg.make_acyclic(wmap, None);
        println!("lcfg: {:?}", Dot::with_config(&lcfg.graph, &[Config::EdgeNoLabel]));
        proc_map.insert(NodeId::from(RANDOM_FCN_ADDR), RwLock::new(Procedure::new(Some(lcfg), false)));
        assert_node_weight(cfg.calc_node_weight(&NodeId::new(0, 0, 0), &proc_map, wmap, true), 10, wmap);
        lcfg = get_cfg_linear();
        lcfg.make_acyclic(wmap, None);
        proc_map.insert(NodeId::from(RANDOM_FCN_ADDR), RwLock::new(Procedure::new(Some(lcfg), false)));
        assert_node_weight(cfg.calc_node_weight(&NodeId::new(0, 0, 0), &proc_map, wmap, true), 1, wmap);
        }
    }

    #[test]
    fn test_icfg_weight_calc() {
        let (mut icfg, wmap) = get_paper_example_icfg();
        let wmap = &wmap;
        icfg.resolve_loops(1, wmap);
        assert_p_weight(&icfg, &NodeId::new(0, 0, MAIN_ADDR), 6, wmap);
        assert_p_weight(&icfg, &NodeId::new(0, 0, FOO_ADDR), 4, wmap);
        assert_p_weight(&icfg, &NodeId::new(0, 0, MAIN_ADDR), 6, wmap);
        assert_p_weight(&icfg, &NodeId::new(0, 0, FOO_ADDR), 4, wmap);
        assert_p_weight(&icfg, &NodeId::new(0, 0, GEE_ADDR), 2, wmap);
    }

    #[test]
    fn test_icfg_no_procedure_duplicates() {
        let (mut icfg, wmap) = get_paper_example_icfg();
        let wmap = &wmap;
        // Add a cloned edge from main -> foo'()
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        icfg.add_edge(
            (NodeId::new(0, 0, MAIN_ADDR), Procedure::new(None, false)),
            (NodeId::new(0, 0, FOO_ADDR), Procedure::new(None, false)),
);
        }
        assert_eq!(icfg.num_procedures(), 3);
        icfg.add_cloned_edge(
            NodeId::new(0, 0, MAIN_ADDR),
            NodeId::new(0, 0, GEE_ADDR),
            wmap,
        );
        assert_eq!(icfg.num_procedures(), 3);
    }

    #[test]
    fn test_cfg_untangle() {
        let wmap = &WeightMap::new();
        let mut cfg = get_paper_example_cfg_loop();
        // println!(
        //     "{:?}",
        //     Dot::with_config(&cfg.graph, &[Config::EdgeNoLabel, Config::NodeIndexLabel])
        // );
        cfg.make_acyclic(wmap, None);
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
        let wmap = &WeightMap::new();
        let mut cfg = get_cfg_no_loop_sub_routine();
        // println!(
        //     "{:?}",
        //     Dot::with_config(&cfg.graph, &[Config::EdgeNoLabel, Config::NodeIndexLabel])
        // );
        cfg.make_acyclic(wmap, None);
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
        let wmap = &WeightMap::new();
        let mut cfg = get_cfg_no_loop_sub_routine_loop_ret();
        // println!(
        //     "Graph:\n{:?}",
        //     Dot::with_config(&cfg.graph, &[Config::EdgeNoLabel, Config::NodeIndexLabel])
        // );
        cfg.make_acyclic(wmap, None);
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
    fn test_cfg_add_duplicate_node() {
        let wmap = &WeightMap::new();
        let mut cfg: CFG = get_cfg_single_node(wmap);
        cfg.add_node(
            (
                NodeId::new(0, 0, 0),
                CFGNodeData::new_test_single(
                    0,
                    InsnNodeType::new(InsnNodeWeightType::Return, false),
                    INVALID_NODE_ID,
                    INVALID_NODE_ID,
                ),
            ),
            wmap,
        );
    }

    #[test]
    fn test_cfg_single_node() {
        let wmap = &WeightMap::new();
        let mut cfg: CFG = get_cfg_single_node(wmap);
        cfg.make_acyclic(wmap, None);
        assert_eq!(cfg.graph.edge_count(), 0);
        assert_eq!(cfg.graph.node_count(), 1);
        assert_eq!(cfg.nodes_meta.len(), 1);
        assert_weight(cfg.get_entry_weight_id(empty_proc_map!(), wmap), 1, wmap);
    }

    #[test]
    fn test_cfg_no_return_node() {
        let wmap = &WeightMap::new();
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
        cfg.make_acyclic(wmap, None);
        assert_weight(cfg.get_entry_weight_id(empty_proc_map!(), wmap), 1, wmap);
    }

    #[test]
    #[should_panic(
        expected = "If get_weight_id() is called on a CFG, the graph has to be made acyclic before"
    )]
    fn test_cfg_no_weight_before_acyclic() {
        let wmap = &WeightMap::new();
        let mut cfg: CFG = get_cfg_single_self_ref();
        cfg.get_entry_weight_id(empty_proc_map!(), wmap);
    }

    #[test]
    fn test_cfg_single_self_ref() {
        let wmap = &WeightMap::new();
        let mut cfg: CFG = get_cfg_single_self_ref();
        assert_eq!(cfg.graph.edge_count(), 1);
        assert_eq!(cfg.graph.node_count(), 1);
        assert_eq!(cfg.nodes_meta.len(), 1);
        cfg.make_acyclic(wmap, None);
        assert_eq!(cfg.graph.edge_count(), 3);
        assert_eq!(cfg.graph.node_count(), 4);
        assert_eq!(cfg.nodes_meta.len(), 4);
        assert_weight(cfg.get_entry_weight_id(empty_proc_map!(), wmap), 1, wmap);
    }

    #[test]
    fn test_cfg_linear() {
        let wmap = &WeightMap::new();
        let mut cfg: CFG = get_cfg_linear();
        assert_eq!(cfg.graph.edge_count(), 3);
        assert_eq!(cfg.graph.node_count(), 4);
        assert_eq!(cfg.nodes_meta.len(), 4);
        cfg.make_acyclic(wmap, None);
        assert_eq!(cfg.graph.edge_count(), 3);
        assert_eq!(cfg.graph.node_count(), 4);
        assert_eq!(cfg.nodes_meta.len(), 4);
        assert_weight(cfg.get_entry_weight_id(empty_proc_map!(), wmap), 1, wmap);
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 0), empty_proc_map!(), wmap, false)), 1, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 1), empty_proc_map!(), wmap, false)), 1, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 2), empty_proc_map!(), wmap, false)), 1, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 3), empty_proc_map!(), wmap, false)), 1, wmap);
        }
    }

    #[test]
    fn test_cfg_simple_loop_single_node_scc() {
        let wmap = &WeightMap::new();
        let mut cfg: CFG = get_cfg_simple_loop_extra_nodes();
        assert_eq!(cfg.graph.edge_count(), 6);
        assert_eq!(cfg.graph.node_count(), 6);
        assert_eq!(cfg.nodes_meta.len(), 6);
        cfg.make_acyclic(wmap, None);
        assert_eq!(cfg.graph.edge_count(), 17);
        assert_eq!(cfg.graph.node_count(), 12);
        assert_eq!(cfg.nodes_meta.len(), 12);
        assert_eq!(cfg.graph.edge_count(), 17);
        assert_eq!(cfg.graph.node_count(), 12);
        assert_eq!(cfg.nodes_meta.len(), 12);
        assert_weight(cfg.get_entry_weight_id(empty_proc_map!(), wmap), 10, wmap);
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 10), empty_proc_map!(), wmap, false)), 10, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 0), empty_proc_map!(), wmap, false)), 10, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 1), empty_proc_map!(), wmap, false)), 4, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 2), empty_proc_map!(), wmap, false)), 4, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 3), empty_proc_map!(), wmap, false)), 1, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 13), empty_proc_map!(), wmap, false)), 1, wmap);

        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 1, 1), empty_proc_map!(), wmap, false)), 3, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 1, 2), empty_proc_map!(), wmap, false)), 3, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 2, 1), empty_proc_map!(), wmap, false)), 2, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 2, 2), empty_proc_map!(), wmap, false)), 2, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 3, 1), empty_proc_map!(), wmap, false)), 1, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 3, 2), empty_proc_map!(), wmap, false)), 1, wmap);
        }
    }

    #[test]
    fn test_cfg_simple_loop() {
        let wmap = &WeightMap::new();
        let mut cfg: CFG = get_cfg_simple_loop();
        assert_eq!(cfg.graph.edge_count(), 4);
        assert_eq!(cfg.graph.node_count(), 4);
        assert_eq!(cfg.nodes_meta.len(), 4);
        cfg.make_acyclic(wmap, None);
        assert_eq!(cfg.graph.edge_count(), 15);
        assert_eq!(cfg.graph.node_count(), 10);
        assert_eq!(cfg.nodes_meta.len(), 10);
        assert_eq!(cfg.graph.edge_count(), 15);
        assert_eq!(cfg.graph.node_count(), 10);
        assert_eq!(cfg.nodes_meta.len(), 10);
        assert_weight(cfg.get_entry_weight_id(empty_proc_map!(), wmap), 10, wmap);
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 0), empty_proc_map!(), wmap, false)), 10, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 1), empty_proc_map!(), wmap, false)), 4, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 2), empty_proc_map!(), wmap, false)), 4, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 3), empty_proc_map!(), wmap, false)), 1, wmap);

        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 1, 1), empty_proc_map!(), wmap, false)), 3, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 1, 2), empty_proc_map!(), wmap, false)), 3, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 2, 1), empty_proc_map!(), wmap, false)), 2, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 2, 2), empty_proc_map!(), wmap, false)), 2, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 3, 1), empty_proc_map!(), wmap, false)), 1, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 3, 2), empty_proc_map!(), wmap, false)), 1, wmap);
        }
    }

    #[test]
    fn test_cfg_self_ref() {
        let wmap = &WeightMap::new();
        let mut cfg: CFG = get_cfg_self_ref_loop();
        assert_eq!(cfg.graph.edge_count(), 3);
        assert_eq!(cfg.graph.node_count(), 3);
        assert_eq!(cfg.nodes_meta.len(), 3);
        cfg.make_acyclic(wmap, None);
        assert_eq!(cfg.graph.edge_count(), 11);
        assert_eq!(cfg.graph.node_count(), 6);
        assert_eq!(cfg.nodes_meta.len(), 6);
        assert_eq!(cfg.graph.edge_count(), 11);
        assert_eq!(cfg.graph.node_count(), 6);
        assert_eq!(cfg.nodes_meta.len(), 6);
        assert_weight(cfg.get_entry_weight_id(empty_proc_map!(), wmap), 10, wmap);
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 0), empty_proc_map!(), wmap, false)), 10, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 1), empty_proc_map!(), wmap, false)), 4, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 2), empty_proc_map!(), wmap, false)), 1, wmap);

        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 1, 1), empty_proc_map!(), wmap, false)), 3, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 2, 1), empty_proc_map!(), wmap, false)), 2, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 3, 1), empty_proc_map!(), wmap, false)), 1, wmap);
        }
    }

    #[test]
    fn test_cfg_looped_self_ref() {
        let wmap = &WeightMap::new();
        let mut cfg: CFG = get_cfg_loop_self_ref();
        assert_eq!(cfg.graph.edge_count(), 6);
        assert_eq!(cfg.graph.node_count(), 5);
        assert_eq!(cfg.nodes_meta.len(), 5);
        // println!(
        //     "{:?}",
        //     Dot::with_config(&cfg.graph, &[Config::EdgeNoLabel, Config::NodeIndexLabel])
        // );
        cfg.make_acyclic(wmap, None);
        // println!("{:?}", Dot::with_config(&cfg.graph, &[]));
        assert_eq!(cfg.graph.edge_count(), 22);
        assert_eq!(cfg.graph.node_count(), 14);
        assert_eq!(cfg.nodes_meta.len(), 14);
        assert_eq!(cfg.graph.edge_count(), 22);
        assert_eq!(cfg.graph.node_count(), 14);
        assert_eq!(cfg.nodes_meta.len(), 14);
        assert_weight(cfg.get_entry_weight_id(empty_proc_map!(), wmap), 30, wmap);
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 0), empty_proc_map!(), wmap, false)), 30, wmap);

        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 1), empty_proc_map!(), wmap, false)), 16, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 1, 1), empty_proc_map!(), wmap, false)), 8, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 2, 1), empty_proc_map!(), wmap, false)), 4, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 3, 1), empty_proc_map!(), wmap, false)), 2, wmap);

        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 2), empty_proc_map!(), wmap, false)), 16, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 1, 2), empty_proc_map!(), wmap, false)), 8, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 2, 2), empty_proc_map!(), wmap, false)), 4, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 3, 2), empty_proc_map!(), wmap, false)), 2, wmap);

        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 4), empty_proc_map!(), wmap, false)), 15, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 1, 4), empty_proc_map!(), wmap, false)), 7, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 2, 4), empty_proc_map!(), wmap, false)), 3, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 3, 4), empty_proc_map!(), wmap, false)), 1, wmap);

        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 3), empty_proc_map!(), wmap, false)), 1, wmap);
        }
    }

    #[test]
    fn test_icfg_endless_acyclic() {
        let (mut icfg, wmap) = get_endless_loop_icfg();
        let wmap = &wmap;
        icfg.resolve_loops(1, wmap);
        // In this edge case, we can resolve a loop, but each path has the weight of 1.
        // Sincen no CFG has a branch.
        assert_p_weight(&icfg, &NodeId::new(0, 0, 0xa0), 1, wmap);
        assert_p_weight(&icfg, &NodeId::new(0, 0, 0xb0), 1, wmap);
        assert_p_weight(&icfg, &NodeId::new(0, 0, 0xc0), 1, wmap);

        assert_p_weight(&icfg, &NodeId::new(1, 0, 0xa0), 1, wmap);
        assert_p_weight(&icfg, &NodeId::new(1, 0, 0xb0), 1, wmap);
        assert_p_weight(&icfg, &NodeId::new(1, 0, 0xc0), 1, wmap);

        assert_p_weight(&icfg, &NodeId::new(2, 0, 0xa0), 1, wmap);
        assert_p_weight(&icfg, &NodeId::new(2, 0, 0xb0), 1, wmap);
        assert_p_weight(&icfg, &NodeId::new(2, 0, 0xc0), 1, wmap);

        assert_p_weight(&icfg, &NodeId::new(3, 0, 0xa0), 1, wmap);
        assert_p_weight(&icfg, &NodeId::new(3, 0, 0xb0), 1, wmap);
        assert_p_weight(&icfg, &NodeId::new(3, 0, 0xc0), 1, wmap);
    }

    #[test]
    fn test_icfg_endless_with_branch_acyclic() {
        let (mut icfg, wmap) = get_endless_loop_icfg_branch();
        icfg.resolve_loops(1, &wmap);
        println!("{:?}", Dot::with_config(&icfg.get_graph(), &[]));

        assert_p_weight(&icfg, &NodeId::new(3, 0, 0xa0), 2, &wmap);
        assert_p_weight(&icfg, &NodeId::new(3, 0, 0xb0), 2, &wmap);
        assert_p_weight(&icfg, &NodeId::new(3, 0, 0xd0), 2, &wmap);

        assert_p_weight(&icfg, &NodeId::new(2, 0, 0xa0), 4, &wmap);
        assert_p_weight(&icfg, &NodeId::new(2, 0, 0xb0), 4, &wmap);
        assert_p_weight(&icfg, &NodeId::new(2, 0, 0xd0), 4, &wmap);

        assert_p_weight(&icfg, &NodeId::new(1, 0, 0xa0), 8, &wmap);
        assert_p_weight(&icfg, &NodeId::new(1, 0, 0xb0), 8, &wmap);
        assert_p_weight(&icfg, &NodeId::new(1, 0, 0xd0), 8, &wmap);

        assert_p_weight(&icfg, &NodeId::new(0, 0, 0xa0), 16, &wmap);
        assert_p_weight(&icfg, &NodeId::new(0, 0, 0xb0), 16, &wmap);
        assert_p_weight(&icfg, &NodeId::new(0, 0, 0xd0), 16, &wmap);
    }

    #[test]
    fn test_icfg_resolve_cycles() {
        let mut icfg = get_icfg_with_selfref_and_recurse_cfg();
        let wmap = &WeightMap::new();
        icfg.resolve_loops(4, wmap);
        assert_eq!(icfg.num_procedures(), 4);
    }

    #[test]
    fn test_fg_check_self_ref_hold() {
        let mut edges = HashSet::<(NodeId, NodeId)>::new();
        let node_0 = NodeId::from(0);
        let node_1 = NodeId::from(1);
        let node_2 = NodeId::from(2);
        edges.insert((node_0, node_0));

        // Correct condition. Self-ref and endless loop
        assert_eq!(CFG::check_self_ref_hold(&edges, &node_0, &node_0), true);

        edges.insert((node_0, node_1));
        // Not self-ref endless loop.
        assert_eq!(CFG::check_self_ref_hold(&edges, &node_0, &node_0), false);
        // Not self ref.
        assert_eq!(CFG::check_self_ref_hold(&edges, &node_0, &node_1), false);
        // Node doesn't exit.
        assert_eq!(CFG::check_self_ref_hold(&edges, &node_0, &node_2), false);
    }

    #[test]
    fn test_endless_loop() {
        let wmap = &WeightMap::new();
        let mut cfg = get_endless_loop_cfg();
        cfg.make_acyclic(wmap, None);
        println!("{:?}", Dot::with_config(&cfg.graph, &[]));
        assert_weight(cfg.get_entry_weight_id(empty_proc_map!(), wmap), 4, wmap);
    }

    #[test]
    fn test_entry_0_graph() {
        let wmap = &WeightMap::new();
        let mut cfg = get_cfg_linear_call();
        cfg.make_acyclic(wmap, None);
        println!("{:?}", Dot::with_config(&cfg.graph, &[]));
        assert_weight(cfg.get_entry_weight_id(empty_proc_map!(), wmap), 1, wmap);
    }
}
