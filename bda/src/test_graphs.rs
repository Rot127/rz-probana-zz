// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::sync::RwLock;

use crate::{
    cfg::{CFGNodeData, InsnNodeType, Procedure, CFG},
    flow_graphs::{Address, NodeId, INVALID_NODE_ID},
    icfg::ICFG,
    weight::WeightMap,
};

pub const NULL_ADDR: Address = 0x00;
pub const A_ADDR: Address = 0xa0;
pub const B_ADDR: Address = 0xb0;
pub const C_ADDR: Address = 0xc0;
pub const D_ADDR: Address = 0xd0;
pub const E_ADDR: Address = 0xe0;
pub const F_ADDR: Address = 0xf0;
pub const GEE_ADDR: Address = 0;
pub const FOO_ADDR: Address = 6;
pub const MAIN_ADDR: Address = 11;
pub const RANDOM_FCN_ADDR: Address = 0x5a5a5a5a5a5a5a5a;

// A -> B -> C -> A
//           \
//            +--> C -> C ....
pub fn get_endless_loop_icfg() -> (ICFG, RwLock<WeightMap>) {
    let mut icfg = ICFG::new();
    let wmapo = WeightMap::new();
    let mut cfg_a = CFG::new();
    let mut cfg_b = CFG::new();
    let mut cfg_c = CFG::new();

    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    let a0 = (NodeId::new(0, 0, 0xa0), CFGNodeData::new_test_single(0xa0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xa1), INVALID_NODE_ID));
    let a1 = (NodeId::new(0, 0, 0xa1), CFGNodeData::new_test_single_call(0xa1, NodeId::new(0, 0, B_ADDR), false, NodeId::new(0, 0, 0xa2)));
    let a2 = (NodeId::new(0, 0, 0xa2), CFGNodeData::new_test_single(0xa2, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));
    cfg_a.add_edge(a0, a1.clone());
    cfg_a.add_edge(a1, a2);

    let b0 = (NodeId::new(0, 0, 0xb0), CFGNodeData::new_test_single(0xb0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xb1), INVALID_NODE_ID));
    let b1 = (NodeId::new(0, 0, 0xb1), CFGNodeData::new_test_single_call(0xb1, NodeId::new(0, 0, C_ADDR), false, NodeId::new(0, 0, 0xb2)));
    let b2 = (NodeId::new(0, 0, 0xb2), CFGNodeData::new_test_single(0xb2, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));
    cfg_b.add_edge(b0, b1.clone());
    cfg_b.add_edge(b1, b2);

    let c0 = (NodeId::new(0, 0, 0xc0), CFGNodeData::new_test_single(0xc0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xc1), INVALID_NODE_ID));
    let c1 = (NodeId::new(0, 0, 0xc1), CFGNodeData::new_test_single_call(0xc1, NodeId::new(0, 0, A_ADDR), false, NodeId::new(0, 0, 0xc2)));
    let c2 = (NodeId::new(0, 0, 0xc2), CFGNodeData::new_test_single_call(0xc2, NodeId::new(0, 0, C_ADDR), false, NodeId::new(0, 0, 0xc3)));
    let c3 = (NodeId::new(0, 0, 0xc3), CFGNodeData::new_test_single(0xc3, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));
    cfg_c.add_edge(c0, c1.clone());
    cfg_c.add_edge(c1, c2.clone());
    cfg_c.add_edge(c2, c3);

    icfg.add_edge_test(
        (NodeId::new(0, 0, A_ADDR), Procedure::new(Some(cfg_a), false, false, false)),
        (NodeId::new(0, 0, B_ADDR), Procedure::new(Some(cfg_b), false, false, false)),
    );
    icfg.add_edge_test(
        (NodeId::new(0, 0, B_ADDR), Procedure::new(None, false, false, false)),
        (NodeId::new(0, 0, C_ADDR), Procedure::new(Some(cfg_c), false, false, false)),
    );
    icfg.add_edge_test(
        (NodeId::new(0, 0, C_ADDR), Procedure::new(None, false, false, false)),
        (NodeId::new(0, 0, C_ADDR), Procedure::new(None, false, false, false)),
    );
    icfg.add_edge_test(
        (NodeId::new(0, 0, C_ADDR), Procedure::new(None, false, false, false)),
        (NodeId::new(0, 0, A_ADDR), Procedure::new(None, false, false, false)),
    );
    }
    (icfg, wmapo)
}

// A -> B -> C -> A
pub fn get_endless_recurse_icfg() -> (ICFG, RwLock<WeightMap>) {
    let mut icfg = ICFG::new();
    let wmapo = WeightMap::new();
    let mut cfg_a = CFG::new();
    let mut cfg_b = CFG::new();
    let mut cfg_c = CFG::new();

    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    let a0 = (NodeId::new(0, 0, 0xa0), CFGNodeData::new_test_single(0xa0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xa1), INVALID_NODE_ID));
    let a1 = (NodeId::new(0, 0, 0xa1), CFGNodeData::new_test_single_call(0xa1, NodeId::new(0, 0, B_ADDR), false, NodeId::new(0, 0, 0xa2)));
    let a2 = (NodeId::new(0, 0, 0xa2), CFGNodeData::new_test_single(0xa2, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));
    cfg_a.add_edge(a0, a1.clone());
    cfg_a.add_edge(a1, a2);

    let b0 = (NodeId::new(0, 0, 0xb0), CFGNodeData::new_test_single(0xb0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xb1), INVALID_NODE_ID));
    let b1 = (NodeId::new(0, 0, 0xb1), CFGNodeData::new_test_single_call(0xb1, NodeId::new(0, 0, C_ADDR), false, NodeId::new(0, 0, 0xb2)));
    let b2 = (NodeId::new(0, 0, 0xb2), CFGNodeData::new_test_single(0xb2, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));
    cfg_b.add_edge(b0, b1.clone());
    cfg_b.add_edge(b1, b2);

    let c0 = (NodeId::new(0, 0, 0xc0), CFGNodeData::new_test_single(0xc0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xc1), INVALID_NODE_ID));
    let c1 = (NodeId::new(0, 0, 0xc1), CFGNodeData::new_test_single_call(0xc1, NodeId::new(0, 0, A_ADDR), false, NodeId::new(0, 0, 0xc2)));
    let c2 = (NodeId::new(0, 0, 0xc2), CFGNodeData::new_test_single(0xc2, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));
    cfg_c.add_edge(c0, c1.clone());
    cfg_c.add_edge(c1, c2);

    icfg.add_edge_test(
        (NodeId::new(0, 0, A_ADDR), Procedure::new(Some(cfg_a), false, false, false)),
        (NodeId::new(0, 0, B_ADDR), Procedure::new(Some(cfg_b), false, false, false)),
    );
    icfg.add_edge_test(
        (NodeId::new(0, 0, B_ADDR), Procedure::new(None, false, false, false)),
        (NodeId::new(0, 0, C_ADDR), Procedure::new(Some(cfg_c), false, false, false)),
    );
    icfg.add_edge_test(
        (NodeId::new(0, 0, C_ADDR), Procedure::new(None, false, false, false)),
        (NodeId::new(0, 0, A_ADDR), Procedure::new(None, false, false, false)),
    );
    }
    (icfg, wmapo)
}

//  0 <-   -> D
//      \/
// B -> C -> A -> C ...
// Middle address CFG to high, to low, to high.
// This tests the back edge defintion of High to low address is a back-edge.
pub fn get_endless_recurse_icfg_nonlinear_address() -> (ICFG, RwLock<WeightMap>) {
    let mut icfg = ICFG::new();
    let wmapo = WeightMap::new();
    let mut cfg_a = CFG::new();
    let mut cfg_b = CFG::new();
    let mut cfg_c = CFG::new();
    let mut cfg_d = CFG::new();
    let mut cfg_0 = CFG::new();

    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    let b0 = (NodeId::new(0, 0, 0xb0), CFGNodeData::new_test_single(0xb0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xb1), INVALID_NODE_ID));
    let b1 = (NodeId::new(0, 0, 0xb1), CFGNodeData::new_test_single_call(0xb1, NodeId::new(0, 0, C_ADDR), false, NodeId::new(0, 0, 0xb2)));
    let b2 = (NodeId::new(0, 0, 0xb2), CFGNodeData::new_test_single(0xb2, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));
    cfg_b.add_edge(b0, b1.clone());
    cfg_b.add_edge(b1, b2);

    let c0 = (NodeId::new(0, 0, 0xc0), CFGNodeData::new_test_single(0xc0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xc1), INVALID_NODE_ID));
    let c1 = (NodeId::new(0, 0, 0xc1), CFGNodeData::new_test_single_call(0xc1, NodeId::new(0, 0, A_ADDR), false, NodeId::new(0, 0, 0xc2)));
    let c2 = (NodeId::new(0, 0, 0xc2), CFGNodeData::new_test_single_call(0xc2, NodeId::new(0, 0, D_ADDR), false, NodeId::new(0, 0, 0xc3)));
    let c3 = (NodeId::new(0, 0, 0xc3), CFGNodeData::new_test_single_call(0xc3, NodeId::new(0, 0, NULL_ADDR), false, NodeId::new(0, 0, 0xc4)));
    let c4 = (NodeId::new(0, 0, 0xc4), CFGNodeData::new_test_single(0xc4, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));
    cfg_c.add_edge(c0, c1.clone());
    cfg_c.add_edge(c1, c2.clone());
    cfg_c.add_edge(c2, c3.clone());
    cfg_c.add_edge(c3, c4);

    let a0 = (NodeId::new(0, 0, 0xa0), CFGNodeData::new_test_single(0xa0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xa1), INVALID_NODE_ID));
    let a1 = (NodeId::new(0, 0, 0xa1), CFGNodeData::new_test_single_call(0xa1, NodeId::new(0, 0, C_ADDR), false, NodeId::new(0, 0, 0xa2)));
    let a2 = (NodeId::new(0, 0, 0xa2), CFGNodeData::new_test_single(0xa2, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));
    cfg_a.add_edge(a0, a1.clone());
    cfg_a.add_edge(a1, a2);

    let d0 = (NodeId::new(0, 0, 0xd0), CFGNodeData::new_test_single(0xd0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xd1), INVALID_NODE_ID));
    let d1 = (NodeId::new(0, 0, 0xd1), CFGNodeData::new_test_single(0xd1, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));
    cfg_d.add_edge(d0, d1);

    let n0 = (NodeId::new(0, 0, 0x00), CFGNodeData::new_test_single(0x00, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0x01), INVALID_NODE_ID));
    let n1 = (NodeId::new(0, 0, 0x01), CFGNodeData::new_test_single(0x01, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));
    cfg_0.add_edge(n0, n1);


    icfg.add_edge_test(
        (NodeId::new(0, 0, B_ADDR), Procedure::new(Some(cfg_b), false, false, false)),
        (NodeId::new(0, 0, C_ADDR), Procedure::new(Some(cfg_c), false, false, false)),
    );
    icfg.add_edge_test(
        (NodeId::new(0, 0, C_ADDR), Procedure::new(None, false, false, false)),
        (NodeId::new(0, 0, A_ADDR), Procedure::new(Some(cfg_a), false, false, false)),
    );
    icfg.add_edge_test(
        (NodeId::new(0, 0, C_ADDR), Procedure::new(None, false, false, false)),
        (NodeId::new(0, 0, D_ADDR), Procedure::new(Some(cfg_d), false, false, false)),
    );
    icfg.add_edge_test(
        (NodeId::new(0, 0, C_ADDR), Procedure::new(None, false, false, false)),
        (NodeId::new(0, 0, NULL_ADDR), Procedure::new(Some(cfg_0), false, false, false)),
    );
    icfg.add_edge_test(
        (NodeId::new(0, 0, A_ADDR), Procedure::new(None, false, false, false)),
        (NodeId::new(0, 0, C_ADDR), Procedure::new(None, false, false, false)),
    );
    }
    (icfg, wmapo)
}

// D -> E -> F -> D ...
//      ^
//      |
//      | E -> B
//      |
// A -> B -> C -> A ...
pub fn get_loop_to_loop_icfg() -> (ICFG, RwLock<WeightMap>) {
    let mut icfg = ICFG::new();
    let wmapo = WeightMap::new();
    let mut cfg_a = CFG::new();
    let mut cfg_b = CFG::new();
    let mut cfg_c = CFG::new();
    let mut cfg_d = CFG::new();
    let mut cfg_e = CFG::new();
    let mut cfg_f = CFG::new();

    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    let cfg_a_0 = (NodeId::new(0, 0, 0xa0), CFGNodeData::new_test_single(0xa0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xa1), INVALID_NODE_ID));
    let cfg_a_1 = (NodeId::new(0, 0, 0xa1), CFGNodeData::new_test_single_call(0xa1, NodeId::new(0, 0, B_ADDR), false, NodeId::new(0, 0, 0xa2)));
    let cfg_a_2 = (NodeId::new(0, 0, 0xa2), CFGNodeData::new_test_single(0xa2, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));
    cfg_a.add_edge(cfg_a_0, cfg_a_1.clone());
    cfg_a.add_edge(cfg_a_1, cfg_a_2);

    let cfg_b_0 = (NodeId::new(0, 0, 0xb0), CFGNodeData::new_test_single(0xb0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xb1), INVALID_NODE_ID));
    let cfg_b_1 = (NodeId::new(0, 0, 0xb1), CFGNodeData::new_test_single_call(0xb1, NodeId::new(0, 0, C_ADDR), false, NodeId::new(0, 0, 0xb2)));
    let cfg_b_2 = (NodeId::new(0, 0, 0xb2), CFGNodeData::new_test_single(0xb2, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));
    cfg_b.add_edge(cfg_b_0, cfg_b_1.clone());
    cfg_b.add_edge(cfg_b_1, cfg_b_2);

    let cfg_c_0 = (NodeId::new(0, 0, 0xc0), CFGNodeData::new_test_single(0xc0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xc1), INVALID_NODE_ID));
    let cfg_c_1 = (NodeId::new(0, 0, 0xc1), CFGNodeData::new_test_single_call(0xc1, NodeId::new(0, 0, A_ADDR), false, NodeId::new(0, 0, 0xc2)));
    let cfg_c_2 = (NodeId::new(0, 0, 0xc2), CFGNodeData::new_test_single(0xc2, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));
    cfg_c.add_edge(cfg_c_0, cfg_c_1.clone());
    cfg_c.add_edge(cfg_c_1, cfg_c_2);

    let cfg_d_0 = (NodeId::new(0, 0, 0xd0), CFGNodeData::new_test_single(0xd0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xd1), INVALID_NODE_ID));
    let cfg_d_1 = (NodeId::new(0, 0, 0xd1), CFGNodeData::new_test_single_call(0xd1, NodeId::new(0, 0, E_ADDR), false, NodeId::new(0, 0, 0xd2)));
    let cfg_d_2 = (NodeId::new(0, 0, 0xd2), CFGNodeData::new_test_single(0xd2, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));
    cfg_d.add_edge(cfg_d_0, cfg_d_1.clone());
    cfg_d.add_edge(cfg_d_1, cfg_d_2);

    let cfg_e_0 = (NodeId::new(0, 0, 0xe0), CFGNodeData::new_test_single(0xe0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xe1), INVALID_NODE_ID));
    let cfg_e_1 = (NodeId::new(0, 0, 0xe1), CFGNodeData::new_test_single_call(0xe1, NodeId::new(0, 0, F_ADDR), false, NodeId::new(0, 0, 0xe2)));
    let cfg_e_2 = (NodeId::new(0, 0, 0xe2), CFGNodeData::new_test_single_call(0xe2, NodeId::new(0, 0, B_ADDR), false, NodeId::new(0, 0, 0xe3)));
    let cfg_e_3 = (NodeId::new(0, 0, 0xe3), CFGNodeData::new_test_single(0xe3, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));
    cfg_e.add_edge(cfg_e_0, cfg_e_1.clone());
    cfg_e.add_edge(cfg_e_1, cfg_e_2.clone());
    cfg_e.add_edge(cfg_e_2, cfg_e_3);

    let cfg_f_0 = (NodeId::new(0, 0, 0xf0), CFGNodeData::new_test_single(0xf0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xf1), INVALID_NODE_ID));
    let cfg_f_1 = (NodeId::new(0, 0, 0xf1), CFGNodeData::new_test_single_call(0xf1, NodeId::new(0, 0, D_ADDR), false, NodeId::new(0, 0, 0xf2)));
    let cfg_f_2 = (NodeId::new(0, 0, 0xf2), CFGNodeData::new_test_single(0xf2, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));
    cfg_f.add_edge(cfg_f_0, cfg_f_1.clone());
    cfg_f.add_edge(cfg_f_1, cfg_f_2);

    icfg.add_edge_test(
        (NodeId::new(0, 0, A_ADDR), Procedure::new(Some(cfg_a), false, false, false)),
        (NodeId::new(0, 0, B_ADDR), Procedure::new(Some(cfg_b), false, false, false)),
    );
    icfg.add_edge_test(
        (NodeId::new(0, 0, B_ADDR), Procedure::new(None, false, false, false)),
        (NodeId::new(0, 0, C_ADDR), Procedure::new(Some(cfg_c), false, false, false)),
    );
    icfg.add_edge_test(
        (NodeId::new(0, 0, C_ADDR), Procedure::new(None, false, false, false)),
        (NodeId::new(0, 0, A_ADDR), Procedure::new(None, false, false, false)),
    );
    icfg.add_edge_test(
        (NodeId::new(0, 0, D_ADDR), Procedure::new(Some(cfg_d), false, false, false)),
        (NodeId::new(0, 0, E_ADDR), Procedure::new(Some(cfg_e), false, false, false)),
    );
    icfg.add_edge_test(
        (NodeId::new(0, 0, E_ADDR), Procedure::new(None, false, false, false)),
        (NodeId::new(0, 0, F_ADDR), Procedure::new(Some(cfg_f), false, false, false)),
    );
    icfg.add_edge_test(
        (NodeId::new(0, 0, F_ADDR), Procedure::new(None, false, false, false)),
        (NodeId::new(0, 0, D_ADDR), Procedure::new(None, false, false, false)),
    );
    icfg.add_edge_test(
        (NodeId::new(0, 0, E_ADDR), Procedure::new(None, false, false, false)),
        (NodeId::new(0, 0, B_ADDR), Procedure::new(None, false, false, false)),
    );
    }
    (icfg, wmapo)
}

pub fn get_endless_loop_icfg_branch() -> (ICFG, RwLock<WeightMap>) {
    let mut icfg = ICFG::new();
    let wmapo = WeightMap::new();
    let mut cfg_a = CFG::new();
    let mut cfg_b = CFG::new();
    let mut cfg_d = CFG::new();

    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    let a0 = (NodeId::new(0, 0, 0xa0), CFGNodeData::new_test_single(0xa0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xa1), INVALID_NODE_ID));
    let a1 = (NodeId::new(0, 0, 0xa1), CFGNodeData::new_test_single_call(0xa1, NodeId::new(0, 0, B_ADDR), false, NodeId::new(0, 0, 0xa2)));
    let a2 = (NodeId::new(0, 0, 0xa2), CFGNodeData::new_test_single(0xa2, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));
    cfg_a.add_edge(a0, a1.clone());
    cfg_a.add_edge(a1, a2);

    let b0 = (NodeId::new(0, 0, 0xb0), CFGNodeData::new_test_single(0xb0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xb1), INVALID_NODE_ID));
    let b1 = (NodeId::new(0, 0, 0xb1), CFGNodeData::new_test_single_call(0xb1, NodeId::new(0, 0, D_ADDR), false, NodeId::new(0, 0, 0xb2)));
    let b2 = (NodeId::new(0, 0, 0xb2), CFGNodeData::new_test_single(0xb2, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));

    cfg_b.add_edge(b0, b1.clone());
    cfg_b.add_edge(b1, b2);

    let d0 = (NodeId::new(0, 0, 0xd0), CFGNodeData::new_test_single(0xd0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xd1), NodeId::new(0, 0, 0xd2)));
    let d1 = (NodeId::new(0, 0, 0xd1), CFGNodeData::new_test_single_call(0xd1, NodeId::new(0, 0, A_ADDR), false, NodeId::new(0, 0, 0xd3)));
    let d2 = (NodeId::new(0, 0, 0xd2), CFGNodeData::new_test_single_call(0xd2, NodeId::new(0, 0, D_ADDR), false, NodeId::new(0, 0, 0xd3)));
    let d3 = (NodeId::new(0, 0, 0xd3), CFGNodeData::new_test_single(0xd3, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));

    cfg_d.add_edge(d0.clone(), d1.clone());
    cfg_d.add_edge(d1, d3.clone());
    cfg_d.add_edge(d0, d2.clone());
    cfg_d.add_edge(d2, d3);

    icfg.add_edge_test(
        (NodeId::new(0, 0, A_ADDR), Procedure::new(Some(cfg_a), false, false, false)),
        (NodeId::new(0, 0, B_ADDR), Procedure::new(Some(cfg_b), false, false, false)),
    );
    icfg.add_edge_test(
        (NodeId::new(0, 0, B_ADDR), Procedure::new(None, false, false, false)),
        (NodeId::new(0, 0, D_ADDR), Procedure::new(Some(cfg_d), false, false, false)),
    );
    icfg.add_edge_test(
        (NodeId::new(0, 0, D_ADDR), Procedure::new(None, false, false, false)),
        (NodeId::new(0, 0, D_ADDR), Procedure::new(None, false, false, false)),
    );
    icfg.add_edge_test(
        (NodeId::new(0, 0, D_ADDR), Procedure::new(None, false, false, false)),
        (NodeId::new(0, 0, A_ADDR), Procedure::new(None, false, false, false)),
    );
    }
    (icfg, wmapo)
}

/// Returns the CFG of the gee() function
/// of the BDA paper [^Figure 2.7.]
/// [^Figure 2.7.] See: [Figure 2.7.](https://doi.org/10.25394/PGS.23542014.v1)
pub fn get_gee_cfg() -> CFG {
    let mut cfg = CFG::new();

    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    // gee()
    cfg.add_edge(
        (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 1), INVALID_NODE_ID)),
        (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::Normal, NodeId::new(0, 0, 2), NodeId::new(0, 0, 3))),
    );
    // if (input()) ... else ...
    cfg.add_edge(
        (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::Normal, NodeId::new(0, 0, 2), NodeId::new(0, 0, 3))),
        (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::Normal, NodeId::new(0, 0, 4), INVALID_NODE_ID)),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::Normal, NodeId::new(0, 0, 2), NodeId::new(0, 0, 3))),
        (NodeId::new(0, 0, 3), CFGNodeData::new_test_single(3, InsnNodeType::Normal, NodeId::new(0, 0, 4), INVALID_NODE_ID)),
    );
    // *a = 0
    cfg.add_edge(
        (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::Normal, NodeId::new(0, 0, 4), INVALID_NODE_ID)),
        (NodeId::new(0, 0, 4), CFGNodeData::new_test_single(4, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID)),
    );
    // *a = 2
    cfg.add_edge(
        (NodeId::new(0, 0, 3), CFGNodeData::new_test_single(3, InsnNodeType::Normal, NodeId::new(0, 0, 4), INVALID_NODE_ID)),
        (NodeId::new(0, 0, 4), CFGNodeData::new_test_single(4, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID)),
    );
    }
    cfg
}

/// Returns the CFG of the foo() function
/// in the BDA paper [^Figure 2.7.]
/// [^Figure 2.7.] See: [Figure 2.7.](https://doi.org/10.25394/PGS.23542014.v1)
pub fn get_foo_cfg() -> CFG {
    let mut cfg = CFG::new();

    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    // foo()
    cfg.add_edge(
        (NodeId::new(0, 0, 6), CFGNodeData::new_test_single(6, InsnNodeType::NormalEntry, NodeId::new(0, 0, 7), INVALID_NODE_ID)),
        (NodeId::new(0, 0, 7), CFGNodeData::new_test_single_call(7, NodeId::new(0, 0, GEE_ADDR), false, NodeId::new(0, 0, 8))),
    );

    // gee()
    cfg.add_edge(
        (NodeId::new(0, 0, 7), CFGNodeData::new_test_single_call(7, NodeId::new(0, 0, GEE_ADDR), false, NodeId::new(0, 0, 8))),
        (NodeId::new(0, 0, 8), CFGNodeData::new_test_single(8, InsnNodeType::Normal, NodeId::new(0, 0, 9), NodeId::new(0, 0, 1))),
    );

    // if (intput())
    cfg.add_edge(
        (NodeId::new(0, 0, 8), CFGNodeData::new_test_single(8, InsnNodeType::Normal, NodeId::new(0, 0, 9), NodeId::new(0, 0, 1))),
        (NodeId::new(0, 0, 9), CFGNodeData::new_test_single(9, InsnNodeType::Normal, NodeId::new(0, 0, 1), INVALID_NODE_ID)),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 8), CFGNodeData::new_test_single(8, InsnNodeType::Normal, NodeId::new(0, 0, 9), NodeId::new(0, 0, 1))),
        (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID)),
    );

    // *a += 1
    cfg.add_edge(
        (NodeId::new(0, 0, 9), CFGNodeData::new_test_single(9, InsnNodeType::Normal, NodeId::new(0, 0, 1), INVALID_NODE_ID)),
        (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID)),
    );
    }

    cfg
}

/// Returns the CFG of the foo() function
/// of the BDA paper [^Figure 2.7.]
/// [^Figure 2.7.] See: [Figure 2.7.](https://doi.org/10.25394/PGS.23542014.v1)
pub fn get_main_cfg() -> CFG {
    let mut cfg = CFG::new();

    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    // main()
    cfg.add_edge(
        (NodeId::new(0, 0, 11), CFGNodeData::new_test_single(11, InsnNodeType::NormalEntry, NodeId::new(0, 0, 12), INVALID_NODE_ID)),
        (NodeId::new(0, 0, 12), CFGNodeData::new_test_single(12, InsnNodeType::Normal, NodeId::new(0, 0, 13), NodeId::new(0, 0, 14))),
    );
    // if (input()) ... else ...
    cfg.add_edge(
        (NodeId::new(0, 0, 12), CFGNodeData::new_test_single(12, InsnNodeType::Normal, NodeId::new(0, 0, 13), NodeId::new(0, 0, 14))),
        (NodeId::new(0, 0, 13), CFGNodeData::new_test_single_call(13, NodeId::new(0, 0, GEE_ADDR), false, NodeId::new(0, 0, 15))),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 12), CFGNodeData::new_test_single(12, InsnNodeType::Normal, NodeId::new(0, 0, 13), NodeId::new(0, 0, 14))),
        (NodeId::new(0, 0, 14), CFGNodeData::new_test_single_call(14, NodeId::new(0, 0, FOO_ADDR), false, NodeId::new(0, 0, 15))),
    );
    // gee()
    cfg.add_edge(
        (NodeId::new(0, 0, 13), CFGNodeData::new_test_single_call(13, NodeId::new(0, 0, GEE_ADDR), false, NodeId::new(0, 0, 15))),
        (NodeId::new(0, 0, 15), CFGNodeData::new_test_single(15, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID)),
    );
    // foo()
    cfg.add_edge(
        (NodeId::new(0, 0, 14), CFGNodeData::new_test_single_call(14, NodeId::new(0, 0, FOO_ADDR), false, NodeId::new(0, 0, 15))),
        (NodeId::new(0, 0, 15), CFGNodeData::new_test_single(15, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID)),
    );
    }

    cfg
}

pub fn get_paper_example_icfg() -> (ICFG, RwLock<WeightMap>) {
    let mut icfg = ICFG::new();
    let wmapo = WeightMap::new();

    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    icfg.add_edge_test(
        (NodeId::new(0, 0, MAIN_ADDR), Procedure::new(Some(get_main_cfg()), false, false, false)),
        (NodeId::new(0, 0, FOO_ADDR), Procedure::new(Some(get_foo_cfg()), false, false, false))
    );
    icfg.add_edge_test(
        (NodeId::new(0, 0, MAIN_ADDR), Procedure::new(None, false, false, false)),
        (NodeId::new(0, 0, GEE_ADDR), Procedure::new(Some(get_gee_cfg()), false, false, false))
    );
    icfg.add_edge_test(
        (NodeId::new(0, 0, FOO_ADDR), Procedure::new(None, false, false, false)),
        (NodeId::new(0, 0, GEE_ADDR), Procedure::new(None, false, false, false))
    );
    }

    (icfg, wmapo)
}

// Entry node is part of loop
// 0 ---> 1 ----> 2
//  <----
pub fn get_entry_loop_cfg() -> CFG {
    let mut cfg = CFG::new();
    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    cfg.add_edge(
        (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 1), INVALID_NODE_ID)),
        (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::Normal, NodeId::new(0, 0, 0), NodeId::new(0, 0, 2))),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::Normal, NodeId::new(0, 0, 2), NodeId::new(0, 0, 0))),
        (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 1), INVALID_NODE_ID)),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::Normal, NodeId::new(0, 0, 2), NodeId::new(0, 0, 0))),
        (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID)),
    );
    }
    cfg
}

// 0 --> 1 -> 2 -> 0
//       ^
//       | 11 -> 1
// 10 -> 11 -> 12 -> 10
pub fn get_loop_to_loop_cfg() -> CFG {
    let mut cfg = CFG::new();
    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    let n0 = (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 1), INVALID_NODE_ID));
    let n1 = (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::Normal, NodeId::new(0, 0, 2), INVALID_NODE_ID));
    let n2 = (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::Normal, NodeId::new(0, 0, 0), INVALID_NODE_ID));
    let n10 = (NodeId::new(0, 0, 10), CFGNodeData::new_test_single(10, InsnNodeType::Normal, NodeId::new(0, 0, 11), INVALID_NODE_ID));
    let n11 = (NodeId::new(0, 0, 11), CFGNodeData::new_test_single(11, InsnNodeType::Normal, NodeId::new(0, 0, 12), NodeId::new(0, 0, 1)));
    let n12 = (NodeId::new(0, 0, 12), CFGNodeData::new_test_single(12, InsnNodeType::Normal, NodeId::new(0, 0, 10), INVALID_NODE_ID));
    cfg.add_edge(n0.clone(), n1.clone());
    cfg.add_edge(n1.clone(), n2.clone());
    cfg.add_edge(n2, n0);

    cfg.add_edge(n10.clone(), n11.clone());
    cfg.add_edge(n11.clone(), n12.clone());
    cfg.add_edge(n11, n1);
    cfg.add_edge(n12, n10);
    }
    cfg
}

//
//        <----------------------------+
// 0 --> 1 --> 2 --> 3 --> 4 --> 5 --> 6 --> 7 --> 8
//             +---------------------------->
pub fn get_cfg_quit_loop() -> CFG {
    let mut cfg = CFG::new();
    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    let n0 = (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 1), INVALID_NODE_ID));
    let n1 = (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::Normal, NodeId::new(0, 0, 2), INVALID_NODE_ID));
    let n2 = (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::Normal, NodeId::new(0, 0, 3), NodeId::new(0, 0, 7)));
    let n3 = (NodeId::new(0, 0, 3), CFGNodeData::new_test_single(3, InsnNodeType::Normal, NodeId::new(0, 0, 4), INVALID_NODE_ID));
    let n4 = (NodeId::new(0, 0, 4), CFGNodeData::new_test_single(4, InsnNodeType::Normal, NodeId::new(0, 0, 5), INVALID_NODE_ID));
    let n5 = (NodeId::new(0, 0, 5), CFGNodeData::new_test_single(5, InsnNodeType::Normal, NodeId::new(0, 0, 6), NodeId::new(0, 0, 1)));
    let n6 = (NodeId::new(0, 0, 6), CFGNodeData::new_test_single(6, InsnNodeType::Normal, NodeId::new(0, 0, 7), INVALID_NODE_ID));
    let n7 = (NodeId::new(0, 0, 7), CFGNodeData::new_test_single(7, InsnNodeType::Normal, NodeId::new(0, 0, 8), INVALID_NODE_ID));
    let n8 = (NodeId::new(0, 0, 8), CFGNodeData::new_test_single(8, InsnNodeType::Return, NodeId::new(0, 0, 9), INVALID_NODE_ID));

    cfg.add_edge(n0.clone(), n1.clone());
    cfg.add_edge(n1.clone(), n2.clone());
    cfg.add_edge(n2.clone(), n3.clone());
    cfg.add_edge(n3.clone(), n4.clone());
    cfg.add_edge(n4.clone(), n5.clone());
    cfg.add_edge(n5.clone(), n6.clone());
    cfg.add_edge(n6.clone(), n7.clone());
    cfg.add_edge(n7.clone(), n8.clone());

    cfg.add_edge(n2.clone(), n7.clone());
    cfg.add_edge(n6.clone(), n1.clone());
    }
    cfg
}

//   0       32
//    ^      ^
//     \    /
//      \  /
// 10 -> 11 -> 10
//       |
//      12
pub fn get_loop_high_low() -> CFG {
    let mut cfg = CFG::new();
    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    let n0 = (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::Normal, NodeId::new(0, 0, 1), INVALID_NODE_ID));
    let n1 = (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::Normal, NodeId::new(0, 0, 2), INVALID_NODE_ID));
    let n2 = (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::Normal, NodeId::new(0, 0, 0), INVALID_NODE_ID));
    let n10 = (NodeId::new(0, 0, 10), CFGNodeData::new_test_single(10, InsnNodeType::NormalEntry, NodeId::new(0, 0, 11), INVALID_NODE_ID));
    let n11 = (NodeId::new(0, 0, 11), CFGNodeData::new_test_single(11, InsnNodeType::Normal, NodeId::new(0, 0, 12), NodeId::new(0, 0, 1)));
    let n12 = (NodeId::new(0, 0, 12), CFGNodeData::new_test_single(12, InsnNodeType::Normal, NodeId::new(0, 0, 10), INVALID_NODE_ID));
    cfg.add_edge(n0.clone(), n1.clone());
    cfg.add_edge(n1.clone(), n2.clone());
    cfg.add_edge(n2, n0);

    cfg.add_edge(n10.clone(), n11.clone());
    cfg.add_edge(n11.clone(), n12.clone());
    cfg.add_edge(n11, n1);
    cfg.add_edge(n12, n10);
    }
    cfg
}

pub fn get_icfg_with_selfref_and_recurse_cfg() -> ICFG {
    let mut icfg = ICFG::new();
    let cfg_recurse_selfref = get_cfg_self_ref_call();

    let entry = cfg_recurse_selfref.get_entry();
    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    icfg.add_edge_test(
        (entry, Procedure::new(Some(cfg_recurse_selfref.get_clone(entry.icfg_clone_id)), false, false, false)),
        (entry, Procedure::new(Some(cfg_recurse_selfref), false, false, false)),
    );
    }

    icfg
}

pub fn get_cfg_no_loop_sub_routine() -> CFG {
    let mut cfg = CFG::new();
    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    let n_10 = (NodeId::new(0, 0, 10), CFGNodeData::new_test_single(10, InsnNodeType::NormalEntry, NodeId::new(0, 0, 11), INVALID_NODE_ID));
    let n_11 = (NodeId::new(0, 0, 11), CFGNodeData::new_test_single(11, InsnNodeType::Normal, NodeId::new(0, 0, 0), INVALID_NODE_ID));
    let n_12 = (NodeId::new(0, 0, 12), CFGNodeData::new_test_single(12, InsnNodeType::Normal, NodeId::new(0, 0, 13), INVALID_NODE_ID));
    let n_13 = (NodeId::new(0, 0, 13), CFGNodeData::new_test_single(13, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));
    let n_0 = (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::Normal, NodeId::new(0, 0, 1), INVALID_NODE_ID));
    let n_1 = (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::Normal, NodeId::new(0, 0, 2), INVALID_NODE_ID));
    let n_2 = (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::Normal, NodeId::new(0, 0, 12), INVALID_NODE_ID));
    cfg.add_edge(n_10, n_11.clone());
    cfg.add_edge(n_11, n_0.clone());
    cfg.add_edge(n_0, n_1.clone());
    cfg.add_edge(n_1, n_2.clone());
    cfg.add_edge(n_2, n_12.clone());
    cfg.add_edge(n_12, n_13);
    }
    cfg
}

// 0 <---> 1 ---> 2
//         ^
//         |
//         + <-----------+
// 10 --> 11 --> 12 --> 13 --> 14
pub fn get_cfg_no_loop_sub_routine_loop_ret() -> CFG {
    let mut cfg = CFG::new();
    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    let n0 = (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::Normal, NodeId::new(0, 0, 1), INVALID_NODE_ID));
    let n1 = (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::Normal, NodeId::new(0, 0, 2), NodeId::new(0, 0, 0)));
    let n2 = (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));
    let n10 = (NodeId::new(0, 0, 10), CFGNodeData::new_test_single(10, InsnNodeType::NormalEntry, NodeId::new(0, 0, 11), NodeId::new(0, 0, 1)));
    let n11 = (NodeId::new(0, 0, 11), CFGNodeData::new_test_single(11, InsnNodeType::Normal, NodeId::new(0, 0, 12), INVALID_NODE_ID));
    let n12 = (NodeId::new(0, 0, 12), CFGNodeData::new_test_single(12, InsnNodeType::Normal, NodeId::new(0, 0, 13), INVALID_NODE_ID));
    let n13 = (NodeId::new(0, 0, 13), CFGNodeData::new_test_single(13, InsnNodeType::Normal, NodeId::new(0, 0, 14), NodeId::new(0, 0, 11)));
    let n14 = (NodeId::new(0, 0, 14), CFGNodeData::new_test_single(14, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));
    cfg.add_edge(n0.clone(), n1.clone());
    cfg.add_edge(n1.clone(), n0.clone());
    cfg.add_edge(n1.clone(), n2);
    cfg.add_edge(n10, n11.clone());
    cfg.add_edge(n11.clone(), n12.clone());
    cfg.add_edge(n12, n13.clone());
    cfg.add_edge(n13.clone(), n11.clone());
    cfg.add_edge(n13, n14);
    cfg.add_edge(n11, n1);
    }
    cfg
}

pub fn get_cfg_single_node() -> CFG {
    let mut cfg = CFG::new();
    cfg.add_node(
        NodeId::new(0, 0, 0),
        CFGNodeData::new_test_single(
            0,
            InsnNodeType::Return | InsnNodeType::Entry,
            INVALID_NODE_ID,
            INVALID_NODE_ID,
        ),
    );
    cfg
}

pub fn get_cfg_single_self_ref() -> CFG {
    let mut cfg = CFG::new();
    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    let n_0 = (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::Return | InsnNodeType::Entry, INVALID_NODE_ID, NodeId::new(0, 0, 0)));
    cfg.add_edge(n_0.clone(), n_0);
    }
    cfg
}

//        Call     self
//                 ref
// 0 ----> 1 -----> 2 -----> 3
pub fn get_cfg_self_ref_call() -> CFG {
    let mut cfg = CFG::new();
    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    cfg.add_edge(
        (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 1), INVALID_NODE_ID)),
        (NodeId::new(0, 0, 1), CFGNodeData::new_test_single_call(1, NodeId::from(0), false, NodeId::new(0, 0, 2))),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 1), CFGNodeData::new_test_single_call(1, NodeId::from(0), false, NodeId::new(0, 0, 2))),
        (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::Normal, NodeId::new(0, 0, 2), NodeId::new(0, 0, 3))),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::Normal, NodeId::new(0, 0, 2), NodeId::new(0, 0, 3))),
        (NodeId::new(0, 0, 3), CFGNodeData::new_test_single(3, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID)),
    );
    }
    cfg
}

pub const LINEAR_CFG_ENTRY: u64 = 0;

pub fn get_cfg_linear() -> CFG {
    let mut cfg = CFG::new();
    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    cfg.add_edge(
        (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 1), INVALID_NODE_ID)),
        (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::Normal, NodeId::new(0, 0, 2), INVALID_NODE_ID)),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::Normal, NodeId::new(0, 0, 2), INVALID_NODE_ID)),
        (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::Normal, NodeId::new(0, 0, 3), INVALID_NODE_ID)),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::Normal, NodeId::new(0, 0, 3), INVALID_NODE_ID)),
        (NodeId::new(0, 0, 3), CFGNodeData::new_test_single(3, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID)),
    );
    }
    cfg
}

pub fn get_cfg_linear_call() -> CFG {
    let mut cfg = CFG::new();
    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    cfg.add_edge(
        (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 1), INVALID_NODE_ID)),
        (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::Normal, NodeId::new(0, 0, 2), INVALID_NODE_ID)),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::Normal, NodeId::new(0, 0, 2), INVALID_NODE_ID)),
        (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::Normal, NodeId::new(0, 0, 3), INVALID_NODE_ID)),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::Normal, NodeId::new(0, 0, 3), INVALID_NODE_ID)),
        (NodeId::new(0, 0, 3), CFGNodeData::new_test_single(3, InsnNodeType::Call, INVALID_NODE_ID, INVALID_NODE_ID)),
    );
    }
    cfg
}

pub const SIMPLE_LOOP_ENTRY: Address = 0;
//
//       <---+
// 0 -> 1 -> 2 -> 3
pub fn get_cfg_simple_loop() -> CFG {
    let mut cfg = CFG::new();
    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    cfg.add_edge(
        (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 1), INVALID_NODE_ID)),
        (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::Normal, NodeId::new(0, 0, 2), INVALID_NODE_ID)),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::Normal, NodeId::new(0, 0, 2), INVALID_NODE_ID)),
        (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::Normal, NodeId::new(0, 0, 3), NodeId::new(0, 0, 1))),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::Normal, NodeId::new(0, 0, 3), NodeId::new(0, 0, 1))),
        (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::Normal, NodeId::new(0, 0, 2), INVALID_NODE_ID)),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::Normal, NodeId::new(0, 0, 3), NodeId::new(0, 0, 1))),
        (NodeId::new(0, 0, 3), CFGNodeData::new_test_single(3, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID)),
    );
    }
    cfg
}

pub fn get_cfg_simple_loop_extra_nodes() -> CFG {
    let mut cfg = CFG::new();
    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    cfg.add_edge(
        (NodeId::new(0, 0, 10), CFGNodeData::new_test_single(10, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0), INVALID_NODE_ID)),
        (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::Normal, NodeId::new(0, 0, 1), INVALID_NODE_ID)),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::Normal, NodeId::new(0, 0, 1), INVALID_NODE_ID)),
        (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::Normal, NodeId::new(0, 0, 2), INVALID_NODE_ID)),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::Normal, NodeId::new(0, 0, 2), INVALID_NODE_ID)),
        (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::Normal, NodeId::new(0, 0, 3), NodeId::new(0, 0, 1))),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::Normal, NodeId::new(0, 0, 3), NodeId::new(0, 0, 1))),
        (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::Normal, NodeId::new(0, 0, 2), INVALID_NODE_ID)),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::Normal, NodeId::new(0, 0, 3), NodeId::new(0, 0, 1))),
        (NodeId::new(0, 0, 3), CFGNodeData::new_test_single(3, InsnNodeType::Normal, NodeId::new(0, 0, 13), INVALID_NODE_ID)),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 3), CFGNodeData::new_test_single(3, InsnNodeType::Normal, NodeId::new(0, 0, 13), INVALID_NODE_ID)),
        (NodeId::new(0, 0, 13), CFGNodeData::new_test_single(13, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID)),
    );
    }
    cfg
}

//      <-
// 0 -> 1 -> 2
pub fn get_cfg_self_ref_loop() -> CFG {
    let mut cfg = CFG::new();
    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    let n0 = (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 1), INVALID_NODE_ID));
    let n1 = (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::Normal, NodeId::new(0, 0, 2), NodeId::new(0, 0, 1)));
    let n2 = (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));
    cfg.add_edge(n0, n1.clone());
    cfg.add_edge(n1.clone(), n1.clone());
    cfg.add_edge(n1, n2);
    }
    cfg
}

//
// ```
//  0
//  |
//  1     +--+
// | \    |  |
// |  4 <-+-+
// | /
// 2
// |
// 3
// ```
pub fn get_cfg_loop_self_ref() -> CFG {
    let mut cfg = CFG::new();
    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    cfg.add_edge(
        (NodeId::new(0, 0, 0), CFGNodeData::new_test_single(0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 1), INVALID_NODE_ID)),
        (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::Normal, NodeId::new(0, 0, 2), INVALID_NODE_ID)),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::Normal, NodeId::new(0, 0, 2), INVALID_NODE_ID)),
        (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::Normal, NodeId::new(0, 0, 3), NodeId::new(0, 0, 4))),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::Normal, NodeId::new(0, 0, 3), INVALID_NODE_ID)),
        (NodeId::new(0, 0, 3), CFGNodeData::new_test_single(3, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID)),
    );

    cfg.add_edge(
        (NodeId::new(0, 0, 2), CFGNodeData::new_test_single(2, InsnNodeType::Normal, NodeId::new(0, 0, 3), NodeId::new(0, 0, 4))),
        (NodeId::new(0, 0, 4), CFGNodeData::new_test_single(4, InsnNodeType::Normal, NodeId::new(0, 0, 1), NodeId::new(0, 0, 4))),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 4), CFGNodeData::new_test_single(4, InsnNodeType::Normal, NodeId::new(0, 0, 1), NodeId::new(0, 0, 4))),
        (NodeId::new(0, 0, 4), CFGNodeData::new_test_single(4, InsnNodeType::Normal, NodeId::new(0, 0, 1), NodeId::new(0, 0, 4))),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 4), CFGNodeData::new_test_single(4, InsnNodeType::Normal, NodeId::new(0, 0, 1), NodeId::new(0, 0, 4))),
        (NodeId::new(0, 0, 1), CFGNodeData::new_test_single(1, InsnNodeType::Normal, NodeId::new(0, 0, 2), INVALID_NODE_ID)),
    );
    }
    cfg
}

pub fn get_paper_example_cfg_loop() -> CFG {
    let cfg = CFG::from(
        "
        0:0:0 := E
        0:0:1 := N
        0:0:2 := C.J
        0:0:3 := C.J
        0:0:4 := R

        0:0:0 -> 0:0:1
        0:0:1 -> 0:0:2
        0:0:2 -> 0:0:3
        0:0:3 -> 0:0:4

        0:0:2 -> 0:0:1
        0:0:3 -> 0:0:2
    ",
    );
    cfg
}

pub const UNSET_INDIRECT_CALL_CFG_ENTRY: Address = 0;
pub const UNSET_INDIRECT_CALL_CFG_CALL: Address = 1;

pub fn get_unset_indirect_call_cfg() -> CFG {
    let mut cfg = CFG::new();

    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    cfg.add_edge(
        (NodeId::new(0, 0, 0), CFGNodeData::new_test_single( 0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 1), INVALID_NODE_ID)),
        (NodeId::new(0, 0, 1), CFGNodeData::new_test_single_call( 1, INVALID_NODE_ID, true, NodeId::new(0, 0, 2))),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 1), CFGNodeData::new_test_single_call( 1, INVALID_NODE_ID, true, NodeId::new(0, 0, 2))),
        (NodeId::new(0, 0, 2), CFGNodeData::new_test_single( 2, InsnNodeType::Return, NodeId::new(0, 0, 3), INVALID_NODE_ID)),
    );
    }

    cfg
}

pub const UNSET_INDIRECT_CALL_TO_0_ENTRY: Address = 0x6000;
pub const UNSET_INDIRECT_CALL_TO_0_CALL: Address = 0x6001;

pub fn get_unset_indirect_call_to_0_cfg() -> CFG {
    let mut cfg = CFG::new();

    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    cfg.add_edge(
        (NodeId::new(0, 0, 0x6000), CFGNodeData::new_test_single(0x6000, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0x6001), INVALID_NODE_ID)),
        (NodeId::new(0, 0, 0x6001), CFGNodeData::new_test_single_call(0x6001, INVALID_NODE_ID, true, NodeId::new(0, 0, 0x6002))),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 0x6001), CFGNodeData::new_test_single_call(0x6001, INVALID_NODE_ID, true, NodeId::new(0, 0, 0x6002))),
        (NodeId::new(0, 0, 0x6002), CFGNodeData::new_test_single(0x6002, InsnNodeType::Return, NodeId::new(0, 0, 0x6003), INVALID_NODE_ID)),
    );
    }

    cfg
}

// 0 ---> 1 <-----> 2
pub fn get_endless_loop_cfg() -> CFG {
    let mut cfg = CFG::new();

    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    cfg.add_edge(
        (NodeId::new(0, 0, 0), CFGNodeData::new_test_single( 0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 1), INVALID_NODE_ID)),
        (NodeId::new(0, 0, 1), CFGNodeData::new_test_single( 1, InsnNodeType::Normal, NodeId::new(0, 0, 2), INVALID_NODE_ID)),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 1), CFGNodeData::new_test_single( 1, InsnNodeType::Normal, NodeId::new(0, 0, 2), INVALID_NODE_ID)),
        (NodeId::new(0, 0, 2), CFGNodeData::new_test_single( 2, InsnNodeType::Normal, NodeId::new(0, 0, 1), INVALID_NODE_ID)),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 2), CFGNodeData::new_test_single( 2, InsnNodeType::Normal, NodeId::new(0, 0, 1), INVALID_NODE_ID)),
        (NodeId::new(0, 0, 1), CFGNodeData::new_test_single( 1, InsnNodeType::Normal, NodeId::new(0, 0, 2), INVALID_NODE_ID)),
    );
    }

    cfg
}

pub const CFG_ENTRY_A: Address = 0xaaaaaa0;
pub const CFG_ENTRY_A_CALL: Address = 0xaaaaaa1;

// 0xaaaaaa0 ----> ind. call ----> 0xaaaaaa2
pub fn get_A() -> CFG {
    let mut cfg = CFG::new();

    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    cfg.add_edge(
        (NodeId::new(0, 0, 0xaaaaaa0), CFGNodeData::new_test_single(0xaaaaaa0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xaaaaaa1), INVALID_NODE_ID)),
        (NodeId::new(0, 0, 0xaaaaaa1), CFGNodeData::new_test_single_call(0xaaaaaa1, INVALID_NODE_ID, true, NodeId::new(0, 0, 0xaaaaaa2))),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 0xaaaaaa1), CFGNodeData::new_test_single_call(0xaaaaaa1, INVALID_NODE_ID, true, NodeId::new(0, 0, 0xaaaaaa2))),
        (NodeId::new(0, 0, 0xaaaaaa2), CFGNodeData::new_test_single(0xaaaaaa2, InsnNodeType::Return, NodeId::new(0, 0, 0xaaaaaa3), INVALID_NODE_ID)),
    );
    }

    cfg
}

pub const CFG_ENTRY_B: Address = 0xbbbbbb0;
pub const CFG_ENTRY_B_CALL_1: Address = 0xbbbbbb1;
pub const CFG_ENTRY_B_CALL_2: Address = 0xbbbbbb2;

//             +--> ind. call -->
//             |
// 0xbbbbbb0 ----> ind. call ----> 0xbbbbbb3
pub fn get_B() -> CFG {
    let mut cfg = CFG::new();

    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    cfg.add_edge(
        (NodeId::new(0, 0, 0xbbbbbb0), CFGNodeData::new_test_single(0xbbbbbb0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xbbbbbb1), NodeId::new(0, 0, 0xbbbbbb2))),
        (NodeId::new(0, 0, 0xbbbbbb1), CFGNodeData::new_test_single_call(0xbbbbbb1, INVALID_NODE_ID, true, NodeId::new(0, 0, 0xbbbbbb3))),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 0xbbbbbb1), CFGNodeData::new_test_single_call(0xbbbbbb1, INVALID_NODE_ID, true, NodeId::new(0, 0, 0xbbbbbb3))),
        (NodeId::new(0, 0, 0xbbbbbb3), CFGNodeData::new_test_single(0xbbbbbb3, InsnNodeType::Return, NodeId::new(0, 0, 0xbbbbbb3), INVALID_NODE_ID)),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 0xbbbbbb0), CFGNodeData::new_test_single(0xbbbbbb0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xbbbbbb1), NodeId::new(0, 0, 0xbbbbbb2))),
        (NodeId::new(0, 0, 0xbbbbbb2), CFGNodeData::new_test_single_call(0xbbbbbb2, INVALID_NODE_ID, true, NodeId::new(0, 0, 0xbbbbbb3))),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 0xbbbbbb2), CFGNodeData::new_test_single_call(0xbbbbbb2, INVALID_NODE_ID, true, NodeId::new(0, 0, 0xbbbbbb3))),
        (NodeId::new(0, 0, 0xbbbbbb3), CFGNodeData::new_test_single(0xbbbbbb3, InsnNodeType::Return, NodeId::new(0, 0, 0xbbbbbb3), INVALID_NODE_ID)),
    );
    }

    cfg
}

pub const CFG_ENTRY_C: Address = 0xcccccc0;

//               +----> 0xcccccc1
// 0xcccccc0 ---->
//               +----> 0xcccccc2
pub fn get_C() -> CFG {
    let mut cfg = CFG::new();

    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    cfg.add_edge(
        (NodeId::new(0, 0, 0xcccccc0), CFGNodeData::new_test_single(0xcccccc0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xcccccc1), NodeId::new(0, 0, 0xcccccc2))),
        (NodeId::new(0, 0, 0xcccccc1), CFGNodeData::new_test_single(0xcccccc1, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID)),
    );
    cfg.add_edge(
        (NodeId::new(0, 0, 0xcccccc0), CFGNodeData::new_test_single(0xcccccc0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xcccccc1), NodeId::new(0, 0, 0xcccccc2))),
        (NodeId::new(0, 0, 0xcccccc2), CFGNodeData::new_test_single(0xcccccc2, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID)),
    );
    }

    cfg
}

pub const CFG_ENTRY_D: Address = 0xdddddd0;
pub const CFG_ENTRY_D_CALL: Address = 0xdddddd1;

//              calls 0xaaaaaaa0
// 0xdddddd0 ---> 0xdddddd1 -----> 0xdddddd3
//           ---> 0xdddddd2
//
pub fn get_D() -> CFG {
    let mut cfg = CFG::new();

    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    let d_n0 = (NodeId::new(0, 0, 0xdddddd0), CFGNodeData::new_test_single(0xdddddd0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xdddddd1), NodeId::new(0, 0, 0xdddddd2)));
    let d_n1 = (NodeId::new(0, 0, 0xdddddd1), CFGNodeData::new_test_single_call(0xdddddd1, NodeId::from(CFG_ENTRY_A), false, NodeId::new(0, 0, 0xdddddd3)));
    let d_n2 = (NodeId::new(0, 0, 0xdddddd2), CFGNodeData::new_test_single(0xdddddd2, InsnNodeType::Normal, NodeId::new(0, 0, 0xdddddd3), INVALID_NODE_ID));
    let d_n3 = (NodeId::new(0, 0, 0xdddddd3), CFGNodeData::new_test_single(0xdddddd3, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));
    cfg.add_edge(d_n0.clone(), d_n1.clone());
    cfg.add_edge(d_n0, d_n2.clone());
    cfg.add_edge(d_n1, d_n3.clone());
    cfg.add_edge(d_n2, d_n3);
    }

    cfg
}

// Two closly connected components in the ICFG, reference each other.
// A <----> B
//
//     C
//   /   \
//  D --> E
//
// A --> D; E --> B
pub fn get_scc_refs_scc() -> (ICFG, RwLock<WeightMap>) {
    let mut icfg = ICFG::new();
    let wmapo = WeightMap::new();
    let mut cfg_a = CFG::new();
    let mut cfg_b = CFG::new();
    let mut cfg_c = CFG::new();
    let mut cfg_d = CFG::new();
    let mut cfg_e = CFG::new();

    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    let cfg_a_n0 = (NodeId::new(0, 0, 0xa0), CFGNodeData::new_test_single(0xa0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xa1), INVALID_NODE_ID));
    let cfg_a_n1 = (NodeId::new(0, 0, 0xa1), CFGNodeData::new_test_single_call(0xa1, NodeId::new(0, 0, B_ADDR), false, NodeId::new(0, 0, 0xa2)));
    let cfg_a_n2 = (NodeId::new(0, 0, 0xa2), CFGNodeData::new_test_single_call(0xa2, NodeId::new(0, 0, D_ADDR), false, NodeId::new(0, 0, 0xa3)));
    let cfg_a_n3 = (NodeId::new(0, 0, 0xa3), CFGNodeData::new_test_single(0xa3, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));

    cfg_a.add_edge(cfg_a_n0, cfg_a_n1.clone());
    cfg_a.add_edge(cfg_a_n1, cfg_a_n2.clone());
    cfg_a.add_edge(cfg_a_n2, cfg_a_n3);

    let cfg_b_n0 = (NodeId::new(0, 0, 0xb0), CFGNodeData::new_test_single(0xb0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xb1), INVALID_NODE_ID));
    let cfg_b_n1 = (NodeId::new(0, 0, 0xb1), CFGNodeData::new_test_single_call(0xb1, NodeId::new(0, 0, A_ADDR), false, NodeId::new(0, 0, 0xb2)));
    let cfg_b_n2 = (NodeId::new(0, 0, 0xb2), CFGNodeData::new_test_single(0xb2, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));

    cfg_b.add_edge(cfg_b_n0, cfg_b_n1.clone());
    cfg_b.add_edge(cfg_b_n1, cfg_b_n2);

    let cfg_c_n0 = (NodeId::new(0, 0, 0xc0), CFGNodeData::new_test_single(0xc0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xc1), INVALID_NODE_ID));
    let cfg_c_n1 = (NodeId::new(0, 0, 0xc1), CFGNodeData::new_test_single_call(0xc1, NodeId::new(0, 0, D_ADDR), false, NodeId::new(0, 0, 0xc2)));
    let cfg_c_n2 = (NodeId::new(0, 0, 0xc2), CFGNodeData::new_test_single(0xc2, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));

    cfg_c.add_edge(cfg_c_n0, cfg_c_n1.clone());
    cfg_c.add_edge(cfg_c_n1, cfg_c_n2);

    let cfg_d_n0 = (NodeId::new(0, 0, 0xd0), CFGNodeData::new_test_single(0xd0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xd1), INVALID_NODE_ID));
    let cfg_d_n1 = (NodeId::new(0, 0, 0xd1), CFGNodeData::new_test_single_call(0xd1, NodeId::new(0, 0, E_ADDR), false, NodeId::new(0, 0, 0xd2)));
    let cfg_d_n2 = (NodeId::new(0, 0, 0xd2), CFGNodeData::new_test_single(0xd2, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));

    cfg_d.add_edge(cfg_d_n0, cfg_d_n1.clone());
    cfg_d.add_edge(cfg_d_n1, cfg_d_n2);

    let cfg_e_n0 = (NodeId::new(0, 0, 0xe0), CFGNodeData::new_test_single(0xe0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xe1), INVALID_NODE_ID));
    let cfg_e_n1 = (NodeId::new(0, 0, 0xe1), CFGNodeData::new_test_single_call(0xe1, NodeId::new(0, 0, C_ADDR), false, NodeId::new(0, 0, 0xe2)));
    let cfg_e_n2 = (NodeId::new(0, 0, 0xe2), CFGNodeData::new_test_single_call(0xe2, NodeId::new(0, 0, B_ADDR), false, NodeId::new(0, 0, 0xe3)));
    let cfg_e_n3 = (NodeId::new(0, 0, 0xe3), CFGNodeData::new_test_single(0xe3, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));

    cfg_e.add_edge(cfg_e_n0, cfg_e_n1.clone());
    cfg_e.add_edge(cfg_e_n1, cfg_e_n2.clone());
    cfg_e.add_edge(cfg_e_n2, cfg_e_n3);

    icfg.add_edge_test(
        (NodeId::new(0, 0, A_ADDR), Procedure::new(Some(cfg_a), false, false, false)),
        (NodeId::new(0, 0, B_ADDR), Procedure::new(Some(cfg_b), false, false, false)),
    );
    icfg.add_edge_test(
        (NodeId::new(0, 0, B_ADDR), Procedure::new(None, false, false, false)),
        (NodeId::new(0, 0, A_ADDR), Procedure::new(None, false, false, false)),
    );
    icfg.add_edge_test(
        (NodeId::new(0, 0, A_ADDR), Procedure::new(None, false, false, false)),
        (NodeId::new(0, 0, D_ADDR), Procedure::new(Some(cfg_d), false, false, false)),
    );
    icfg.add_edge_test(
        (NodeId::new(0, 0, C_ADDR), Procedure::new(Some(cfg_c), false, false, false)),
        (NodeId::new(0, 0, D_ADDR), Procedure::new(None, false, false, false)),
    );
    icfg.add_edge_test(
        (NodeId::new(0, 0, D_ADDR), Procedure::new(None, false, false, false)),
        (NodeId::new(0, 0, E_ADDR), Procedure::new(Some(cfg_e), false, false, false)),
    );
    icfg.add_edge_test(
        (NodeId::new(0, 0, E_ADDR), Procedure::new(None, false, false, false)),
        (NodeId::new(0, 0, C_ADDR), Procedure::new(None, false, false, false)),
    );
    icfg.add_edge_test(
        (NodeId::new(0, 0, E_ADDR), Procedure::new(None, false, false, false)),
        (NodeId::new(0, 0, B_ADDR), Procedure::new(None, false, false, false)),
    );
    }
    (icfg, wmapo)
}

pub fn get_node_data_iter_test() -> (CFG, CFG, CFG) {
    let mut cfg_call_mix = CFG::new();
    let mut cfg_no_call = CFG::new();
    let mut cfg_only_indirect = CFG::new();

    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    let cfg_cm_n0 = (NodeId::new(0, 0, 0xa0), CFGNodeData::new_test_single(0xa0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xa1), INVALID_NODE_ID));
    let cfg_cm_n1 = (NodeId::new(0, 0, 0xa1), CFGNodeData::new_test_single_call(0xa1, NodeId::new(0, 0, B_ADDR), false, NodeId::new(0, 0, 0xa2)));
    let cfg_cm_n2 = (NodeId::new(0, 0, 0xa2), CFGNodeData::new_test_single_call(0xa2, NodeId::new(0, 0, D_ADDR), false, NodeId::new(0, 0, 0xa3)));
    let cfg_cm_n3 = (NodeId::new(0, 0, 0xa3), CFGNodeData::new_test_single_call(0xa3, INVALID_NODE_ID, true, NodeId::new(0, 0, 0xa4)));
    let cfg_cm_n4 = (NodeId::new(0, 0, 0xa4), CFGNodeData::new_test_single(0xa4, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));

    cfg_call_mix.add_edge(cfg_cm_n0, cfg_cm_n1.clone());
    cfg_call_mix.add_edge(cfg_cm_n1, cfg_cm_n2.clone());
    cfg_call_mix.add_edge(cfg_cm_n2, cfg_cm_n3.clone());
    cfg_call_mix.add_edge(cfg_cm_n3, cfg_cm_n4);

    let cfg_nc_n0 = (NodeId::new(0, 0, 0xa0), CFGNodeData::new_test_single(0xa0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xa1), INVALID_NODE_ID));
    let cfg_nc_n1 = (NodeId::new(0, 0, 0xa1), CFGNodeData::new_test_single(0xa1, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));
    cfg_no_call.add_edge(cfg_nc_n0, cfg_nc_n1);

    let cfg_oi_n0 = (NodeId::new(0, 0, 0xa0), CFGNodeData::new_test_single(0xa0, InsnNodeType::NormalEntry, NodeId::new(0, 0, 0xa1), INVALID_NODE_ID));
    let cfg_oi_n1 = (NodeId::new(0, 0, 0xa1), CFGNodeData::new_test_single_call(0xa1, INVALID_NODE_ID, true, NodeId::new(0, 0, 0xa2)));
    let cfg_oi_n2 = (NodeId::new(0, 0, 0xa2), CFGNodeData::new_test_single(0xa2, InsnNodeType::Normal, NodeId::new(0, 0, 0xa3), INVALID_NODE_ID));
    let cfg_oi_n3 = (NodeId::new(0, 0, 0xa3), CFGNodeData::new_test_single_call(0xa3, INVALID_NODE_ID, true, NodeId::new(0, 0, 0xa4)));
    let cfg_oi_n4 = (NodeId::new(0, 0, 0xa4), CFGNodeData::new_test_single(0xa4, InsnNodeType::Return, INVALID_NODE_ID, INVALID_NODE_ID));

    cfg_only_indirect.add_edge(cfg_oi_n0, cfg_oi_n1.clone());
    cfg_only_indirect.add_edge(cfg_oi_n1, cfg_oi_n2.clone());
    cfg_only_indirect.add_edge(cfg_oi_n2, cfg_oi_n3.clone());
    cfg_only_indirect.add_edge(cfg_oi_n3, cfg_oi_n4);
    }
    (cfg_call_mix, cfg_no_call, cfg_only_indirect)
}

// 0 --> 1 ---> 2 ---> 3 ---> 4 ---> 5 ---> 6 ---> 7 ---> 8 ---> 9
//       <------|----------------------------------+     ^
//              +----------------------------------------+
pub fn get_offset_loop() -> CFG {
    let cfg = CFG::from(
        "
            0:0:0 := E
            0:0:1 := N
            0:0:2 := C.J
            0:0:3 := N
            0:0:4 := N
            0:0:5 := N
            0:0:6 := C.J
            0:0:7 := N
            0:0:8 := R

            0:0:0 -> 0:0:1
            0:0:1 -> 0:0:2
            0:0:2 -> 0:0:3
            0:0:3 -> 0:0:4
            0:0:4 -> 0:0:5
            0:0:5 -> 0:0:6
            0:0:6 -> 0:0:7
            0:0:7 -> 0:0:8

            # Jumps
            0:0:6 -> 0:0:1
            0:0:2 -> 0:0:7
        ",
    );
    cfg
}
