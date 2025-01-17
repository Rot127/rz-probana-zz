// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#[cfg(test)]
mod tests {

    use std::{collections::HashSet, sync::RwLock};

    use petgraph::dot::Dot;

    use crate::{
        cfg::{CFGNodeData, InsnNodeType, Procedure, CFG},
        flow_graphs::{FlowGraphOperations, NodeId, ProcedureMap, INVALID_NODE_ID},
        icfg::ICFG,
        proc_map_get_cfg_mut,
        test_graphs::{
            get_cfg_linear, get_cfg_linear_call, get_cfg_loop_self_ref,
            get_cfg_no_loop_sub_routine, get_cfg_no_loop_sub_routine_loop_ret, get_cfg_quit_loop,
            get_cfg_self_ref_loop, get_cfg_simple_loop, get_cfg_simple_loop_extra_nodes,
            get_cfg_single_node, get_cfg_single_self_ref, get_endless_loop_cfg,
            get_endless_loop_icfg, get_endless_loop_icfg_branch, get_endless_recurse_icfg,
            get_endless_recurse_icfg_nonlinear_address, get_entry_loop_cfg, get_gee_cfg,
            get_icfg_with_selfref_and_recurse_cfg, get_loop_to_loop_cfg, get_loop_to_loop_icfg,
            get_main_cfg, get_offset_loop, get_paper_example_cfg_loop, get_paper_example_icfg,
            get_scc_refs_scc, get_unset_indirect_call_to_0_cfg, A_ADDR, B_ADDR, C_ADDR, D_ADDR,
            E_ADDR, FOO_ADDR, F_ADDR, GEE_ADDR, LINEAR_CFG_ENTRY, MAIN_ADDR, NULL_ADDR,
            SIMPLE_LOOP_ENTRY, UNSET_INDIRECT_CALL_TO_0_CALL, UNSET_INDIRECT_CALL_TO_0_ENTRY,
        },
        weight::{WeightID, WeightMap},
    };

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
            "Proc weight {}: {} != {} (expected)",
            proc,
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
    fn test_cfg_from_string() {
        let cfg = get_offset_loop();
        let n0 = NodeId::from("0:0:0");
        assert!(cfg.has_node(n0));
        let n1 = NodeId::from("0:0:1");
        assert!(cfg.has_node(n1));
        let n2 = NodeId::from("0:0:2");
        assert!(cfg.has_node(n2));
        let n3 = NodeId::from("0:0:3");
        assert!(cfg.has_node(n3));
        let n4 = NodeId::from("0:0:4");
        assert!(cfg.has_node(n4));
        let n5 = NodeId::from("0:0:5");
        assert!(cfg.has_node(n5));
        let n6 = NodeId::from("0:0:6");
        assert!(cfg.has_node(n6));
        let n7 = NodeId::from("0:0:7");
        assert!(cfg.has_node(n7));
        let n8 = NodeId::from("0:0:8");
        assert!(cfg.has_node(n8));

        assert!(cfg.has_edge(n0, n1));
        assert!(cfg.has_edge(n1, n2));
        assert!(cfg.has_edge(n2, n3));
        assert!(cfg.has_edge(n3, n4));
        assert!(cfg.has_edge(n4, n5));
        assert!(cfg.has_edge(n5, n6));
        assert!(cfg.has_edge(n6, n7));
        assert!(cfg.has_edge(n7, n8));

        assert!(cfg.has_edge(n2, n7));
        assert!(cfg.has_edge(n6, n1));
        assert_eq!(cfg.get_graph().node_count(), 9);
        assert_eq!(cfg.get_graph().edge_count(), 10);

        assert!(cfg
            .get_insn_node_data(&n0)
            .is_some_and(|cfgd| cfgd.has_type(InsnNodeType::Entry)));
        assert!(cfg
            .get_insn_node_data(&n1)
            .is_some_and(|cfgd| cfgd.has_type(InsnNodeType::Normal)));
        assert!(cfg
            .get_insn_node_data(&n2)
            .is_some_and(|cfgd| cfgd.has_type(InsnNodeType::Cond | InsnNodeType::Jump)));
        assert!(cfg
            .get_insn_node_data(&n3)
            .is_some_and(|cfgd| cfgd.has_type(InsnNodeType::Normal)));
        assert!(cfg
            .get_insn_node_data(&n4)
            .is_some_and(|cfgd| cfgd.has_type(InsnNodeType::Normal)));
        assert!(cfg
            .get_insn_node_data(&n5)
            .is_some_and(|cfgd| cfgd.has_type(InsnNodeType::Normal)));
        assert!(cfg
            .get_insn_node_data(&n6)
            .is_some_and(|cfgd| cfgd.has_type(InsnNodeType::Cond | InsnNodeType::Jump)));
        assert!(cfg
            .get_insn_node_data(&n7)
            .is_some_and(|cfgd| cfgd.has_type(InsnNodeType::Normal)));
        assert!(cfg
            .get_insn_node_data(&n8)
            .is_some_and(|cfgd| cfgd.has_type(InsnNodeType::Return)));
    }

    #[test]
    #[should_panic = "Check Normal type mismatch"]
    fn test_cfg_has_type() {
        let cfg = get_offset_loop();
        let n6 = NodeId::from("0:0:6");
        assert!(
            cfg.get_insn_node_data(&n6)
                .is_some_and(|cfgd| cfgd.has_type(InsnNodeType::Normal)),
            "Check Normal type mismatch"
        );
    }

    #[test]
    fn test_cfg_weight_calc_no_call() {
        let wmap = &WeightMap::new();
        let mut gee_cfg = get_gee_cfg();
        gee_cfg.make_acyclic(None);
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        assert_node_weight(gee_cfg.calc_node_weight(&NodeId::new(0, 0, 0), empty_proc_map!(), wmap), 2, wmap);
        assert_node_weight(gee_cfg.calc_node_weight(&NodeId::new(0, 0, 1), empty_proc_map!(), wmap), 2, wmap);
        assert_node_weight(gee_cfg.calc_node_weight(&NodeId::new(0, 0, 2), empty_proc_map!(), wmap), 1, wmap);
        assert_node_weight(gee_cfg.calc_node_weight(&NodeId::new(0, 0, 3), empty_proc_map!(), wmap), 1, wmap);
        assert_node_weight(gee_cfg.calc_node_weight(&NodeId::new(0, 0, 4), empty_proc_map!(), wmap), 1, wmap);
        assert_weight(gee_cfg.get_entry_weight_id(empty_proc_map!(), wmap), 2, wmap);
        }
    }

    #[test]
    #[should_panic = "Can't add procedure. Index and entry node address miss-match: index((0:0:0x99999999999999)) != entry((0:0:0xb))"]
    fn test_proc_insert_mmismatch() {
        let mut icfg = ICFG::new();
        icfg.add_procedure(
            NodeId::from(0x99999999999999),
            Procedure::new(Some(get_main_cfg()), false, false, false),
        );
    }

    #[test]
    fn test_undiscovered_indirect_call() {
        let wmap = &WeightMap::new();
        let mut proc_map = ProcedureMap::new();
        let unset_0_entry = NodeId::from(UNSET_INDIRECT_CALL_TO_0_ENTRY);
        proc_map.insert(
            unset_0_entry,
            RwLock::new(Procedure::new(
                Some(get_unset_indirect_call_to_0_cfg()),
                false,
                false,
                false,
            )),
        );
        proc_map_get_cfg_mut!(proc_map, &unset_0_entry).make_acyclic(None);

        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        assert_node_weight(proc_map_get_cfg_mut!(proc_map, &unset_0_entry).calc_node_weight(&unset_0_entry, empty_proc_map!(), wmap), 1, wmap);

        let mut lcfg = get_cfg_simple_loop();
        lcfg.make_acyclic(None);
        proc_map.insert(NodeId::from(SIMPLE_LOOP_ENTRY), RwLock::new(Procedure::new(Some(lcfg), false, false, false)));
        proc_map.get(&unset_0_entry).unwrap().write().unwrap()
            .insert_call_target(&NodeId::from(UNSET_INDIRECT_CALL_TO_0_CALL), -1, &NodeId::from(SIMPLE_LOOP_ENTRY));
        assert_node_weight(proc_map_get_cfg_mut!(proc_map, &unset_0_entry).calc_node_weight(&unset_0_entry, &proc_map, wmap), 10, wmap);

        proc_map.get(&unset_0_entry).unwrap().write().unwrap()
            .insert_call_target(&NodeId::from(UNSET_INDIRECT_CALL_TO_0_CALL), -1, &NodeId::from(LINEAR_CFG_ENTRY));
        lcfg = get_cfg_linear();
        lcfg.make_acyclic(None);
        proc_map.insert(NodeId::from(LINEAR_CFG_ENTRY), RwLock::new(Procedure::new(Some(lcfg), false, false, false)));
        assert_node_weight(proc_map_get_cfg_mut!(proc_map, &unset_0_entry).calc_node_weight(&unset_0_entry, &proc_map, wmap), 1, wmap);
        }
    }

    #[test]
    fn test_icfg_weight_calc() {
        let (mut icfg, wmap) = get_paper_example_icfg();
        let wmap = &wmap;
        icfg.resolve_loops(1);
        assert_p_weight(&icfg, &NodeId::new(0, 0, MAIN_ADDR), 6, wmap);
        assert_p_weight(&icfg, &NodeId::new(0, 0, FOO_ADDR), 4, wmap);
        assert_p_weight(&icfg, &NodeId::new(0, 0, MAIN_ADDR), 6, wmap);
        assert_p_weight(&icfg, &NodeId::new(0, 0, FOO_ADDR), 4, wmap);
        assert_p_weight(&icfg, &NodeId::new(0, 0, GEE_ADDR), 2, wmap);
    }

    #[test]
    fn test_icfg_no_procedure_duplicates() {
        let (mut icfg, _wmap) = get_paper_example_icfg();
        // Add a cloned edge from main -> foo'()
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        icfg.add_edge_test(
            (NodeId::new(0, 0, MAIN_ADDR), Procedure::new(None, false, false, false)),
            (NodeId::new(0, 0, FOO_ADDR), Procedure::new(None, false, false, false)),
);
        }
        assert_eq!(icfg.num_procedures(), 3);
        icfg.add_cloned_edge(
            NodeId::new(0, 0, MAIN_ADDR),
            NodeId::new(0, 0, GEE_ADDR),
            &crate::flow_graphs::EdgeFlow::BackEdge,
        );
        assert_eq!(icfg.num_procedures(), 3);
    }

    #[test]
    fn test_cfg_untangle() {
        let mut cfg = get_paper_example_cfg_loop();
        // println!(
        //     "{:?}",
        //     Dot::with_config(&cfg.graph, &[Config::EdgeNoLabel, Config::NodeIndexLabel])
        // );
        cfg.make_acyclic(None);
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
        cfg.make_acyclic(None);
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
        cfg.make_acyclic(None);
        println!("Acyclic:\n{:?}", Dot::with_config(&cfg.graph, &[]));
        assert_eq!(cfg.graph.node_count(), 23);
        assert_eq!(cfg.graph.edge_count(), 46);

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
        assert!(cfg.graph.contains_edge(NodeId::new(0, 1, 11), NodeId::new(0, 1, 1)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 1, 11), NodeId::new(0, 2, 1)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 1, 11), NodeId::new(0, 3, 1)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 2, 11), NodeId::new(0, 0, 1)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 2, 11), NodeId::new(0, 1, 1)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 2, 11), NodeId::new(0, 2, 1)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 2, 11), NodeId::new(0, 3, 1)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 3, 11), NodeId::new(0, 0, 1)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 3, 11), NodeId::new(0, 1, 1)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 3, 11), NodeId::new(0, 2, 1)));
        assert!(cfg.graph.contains_edge(NodeId::new(0, 3, 11), NodeId::new(0, 3, 1)));

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
    fn test_cfg_single_node() {
        let wmap = &WeightMap::new();
        let mut cfg: CFG = get_cfg_single_node();
        cfg.make_acyclic(None);
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
                CFGNodeData::new_test_single(0, InsnNodeType::Normal | InsnNodeType::Entry, NodeId::new(0, 0, 1), INVALID_NODE_ID),
            ),
            (
                NodeId::new(0, 0, 1),
                CFGNodeData::new_test_single(1, InsnNodeType::Normal, NodeId::new(0, 0, 2), INVALID_NODE_ID),
            ),
        );
        }
        cfg.make_acyclic(None);
        assert_weight(cfg.get_entry_weight_id(empty_proc_map!(), wmap), 1, wmap);
    }

    #[test]
    #[should_panic(
        expected = "Graph was not sorted in topological order. This indicates it was not made acyclic before. An acyclic graph is required for weight calculation."
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
        cfg.make_acyclic(None);
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
        cfg.make_acyclic(None);
        println!("{:?}", cfg.get_sccs());
        println!("{:?}", Dot::with_config(&cfg.get_graph(), &[]));
        assert_eq!(cfg.graph.edge_count(), 3);
        assert_eq!(cfg.graph.node_count(), 4);
        assert_eq!(cfg.nodes_meta.len(), 4);
        assert_weight(cfg.get_entry_weight_id(empty_proc_map!(), wmap), 1, wmap);
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 0), empty_proc_map!(), wmap)), 1, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 1), empty_proc_map!(), wmap)), 1, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 2), empty_proc_map!(), wmap)), 1, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 3), empty_proc_map!(), wmap)), 1, wmap);
        }
    }

    #[test]
    fn test_cfg_simple_loop_single_node_scc() {
        let wmap = &WeightMap::new();
        let mut cfg: CFG = get_cfg_simple_loop_extra_nodes();
        assert_eq!(cfg.graph.edge_count(), 6);
        assert_eq!(cfg.graph.node_count(), 6);
        assert_eq!(cfg.nodes_meta.len(), 6);
        cfg.make_acyclic(None);
        assert_eq!(cfg.graph.edge_count(), 17);
        assert_eq!(cfg.graph.node_count(), 12);
        assert_eq!(cfg.nodes_meta.len(), 12);
        assert_eq!(cfg.graph.edge_count(), 17);
        assert_eq!(cfg.graph.node_count(), 12);
        assert_eq!(cfg.nodes_meta.len(), 12);
        assert_weight(cfg.get_entry_weight_id(empty_proc_map!(), wmap), 10, wmap);
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 10), empty_proc_map!(), wmap)), 10, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 0), empty_proc_map!(), wmap)), 10, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 1), empty_proc_map!(), wmap)), 4, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 2), empty_proc_map!(), wmap)), 4, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 3), empty_proc_map!(), wmap)), 1, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 13), empty_proc_map!(), wmap)), 1, wmap);

        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 1, 1), empty_proc_map!(), wmap)), 3, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 1, 2), empty_proc_map!(), wmap)), 3, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 2, 1), empty_proc_map!(), wmap)), 2, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 2, 2), empty_proc_map!(), wmap)), 2, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 3, 1), empty_proc_map!(), wmap)), 1, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 3, 2), empty_proc_map!(), wmap)), 1, wmap);
        }
    }

    #[test]
    fn test_cfg_simple_loop() {
        let wmap = &WeightMap::new();
        let mut cfg: CFG = get_cfg_simple_loop();
        assert_eq!(cfg.graph.edge_count(), 4);
        assert_eq!(cfg.graph.node_count(), 4);
        assert_eq!(cfg.nodes_meta.len(), 4);
        cfg.make_acyclic(None);
        assert_eq!(cfg.graph.edge_count(), 15);
        assert_eq!(cfg.graph.node_count(), 10);
        assert_eq!(cfg.nodes_meta.len(), 10);
        assert_eq!(cfg.graph.edge_count(), 15);
        assert_eq!(cfg.graph.node_count(), 10);
        assert_eq!(cfg.nodes_meta.len(), 10);
        assert_weight(cfg.get_entry_weight_id(empty_proc_map!(), wmap), 10, wmap);
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 0), empty_proc_map!(), wmap)), 10, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 1), empty_proc_map!(), wmap)), 4, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 2), empty_proc_map!(), wmap)), 4, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 3), empty_proc_map!(), wmap)), 1, wmap);

        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 1, 1), empty_proc_map!(), wmap)), 3, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 1, 2), empty_proc_map!(), wmap)), 3, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 2, 1), empty_proc_map!(), wmap)), 2, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 2, 2), empty_proc_map!(), wmap)), 2, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 3, 1), empty_proc_map!(), wmap)), 1, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 3, 2), empty_proc_map!(), wmap)), 1, wmap);
        }
    }

    #[test]
    fn test_cfg_self_ref() {
        let wmap = &WeightMap::new();
        let mut cfg: CFG = get_cfg_self_ref_loop();
        assert_eq!(cfg.graph.edge_count(), 3);
        assert_eq!(cfg.graph.node_count(), 3);
        assert_eq!(cfg.nodes_meta.len(), 3);
        cfg.make_acyclic(None);
        println!("{:?}", cfg.get_sccs());
        println!("{:?}", Dot::with_config(&cfg.get_graph(), &[]));
        assert_eq!(cfg.graph.edge_count(), 11);
        assert_eq!(cfg.graph.node_count(), 6);
        assert_eq!(cfg.nodes_meta.len(), 6);
        assert_weight(cfg.get_entry_weight_id(empty_proc_map!(), wmap), 10, wmap);
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 0), empty_proc_map!(), wmap)), 10, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 1), empty_proc_map!(), wmap)), 4, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 2), empty_proc_map!(), wmap)), 1, wmap);

        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 1, 1), empty_proc_map!(), wmap)), 3, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 2, 1), empty_proc_map!(), wmap)), 2, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 3, 1), empty_proc_map!(), wmap)), 1, wmap);
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
        cfg.make_acyclic(None);
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
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 0), empty_proc_map!(), wmap)), 30, wmap);

        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 1), empty_proc_map!(), wmap)), 16, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 1, 1), empty_proc_map!(), wmap)), 8, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 2, 1), empty_proc_map!(), wmap)), 4, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 3, 1), empty_proc_map!(), wmap)), 2, wmap);

        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 2), empty_proc_map!(), wmap)), 16, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 1, 2), empty_proc_map!(), wmap)), 8, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 2, 2), empty_proc_map!(), wmap)), 4, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 3, 2), empty_proc_map!(), wmap)), 2, wmap);

        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 4), empty_proc_map!(), wmap)), 15, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 1, 4), empty_proc_map!(), wmap)), 7, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 2, 4), empty_proc_map!(), wmap)), 3, wmap);
        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 3, 4), empty_proc_map!(), wmap)), 1, wmap);

        assert_weight(Some(cfg.calc_node_weight(&NodeId::new(0, 0, 3), empty_proc_map!(), wmap)), 1, wmap);
        }
    }

    #[test]
    fn test_icfg_endless_acyclic() {
        let (mut icfg, wmap) = get_endless_loop_icfg();
        let wmap = &wmap;
        icfg.resolve_loops(1);
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
    fn test_icfg_endless_recurse_acyclic() {
        let (mut icfg, wmap) = get_endless_recurse_icfg();
        let wmap = &wmap;
        icfg.resolve_loops(1);
        assert_eq!(icfg.get_procedures().len(), 12, "Mismatch procedures");
        assert_eq!(icfg.get_graph().edge_count(), 11, "Mismatch edges");
        assert_eq!(icfg.get_graph().node_count(), 12, "Mismatch nodes");

        // Add the removed back edge again and do the resolve loop again.
        // It should prduce the same graph
        icfg.add_edge(
            (NodeId::new(0, 0, C_ADDR), None),
            (NodeId::new(0, 0, A_ADDR), None),
            Some(NodeId::new_original(0xc1)),
        );
        icfg.resolve_loops(1);
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        assert_eq!(icfg.get_procedures().len(), 12, "Re-resolve loops mismatch procedures");
        assert_eq!(icfg.get_graph().edge_count(), 11, "Re-resolve loops mismatch edges");
        assert_eq!(icfg.get_graph().node_count(), 12, "Re-resolve loops mismatch nodes");
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
    }

    #[test]
    fn test_icfg_endless_recurse_acyclic_nonlinear_address() {
        let (mut icfg, _) = get_endless_recurse_icfg_nonlinear_address();
        icfg.resolve_loops(1);
        icfg.dot_graph_to_stdout();

        let c_nodes = vec![
            NodeId::new(0, 0, C_ADDR),
            NodeId::new(1, 0, C_ADDR),
            NodeId::new(2, 0, C_ADDR),
            NodeId::new(3, 0, C_ADDR),
        ];
        check_procedures(&icfg, &c_nodes);
        check_saved_calls(&icfg);

        // Add the removed back edge again and do the resolve loop again.
        // It should prduce the same graph
        icfg.add_edge(
            (NodeId::new(0, 0, C_ADDR), None),
            (NodeId::new(0, 0, A_ADDR), None),
            Some(NodeId::new_original(0xc1)),
        );
        icfg.resolve_loops(1);
        check_procedures(&icfg, &c_nodes);
        check_saved_calls(&icfg);

        // Add one between clones and check everything again.
        icfg.add_edge(
            (NodeId::new(1, 0, C_ADDR), None),
            (NodeId::new(1, 0, A_ADDR), None),
            Some(NodeId::new(1, 0, 0xc1)),
        );
        icfg.resolve_loops(1);
        check_procedures(&icfg, &c_nodes);
        check_saved_calls(&icfg);

        // Add one between clones and check everything again.
        icfg.add_edge(
            (NodeId::new(1, 0, A_ADDR), None),
            (NodeId::new(1, 0, C_ADDR), None),
            Some(NodeId::new(1, 0, 0xa1)),
        );
        icfg.resolve_loops(1);
        check_procedures(&icfg, &c_nodes);
        check_saved_calls(&icfg);

        icfg.dot_graph_to_stdout();
        // Attempt to add contrary to cloned back edge.
        icfg.add_edge(
            (NodeId::new(2, 0, A_ADDR), None),
            (NodeId::new(1, 0, C_ADDR), None),
            Some(NodeId::new(2, 0, 0xa1)),
        );
        icfg.resolve_loops(1);
        check_procedures(&icfg, &c_nodes);
        check_saved_calls(&icfg);

        // Just add edges and resolve loops to check reproducability
        let edges: &[(NodeId, NodeId, Option<NodeId>)] = &[
            (
                NodeId::new(1, 0, C_ADDR),
                NodeId::new(1, 0, A_ADDR),
                Some(NodeId::new(1, 0, 0xc1)),
            ),
            (
                NodeId::new(1, 0, C_ADDR),
                NodeId::new(1, 0, A_ADDR),
                Some(NodeId::new(1, 0, 0xc1)),
            ),
            (
                NodeId::new(1, 0, C_ADDR),
                NodeId::new(1, 0, A_ADDR),
                Some(NodeId::new(1, 0, 0xc1)),
            ),
            (
                NodeId::new(1, 0, C_ADDR),
                NodeId::new(2, 0, A_ADDR),
                Some(NodeId::new(1, 0, 0xc1)),
            ),
            (
                NodeId::new(1, 0, C_ADDR),
                NodeId::new(2, 0, A_ADDR),
                Some(NodeId::new(1, 0, 0xc1)),
            ),
            (
                NodeId::new(2, 0, A_ADDR),
                NodeId::new(1, 0, C_ADDR),
                Some(NodeId::new(2, 0, 0xa1)),
            ),
            (
                NodeId::new(1, 0, A_ADDR),
                NodeId::new(1, 0, C_ADDR),
                Some(NodeId::new(1, 0, 0xa1)),
            ),
            (
                NodeId::new(1, 0, A_ADDR),
                NodeId::new(1, 0, C_ADDR),
                Some(NodeId::new(1, 0, 0xa1)),
            ),
            (
                NodeId::new(1, 0, A_ADDR),
                NodeId::new(1, 0, C_ADDR),
                Some(NodeId::new(1, 0, 0xa1)),
            ),
            (
                NodeId::new(0, 0, A_ADDR),
                NodeId::new(0, 0, C_ADDR),
                Some(NodeId::new(0, 0, 0xa1)),
            ),
            (
                NodeId::new(0, 0, A_ADDR),
                NodeId::new(0, 0, C_ADDR),
                Some(NodeId::new(0, 0, 0xa1)),
            ),
            (
                NodeId::new(0, 0, A_ADDR),
                NodeId::new(0, 0, C_ADDR),
                Some(NodeId::new(0, 0, 0xa1)),
            ),
            (
                NodeId::new(0, 0, A_ADDR),
                NodeId::new(0, 0, C_ADDR),
                Some(NodeId::new(0, 0, 0xa1)),
            ),
            (
                NodeId::new(0, 0, A_ADDR),
                NodeId::new(0, 0, C_ADDR),
                Some(NodeId::new(0, 0, 0xa1)),
            ),
        ];
        for i in 0..1000 {
            let edge = edges.get(i % edges.len()).unwrap();
            println!("Add {:?}", edge);
            icfg.add_edge((edge.0, None), (edge.1, None), edge.2);
            icfg.resolve_loops(4);
            check_procedures(&icfg, &c_nodes);
            check_saved_calls(&icfg);
        }
    }

    fn check_procedures(icfg: &ICFG, c_nodes: &Vec<NodeId>) {
        assert_eq!(
            icfg.get_graph()
                .edges_directed(NodeId::from(D_ADDR), petgraph::Direction::Outgoing)
                .count(),
            0
        );
        assert_eq!(
            icfg.get_graph()
                .edges_directed(NodeId::from(D_ADDR), petgraph::Direction::Incoming)
                .count(),
            4
        );
        assert_eq!(
            icfg.get_graph()
                .edges_directed(NodeId::from(NULL_ADDR), petgraph::Direction::Outgoing)
                .count(),
            0
        );
        assert_eq!(
            icfg.get_graph()
                .edges_directed(NodeId::from(NULL_ADDR), petgraph::Direction::Incoming)
                .count(),
            4
        );
        assert!(icfg
            .get_graph()
            .edges_directed(NodeId::from(D_ADDR), petgraph::Direction::Incoming)
            .all(|e| e.0.address == C_ADDR));
        assert!(icfg
            .get_graph()
            .edges_directed(NodeId::from(NULL_ADDR), petgraph::Direction::Incoming)
            .all(|e| e.0.address == C_ADDR));
        let in_d_nodes = Vec::from_iter(
            icfg.get_graph()
                .edges_directed(NodeId::from(D_ADDR), petgraph::Direction::Incoming)
                .map(|e| e.0)
                .into_iter(),
        );
        let in_0_nodes = Vec::from_iter(
            icfg.get_graph()
                .edges_directed(NodeId::from(NULL_ADDR), petgraph::Direction::Incoming)
                .map(|e| e.0)
                .into_iter(),
        );
        for n in c_nodes.iter() {
            assert!(in_d_nodes.contains(&n));
            assert!(in_0_nodes.contains(&n));
        }

        assert_eq!(
            icfg.get_procedures().len(),
            11,
            "Re-resolve loops mismatch procedures"
        );
        assert_eq!(
            icfg.get_graph().edge_count(),
            19,
            "Re-resolve loops mismatch edges"
        );
        assert_eq!(
            icfg.get_graph().node_count(),
            11,
            "Re-resolve loops mismatch nodes"
        );
    }

    fn check_saved_calls(icfg: &ICFG) {
        assert_eq!(
            icfg.get_procedure(&NodeId::new(0, 0, C_ADDR))
                .read()
                .unwrap()
                .get_cfg()
                .nodes_meta
                .ct_iter()
                .count(),
            3
        );

        let c0_ct = HashSet::<NodeId>::from_iter(
            icfg.get_procedure(&NodeId::new(0, 0, C_ADDR))
                .read()
                .unwrap()
                .get_cfg()
                .nodes_meta
                .ct_iter()
                .cloned(),
        );
        let c0_expected_ct = HashSet::from_iter(
            [
                NodeId::from(NULL_ADDR),
                NodeId::from(D_ADDR),
                NodeId::new(1, 0, A_ADDR),
            ]
            .to_vec()
            .into_iter(),
        );
        assert!(
            c0_ct.intersection(&c0_expected_ct).count() == 3,
            "Mistmatch in calltargets. {:?} != {:?}",
            c0_ct,
            c0_expected_ct
        );

        let c1_ct = HashSet::<NodeId>::from_iter(
            icfg.get_procedure(&NodeId::new(1, 0, C_ADDR))
                .read()
                .unwrap()
                .get_cfg()
                .nodes_meta
                .ct_iter()
                .cloned(),
        );
        let c1_expected_ct = HashSet::from_iter(
            [
                NodeId::from(NULL_ADDR),
                NodeId::from(D_ADDR),
                NodeId::new(2, 0, A_ADDR),
            ]
            .to_vec()
            .into_iter(),
        );
        assert!(
            c1_ct.intersection(&c1_expected_ct).count() == 3,
            "Mistmatch in calltargets. {:?} != {:?}",
            c1_ct,
            c1_expected_ct
        );

        let c2_ct = HashSet::<NodeId>::from_iter(
            icfg.get_procedure(&NodeId::new(2, 0, C_ADDR))
                .read()
                .unwrap()
                .get_cfg()
                .nodes_meta
                .ct_iter()
                .cloned(),
        );
        let c2_expected_ct = HashSet::from_iter(
            [
                NodeId::from(NULL_ADDR),
                NodeId::from(D_ADDR),
                NodeId::new(3, 0, A_ADDR),
            ]
            .to_vec()
            .into_iter(),
        );
        assert!(
            c2_ct.intersection(&c2_expected_ct).count() == 3,
            "Mistmatch in calltargets. {:?} != {:?}",
            c2_ct,
            c2_expected_ct
        );

        let c3_ct = HashSet::<NodeId>::from_iter(
            icfg.get_procedure(&NodeId::new(3, 0, C_ADDR))
                .read()
                .unwrap()
                .get_cfg()
                .nodes_meta
                .ct_iter()
                .cloned(),
        );
        let c3_expected_ct = HashSet::from_iter(
            [NodeId::from(NULL_ADDR), NodeId::from(D_ADDR)]
                .to_vec()
                .into_iter(),
        );
        assert!(
            c3_ct.intersection(&c3_expected_ct).count() == 2,
            "Mistmatch in calltargets. {:?} != {:?}",
            c3_ct,
            c3_expected_ct
        );
    }

    #[test]
    fn test_icfg_endless_with_branch_acyclic() {
        let (mut icfg, wmap) = get_endless_loop_icfg_branch();
        icfg.resolve_loops(1);
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
        icfg.resolve_loops(4);
        assert_eq!(icfg.num_procedures(), 4);
        assert_eq!(icfg.get_graph().edge_count(), 3);
    }

    #[test]
    fn test_loop_to_loop_cfg() {
        let mut cfg = get_loop_to_loop_cfg();
        cfg.make_acyclic(None);
        println!("{:?}", Dot::with_config(&cfg.graph, &[]));
        let all_edges = Vec::from_iter(cfg.get_graph().all_edges().map(|e| (e.0, e.1)));
        println!("{:?}", all_edges);
        assert!(all_edges.contains(&(NodeId::new(0, 0, 0x0), NodeId::new(0, 0, 0x1))));
        assert!(all_edges.contains(&(NodeId::new(0, 0, 0x1), NodeId::new(0, 0, 0x2))));
        assert!(all_edges.contains(&(NodeId::new(0, 0, 0x2), NodeId::new(0, 1, 0x0))));
        assert!(all_edges.contains(&(NodeId::new(0, 1, 0x0), NodeId::new(0, 1, 0x1))));
        assert!(all_edges.contains(&(NodeId::new(0, 1, 0x1), NodeId::new(0, 1, 0x2))));
        assert!(all_edges.contains(&(NodeId::new(0, 1, 0x2), NodeId::new(0, 2, 0x0))));
        assert!(all_edges.contains(&(NodeId::new(0, 2, 0x0), NodeId::new(0, 2, 0x1))));
        assert!(all_edges.contains(&(NodeId::new(0, 2, 0x1), NodeId::new(0, 2, 0x2))));
        assert!(all_edges.contains(&(NodeId::new(0, 2, 0x2), NodeId::new(0, 3, 0x0))));
        assert!(all_edges.contains(&(NodeId::new(0, 3, 0x0), NodeId::new(0, 3, 0x1))));
        assert!(all_edges.contains(&(NodeId::new(0, 3, 0x1), NodeId::new(0, 3, 0x2))));

        assert!(all_edges.contains(&(NodeId::new(0, 0, 0xa), NodeId::new(0, 0, 0xb))));
        assert!(all_edges.contains(&(NodeId::new(0, 0, 0xb), NodeId::new(0, 0, 0xc))));
        assert!(all_edges.contains(&(NodeId::new(0, 0, 0xc), NodeId::new(0, 1, 0xa))));
        assert!(all_edges.contains(&(NodeId::new(0, 1, 0xa), NodeId::new(0, 1, 0xb))));
        assert!(all_edges.contains(&(NodeId::new(0, 1, 0xb), NodeId::new(0, 1, 0xc))));
        assert!(all_edges.contains(&(NodeId::new(0, 1, 0xc), NodeId::new(0, 2, 0xa))));
        assert!(all_edges.contains(&(NodeId::new(0, 2, 0xa), NodeId::new(0, 2, 0xb))));
        assert!(all_edges.contains(&(NodeId::new(0, 2, 0xb), NodeId::new(0, 2, 0xc))));
        assert!(all_edges.contains(&(NodeId::new(0, 2, 0xc), NodeId::new(0, 3, 0xa))));
        assert!(all_edges.contains(&(NodeId::new(0, 3, 0xa), NodeId::new(0, 3, 0xb))));
        assert!(all_edges.contains(&(NodeId::new(0, 3, 0xb), NodeId::new(0, 3, 0xc))));

        assert!(all_edges.contains(&(NodeId::new(0, 0, 0xb), NodeId::new(0, 0, 0x1))));
        assert!(all_edges.contains(&(NodeId::new(0, 0, 0xb), NodeId::new(0, 1, 0x1))));
        assert!(all_edges.contains(&(NodeId::new(0, 0, 0xb), NodeId::new(0, 2, 0x1))));
        assert!(all_edges.contains(&(NodeId::new(0, 0, 0xb), NodeId::new(0, 3, 0x1))));
        assert!(all_edges.contains(&(NodeId::new(0, 1, 0xb), NodeId::new(0, 0, 0x1))));
        assert!(all_edges.contains(&(NodeId::new(0, 1, 0xb), NodeId::new(0, 1, 0x1))));
        assert!(all_edges.contains(&(NodeId::new(0, 1, 0xb), NodeId::new(0, 2, 0x1))));
        assert!(all_edges.contains(&(NodeId::new(0, 1, 0xb), NodeId::new(0, 3, 0x1))));
        assert!(all_edges.contains(&(NodeId::new(0, 2, 0xb), NodeId::new(0, 0, 0x1))));
        assert!(all_edges.contains(&(NodeId::new(0, 2, 0xb), NodeId::new(0, 1, 0x1))));
        assert!(all_edges.contains(&(NodeId::new(0, 2, 0xb), NodeId::new(0, 2, 0x1))));
        assert!(all_edges.contains(&(NodeId::new(0, 2, 0xb), NodeId::new(0, 3, 0x1))));
        assert!(all_edges.contains(&(NodeId::new(0, 3, 0xb), NodeId::new(0, 0, 0x1))));
        assert!(all_edges.contains(&(NodeId::new(0, 3, 0xb), NodeId::new(0, 1, 0x1))));
        assert!(all_edges.contains(&(NodeId::new(0, 3, 0xb), NodeId::new(0, 2, 0x1))));
        assert!(all_edges.contains(&(NodeId::new(0, 3, 0xb), NodeId::new(0, 3, 0x1))));
        assert_eq!(all_edges.len(), 38);
    }

    #[test]
    fn test_cfg_quit_loop() {
        let mut cfg = get_cfg_quit_loop();
        cfg.make_acyclic(None);
        println!("{:?}", Dot::with_config(&cfg.graph, &[]));
        let all_edges = Vec::from_iter(cfg.get_graph().all_edges().map(|e| (e.0, e.1)));
        println!("{:?}", all_edges);
        assert!(all_edges.contains(&(NodeId::new(0, 0, 0x0), NodeId::new(0, 0, 0x1))));
        assert!(all_edges.contains(&(NodeId::new(0, 0, 0x0), NodeId::new(0, 1, 0x1))));
        assert!(all_edges.contains(&(NodeId::new(0, 0, 0x0), NodeId::new(0, 2, 0x1))));
        assert!(all_edges.contains(&(NodeId::new(0, 0, 0x0), NodeId::new(0, 3, 0x1))));

        assert!(all_edges.contains(&(NodeId::new(0, 0, 0x1), NodeId::new(0, 0, 0x2))));
        assert!(all_edges.contains(&(NodeId::new(0, 0, 0x2), NodeId::new(0, 0, 0x3))));
        assert!(all_edges.contains(&(NodeId::new(0, 0, 0x3), NodeId::new(0, 0, 0x4))));
        assert!(all_edges.contains(&(NodeId::new(0, 0, 0x4), NodeId::new(0, 0, 0x5))));
        assert!(all_edges.contains(&(NodeId::new(0, 0, 0x5), NodeId::new(0, 0, 0x6))));
        assert!(all_edges.contains(&(NodeId::new(0, 1, 0x1), NodeId::new(0, 1, 0x2))));
        assert!(all_edges.contains(&(NodeId::new(0, 1, 0x2), NodeId::new(0, 1, 0x3))));
        assert!(all_edges.contains(&(NodeId::new(0, 1, 0x3), NodeId::new(0, 1, 0x4))));
        assert!(all_edges.contains(&(NodeId::new(0, 1, 0x4), NodeId::new(0, 1, 0x5))));
        assert!(all_edges.contains(&(NodeId::new(0, 1, 0x5), NodeId::new(0, 1, 0x6))));
        assert!(all_edges.contains(&(NodeId::new(0, 2, 0x1), NodeId::new(0, 2, 0x2))));
        assert!(all_edges.contains(&(NodeId::new(0, 2, 0x2), NodeId::new(0, 2, 0x3))));
        assert!(all_edges.contains(&(NodeId::new(0, 2, 0x3), NodeId::new(0, 2, 0x4))));
        assert!(all_edges.contains(&(NodeId::new(0, 2, 0x4), NodeId::new(0, 2, 0x5))));
        assert!(all_edges.contains(&(NodeId::new(0, 2, 0x5), NodeId::new(0, 2, 0x6))));
        assert!(all_edges.contains(&(NodeId::new(0, 3, 0x1), NodeId::new(0, 3, 0x2))));
        assert!(all_edges.contains(&(NodeId::new(0, 3, 0x2), NodeId::new(0, 3, 0x3))));
        assert!(all_edges.contains(&(NodeId::new(0, 3, 0x3), NodeId::new(0, 3, 0x4))));
        assert!(all_edges.contains(&(NodeId::new(0, 3, 0x4), NodeId::new(0, 3, 0x5))));
        assert!(all_edges.contains(&(NodeId::new(0, 3, 0x5), NodeId::new(0, 3, 0x6))));

        assert!(all_edges.contains(&(NodeId::new(0, 0, 0x6), NodeId::new(0, 1, 0x1))));
        assert!(all_edges.contains(&(NodeId::new(0, 1, 0x6), NodeId::new(0, 2, 0x1))));
        assert!(all_edges.contains(&(NodeId::new(0, 2, 0x6), NodeId::new(0, 3, 0x1))));

        assert!(all_edges.contains(&(NodeId::new(0, 0, 0x6), NodeId::new(0, 0, 0x7))));
        assert!(all_edges.contains(&(NodeId::new(0, 1, 0x6), NodeId::new(0, 0, 0x7))));
        assert!(all_edges.contains(&(NodeId::new(0, 2, 0x6), NodeId::new(0, 0, 0x7))));
        assert!(all_edges.contains(&(NodeId::new(0, 3, 0x6), NodeId::new(0, 0, 0x7))));

        assert!(all_edges.contains(&(NodeId::new(0, 0, 0x2), NodeId::new(0, 0, 0x7))));
        assert!(all_edges.contains(&(NodeId::new(0, 1, 0x2), NodeId::new(0, 0, 0x7))));
        assert!(all_edges.contains(&(NodeId::new(0, 2, 0x2), NodeId::new(0, 0, 0x7))));
        assert!(all_edges.contains(&(NodeId::new(0, 3, 0x2), NodeId::new(0, 0, 0x7))));

        assert!(all_edges.contains(&(NodeId::new(0, 0, 0x7), NodeId::new(0, 0, 0x8))));

        assert_eq!(all_edges.len(), 36);
    }

    #[test]
    fn test_icfg_call_targets_loop_to_loop() {
        let (mut icfg, _) = get_loop_to_loop_icfg();
        icfg.resolve_loops(4);
        assert_eq!(icfg.num_procedures(), 24);
        assert_eq!(icfg.get_graph().edge_count(), 38);
        let mut all_call_targets = Vec::<NodeId>::new();
        icfg.get_procedures().iter().for_each(|p| {
            p.1.write()
                .unwrap()
                .get_cfg_mut()
                .nodes_meta
                .for_each_ct_mut(|ct| all_call_targets.push(ct.clone()))
        });
        assert_eq!(all_call_targets.len(), 38);

        let ct_hashset = HashSet::<NodeId>::from_iter(all_call_targets);
        let ct_expected = HashSet::from_iter(
            [
                NodeId::new(1, 0, A_ADDR),
                NodeId::new(2, 0, A_ADDR),
                NodeId::new(3, 0, A_ADDR),
                NodeId::new(0, 0, B_ADDR), // Also called by all E clones.
                NodeId::new(1, 0, B_ADDR), // Also called by all E clones.
                NodeId::new(2, 0, B_ADDR), // Also called by all E clones.
                NodeId::new(3, 0, B_ADDR), // Also called by all E clones.
                NodeId::new(0, 0, C_ADDR),
                NodeId::new(1, 0, C_ADDR),
                NodeId::new(2, 0, C_ADDR),
                NodeId::new(3, 0, C_ADDR),
                NodeId::new(1, 0, D_ADDR),
                NodeId::new(2, 0, D_ADDR),
                NodeId::new(3, 0, D_ADDR),
                NodeId::new(0, 0, E_ADDR),
                NodeId::new(1, 0, E_ADDR),
                NodeId::new(2, 0, E_ADDR),
                NodeId::new(3, 0, E_ADDR),
                NodeId::new(0, 0, F_ADDR),
                NodeId::new(1, 0, F_ADDR),
                NodeId::new(2, 0, F_ADDR),
                NodeId::new(3, 0, F_ADDR),
            ]
            .to_vec()
            .into_iter(),
        );
        assert!(
            ct_hashset.intersection(&ct_expected).count() == ct_expected.len(),
            "Mistmatch in calltargets. {:?} != {:?}",
            ct_hashset,
            ct_expected
        );
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
    fn test_entry_loop_cfg() {
        // Check if after making a graph acyclic, where the entry node is part of a loop,
        // the entry is still the same.
        let wmap = &WeightMap::new();
        let mut cfg = get_entry_loop_cfg();
        cfg.make_acyclic(None);
        println!("{:?}", Dot::with_config(&cfg.graph, &[]));
        assert_weight(cfg.get_entry_weight_id(empty_proc_map!(), wmap), 4, wmap);
        assert_eq!(cfg.get_entry(), NodeId::new(0, 0, 0));
        assert_eq!(cfg.graph.edge_count(), 11);
        assert_eq!(cfg.graph.node_count(), 9);
        assert_eq!(cfg.nodes_meta.len(), 9);
    }

    #[test]
    fn test_endless_loop() {
        let wmap = &WeightMap::new();
        let mut cfg = get_endless_loop_cfg();
        cfg.make_acyclic(None);
        println!("{:?}", Dot::with_config(&cfg.graph, &[]));
        assert_weight(cfg.get_entry_weight_id(empty_proc_map!(), wmap), 4, wmap);
    }

    #[test]
    fn test_entry_0_graph() {
        let wmap = &WeightMap::new();
        let mut cfg = get_cfg_linear_call();
        cfg.make_acyclic(None);
        println!("{:?}", Dot::with_config(&cfg.graph, &[]));
        assert_weight(cfg.get_entry_weight_id(empty_proc_map!(), wmap), 1, wmap);
    }

    #[test]
    fn test_interconnected_sccs() {
        let (mut icfg, _wmap) = get_scc_refs_scc();
        icfg.resolve_loops(1);
        icfg.dot_graph_to_stdout();
    }
}
