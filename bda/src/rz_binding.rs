// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::ptr::{null, null_mut};

use binding::{
    log_rizn_style, log_rz, rz_core_graph_cfg_iwords, RzCmdStatus,
    RzGraphNodeSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_COND, LOG_DEBUG, LOG_WARN,
};

use crate::cfg::{CFGNodeData, InsnNodeType, CFG};
use crate::flow_graphs::{
    Address, FlowGraph, FlowGraphOperations, NodeId, SamplingBias, MAX_ADDRESS, UNDETERMINED_WEIGHT,
};
use crate::icfg::{Procedure, ICFG};
use binding::{
    rz_analysis_function_is_malloc, rz_analysis_get_function_at,
    rz_cmd_status_t_RZ_CMD_STATUS_ERROR, rz_cmd_status_t_RZ_CMD_STATUS_OK, rz_core_graph_cfg,
    rz_core_graph_icfg, RzAnalysis, RzCore, RzGraph, RzGraphNode, RzGraphNodeInfo,
    RzGraphNodeSubType, RzGraphNodeSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_CALL,
    RzGraphNodeSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY,
    RzGraphNodeSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY_CALL,
    RzGraphNodeSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY_EXIT,
    RzGraphNodeSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY_RETURN,
    RzGraphNodeSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_EXIT,
    RzGraphNodeSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_RETURN,
    RzGraphNodeSubType_RZ_GRAPH_NODE_SUBTYPE_NONE, RzGraphNodeType_RZ_GRAPH_NODE_TYPE_CFG,
    RzGraphNodeType_RZ_GRAPH_NODE_TYPE_CFG_IWORD, RzGraphNodeType_RZ_GRAPH_NODE_TYPE_ICFG, RzList,
    RzListIter,
};

fn graph_nodes_list_to_vec(list: *mut RzList) -> Vec<(*mut RzGraphNode, *mut RzGraphNodeInfo)> {
    let mut vec: Vec<(*mut RzGraphNode, *mut RzGraphNodeInfo)> = Vec::new();
    let len = unsafe { (*list).length };
    vec.reserve(len as usize);
    let mut iter: *mut RzListIter = unsafe { (*list).head };
    if iter.is_null() {
        assert_eq!(len, vec.len().try_into().unwrap());
        return vec;
    }
    loop {
        let elem: *mut RzGraphNode = unsafe { (*iter).elem as *mut RzGraphNode };
        let info: *mut RzGraphNodeInfo = unsafe { (*elem).data as *mut RzGraphNodeInfo };
        vec.push((elem, info));
        if unsafe { *iter }.next == null_mut() {
            break;
        }
        iter = unsafe { (*iter).next };
    }
    assert_eq!(len, vec.len().try_into().unwrap());
    vec
}

macro_rules! get_node_info_address {
    ( $node_info:ident ) => {
        unsafe {
            match (*$node_info).type_ {
                RzGraphNodeType_RZ_GRAPH_NODE_TYPE_CFG => {
                    (*$node_info).__bindgen_anon_1.cfg.address
                }
                RzGraphNodeType_RZ_GRAPH_NODE_TYPE_CFG_IWORD => {
                    (*$node_info).__bindgen_anon_1.cfg_iword.address
                }
                RzGraphNodeType_RZ_GRAPH_NODE_TYPE_ICFG => {
                    (*$node_info).__bindgen_anon_1.icfg.address
                }
                _ => panic!("Node type {} not handled.", (*$node_info).type_),
            }
        }
    };
}

/// Converts a graph from Rizin to our internal FlowGraph representation.
fn get_graph(rz_graph: *mut RzGraph) -> FlowGraph {
    let nodes: Vec<(*mut RzGraphNode, *mut RzGraphNodeInfo)> =
        graph_nodes_list_to_vec(unsafe { (*rz_graph).nodes });
    let mut graph: FlowGraph = FlowGraph::new();
    for (node, node_info) in nodes {
        let out_nodes: Vec<(*mut RzGraphNode, *mut RzGraphNodeInfo)> =
            graph_nodes_list_to_vec(unsafe { (*node).out_nodes });
        let in_nodes: Vec<(*mut RzGraphNode, *mut RzGraphNodeInfo)> =
            graph_nodes_list_to_vec(unsafe { (*node).in_nodes });
        let node_addr: Address = get_node_info_address!(node_info);
        let num_neigh = in_nodes.len() + out_nodes.len();
        for (_, out_node_info) in out_nodes {
            let out_addr: Address = get_node_info_address!(out_node_info);
            graph.add_edge(
                NodeId::from(node_addr),
                NodeId::from(out_addr),
                SamplingBias::new_unset(),
            );
            log_rz!(
                LOG_DEBUG,
                format!("Added edge {:#x} -> {:#x}", node_addr, out_addr)
            );
        }
        for (_, in_node_info) in in_nodes {
            let in_addr: Address = get_node_info_address!(in_node_info);
            graph.add_edge(
                NodeId::from(in_addr),
                NodeId::from(node_addr),
                SamplingBias::new_unset(),
            );
            log_rz!(
                LOG_DEBUG,
                format!("Added edge {:#x} -> {:#x}", in_addr, node_addr)
            );
        }
        if num_neigh == 0 {
            graph.add_node(NodeId::from(node_addr));
            log_rz!(LOG_DEBUG, format!("Added single node: {:#x}", node_addr));
        }
    }
    assert_eq!(graph.node_count(), unsafe { (*rz_graph).n_nodes } as usize);
    assert_eq!(graph.edge_count(), unsafe { (*rz_graph).n_edges } as usize);

    log_rz!(
        LOG_DEBUG,
        format!(
            "Parsed a graph with {} nodes and {} edges.",
            graph.node_count(),
            graph.edge_count(),
        )
    );
    graph
}

fn convert_rz_cfg_node_type(rz_node_type: RzGraphNodeSubType) -> InsnNodeType {
    let type_without_cond = rz_node_type & !RzGraphNodeSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_COND;
    match type_without_cond {
        RzGraphNodeSubType_RZ_GRAPH_NODE_SUBTYPE_NONE => InsnNodeType::Normal,
        RzGraphNodeSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY => InsnNodeType::Entry,
        RzGraphNodeSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_CALL => InsnNodeType::Call,
        RzGraphNodeSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY_CALL => InsnNodeType::Call,
        RzGraphNodeSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_RETURN => InsnNodeType::Return,
        RzGraphNodeSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY_RETURN => InsnNodeType::Return,
        RzGraphNodeSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_EXIT => InsnNodeType::Exit,
        RzGraphNodeSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY_EXIT => InsnNodeType::Return,
        _ => {
            panic!("RzGraphNodeSubType {} not handled.", rz_node_type)
        }
    }
}

fn set_cfg_node_data(cfg: &mut CFG, rz_cfg: *mut RzGraph) {
    let nodes: Vec<(*mut RzGraphNode, *mut RzGraphNodeInfo)> =
        graph_nodes_list_to_vec(unsafe { (*rz_cfg).nodes });
    for (_, node_info) in nodes {
        assert!(unsafe { (*node_info).type_ == RzGraphNodeType_RZ_GRAPH_NODE_TYPE_CFG });
        let nid = NodeId::new_original(unsafe { (*node_info).__bindgen_anon_1.cfg.address });
        let ntype = convert_rz_cfg_node_type(unsafe { (*node_info).subtype });
        let call_target =
            NodeId::new_original(unsafe { (*node_info).__bindgen_anon_1.cfg.call_address });
        let is_indirect_call = ntype == InsnNodeType::Call && call_target.address == MAX_ADDRESS;
        cfg.add_node_data(
            nid,
            CFGNodeData {
                addr: nid.address,
                weight: UNDETERMINED_WEIGHT,
                ntype,
                call_target,
                is_indirect_call,
            },
        );
    }
}

pub extern "C" fn run_bda_analysis(a: *mut RzAnalysis) {
    // get iCFG
    let rz_icfg = unsafe { rz_core_graph_icfg((*a).core as *mut RzCore) };
    if rz_icfg.is_null() {
        return;
    }
    let mut icfg = ICFG::new_graph(get_graph(rz_icfg));
    // TODO: Consider moving both loops into a method of the iCFG.
    // So we can get rid of the copying the node IDs.
    let mut nodes: Vec<NodeId> = Vec::new();
    for n in icfg.get_graph().nodes().into_iter() {
        nodes.push(n);
    }
    for n in nodes {
        let get_iword_cfg = unsafe { (*(*a).cur).decode_iword.is_some() };
        let rz_cfg = if get_iword_cfg {
            unsafe { rz_core_graph_cfg_iwords((*a).core as *mut RzCore, n.address) }
        } else {
            unsafe { rz_core_graph_cfg((*a).core as *mut RzCore, n.address) }
        };
        if rz_cfg.is_null() {
            return;
        }
        icfg.add_procedure(
            n,
            Procedure::new(Some(CFG::new_graph(get_graph(rz_cfg))), unsafe {
                rz_analysis_function_is_malloc(rz_analysis_get_function_at(
                    a as *mut RzAnalysis,
                    n.address,
                ))
            }),
        );
        set_cfg_node_data(icfg.get_procedure_mut(n).get_cfg_mut(), rz_cfg);
    }
    // Run analysis
}

pub extern "C" fn rz_analysis_bda_handler(
    core: *mut RzCore,
    _argc: i32,
    _argv: *mut *const i8,
) -> RzCmdStatus {
    if unsafe { (*core).analysis.cast_const() == null() } {
        log_rz!(
            LOG_WARN,
            "core.analysis is null. Without it it cannot run the analysis.".to_string()
        );
        return rz_cmd_status_t_RZ_CMD_STATUS_ERROR;
    }
    run_bda_analysis(unsafe { (*core).analysis });
    return rz_cmd_status_t_RZ_CMD_STATUS_OK;
}
