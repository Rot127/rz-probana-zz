// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::ptr::{null, null_mut};

use crate::cfg::{CFGNodeData, InsnNodeData, InsnNodeType, CFG};
use crate::flow_graphs::{
    Address, FlowGraph, FlowGraphOperations, NodeId, SamplingBias, MAX_ADDRESS, UNDETERMINED_WEIGHT,
};
use crate::icfg::{Procedure, ICFG};
use binding::{
    log_rizn_style, log_rz, rz_analysis_function_is_malloc, rz_analysis_get_function_at,
    rz_cmd_status_t_RZ_CMD_STATUS_ERROR, rz_cmd_status_t_RZ_CMD_STATUS_OK, rz_core_graph_cfg,
    rz_core_graph_cfg_iwords, rz_core_graph_icfg, RzAnalysis, RzCmdStatus, RzCore, RzGraph,
    RzGraphNode, RzGraphNodeCFGSubType, RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_CALL,
    RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_COND,
    RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY,
    RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY_CALL,
    RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY_EXIT,
    RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY_RETURN,
    RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_EXIT,
    RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_NONE,
    RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_RETURN, RzGraphNodeInfo,
    RzGraphNodeInfoDataCFG, RzGraphNodeType, RzGraphNodeType_RZ_GRAPH_NODE_TYPE_CFG,
    RzGraphNodeType_RZ_GRAPH_NODE_TYPE_CFG_IWORD, RzGraphNodeType_RZ_GRAPH_NODE_TYPE_ICFG, RzList,
    RzListIter, RzPVector, LOG_DEBUG, LOG_WARN,
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

fn convert_rz_cfg_node_type(rz_node_type: RzGraphNodeCFGSubType) -> InsnNodeType {
    let type_without_cond = rz_node_type & !RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_COND;
    match type_without_cond {
        RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_NONE => InsnNodeType::Normal,
        RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY => InsnNodeType::Entry,
        RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_CALL => InsnNodeType::Call,
        RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY_CALL => InsnNodeType::Call,
        RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_RETURN => InsnNodeType::Return,
        RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY_RETURN => InsnNodeType::Return,
        RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_EXIT => InsnNodeType::Exit,
        RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY_EXIT => InsnNodeType::Return,
        _ => {
            panic!("RzGraphNodeSubType {} not handled.", rz_node_type)
        }
    }
}

fn get_insn_node_data(
    nid: NodeId,
    inode_type: InsnNodeType,
    data: &RzGraphNodeInfoDataCFG,
) -> InsnNodeData {
    let call_target = NodeId::new_original(data.call_address);
    let jump_target = NodeId::new_original(data.jump_address);
    let next = NodeId::new_original(data.next);
    let is_indirect_call = inode_type == InsnNodeType::Call && call_target.address == MAX_ADDRESS;
    InsnNodeData {
        addr: nid.address,
        weight: UNDETERMINED_WEIGHT,
        itype: inode_type,
        call_target,
        orig_jump_target: jump_target,
        orig_next: next,
        is_indirect_call,
    }
}

fn get_rz_node_info_nodeid(node_info: &RzGraphNodeInfo) -> NodeId {
    let rz_node_type: RzGraphNodeType = node_info.type_;
    let addr = match rz_node_type {
        RzGraphNodeType_RZ_GRAPH_NODE_TYPE_CFG => unsafe { node_info.__bindgen_anon_1.cfg.address },
        RzGraphNodeType_RZ_GRAPH_NODE_TYPE_CFG_IWORD => unsafe {
            node_info.__bindgen_anon_1.cfg_iword.address
        },
        _ => panic!("Unhandled type"),
    };
    NodeId::new_original(addr)
}

pub fn pvec_to_vec<T>(pvec: *mut RzPVector) -> Vec<*mut T> {
    let mut vec: Vec<*mut T> = Vec::new();
    let len = unsafe { (*pvec).v.len };
    if len <= 0 {
        return vec;
    }
    vec.reserve(len as usize);
    let data_arr: &mut [*mut T] =
        unsafe { std::slice::from_raw_parts_mut((*pvec).v.a as *mut *mut T, len as usize) };
    for i in 0..len {
        vec.push(data_arr[i]);
    }
    assert_eq!(len, vec.len().try_into().unwrap());
    vec
}

fn make_cfg_node(node_info: &RzGraphNodeInfo) -> CFGNodeData {
    let nid = get_rz_node_info_nodeid(node_info);
    let mut node_data: CFGNodeData = CFGNodeData {
        nid,
        weight: UNDETERMINED_WEIGHT,
        insns: Vec::new(),
    };
    let rz_node_type: RzGraphNodeType = node_info.type_;
    if rz_node_type == RzGraphNodeType_RZ_GRAPH_NODE_TYPE_CFG {
        let ntype = convert_rz_cfg_node_type(unsafe { node_info.__bindgen_anon_1.cfg.subtype });
        node_data.insns.push(get_insn_node_data(nid, ntype, unsafe {
            &node_info.__bindgen_anon_1.cfg
        }));
        return node_data;
    } else if rz_node_type == RzGraphNodeType_RZ_GRAPH_NODE_TYPE_CFG_IWORD {
        for idata in pvec_to_vec::<RzGraphNodeInfoDataCFG>(unsafe {
            node_info.__bindgen_anon_1.cfg_iword.insn
        }) {
            let ntype = convert_rz_cfg_node_type(unsafe { *idata }.subtype);
            node_data
                .insns
                .push(get_insn_node_data(nid, ntype, unsafe { &*idata }));
        }
        return node_data;
    }
    panic!("UNhandled node type");
}

fn set_cfg_node_data(cfg: &mut CFG, rz_cfg: *mut RzGraph) {
    let nodes: Vec<(*mut RzGraphNode, *mut RzGraphNodeInfo)> =
        graph_nodes_list_to_vec(unsafe { (*rz_cfg).nodes });
    for (_, node_info) in nodes {
        let s_node_info = if node_info.is_null() {
            panic!("node_info is NULL.")
        } else {
            unsafe { *node_info }
        };
        let nid = get_rz_node_info_nodeid(&s_node_info);
        cfg.add_node_data(nid, make_cfg_node(&s_node_info));
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
