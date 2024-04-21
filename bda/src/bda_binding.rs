// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::panic;
use std::ptr::{null, null_mut};

use crate::bda::run_bda;
use crate::cfg::{CFGNodeData, InsnNodeData, InsnNodeType, InsnNodeWeightType, CFG};
use crate::flow_graphs::{Address, FlowGraph, FlowGraphOperations, NodeId, MAX_ADDRESS};
use crate::icfg::{Procedure, ICFG};
use crate::weight::{Weight, UNDETERMINED_WEIGHT};
use binding::{
    log_rizn, log_rz, rz_analysis_function_is_malloc, rz_analysis_get_function_at,
    rz_bin_object_get_entries, rz_cmd_status_t_RZ_CMD_STATUS_ERROR,
    rz_cmd_status_t_RZ_CMD_STATUS_OK, rz_core_graph_cfg, rz_core_graph_cfg_iwords,
    rz_core_graph_icfg, rz_notify_error, RzAnalysis, RzBinAddr, RzBinFile, RzCmdStatus, RzCore,
    RzGraph, RzGraphNode, RzGraphNodeCFGSubType,
    RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_CALL,
    RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_COND,
    RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY,
    RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_EXIT,
    RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_NONE,
    RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_RETURN, RzGraphNodeInfo,
    RzGraphNodeInfoDataCFG, RzGraphNodeType, RzGraphNodeType_RZ_GRAPH_NODE_TYPE_CFG,
    RzGraphNodeType_RZ_GRAPH_NODE_TYPE_CFG_IWORD, RzGraphNodeType_RZ_GRAPH_NODE_TYPE_ICFG, RzList,
    RzListIter, RzPVector, LOG_DEBUG, LOG_ERROR, LOG_WARN,
};
use helper::progress::ProgressBar;

pub fn mpvec_to_vec<T>(pvec: *mut RzPVector) -> Vec<*mut T> {
    let mut vec: Vec<*mut T> = Vec::new();
    if pvec.is_null() {
        println!("PVector pointer is null.");
        return vec;
    }

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
    assert_eq!(len, vec.len());
    vec
}

pub fn cpvec_to_vec<T>(pvec: *const RzPVector) -> Vec<*mut T> {
    let mut vec: Vec<*mut T> = Vec::new();
    if pvec.is_null() {
        println!("PVector pointer is null.");
        return vec;
    }

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
    assert_eq!(len, vec.len());
    vec
}

pub fn list_to_vec<T>(
    list: *mut RzList,
    elem_conv: fn(*mut ::std::os::raw::c_void) -> T,
) -> Vec<T> {
    let mut vec: Vec<T> = Vec::new();
    if list.is_null() {
        println!("List pointer is null.");
        return vec;
    }
    let len = unsafe { (*list).length };
    vec.reserve(len as usize);
    let mut iter: *mut RzListIter = unsafe { (*list).head };
    if iter.is_null() {
        assert_eq!(len, vec.len() as u32);
        return vec;
    }
    loop {
        vec.push(elem_conv(unsafe { (*iter).elem }));
        if unsafe { *iter }.next == null_mut() {
            break;
        }
        iter = unsafe { (*iter).next };
    }
    assert_eq!(len, vec.len() as u32);
    vec
}

fn list_elem_to_graph_node_tuple(
    elem: *mut ::std::os::raw::c_void,
) -> (*mut RzGraphNode, *mut RzGraphNodeInfo) {
    (elem as *mut RzGraphNode, unsafe {
        (*(elem as *mut RzGraphNode)).data as *mut RzGraphNodeInfo
    })
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

pub fn get_bin_entries(rz_core: *mut RzCore) -> Vec<Address> {
    let binfiles: Vec<*mut RzBinFile> = unsafe {
        list_to_vec::<*mut RzBinFile>((*(*rz_core).bin).binfiles, |elem| elem as *mut RzBinFile)
    };
    let mut entries: Vec<Address> = Vec::new();
    unsafe {
        let entry_vectors = binfiles
            .into_iter()
            .map(|binfile| rz_bin_object_get_entries((*binfile).o));
        entry_vectors.into_iter().for_each(|entry_vec| {
            cpvec_to_vec::<RzBinAddr>(entry_vec)
                .into_iter()
                .for_each(|addr| entries.push((*addr).vaddr))
        });
    }
    entries
}

/// Converts a graph from Rizin to our internal FlowGraph representation.
fn get_graph(rz_graph: *mut RzGraph) -> FlowGraph {
    let nodes: Vec<(*mut RzGraphNode, *mut RzGraphNodeInfo)> =
        list_to_vec::<(*mut RzGraphNode, *mut RzGraphNodeInfo)>(
            unsafe { (*rz_graph).nodes },
            list_elem_to_graph_node_tuple,
        );
    let mut graph: FlowGraph = FlowGraph::new();
    for (node, node_info) in nodes {
        let out_nodes: Vec<(*mut RzGraphNode, *mut RzGraphNodeInfo)> =
            list_to_vec::<(*mut RzGraphNode, *mut RzGraphNodeInfo)>(
                unsafe { (*node).out_nodes },
                list_elem_to_graph_node_tuple,
            );
        let in_nodes: Vec<(*mut RzGraphNode, *mut RzGraphNodeInfo)> =
            list_to_vec::<(*mut RzGraphNode, *mut RzGraphNodeInfo)>(
                unsafe { (*node).in_nodes },
                list_elem_to_graph_node_tuple,
            );

        let node_addr: Address = get_node_info_address!(node_info);
        let num_neigh = in_nodes.len() + out_nodes.len();
        for (_, out_node_info) in out_nodes {
            let out_addr: Address = get_node_info_address!(out_node_info);
            graph.add_edge(NodeId::from(node_addr), NodeId::from(out_addr), 0);
            log_rz!(
                LOG_DEBUG,
                None,
                format!("Added edge {:#x} -> {:#x}", node_addr, out_addr)
            );
        }
        for (_, in_node_info) in in_nodes {
            let in_addr: Address = get_node_info_address!(in_node_info);
            graph.add_edge(NodeId::from(in_addr), NodeId::from(node_addr), 0);
            log_rz!(
                LOG_DEBUG,
                None,
                format!("Added edge {:#x} -> {:#x}", in_addr, node_addr)
            );
        }
        if num_neigh == 0 {
            graph.add_node(NodeId::from(node_addr));
            log_rz!(
                LOG_DEBUG,
                None,
                format!("Added single node: {:#x}", node_addr)
            );
        }
    }
    assert_eq!(graph.node_count(), unsafe { (*rz_graph).n_nodes } as usize);
    assert_eq!(graph.edge_count(), unsafe { (*rz_graph).n_edges } as usize);

    log_rz!(
        LOG_DEBUG,
        None,
        format!(
            "Parsed a graph with {} nodes and {} edges.",
            graph.node_count(),
            graph.edge_count(),
        )
    );
    graph
}

fn convert_rz_cfg_node_type(rz_node_type: RzGraphNodeCFGSubType) -> InsnNodeType {
    let is_entry: bool =
        (rz_node_type & RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY) != 0;
    let mut node_type = rz_node_type & !RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY;
    node_type = node_type & !RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_COND;
    if node_type == RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_NONE {
        return InsnNodeType::new(InsnNodeWeightType::Normal, is_entry);
    }
    if (node_type & RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_CALL) != 0 {
        return InsnNodeType::new(InsnNodeWeightType::Call, is_entry);
    }
    if (node_type & RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_RETURN) != 0 {
        return InsnNodeType::new(InsnNodeWeightType::Return, is_entry);
    }
    if (node_type & RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_EXIT) != 0 {
        return InsnNodeType::new(InsnNodeWeightType::Exit, is_entry);
    }
    panic!("RzGraphNodeSubType {} not handled.", rz_node_type);
}

fn get_insn_node_data(
    nid: NodeId,
    inode_type: InsnNodeType,
    data: &RzGraphNodeInfoDataCFG,
) -> InsnNodeData {
    let call_target = NodeId::new_original(data.call_address);
    let jump_target = NodeId::new_original(data.jump_address);
    let next = NodeId::new_original(data.next);
    let is_indirect_call =
        inode_type.weight_type == InsnNodeWeightType::Call && call_target.address == MAX_ADDRESS;
    InsnNodeData {
        addr: nid.address,
        weight: UNDETERMINED_WEIGHT!(),
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

fn make_cfg_node(node_info: &RzGraphNodeInfo) -> CFGNodeData {
    let nid = get_rz_node_info_nodeid(node_info);
    let mut node_data: CFGNodeData = CFGNodeData {
        nid,
        weight: UNDETERMINED_WEIGHT!(),
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
        for idata in mpvec_to_vec::<RzGraphNodeInfoDataCFG>(unsafe {
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
        list_to_vec::<(*mut RzGraphNode, *mut RzGraphNodeInfo)>(
            unsafe { (*rz_cfg).nodes },
            list_elem_to_graph_node_tuple,
        );
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

fn bin_entry_present(bin_entries: &Vec<Address>) -> bool {
    if bin_entries.len() == 0 {
        log_rz!(
            LOG_WARN,
            Some("BDA".to_string()),
            "Binary file has no entry point set. Set it in Rizin and run the analysis again."
                .to_string()
        );
        return false;
    }
    true
}

pub extern "C" fn run_bda_analysis(core: *mut RzCore, a: *mut RzAnalysis) {
    if !bin_entry_present(&get_bin_entries(core)) {
        rz_notify_error(core, "BDA analysis failed with an error".to_owned());
        return;
    }
    // get iCFG
    let rz_icfg = unsafe { rz_core_graph_icfg(core) };
    if rz_icfg.is_null() {
        log_rz!(
            LOG_ERROR,
            Some("BDA".to_string()),
            "No iCFG present.".to_string()
        );
        rz_notify_error(core, "BDA analysis failed with an error".to_owned());
        return;
    }
    let mut icfg = ICFG::new_graph(get_graph(rz_icfg));
    // TODO: Consider moving both loops into a method of the iCFG.
    // So we can get rid of the copying the node IDs.
    let mut nodes: Vec<NodeId> = Vec::new();
    for n in icfg.get_graph().nodes().into_iter() {
        nodes.push(n);
    }
    let mut progress_bar = ProgressBar::new(String::from("Transfer CFGs"), nodes.len());
    let mut done = 0;
    for n in nodes {
        let get_iword_cfg = unsafe { (*(*a).cur).decode_iword.is_some() };
        let rz_cfg = if get_iword_cfg {
            unsafe { rz_core_graph_cfg_iwords(core, n.address) }
        } else {
            unsafe { rz_core_graph_cfg(core, n.address) }
        };
        if rz_cfg.is_null() {
            panic!("A value for an CFG was NULL");
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
        set_cfg_node_data(icfg.get_procedure_mut(&n).get_cfg_mut(), rz_cfg);
        done += 1;
        progress_bar.update_print(done);
    }
    run_bda(core, &mut icfg);
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
            None,
            "core.analysis is null. Without it it cannot run the analysis.".to_string()
        );
        return rz_cmd_status_t_RZ_CMD_STATUS_ERROR;
    }
    let result = std::panic::catch_unwind(|| run_bda_analysis(core, unsafe { (*core).analysis }));
    if result.is_ok() {
        return rz_cmd_status_t_RZ_CMD_STATUS_OK;
    }
    unsafe {
        rz_core_notify_error_bind(core, "BDA analysis failed with an error\0".as_ptr().cast())
    };
    rz_cmd_status_t_RZ_CMD_STATUS_ERROR
}
