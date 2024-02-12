// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use cty::c_void;

use crate::cfg::{CFGNodeData, CFGNodeType, CFG};
use crate::flow_graphs::{
    Address, FlowGraph, FlowGraphOperations, NodeId, SamplingBias, MAX_ADDRESS, UNDETERMINED_WEIGHT,
};
use crate::icfg::{Procedure, ICFG};
use probana::{
    rz_analysis_function_is_malloc, rz_analysis_get_function_at, rz_cmd_desc_argv_new,
    rz_cmd_status_t_RZ_CMD_STATUS_OK, rz_core_graph_cfg, rz_core_graph_icfg, RzAnalysis, RzCmdDesc,
    RzCmdDescHelp, RzCmdStatus, RzCore, RzCorePlugin, RzGraph, RzGraphNode, RzGraphNodeInfo,
    RzGraphNodeSubType, RzGraphNodeSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_CALL,
    RzGraphNodeSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY,
    RzGraphNodeSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_EXIT,
    RzGraphNodeSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_RETURN,
    RzGraphNodeSubType_RZ_GRAPH_NODE_SUBTYPE_NONE, RzGraphNodeType_RZ_GRAPH_NODE_TYPE_CFG,
    RzGraphNodeType_RZ_GRAPH_NODE_TYPE_ICFG, RzLibType, RzLibType_RZ_LIB_TYPE_CORE, RzList,
    RzListIter, RZ_VERSION,
};

// We redefine this struct and don't use the auto-generated one.
// Because the .data member is otherwise defined a mutable.
// This is a problem, because we can define the RzAnalysisPlugin struct only
// as const. And hence the assignment fails.
#[doc = " \\brief Represent the content of a plugin\n\n This structure should be pointed by the 'rizin_plugin' symbol found in the\n loaded library (e.g. .so file)."]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rz_lib_struct_t {
    #[doc = "< type of the plugin to load"]
    pub type_: RzLibType,
    #[doc = "< pointer to data handled by plugin handler (e.g. RzBinPlugin, RzAsmPlugin, etc.)"]
    pub data: *const ::std::os::raw::c_void,
    #[doc = "< rizin version this plugin was compiled for"]
    pub version: *const ::std::os::raw::c_char,
    pub free: ::std::option::Option<unsafe extern "C" fn(data: *mut ::std::os::raw::c_void)>,
}

fn graph_nodes_list_to_vec(list: *mut RzList) -> Vec<(*mut RzGraphNode, *mut RzGraphNodeInfo)> {
    let mut vec: Vec<(*mut RzGraphNode, *mut RzGraphNodeInfo)> = Vec::new();
    let len = unsafe { (*list).length };
    vec.reserve(len as usize);
    let mut iter: *mut RzListIter = unsafe { (*list).head };
    let mut elem: *mut RzGraphNode = unsafe { (*iter).elem as *mut RzGraphNode };
    let mut info: *mut RzGraphNodeInfo = unsafe { (*elem).data as *mut RzGraphNodeInfo };
    for _ in 0..len {
        vec.push((elem, info));
        iter = unsafe { (*iter).next };
        elem = unsafe { (*iter).elem as *mut RzGraphNode };
        info = unsafe { (*elem).data as *mut RzGraphNodeInfo };
    }
    vec
}

macro_rules! get_node_info_address {
    ( $node_info:ident ) => {
        unsafe {
            match (*$node_info).type_ {
                RzGraphNodeType_RZ_GRAPH_NODE_TYPE_CFG => {
                    (*$node_info).__bindgen_anon_1.cfg.address
                }
                RzGraphNodeType_RZ_GRAPH_NODE_TYPE_ICFG => {
                    (*$node_info).__bindgen_anon_1.icfg.address
                }
                _ => panic!("Node type {} not handled.", (*$node_info).type_),
            }
        }
    };
}

/// Converts a graph from RIzin to our internal FlowGraph representation.
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
        for (_, out_node_info) in out_nodes {
            let out_addr: Address = get_node_info_address!(out_node_info);
            graph.add_edge(
                NodeId::from(node_addr),
                NodeId::from(out_addr),
                SamplingBias::new_unset(),
            );
        }
        for (_, in_node_info) in in_nodes {
            let in_addr: Address = get_node_info_address!(in_node_info);
            graph.add_edge(
                NodeId::from(in_addr),
                NodeId::from(node_addr),
                SamplingBias::new_unset(),
            );
        }
    }
    graph
}

fn convert_rz_cfg_node_type(rz_node_type: RzGraphNodeSubType) -> CFGNodeType {
    match rz_node_type {
        RzGraphNodeSubType_RZ_GRAPH_NODE_SUBTYPE_NONE => CFGNodeType::Normal,
        RzGraphNodeSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY => CFGNodeType::Entry,
        RzGraphNodeSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_CALL => CFGNodeType::Call,
        RzGraphNodeSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_RETURN => CFGNodeType::Return,
        RzGraphNodeSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_EXIT => CFGNodeType::Exit,
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
        let is_indirect_call = ntype == CFGNodeType::Call && call_target.address == MAX_ADDRESS;
        cfg.add_node_data(
            nid,
            CFGNodeData {
                weight: UNDETERMINED_WEIGHT,
                ntype,
                call_target,
                is_indirect_call,
            },
        );
    }
}

#[allow(dead_code)]
pub extern "C" fn run_bda_analysis(a: *mut RzAnalysis) -> ::std::os::raw::c_int {
    // get iCFG
    let mut icfg = ICFG::new_graph(get_graph(unsafe {
        rz_core_graph_icfg((*a).core as *mut RzCore)
    }));
    // TODO: Consider moving both loops into a method of the iCFG.
    // So we can get rid of the copying the node IDs.
    let mut nodes: Vec<NodeId> = Vec::new();
    for n in icfg.get_graph().nodes().into_iter() {
        nodes.push(n);
    }
    for n in nodes {
        let rz_cfg = unsafe { rz_core_graph_cfg((*a).core as *mut RzCore, n.address) };
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

    // Return some dummy value
    1
}

pub extern "C" fn rz_analysis_bda_handler(
    core: *mut RzCore,
    _argc: i32,
    _argv: *mut *const i8,
) -> RzCmdStatus {
    run_bda_analysis(unsafe { (*core).analysis });
    return rz_cmd_status_t_RZ_CMD_STATUS_OK;
}

pub const analysis_bda_help: RzCmdDescHelp = RzCmdDescHelp {
    summary: "Run bda dependency analysis (algorithm: BDA)."
        .as_ptr()
        .cast(),
    description: "Detect memory dependencies via abstract interpretation over sampled paths."
        .as_ptr()
        .cast(),
    args_str: "".as_ptr().cast(),
    usage: "".as_ptr().cast(),
    options: "".as_ptr().cast(),
    sort_subcommands: false,
    details: "".as_ptr().cast(),
    details_cb: None,
    args: "".as_ptr().cast(),
};

pub extern "C" fn rz_bda_init_core(core: *mut RzCore) -> bool {
    unsafe {
        let probana_cd: *mut RzCmdDesc = ::probana::rz_binding::get_probana_cmd_desc(core);
        rz_cmd_desc_argv_new(
            (*core).rcmd,
            probana_cd,
            "aaaaPb".as_ptr().cast(),
            Some(rz_analysis_bda_handler),
            &analysis_bda_help,
        )
    };
    true
}

pub const rz_core_plugin_bda: RzCorePlugin = RzCorePlugin {
    name: "BDA".as_ptr().cast(),
    desc: "Dependency detection algorithm by Zhuo Zhang."
        .as_ptr()
        .cast(),
    license: "LGPL-3.0-only".as_ptr().cast(),
    author: "Rot127".as_ptr().cast(),
    version: "0.1".as_ptr().cast(),
    init: Some(rz_bda_init_core),
    fini: None,
    analysis: None,
};

pub type RzLibStruct = rz_lib_struct_t;
#[allow(dead_code)]
pub const rizin_plugin: RzLibStruct = RzLibStruct {
    type_: RzLibType_RZ_LIB_TYPE_CORE, // Until RzArch is introduced, we leave this as a core plugin, so we can add the command.
    data: &rz_core_plugin_bda as *const _ as *const c_void,
    version: RZ_VERSION.as_ptr().cast(),
    free: None,
};

// CMD handler

// RzCmdDesc *analyze_everything_cd = rz_cmd_desc_argv_new(core->rcmd, aa_cd, "aaa", rz_analyze_everything_handler, &analyze_everything_help);
// rz_warn_if_fail(analyze_everything_cd);
