// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use cty::c_void;

use crate::flow_graphs::{Address, FlowGraph, NodeId, SamplingBias, UNDETERMINED_WEIGHT};
use crate::{
    rz_core_graph_icfg, RzAnalysis, RzAnalysisOp, RzAnalysisOpMask, RzAnalysisPlugin, RzCore,
    RzGraph, RzGraphNode, RzGraphNodeInfo, RzGraphNodeType_RZ_GRAPH_NODE_TYPE_CFG,
    RzGraphNodeType_RZ_GRAPH_NODE_TYPE_ICFG, RzLibType, RzLibType_RZ_LIB_TYPE_ANALYSIS, RzList,
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

pub type RzLibStruct = rz_lib_struct_t;

pub const rz_analysis_plugin_probana: RzAnalysisPlugin = RzAnalysisPlugin {
    name: "rz_probana".as_ptr().cast(),
    desc: "Probabilistic Binary Analysis Algorithms".as_ptr().cast(),
    license: "LGPL-3.0-only".as_ptr().cast(),
    arch: "".as_ptr().cast(),
    author: "Rot127".as_ptr().cast(),
    version: "0.1".as_ptr().cast(),
    bits: 0,
    esil: 0,
    fileformat_type: 0,
    init: Some(rz_probana_init),
    fini: None,
    archinfo: None,
    analysis_mask: None,
    preludes: None,
    address_bits: None,
    op: None,
    get_reg_profile: None,
    esil_init: None,
    esil_post_loop: None,
    esil_trap: None,
    esil_fini: None,
    il_config: None,
};

pub const rizin_plugin: RzLibStruct = RzLibStruct {
    type_: RzLibType_RZ_LIB_TYPE_ANALYSIS,
    data: &rz_analysis_plugin_probana as *const _ as *const c_void,
    version: RZ_VERSION.as_ptr().cast(),
    free: None,
};

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

macro_rules! get_node_address {
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
        let node_addr: Address = get_node_address!(node_info);
        for (_, out_node_info) in out_nodes {
            let out_addr: Address = get_node_address!(out_node_info);
            graph.add_edge(
                NodeId::from(node_addr),
                NodeId::from(out_addr),
                SamplingBias::new_unset(),
            );
        }
        for (_, in_node_info) in in_nodes {
            let in_addr: Address = get_node_address!(in_node_info);
            graph.add_edge(
                NodeId::from(in_addr),
                NodeId::from(node_addr),
                SamplingBias::new_unset(),
            );
        }
    }
    graph
}

pub extern "C" fn run_probability_analysis(
    a: *mut RzAnalysis,
    op: *mut RzAnalysisOp,
    addr: ::std::os::raw::c_ulonglong,
    data: *const ::std::os::raw::c_uchar,
    len: ::std::os::raw::c_int,
    mask: RzAnalysisOpMask,
) -> ::std::os::raw::c_int {
    // get iCFG
    let icfg = get_graph(unsafe { rz_core_graph_icfg((*a).core as *mut RzCore) });
    let cfg = get_graph(unsafe { rz_core_graph_cfg((*a).core as *mut RzCore) });
    // Run analysis

    // Return some dummy value
    1
}

pub extern "C" fn rz_probana_init(_user: *mut *mut c_void) -> bool {
    true
}
