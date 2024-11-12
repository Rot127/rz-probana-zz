// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::ffi::CString;
use std::ptr::null;
use std::{panic, ptr};

use crate::bda::run_bda;
use crate::cfg::{CFGNodeData, InsnNodeData, InsnNodeType, Procedure, CFG};
use crate::flow_graphs::{Address, FlowGraph, FlowGraphOperations, NodeId, MAX_ADDRESS};
use crate::icfg::ICFG;
use crate::state::BDAState;

use binding::{
    cpvec_to_vec, list_to_vec, log_rizin, log_rz, mpvec_to_vec, pderef, rz_analysis_create_block,
    rz_analysis_create_function, rz_analysis_function_add_block, rz_analysis_function_is_input,
    rz_analysis_function_is_malloc, rz_analysis_get_block_at, rz_analysis_get_function_at,
    rz_bin_object_get_entries, rz_cmd_status_t_RZ_CMD_STATUS_ERROR, rz_core_graph_icfg, rz_core_t,
    rz_graph_free, rz_notify_error, str_to_c, GRzCore, RzAnalysisFcnType_RZ_ANALYSIS_FCN_TYPE_LOC,
    RzBinAddr, RzBinFile, RzCmdStatus, RzCore, RzCoreWrapper, RzGraph, RzGraphNode,
    RzGraphNodeCFGIWordSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_IWORD_COND,
    RzGraphNodeCFGIWordSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_IWORD_ENTRY,
    RzGraphNodeCFGIWordSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_IWORD_EXIT,
    RzGraphNodeCFGIWordSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_IWORD_NONE,
    RzGraphNodeCFGIWordSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_IWORD_RETURN,
    RzGraphNodeCFGIWordSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_IWORD_TAIL, RzGraphNodeCFGSubType,
    RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_COND,
    RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY,
    RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_EXIT,
    RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_NONE,
    RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_RETURN,
    RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_TAIL, RzGraphNodeInfo, RzGraphNodeInfoDataCFG,
    RzGraphNodeType, RzGraphNodeType_RZ_GRAPH_NODE_TYPE_CFG,
    RzGraphNodeType_RZ_GRAPH_NODE_TYPE_CFG_IWORD, RzGraphNodeType_RZ_GRAPH_NODE_TYPE_ICFG,
    LOG_DEBUG, LOG_ERROR, LOG_INFO, LOG_WARN,
};
use flexi_logger::{Duplicate, FileSpec, Logger};
use helper::progress::ProgressBar;
use helper::spinner::Spinner;

pub struct BDAPrivateData {
    _dummy_val: u64,
}

impl BDAPrivateData {
    pub fn new() -> BDAPrivateData {
        BDAPrivateData { _dummy_val: 0 }
    }
}

fn list_elem_to_graph_node_tuple(
    elem: *mut ::std::os::raw::c_void,
) -> (*mut RzGraphNode, *mut RzGraphNodeInfo) {
    (
        elem as *mut RzGraphNode,
        pderef!(elem as *mut RzGraphNode).data as *mut RzGraphNodeInfo,
    )
}

macro_rules! get_node_info_address {
    ( $node_info:ident ) => {
        unsafe {
            match pderef!($node_info).type_ {
                RzGraphNodeType_RZ_GRAPH_NODE_TYPE_CFG => {
                    pderef!($node_info).__bindgen_anon_1.cfg.address
                }
                RzGraphNodeType_RZ_GRAPH_NODE_TYPE_CFG_IWORD => {
                    pderef!($node_info).__bindgen_anon_1.cfg_iword.address
                }
                RzGraphNodeType_RZ_GRAPH_NODE_TYPE_ICFG => {
                    pderef!($node_info).__bindgen_anon_1.icfg.address
                }
                _ => panic!("Node type {} not handled.", pderef!($node_info).type_),
            }
        }
    };
}

pub fn get_bin_entries(rz_core: GRzCore) -> Vec<Address> {
    let binfiles: Vec<*mut RzBinFile> = unsafe {
        let core = rz_core.lock().unwrap();
        list_to_vec::<*mut RzBinFile>((*(pderef!(core.get_ptr())).bin).binfiles, |elem| {
            elem as *mut RzBinFile
        })
    };
    let mut entries: Vec<Address> = Vec::new();
    unsafe {
        let entry_vectors = binfiles
            .into_iter()
            .map(|binfile| rz_bin_object_get_entries(pderef!(binfile).o));
        entry_vectors.into_iter().for_each(|entry_vec| {
            cpvec_to_vec::<RzBinAddr>(entry_vec)
                .into_iter()
                .for_each(|addr| entries.push(pderef!(addr).vaddr))
        });
    }
    entries
}

/// Converts a graph from Rizin to our internal FlowGraph representation.
pub fn get_graph(rz_graph: *mut RzGraph) -> FlowGraph {
    let nodes: Vec<(*mut RzGraphNode, *mut RzGraphNodeInfo)> =
        list_to_vec::<(*mut RzGraphNode, *mut RzGraphNodeInfo)>(
            pderef!(rz_graph).nodes,
            list_elem_to_graph_node_tuple,
        );
    let mut graph: FlowGraph = FlowGraph::new();
    for (node, node_info) in nodes {
        let out_nodes: Vec<(*mut RzGraphNode, *mut RzGraphNodeInfo)> =
            list_to_vec::<(*mut RzGraphNode, *mut RzGraphNodeInfo)>(
                pderef!(node).out_nodes,
                list_elem_to_graph_node_tuple,
            );
        let in_nodes: Vec<(*mut RzGraphNode, *mut RzGraphNodeInfo)> =
            list_to_vec::<(*mut RzGraphNode, *mut RzGraphNodeInfo)>(
                pderef!(node).in_nodes,
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
    assert_eq!(graph.node_count(), pderef!(rz_graph).n_nodes as usize);
    assert_eq!(graph.edge_count(), pderef!(rz_graph).n_edges as usize);

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
    InsnNodeType::from_bits(rz_node_type).expect("Unknown bits were set.")
}

fn get_insn_node_data(
    nid: NodeId,
    inode_type: InsnNodeType,
    data: &RzGraphNodeInfoDataCFG,
) -> InsnNodeData {
    let call_target = NodeId::new_original(data.call_address);
    let jump_target = NodeId::new_original(data.jump_address);
    let next = NodeId::new_original(data.next);
    let is_indirect_call = inode_type.is_call() && call_target.address == MAX_ADDRESS;
    InsnNodeData::new(
        nid.address,
        inode_type,
        call_target,
        jump_target,
        next,
        is_indirect_call,
    )
}

fn test_enum_sync_assumption() {
    #[cfg_attr(rustfmt, rustfmt_skip)]
    {
    debug_assert_eq!(RzGraphNodeCFGIWordSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_IWORD_NONE, RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_NONE, "Enums out of sync");
    debug_assert_eq!(RzGraphNodeCFGIWordSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_IWORD_ENTRY, RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_ENTRY, "Enums out of sync");
    debug_assert_eq!(RzGraphNodeCFGIWordSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_IWORD_RETURN, RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_RETURN, "Enums out of sync");
    debug_assert_eq!(RzGraphNodeCFGIWordSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_IWORD_EXIT, RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_EXIT, "Enums out of sync");
    debug_assert_eq!(RzGraphNodeCFGIWordSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_IWORD_COND, RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_COND, "Enums out of sync");
    debug_assert_eq!(RzGraphNodeCFGIWordSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_IWORD_TAIL, RzGraphNodeCFGSubType_RZ_GRAPH_NODE_SUBTYPE_CFG_TAIL, "Enums out of sync");
    }
}

fn get_rz_node_info_nodeid(node_info: &RzGraphNodeInfo) -> NodeId {
    test_enum_sync_assumption();
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
    let mut node_data = CFGNodeData::new(nid);
    let rz_node_type: RzGraphNodeType = node_info.type_;
    if rz_node_type == RzGraphNodeType_RZ_GRAPH_NODE_TYPE_CFG {
        let ntype = convert_rz_cfg_node_type(unsafe { node_info.__bindgen_anon_1.cfg.subtype });
        if ntype.is_entry() {
            node_data.node_type |= InsnNodeType::Entry;
        }
        if ntype.is_tail() {
            node_data.node_type |= InsnNodeType::Tail;
        }
        if ntype.is_exit() {
            node_data.node_type |= InsnNodeType::Exit;
        }
        if ntype.is_return() {
            node_data.node_type |= InsnNodeType::Return;
        }
        if ntype.is_cond() {
            node_data.node_type |= InsnNodeType::Cond;
        }
        node_data.insns.push(get_insn_node_data(nid, ntype, unsafe {
            &node_info.__bindgen_anon_1.cfg
        }));
        return node_data;
    } else if rz_node_type == RzGraphNodeType_RZ_GRAPH_NODE_TYPE_CFG_IWORD {
        node_data.node_type =
            convert_rz_cfg_node_type(unsafe { node_info.__bindgen_anon_1.cfg_iword.subtype });
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
            pderef!(rz_cfg).nodes,
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

fn guarded_rz_core_graph_icfg(core: GRzCore) -> *mut RzGraph {
    let c = core.lock().unwrap();
    unsafe { rz_core_graph_icfg(c.get_ptr()) }
}

/// Sets up a procedure by pulling all relevant data
/// from Rizin and initializing the Procedure struct.
pub fn setup_procedure_at_addr(core: &RzCoreWrapper, address: Address) -> Option<Procedure> {
    unsafe {
        let mut is_unmapped = false;
        let mut fcn_ptr = rz_analysis_get_function_at(core.get_analysis(), address);
        if fcn_ptr == ptr::null_mut() {
            log_rz!(
                LOG_DEBUG,
                Some("BDA"),
                format!(
                    "Attempt to make a invalid procedure at: {:#x}. Symbol not defined in Rizin.",
                    address
                )
            );
            let name;
            if let Some(fname) = core.get_flag_name_at(address) {
                name = fname;
            } else {
                name = format!("unmapped_{}", address);
            }

            fcn_ptr = rz_analysis_create_function(
                core.get_analysis(),
                str_to_c!(name.clone()),
                address,
                RzAnalysisFcnType_RZ_ANALYSIS_FCN_TYPE_LOC,
            );
            is_unmapped = true;
            let mut block_ptr = rz_analysis_create_block(core.get_analysis(), address, 1);
            if block_ptr == std::ptr::null_mut() {
                is_unmapped = false;
                block_ptr = rz_analysis_get_block_at(core.get_analysis(), address);
                assert_ne!(
                    block_ptr,
                    std::ptr::null_mut(),
                    "Function block at {:#x} is miss aligned.",
                    address
                )
            }
            rz_analysis_function_add_block(fcn_ptr, block_ptr);
            log_rz!(
                LOG_INFO,
                Some("BDA"),
                format!("Added new function {}", name)
            );
        }
        let rz_cfg = core.get_rz_cfg(address);
        if rz_cfg == std::ptr::null_mut() {
            log_rz!(LOG_WARN, Some("BDA"), "A value for an CFG was NULL");
            return None;
        }
        let mut cfg = CFG::new_graph(get_graph(rz_cfg));
        set_cfg_node_data(&mut cfg, rz_cfg);
        let proc = Procedure::new(
            Some(cfg),
            rz_analysis_function_is_malloc(fcn_ptr),
            rz_analysis_function_is_input(fcn_ptr),
            is_unmapped,
        );
        rz_graph_free(rz_cfg);
        return Some(proc);
    }
}

pub extern "C" fn run_bda_analysis(rz_core: *mut rz_core_t) {
    Logger::try_with_str("info")
        .expect("Logger init failed")
        .log_to_file(FileSpec::default())
        .duplicate_to_stderr(Duplicate::Warn)
        .start()
        .expect("Logger start failed");
    let core: GRzCore = RzCoreWrapper::new(rz_core);
    let rz_icfg = guarded_rz_core_graph_icfg(core.clone());
    if rz_icfg.is_null() {
        log_rz!(LOG_ERROR, Some("BDA"), "No iCFG present.".to_string());
        rz_notify_error(core, "BDA analysis failed with an error".to_owned());
        return;
    }
    let mut icfg = ICFG::new_graph(get_graph(rz_icfg));
    unsafe {
        rz_graph_free(rz_icfg);
    }
    let nthreads = core
        .lock()
        .unwrap()
        .get_bda_threads()
        .expect("Should been set before.");
    let runtime = core
        .lock()
        .unwrap()
        .get_bda_sampling_runtime()
        .expect("Should have been checked before.");
    let icfg_enforce_update_timeout: u64 = core
        .lock()
        .unwrap()
        .get_bda_icfg_enforce_update_timeout()
        .expect("Should been set before.");
    let unknown_code_xrefs_theshold = core
        .lock()
        .unwrap()
        .get_bda_unknown_code_xrefs_theshold()
        .expect("Should have been checked before.");
    let mut state = BDAState::new(
        nthreads,
        runtime,
        icfg_enforce_update_timeout,
        unknown_code_xrefs_theshold,
    );
    add_procedures_to_icfg(core.clone(), &mut icfg);
    icfg.make_icfg_consistent();
    debug_assert!(icfg.icfg_consistency_check());
    run_bda(core, &mut icfg, &mut state);
}

pub fn add_procedures_to_icfg(core: GRzCore, icfg: &mut ICFG) {
    let dup_cnt = core.lock().unwrap().get_bda_node_duplicates();
    icfg.set_node_dup_count(dup_cnt);

    let mut progress_bar = ProgressBar::new(
        String::from("Transfer CFGs"),
        icfg.get_graph().nodes().len(),
    );
    let mut nodes: Vec<NodeId> = Vec::new();
    for n in icfg.get_graph().nodes().into_iter() {
        nodes.push(n);
    }
    let mut done = 0;
    for n in nodes {
        if let Some(proc) = setup_procedure_at_addr(&core.lock().unwrap(), n.address) {
            icfg.add_procedure(n, proc);
        } else {
            log_rz!(
                LOG_WARN,
                Some("BDA"),
                format!("Did not add CFG located at {:#x}", n.address)
            )
        }
        done += 1;
        progress_bar.update_print(done, None);
    }
    add_called_procedures(icfg, core.clone());
}

fn add_called_procedures(icfg: &mut ICFG, core: GRzCore) {
    // Iterate over all call xrefs and ensure they are added as procedures.
    let mut undisc_procs = Vec::<NodeId>::new();
    let mut undisc_edges = Vec::<(NodeId, NodeId)>::new();
    for (pid, p) in icfg.get_procedures().iter() {
        for ct in p.read().unwrap().get_cfg().nodes_meta.ct_iter() {
            let pair = (pid.clone(), *ct);
            if !icfg.has_procedure(&ct) {
                undisc_procs.push(*ct);
            }
            if !icfg.has_edge(pair.0, pair.1) {
                undisc_edges.push(pair);
            }
        }
    }
    let mut status = Spinner::new("Follow call refernces:\t".to_owned());
    let mut new_procs = 0;
    let mut new_edges = undisc_edges.len();

    // Drain them, for the edge case that we have no procedures.
    undisc_edges.drain(0..).for_each(|(from, to)| {
        icfg.get_graph_mut().add_edge(from, to, 0);
    });

    while !undisc_procs.is_empty() {
        let call_target = undisc_procs.pop().unwrap().clone();
        if let Some(called_proc) =
            setup_procedure_at_addr(&core.lock().unwrap(), call_target.address)
        {
            // Get the calls of the undiscovered procedure.
            for cp_ct in called_proc.get_cfg().nodes_meta.ct_iter() {
                if !icfg.has_procedure(cp_ct) {
                    undisc_procs.push(*cp_ct);
                }
                if !icfg.has_edge(call_target, *cp_ct) {
                    undisc_edges.push((call_target, *cp_ct));
                }
            }
            if icfg.add_procedure(call_target, called_proc) {
                new_procs += 1;
            }
            new_edges += undisc_edges.len();
            undisc_edges.drain(0..).for_each(|(from, to)| {
                new_edges += 1;
                icfg.get_graph_mut().add_edge(from, to, 0);
            });
            status.update(Some(format!(
                "New call edges: {} -- New functions: {}",
                new_edges, new_procs
            )));
            continue;
        }
        panic!(
            "A valid call target to {} could be initialized as procedure.",
            call_target
        );
    }
    status.done(format!(
        "New call edges: {} -- New functions: {}",
        new_edges, new_procs
    ));
}

pub extern "C" fn rz_analysis_bda_handler(
    core: *mut RzCore,
    _argc: i32,
    _argv: *mut *const i8,
) -> RzCmdStatus {
    if pderef!(core).analysis.cast_const() == null() {
        log_rz!(
            LOG_WARN,
            None,
            "core.analysis is null. Without it it cannot run the analysis.".to_string()
        );
        return rz_cmd_status_t_RZ_CMD_STATUS_ERROR;
    }
    run_bda_analysis(core);
    rz_cmd_status_t_RZ_CMD_STATUS_ERROR
}
