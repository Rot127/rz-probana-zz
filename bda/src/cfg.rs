// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use core::panic;
use std::collections::{HashMap, HashSet};

use binding::{log_rizn_style, log_rz, LOG_DEBUG};
use petgraph::{algo::toposort, Direction::Outgoing};

use crate::flow_graphs::{
    Address, FlowGraph, FlowGraphOperations, NodeId, SamplingBias, Weight, INVALID_NODE_ID,
    INVALID_WEIGHT, UNDETERMINED_WEIGHT,
};

/// The type of a node which determines the weight calculation of it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum InsnNodeWeightType {
    /// A node without any special meaning in the graph.
    /// It's weight is:
    ///
    ///   foreach s in addr.successors:
    ///     W\[iaddr\] = W\[iaddr\] + W\[s\]
    ///
    Normal,
    /// A node which calls a procedure.
    /// Its weight is defined as:
    ///
    ///   W\[iaddr\] = W\[ret_addr\] × W\[callee\]
    ///
    Call,
    /// A return node. This is always a leaf and always has
    ///
    ///   W\[iaddr\] = 1
    ///
    Return,
    /// A node which exits the procedure without return.
    /// Its weight is defined by:
    ///
    ///   W\[iaddr\] = 1
    ///
    Exit,
}

/// The node type of a instruction.
#[derive(Clone, Debug, PartialEq)]
pub struct InsnNodeType {
    pub is_entry: bool,
    pub weight_type: InsnNodeWeightType,
}

impl InsnNodeType {
    pub fn new(weight_type: InsnNodeWeightType, is_entry: bool) -> InsnNodeType {
        InsnNodeType {
            is_entry,
            weight_type,
        }
    }
}

/// An instruction node which is always part of an
/// instruction word node.
#[derive(Clone, Debug, PartialEq)]
pub struct InsnNodeData {
    /// The memory address the instruction is located.
    pub addr: Address,
    /// The weight of the instruction.
    pub weight: Weight,
    /// Instruction type. Determines weight calculation.
    pub itype: InsnNodeType,
    /// Node this instruction calls. The NodeId points to another CFG.
    /// It can point to a cloned NodeId.
    pub call_target: NodeId,
    /// Node this instruction jumps to.
    /// It always points to the original NodeId. It is not updated if a cloned edge is added.
    pub orig_jump_target: NodeId,
    /// Follwing instruction address.
    /// It always points to the original NodeId. It is not updated if a cloned edge is added.
    pub orig_next: NodeId,
    /// Flag if this instruction is an indirect call.
    pub is_indirect_call: bool,
}

impl InsnNodeData {
    pub fn new_call(
        addr: Address,
        call_target: NodeId,
        is_indirect_call: bool,
        jump_target: NodeId,
        next: NodeId,
    ) -> InsnNodeData {
        InsnNodeData {
            addr,
            weight: UNDETERMINED_WEIGHT,
            itype: InsnNodeType::new(InsnNodeWeightType::Call, false),
            call_target,
            orig_jump_target: jump_target,
            orig_next: next,
            is_indirect_call,
        }
    }

    /// Calculate the weight of the instruction node from the successor node weights.
    pub fn calc_weight(
        &mut self,
        iword_succ_weights: &HashMap<NodeId, Weight>,
        call_target_weights: &HashMap<NodeId, Weight>,
    ) -> Weight {
        let mut sum_succ_weights = 0;
        for (target_id, target_weight) in iword_succ_weights.iter() {
            if *target_id == self.call_target
                || self.orig_jump_target.get_orig_node_id() == target_id.get_orig_node_id()
                || self.orig_next.get_orig_node_id() == target_id.get_orig_node_id()
            {
                sum_succ_weights += *target_weight;
            }
        }
        self.weight = match self.itype.weight_type {
            InsnNodeWeightType::Return => 1,
            InsnNodeWeightType::Exit => 1,
            InsnNodeWeightType::Normal => sum_succ_weights,
            InsnNodeWeightType::Call => {
                sum_succ_weights
                    * match call_target_weights.get(&self.call_target) {
                        Some(w) => *w,
                        None => 1,
                    }
            }
        };
        self.weight
    }
}

/// A CFG node. This is equivalent to an instruction word.
/// For most architectures this instruction word
/// contains one instruction.
/// For a few (e.g. Hexagon) it can contain more.
#[derive(Clone, Debug, PartialEq)]
pub struct CFGNodeData {
    pub nid: NodeId,
    pub weight: Weight,
    pub insns: Vec<InsnNodeData>,
}

impl CFGNodeData {
    /// Initialize an CFG node with a single instruction.
    pub fn new_test_single(
        addr: Address,
        ntype: InsnNodeType,
        jump_target: NodeId,
        next: NodeId,
    ) -> CFGNodeData {
        let mut node = CFGNodeData {
            nid: NodeId::from(addr),
            weight: UNDETERMINED_WEIGHT,
            insns: Vec::new(),
        };
        node.insns.push(InsnNodeData {
            addr,
            weight: UNDETERMINED_WEIGHT,
            itype: ntype,
            call_target: INVALID_NODE_ID,
            orig_jump_target: jump_target,
            orig_next: next,
            is_indirect_call: false,
        });
        node
    }

    /// Calculates the total weight of the CFG node.
    pub fn calc_weight(
        &mut self,
        successor_weights: &HashMap<NodeId, Weight>,
        call_weights: &HashMap<NodeId, Weight>,
    ) {
        assert_ne!(self.insns.len(), 0);
        let mut total_node_weight = 0;
        for insn in self.insns.iter_mut() {
            total_node_weight += insn.calc_weight(successor_weights, call_weights);
        }
        self.weight = total_node_weight;
    }

    /// Initialize an CFG node with a single call instruction.
    pub fn new_test_single_call(
        addr: Address,
        call_target: NodeId,
        is_indirect_call: bool,
        next: NodeId,
    ) -> CFGNodeData {
        let mut node = CFGNodeData {
            nid: NodeId::from(addr),
            weight: UNDETERMINED_WEIGHT,
            insns: Vec::new(),
        };
        node.insns.push(InsnNodeData::new_call(
            addr,
            call_target,
            is_indirect_call,
            INVALID_NODE_ID,
            next,
        ));
        node
    }

    pub fn get_clone(&self, icfg_clone_id: u32, cfg_clone_id: u32) -> CFGNodeData {
        let mut clone = self.clone();
        clone.nid.icfg_clone_id = icfg_clone_id;
        clone.nid.cfg_clone_id = cfg_clone_id;
        clone
    }

    pub fn has_type(&self, wtype: InsnNodeWeightType) -> bool {
        for i in self.insns.iter() {
            if i.itype.weight_type == wtype {
                return true;
            }
        }
        false
    }

    pub fn has_entry(&self) -> bool {
        for i in self.insns.iter() {
            if i.itype.is_entry {
                return true;
            }
        }
        false
    }

    /// If an instruction has a call target to the address of the passed NoodeId,
    /// it updates its call target node id with the given one.
    pub fn update_call_target(&mut self, call_target: NodeId) {
        if !self.has_type(InsnNodeWeightType::Call) {
            return;
        }
        for idata in self.insns.iter_mut() {
            if idata.call_target.get_orig_node_id() == call_target.get_orig_node_id() {
                idata.call_target = call_target;
            }
        }
    }
}

/// A control-flow graph of a procedure
#[derive(Clone)]
pub struct CFG {
    /// The graph.
    pub graph: FlowGraph,
    /// Meta data for every node.
    pub nodes_meta: HashMap<NodeId, CFGNodeData>,
    /// Weights of procedures this CFG calls.
    pub call_target_weights: HashMap<NodeId, Weight>,
    /// Set of exit nodes, discovered while building the CFG.
    discovered_exits: HashSet<NodeId>,
    /// Reverse topoloical sorted graph
    rev_topograph: Vec<NodeId>,
    /// The node id of the entry node
    entry: NodeId,
}

impl std::fmt::Display for CFG {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (nid, info) in self.nodes_meta.iter() {
            if info.has_entry() {
                return write!(f, "CFG{}", nid);
            }
        }
        write!(f, "CFG(empty)")
    }
}

macro_rules! get_nodes_meta_mut {
    ( $cfg:ident, $nid:expr ) => {
        match $cfg.nodes_meta.get_mut(&$nid) {
            Some(m) => m,
            None => panic!("The {} has no meta info for node {}.", $cfg, $nid),
        }
    };
}

macro_rules! get_nodes_meta {
    ( $cfg:ident, $node_id:expr ) => {
        match $cfg.nodes_meta.get(&$node_id) {
            Some(m) => m.clone(),
            None => panic!("The {} has no meta info for node {}.", $cfg, $node_id),
        }
    };
}

impl CFG {
    pub fn new() -> CFG {
        CFG {
            graph: FlowGraph::new(),
            nodes_meta: HashMap::new(),
            call_target_weights: HashMap::new(),
            rev_topograph: Vec::new(),
            discovered_exits: HashSet::new(),
            entry: INVALID_NODE_ID,
        }
    }

    pub fn new_graph(graph: FlowGraph) -> CFG {
        CFG {
            graph,
            nodes_meta: HashMap::new(),
            call_target_weights: HashMap::new(),
            rev_topograph: Vec::new(),
            discovered_exits: HashSet::new(),
            entry: INVALID_NODE_ID,
        }
    }

    pub fn get_entry(&self) -> NodeId {
        if self.entry == INVALID_NODE_ID {
            panic!("CFG has no valid entry point set.");
        }
        self.entry
    }

    /// Clones itself and updates the node IDs with the given iCFG clone id
    pub fn get_clone(&self, icfg_clone_id: u32) -> CFG {
        let mut cloned_cfg: CFG = self.clone();
        // First update the call nodes
        let mut new_call_targets: HashMap<NodeId, Weight> = HashMap::new();
        for (nid, weight) in cloned_cfg.call_target_weights.iter() {
            let mut new_nid = nid.clone();
            new_nid.icfg_clone_id = icfg_clone_id;
            new_call_targets.insert(new_nid, *weight);
        }
        cloned_cfg.call_target_weights.clear();
        cloned_cfg.call_target_weights.extend(new_call_targets);

        // Update the node IDs for the meta information
        let mut new_meta_map: HashMap<NodeId, CFGNodeData> = HashMap::new();
        for (nid, meta) in cloned_cfg.nodes_meta.iter() {
            let mut new_nid = nid.clone();
            new_nid.icfg_clone_id = icfg_clone_id;
            let new_meta = meta.get_clone(icfg_clone_id, meta.nid.cfg_clone_id);
            new_meta_map.insert(new_nid, new_meta);
        }
        cloned_cfg.nodes_meta.clear();
        cloned_cfg.nodes_meta.extend(new_meta_map);

        // Lastly update the graph nodes.
        cloned_cfg.graph.clear();
        for (from, to, bias) in self.graph.all_edges() {
            let mut from_new: NodeId = from;
            from_new.icfg_clone_id = icfg_clone_id;
            let mut to_new: NodeId = to;
            to_new.icfg_clone_id = icfg_clone_id;
            cloned_cfg.graph.add_edge(from_new, to_new, bias.clone());
        }

        cloned_cfg
    }

    /// Updates the weight of a procedure.
    /// If the given procedure is not called from the CFG, it panics.
    pub fn update_procedure_weight(&mut self, pid: NodeId, pweight: Weight) {
        if !self.call_target_weights.contains_key(&pid) {
            panic!(
                "Attempt to add weight of procedure {} to {}. But this CFG doesn't call the procedure",
                pid, self
            )
        }
        self.set_call_weight(pid, pweight);
    }

    pub fn add_call_target_weights(&mut self, call_target_weights: &[&(NodeId, Weight)]) {
        for cw in call_target_weights {
            self.set_call_weight(cw.0, cw.1);
        }
    }

    pub fn set_call_weight(&mut self, procedure_nid: NodeId, proc_weight: Weight) {
        self.call_target_weights.insert(procedure_nid, proc_weight);
    }

    /// Get the total weight of the CFG.
    pub fn get_node_weight(&self, node: NodeId) -> Weight {
        if self.graph.node_count() == 0 {
            return INVALID_WEIGHT;
        }
        get_nodes_meta!(self, node).weight
    }

    /// Get the total weight of the CFG.
    pub fn get_weight(&self) -> Weight {
        if self.graph.node_count() == 0 {
            return INVALID_WEIGHT;
        }
        let entry_nid = match self.rev_topograph.last() {
            Some(first) => *first,
            None => panic!(
                "If get_weight() is called on a CFG, the weights must have been calculated before."
            ),
        };
        get_nodes_meta!(self, entry_nid).weight
    }

    /// Adds an edge to the graph.
    /// The edge is only added once.
    pub fn add_edge(&mut self, from: (NodeId, CFGNodeData), to: (NodeId, CFGNodeData)) {
        if from.0 == to.0 {
            assert_eq!(from.1, to.1);
        }
        if from.1.has_entry() {
            self.entry = from.0;
        }
        for i in from.1.insns.iter() {
            if i.itype.weight_type == InsnNodeWeightType::Call {
                self.set_call_weight(i.call_target, UNDETERMINED_WEIGHT);
            }
        }
        if !self.nodes_meta.contains_key(&from.0) {
            self.nodes_meta.insert(from.0, from.1);
        }
        if !self.nodes_meta.contains_key(&to.0) {
            self.nodes_meta.insert(to.0, to.1);
        }
        if !self.graph.contains_edge(from.0, to.0) {
            self.graph.add_edge(from.0, to.0, SamplingBias::new_unset());
        }
    }

    /// Adds an node to the graph.
    /// If the node was present before, it nothing is done.
    pub fn add_node(&mut self, node: (NodeId, CFGNodeData)) {
        if self.nodes_meta.contains_key(&node.0) && self.graph.contains_node(node.0) {
            return;
        }
        for i in node.1.insns.iter() {
            if i.itype.weight_type == InsnNodeWeightType::Call {
                self.set_call_weight(i.call_target, UNDETERMINED_WEIGHT);
            }
        }
        self.nodes_meta.insert(node.0, node.1);
        self.graph.add_node(node.0);
    }

    pub fn add_node_data(&mut self, node_id: NodeId, data: CFGNodeData) {
        assert!(self.graph.contains_node(node_id));
        if data.insns.iter().any(|i| i.itype.is_entry) {
            self.entry = node_id;
        }
        self.nodes_meta.insert(node_id, data);
    }
}

impl FlowGraphOperations for CFG {
    fn get_graph_mut(&mut self) -> &mut FlowGraph {
        &mut self.graph
    }

    fn clean_up_acyclic(&mut self) {
        // Update the node types for Exit nodes.
        for n in self.discovered_exits.iter() {
            let exit: &mut InsnNodeData = self
                .nodes_meta
                .get_mut(&n)
                .unwrap()
                .insns
                .last_mut()
                .unwrap();
            exit.itype.weight_type = InsnNodeWeightType::Exit;
        }
    }

    fn get_graph(&self) -> &FlowGraph {
        &self.graph
    }

    fn sort(&mut self) {
        // Remove cycles
        self.rev_topograph = match toposort(&self.graph, None) {
            Ok(graph) => graph,
            Err(_) => panic!("Graph contains cycles. Cannot sort it to topological order."),
        };
        self.rev_topograph.reverse();
    }

    /// Increments [nid.cfg_clone_count] by [increment].
    fn get_next_node_id_clone(increment: u32, nid: NodeId) -> NodeId {
        let mut clone: NodeId = nid.clone();
        clone.cfg_clone_id += increment;
        clone
    }

    fn calc_weight(&mut self) -> Weight {
        self.sort();
        for n in self.rev_topograph.iter() {
            let mut succ_weights: HashMap<NodeId, Weight> = HashMap::new();
            for neigh in self.graph.neighbors_directed(*n, Outgoing) {
                let nw: Weight = get_nodes_meta!(self, neigh).weight;
                succ_weights.insert(neigh, nw);
            }

            let node_data: &mut CFGNodeData = get_nodes_meta_mut!(self, n);
            node_data.calc_weight(&succ_weights, &self.call_target_weights);
            // Update weight of edges/edge sampling bias
            for (k, nw) in succ_weights.iter() {
                let bias: SamplingBias = SamplingBias {
                    numerator: *nw,
                    denominator: node_data.weight,
                };
                self.graph.add_edge(*n, *k, bias);
            }
        }
        if self.get_weight() == 0 {
            panic!(
                "Generated weight of {} has weight 0. Does a return or invalid instruction exists?",
                self
            )
        }
        self.get_weight()
    }

    fn add_cloned_edge(&mut self, cloned_from: NodeId, cloned_to: NodeId) {
        log_rz!(
            LOG_DEBUG,
            format!("Add cloned edge: {} -> {}", cloned_from, cloned_to)
        );
        self.add_edge(
            (
                cloned_from,
                get_nodes_meta!(self, cloned_from.get_orig_node_id())
                    .get_clone(cloned_from.icfg_clone_id, cloned_from.cfg_clone_id),
            ),
            (
                cloned_to,
                get_nodes_meta!(self, cloned_to.get_orig_node_id())
                    .get_clone(cloned_to.icfg_clone_id, cloned_to.cfg_clone_id),
            ),
        );
    }

    fn mark_exit_node(&mut self, nid: &NodeId) {
        self.discovered_exits.insert(*nid);
    }
}
