// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::collections::HashMap;

use petgraph::{algo::toposort, Direction::Outgoing};

use crate::flow_graphs::{
    FlowGraph, FlowGraphOperations, NodeId, SamplingBias, Weight, INVALID_NODE_ID, INVALID_WEIGHT,
    UNDETERMINED_WEIGHT,
};

/// The node type of a CFG.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CFGNodeType {
    /// First node of a procedure. It has only incomming
    /// edges from other procedures and always a weight of
    ///
    ///   W\[iaddr\] = W\[successor\]
    ///
    Entry,
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

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CFGNodeData {
    pub weight: Weight,
    pub ntype: CFGNodeType,
    pub call_target: NodeId,
    pub is_indirect_call: bool,
}

impl CFGNodeData {
    pub fn new(ntype: CFGNodeType) -> CFGNodeData {
        CFGNodeData {
            weight: UNDETERMINED_WEIGHT,
            ntype,
            call_target: INVALID_NODE_ID,
            is_indirect_call: false,
        }
    }

    pub fn get_clone(&self, icfg_clone_id: u32, cfg_clone_id: u32) -> CFGNodeData {
        let clone = self.clone();
        clone
    }

    pub fn new_call(call_target: NodeId, is_indirect_call: bool) -> CFGNodeData {
        CFGNodeData {
            weight: UNDETERMINED_WEIGHT,
            ntype: CFGNodeType::Call,
            call_target,
            is_indirect_call,
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
    /// Reverse topoloical sorted graph
    rev_topograph: Vec<NodeId>,
}

impl std::fmt::Display for CFG {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (nid, info) in self.nodes_meta.iter() {
            if info.ntype == CFGNodeType::Entry {
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

macro_rules! get_call_weight {
    ( $self:ident, $info:ident ) => {
        match $self.call_target_weights.get(&$info.call_target) {
            Some(w) => *w,
            None => 1,
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
        }
    }

    pub fn new_graph(graph: FlowGraph) -> CFG {
        CFG {
            graph,
            nodes_meta: HashMap::new(),
            call_target_weights: HashMap::new(),
            rev_topograph: Vec::new(),
        }
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
            let new_meta = meta.get_clone(icfg_clone_id, meta.call_target.cfg_clone_id);
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
        if !self.nodes_meta.contains_key(&from.0) {
            self.nodes_meta.insert(from.0, from.1);
        }
        if !self.nodes_meta.contains_key(&to.0) {
            self.nodes_meta.insert(to.0, to.1);
        }
        if !self.graph.contains_edge(from.0, to.0) {
            self.graph.add_edge(from.0, to.0, SamplingBias::new_unset());
        }
        if from.1.ntype == CFGNodeType::Call {
            self.set_call_weight(from.1.call_target, UNDETERMINED_WEIGHT);
        }
        if to.1.ntype == CFGNodeType::Call {
            self.set_call_weight(to.1.call_target, UNDETERMINED_WEIGHT);
        }
    }

    /// Adds an node to the graph.
    /// If the node was present before, it nothing is done.
    pub fn add_node(&mut self, node: (NodeId, CFGNodeData)) {
        if self.nodes_meta.contains_key(&node.0) && self.graph.contains_node(node.0) {
            return;
        }
        self.nodes_meta.insert(node.0, node.1);
        self.graph.add_node(node.0);
        if node.1.ntype == CFGNodeType::Call {
            self.set_call_weight(node.1.call_target, UNDETERMINED_WEIGHT);
        }
    }

    pub fn add_node_data(&mut self, node_id: NodeId, data: CFGNodeData) {
        assert!(self.graph.contains_node(node_id));
        self.nodes_meta.insert(node_id, data);
    }
}

impl FlowGraphOperations for CFG {
    fn get_graph_mut(&mut self) -> &mut FlowGraph {
        &mut self.graph
    }

    fn clean_up_acyclic(&mut self) {}

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
            let mut succ_weight: HashMap<NodeId, Weight> = HashMap::new();
            for neigh in self.graph.neighbors_directed(*n, Outgoing) {
                let nw: Weight = get_nodes_meta!(self, neigh).weight;
                succ_weight.insert(neigh, nw);
            }

            let info: &mut CFGNodeData = get_nodes_meta_mut!(self, n);
            let sum_succ_weight = succ_weight.values().sum();
            info.weight = match info.ntype {
                CFGNodeType::Return => 1,
                CFGNodeType::Exit => 1,
                CFGNodeType::Normal => sum_succ_weight,
                CFGNodeType::Entry => sum_succ_weight,
                CFGNodeType::Call => sum_succ_weight * get_call_weight!(self, info),
            };
            // Update weight of edges/edge sampling bias
            for (k, nw) in succ_weight.iter() {
                let bias: SamplingBias = SamplingBias {
                    numerator: *nw,
                    denominator: info.weight,
                };
                self.graph.add_edge(*n, *k, bias);
            }
        }
        if self.get_weight() == 0 {
            panic!("Generated weight of CFG has weight 0. Does a return or invalid instruction exists?")
        }
        self.get_weight()
    }

    fn add_cloned_edge(&mut self, cloned_from: NodeId, cloned_to: NodeId) {
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
}
