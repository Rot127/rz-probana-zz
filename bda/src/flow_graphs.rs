// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use petgraph::algo::{tarjan_scc, toposort};
use petgraph::prelude::DiGraphMap;
use petgraph::Direction::{Incoming, Outgoing};

use std::collections::{HashMap, HashSet};

pub type FlowGraph = DiGraphMap<Address, SamplingBias>;

pub type Weight = u64;

/// The invalid weight value.
/// The invalid weight isn't zero because we can have
/// nodes in the iCFG which are not connected.
/// Those have a weight of zero. But might get edges later
/// during abstract interpretation.
pub const INVALID_WEIGHT: Weight = u64::MAX;

/// Value for undetermined weights.
/// This is used for unresolved indirect calls and procedures
/// which have no weight assigned yet.
pub const UNDETERMINED_WEIGHT: Weight = 0;

/// An address. It is used as node identifier. The high 64bits
/// indicate the the clone ID.
/// Each node, which is part of a loop, gets duplicated
/// up to i times to resolve cycles. [^2.4.3]
///
/// We can sacrifice some of the high bits to the lower
/// bits if we need 48bit addresses (or other) in the future.
///
/// [^2.4.3] https://doi.org/10.25394/PGS.23542014.v1
pub type Address = u128;

/// Returns the address value without the clone ID.
pub fn get_raw_addr(addr: Address) -> u128 {
    addr & 0xffffffffffffffff
}

pub const INVALID_ADDRESS: Address = u128::MAX;

/// Minimum times nodes of a loop get duplicated in a graph
/// to make it loop free.
pub const MIN_DUPLICATE_BOUND: u64 = 3;

/// Increments the clone count of the [addr] by [c] and returns the result.
pub fn get_clone_addr(addr: Address, c: u128) -> Address {
    addr + (c << 64)
}

/// The node type of a CFG.
#[derive(Clone, Copy)]
pub enum NodeType {
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

/// Sampling bias of each path. Used as edge weight.
///
/// # Example
/// If from node A 6000 paths can be reached and the outgoing
/// edge (A, B) leads to 40 of those, the sampling bias is 40/6000
/// for edge (A, B)
#[derive(Debug)]
pub struct SamplingBias {
    numerator: Weight,
    denominator: Weight,
}

impl std::fmt::Display for SamplingBias {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#x}/{:#x}", self.numerator, self.denominator)
    }
}

impl SamplingBias {
    pub fn new(numerator: u64, denominator: u64) -> Self {
        SamplingBias {
            numerator,
            denominator,
        }
    }

    pub fn new_unset() -> Self {
        SamplingBias {
            numerator: INVALID_WEIGHT,
            denominator: INVALID_WEIGHT,
        }
    }
}

/// Categories of edges for cycle removement by cloning
/// strongly connected components.
#[derive(PartialEq, Eq)]
pub enum EdgeFlow {
    /// Into/out of an stringly connected component.
    Outsider,
    /// A back edge in a graph.
    BackEdge,
    /// A normal edge.
    ForwardEdge,
}

/// Traits of the CFG and iCFG.
pub trait FlowGraphOperations {
    /// Add a cloned edge to the graph.
    /// The CFG and iCFG have to add the meta inforation to the cloned edge
    /// and add it afterwards to the real graph object.
    fn add_cloned_edge(&mut self, from: Address, to: Address);

    /// Adds clones of an edge to the graph of [self].
    /// The edge [from] -> [to] is duplicated [dup_bound] times.
    /// It depends on [flow] how the edge is cloned.
    /// For edges within the SCC, [from] and [to] are duplicated and the original edge is removed.
    /// For all others, one node ([fixed_node]) is not cloned. Instead edges between the [fixed_node]
    /// from/to the cloned node are added.
    fn add_clones_to_graph(
        &mut self,
        from: &Address,
        to: &Address,
        fix_node: &Address,
        flow: EdgeFlow,
        dup_bound: u64,
    ) {
        assert!(
            from == fix_node
                || to == fix_node
                || (*fix_node == INVALID_ADDRESS && flow != EdgeFlow::Outsider)
        );

        for i in 0..=dup_bound {
            let c = i as u128;
            if flow == EdgeFlow::BackEdge && i == dup_bound {
                break;
            }
            let new_edge: (Address, Address) = match flow {
                EdgeFlow::Outsider => {
                    if *from == *fix_node {
                        (*from, get_clone_addr(*to, c))
                    } else {
                        (get_clone_addr(*from, c), *to)
                    }
                }
                EdgeFlow::BackEdge => (get_clone_addr(*from, c), get_clone_addr(*to, c + 1)),
                EdgeFlow::ForwardEdge => (get_clone_addr(*from, c), get_clone_addr(*to, c)),
            };
            self.add_cloned_edge(new_edge.0, new_edge.1);
        }
    }

    /// Determines if the edge (from, to) is a back edge in the graph.
    /// Currently it implies, that the flow is from the lower
    /// to the higher address.
    /// This function is only valid, if both nodes
    /// are part of the same strongly connected component.
    fn is_back_edge(&self, from: &Address, to: &Address) -> bool {
        from >= to
    }

    /// Remove an edge from the graph.
    fn remove_edge(&mut self, from: &Address, to: &Address) {
        self.get_graph_mut().remove_edge(*from, *to);
    }

    /// Clones the nodes of an SCC within the graph of [self].
    /// Edges are added or removed so the SCC is afterwards cycle free.
    fn clone_nodes(&mut self, scc: &Vec<Address>, scc_edges: &HashSet<(Address, Address)>) {
        for (from, to) in scc_edges {
            if !scc.contains(&from) {
                // Edge into the SCC
                self.add_clones_to_graph(
                    &from,
                    &to,
                    &from,
                    EdgeFlow::Outsider,
                    MIN_DUPLICATE_BOUND,
                );
            } else if !scc.contains(&to) {
                // Edge out of the SCC
                self.add_clones_to_graph(&from, &to, &to, EdgeFlow::Outsider, MIN_DUPLICATE_BOUND);
            } else if self.is_back_edge(&from, &to) {
                // Back edge. remove the original and connect it to the clone
                self.add_clones_to_graph(
                    &from,
                    &to,
                    &INVALID_ADDRESS,
                    EdgeFlow::BackEdge,
                    MIN_DUPLICATE_BOUND,
                );
                self.remove_edge(from, to);
            } else {
                self.add_clones_to_graph(
                    &from,
                    &to,
                    &INVALID_ADDRESS,
                    EdgeFlow::ForwardEdge,
                    MIN_DUPLICATE_BOUND,
                );
            }
        }
    }

    /// Removes cycles in the graph.
    ///
    /// The cycle removement does the following:
    /// 1. Find strongly connected components (SCCs)
    /// 2. foreach scc:
    /// 3.    Get edges within, from, to SCC
    /// 4. foreach (scc, scc_edges):
    /// 5.    Clone SCC and its edges
    fn make_acyclic(&mut self) {
        // Strongly connected components
        let sccs = tarjan_scc(self.get_graph());
        // The SCC and Edges from, to and within the SCC
        let mut scc_groups: Vec<(Vec<Address>, HashSet<(Address, Address)>)> = Vec::new();

        // SCCs are in reverse topological order. The nodes in each SCC are arbitrary
        for scc in sccs {
            let mut edges: HashSet<(Address, Address)> = HashSet::new();
            if scc.len() <= 1 {
                continue;
            }
            // Accumulate all edges of an SCC
            for node in scc.iter() {
                for incomming in self.get_graph().neighbors_directed(*node, Incoming) {
                    edges.insert((incomming, *node));
                }
                for outgoing in self.get_graph().neighbors_directed(*node, Outgoing) {
                    edges.insert((*node, outgoing));
                }
            }
            scc_groups.push((scc, edges));
        }
        // Resolve loops for each SCC
        for group in scc_groups {
            self.clone_nodes(&group.0, &group.1);
        }
        self.update_weights();
    }

    /// Update weights of graph
    fn update_weights(&mut self) {
        self.calc_weight();
    }

    /// Calculate the node and edge weights over the whole graph.
    fn calc_weight(&mut self);

    /// Sort the graph in reverse topological order.
    fn sort(&mut self);

    fn get_graph_mut(&mut self) -> &mut FlowGraph;

    fn get_graph(&self) -> &FlowGraph;
}

#[derive(Clone, Copy)]
pub struct CFGNodeData {
    pub weight: Weight,
    pub ntype: NodeType,
    pub call_target: Address,
    pub is_indirect_call: bool,
}

impl CFGNodeData {
    pub fn new(ntype: NodeType) -> CFGNodeData {
        CFGNodeData {
            weight: INVALID_WEIGHT,
            ntype,
            call_target: INVALID_ADDRESS,
            is_indirect_call: false,
        }
    }
    pub fn new_call(call_target: Address, is_indirect_call: bool) -> CFGNodeData {
        CFGNodeData {
            weight: UNDETERMINED_WEIGHT,
            ntype: NodeType::Call,
            call_target,
            is_indirect_call,
        }
    }
}

/// A control-flow graph of a procedure
pub struct CFG {
    /// The graph. Nodes are the addresses of instruction words
    pub graph: DiGraphMap<Address, SamplingBias>,
    /// Meta data for every node. Indexed by address.
    pub nodes_meta: HashMap<Address, CFGNodeData>,
    /// Weights of procedures this CFG calls.
    pub call_target_weights: HashMap<Address, Weight>,
    /// Reverse topoloical sorted graph
    rev_topograph: Vec<Address>,
}

macro_rules! get_nodes_meta_mut {
    ( $cfg:ident, $addr:expr ) => {
        match $cfg.nodes_meta.get_mut(&$addr) {
            Some(m) => m,
            None => panic!("The CFG has no meta info for node {}.", $addr),
        }
    };
}

macro_rules! get_nodes_meta {
    ( $cfg:ident, $addr:expr ) => {
        match $cfg.nodes_meta.get(&$addr) {
            Some(m) => m,
            None => panic!("The CFG has no meta info for node {}.", $addr),
        }
    };
}

impl CFG {
    pub fn new() -> CFG {
        CFG {
            graph: DiGraphMap::new(),
            nodes_meta: HashMap::new(),
            call_target_weights: HashMap::new(),
            rev_topograph: Vec::new(),
        }
    }

    pub fn add_call_target_weights(&mut self, call_target_weights: &[&(Address, Weight)]) {
        for cw in call_target_weights {
            self.call_target_weights.insert(cw.0, cw.1);
        }
    }

    pub fn set_call_weight(&mut self, call_weight: (Address, Weight)) {
        self.call_target_weights
            .insert(call_weight.0, call_weight.1);
    }

    /// Get the total weight of the CFG.
    pub fn get_weight(&self) -> Weight {
        let entry_addr = match self.rev_topograph.last() {
            Some(first) => *first,
            None => panic!("If get_weight() is called on a CFG, the weights must have been calculated before and it has to have nodes.")
        };
        get_nodes_meta!(self, entry_addr).weight
    }

    /// Adds an edge to the graph.
    /// The edge is only added once.
    pub fn add_edge(&mut self, from: (Address, CFGNodeData), to: (Address, CFGNodeData)) {
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
}

impl FlowGraphOperations for CFG {
    fn get_graph_mut(&mut self) -> &mut FlowGraph {
        &mut self.graph
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

    fn calc_weight(&mut self) {
        self.sort();
        for n in self.rev_topograph.iter() {
            let mut succ_weight: HashMap<Address, Weight> = HashMap::new();
            for neigh in self.graph.neighbors_directed(*n, Outgoing) {
                let nw: Weight = get_nodes_meta!(self, neigh).weight;
                succ_weight.insert(neigh, nw);
            }

            let info: &mut CFGNodeData = get_nodes_meta_mut!(self, n);
            let sum_succ_weight = succ_weight.values().sum();
            info.weight = match info.ntype {
                NodeType::Return => 1,
                NodeType::Exit => 1,
                NodeType::Normal => sum_succ_weight,
                NodeType::Entry => sum_succ_weight,
                NodeType::Call => {
                    sum_succ_weight
                        * match self.call_target_weights.get(&info.call_target) {
                            Some(weight) => *weight,
                            None => {
                                if info.is_indirect_call {
                                    // Weight not yet determined. Maybe later during abstract interpretation.
                                    1
                                } else {
                                    panic!("There is no weight set for the called procedure.")
                                }
                            }
                        }
                }
            };
            // Update weight of edges
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
    }

    fn add_cloned_edge(&mut self, from: Address, to: Address) {
        let from_info: &CFGNodeData = get_nodes_meta!(self, get_raw_addr(from));
        let to_info: &CFGNodeData = get_nodes_meta!(self, get_raw_addr(to));
        self.add_edge((from, *from_info), (to, *to_info));
    }
}

/// A node in an iCFG describing a procedure.
pub struct Procedure {
    // The CFG of the procedure
    pub cfg: CFG,
    /// Flag if this procedure is malloc.
    pub is_malloc: bool,
}

impl Procedure {
    pub fn new(is_malloc: bool) -> Procedure {
        Procedure {
            cfg: CFG::new(),
            is_malloc,
        }
    }
}

/// An inter-procedual control flow graph.
pub struct ICFG {
    /// The actual graph. Nodes are indexed by address of the procedures.
    graph: DiGraphMap<Address, SamplingBias>,
    /// Map of procedures in the CFG. Indexed by entry point address.
    procedures: HashMap<Address, Procedure>,
    /// Reverse topoloical sorted graph
    rev_topograph: Vec<Address>,
}

macro_rules! get_procedure_mut {
    ( $icfg:ident, $addr:expr ) => {
        match $icfg.procedures.get_mut(&get_raw_addr($addr)) {
            Some(p) => p,
            None => panic!("The iCFG has no procedure for {}.", $addr),
        }
    };
}

macro_rules! get_procedure {
    ( $icfg:ident, $addr:expr ) => {
        match $icfg.procedures.get(&get_raw_addr($addr)) {
            Some(p) => p,
            None => panic!("The iCFG has no procedure for {}.", $addr),
        }
    };
}

impl ICFG {
    pub fn new() -> ICFG {
        ICFG {
            graph: DiGraphMap::new(),
            procedures: HashMap::new(),
            rev_topograph: Vec::new(),
        }
    }

    pub fn get_procedure_weight(&self, proc_addr: Address) -> Weight {
        get_procedure!(self, proc_addr).cfg.get_weight()
    }

    fn get_call_weights(&self, procedure: Address) -> HashMap<Address, Weight> {
        let mut p_weights: HashMap<Address, Weight> = HashMap::new();
        for n in self.graph.neighbors_directed(procedure, Outgoing) {
            let n_weight: Weight = get_procedure!(self, n).cfg.get_weight();
            p_weights.insert(n, n_weight);
        }
        p_weights
    }

    fn get_successor_weights(&self, procedure: &Address) -> HashMap<Address, Weight> {
        let mut succ_weight: HashMap<Address, Weight> = HashMap::new();
        for neigh in self.graph.neighbors_directed(*procedure, Outgoing) {
            let nw: Weight = get_procedure!(self, neigh).cfg.get_weight();
            succ_weight.insert(neigh, nw);
        }
        succ_weight
    }

    /// Adds an edge to the graph.
    /// The edge is only added once.
    pub fn add_edge(&mut self, from: (Address, Procedure), to: (Address, Procedure)) {
        // Check if a procedure is located at the actual address.
        // For cloned node addresses we do not save procedures.
        let from_actual_addr = get_raw_addr(from.0);
        if !self.procedures.contains_key(&from_actual_addr) {
            self.procedures.insert(from_actual_addr, from.1);
        }
        let to_actual_addr = get_raw_addr(to.0);
        if !self.procedures.contains_key(&to_actual_addr) {
            self.procedures.insert(to_actual_addr, to.1);
        }

        // Add actual edge
        if !self.graph.contains_edge(from.0, to.0) {
            self.graph.add_edge(from.0, to.0, SamplingBias::new_unset());
        }
    }

    pub fn num_procedures(&self) -> usize {
        self.procedures.len()
    }
}

impl FlowGraphOperations for ICFG {
    fn get_graph_mut(&mut self) -> &mut FlowGraph {
        &mut self.graph
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

    /// Calculate the weight of the whole iCFG and all CFGs part of it.
    fn calc_weight(&mut self) {
        self.sort();
        for paddr in self.rev_topograph.iter() {
            // Get weight of all successor procedures
            let succ_weights = self.get_successor_weights(paddr);
            // Get weight of all procedures this one calls
            let call_weights: HashMap<Address, Weight> = self.get_call_weights(*paddr);
            let procedure: &mut Procedure = get_procedure_mut!(self, *paddr);
            // Update the weights of the called procedures.
            for (target_addr, traget_weight) in call_weights.iter() {
                procedure
                    .cfg
                    .set_call_weight((*target_addr, *traget_weight));
            }
            procedure.cfg.calc_weight();

            // Update weight of edges
            for (neighbor_addr, neighbor_weight) in succ_weights.iter() {
                let bias: SamplingBias = SamplingBias {
                    numerator: *neighbor_weight,
                    denominator: procedure.cfg.get_weight(),
                };
                self.graph.add_edge(*paddr, *neighbor_addr, bias);
            }
        }
    }

    fn add_cloned_edge(&mut self, from: Address, to: Address) {
        if !self.graph.contains_edge(from, to) {
            self.graph.add_edge(from, to, SamplingBias::new_unset());
        }
    }
}

// - Translate graph
//   - Check for malloc in graph
// - Check for malloc in arguments
// - Warn if no malloc given with sleep
// - Check and mark loops/recursions.
//   - Resolve loops?
//
