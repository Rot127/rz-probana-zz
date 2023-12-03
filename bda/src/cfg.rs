// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use petgraph::algo::toposort;
use petgraph::prelude::DiGraphMap;
use petgraph::Direction::Outgoing;

use std::collections::HashMap;

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

pub type Address = u64;
/// Technically no an invalid address. But
/// 0x0 should pretty much never be used as address in a
/// real binary.
pub const INVALID_ADDRESS: Address = u64::MIN;

/// The node type of a CFG.
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
pub struct SamplingBias {
    numerator: Weight,
    denominator: Weight,
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

/// Traits of the CFG and iCFG.
pub trait CFGOperations {
    /// Removes cycles in the graph.
    fn make_acyclic(&mut self) -> &Self {
        todo!()
    }

    /// Update weights of graph starting at [node_id]
    fn update_weights(&mut self, node_id: Address) -> &Self {
        todo!()
    }

    /// Calculate the node and edge weights over the whole graph.
    fn calc_weight(&mut self);

    /// Sort the graph in reverse topological order.
    fn sort(&mut self);
}

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
        let entry_addr = match self.rev_topograph.first() {
            Some(first) => *first,
            None => panic!("If get_weight() is called on a CFG, the weights must have been calculated before and it has to have nodes.")
        };
        match self.nodes_meta.get(&entry_addr) {
            Some(entry_weight) => entry_weight.weight,
            None => panic!("Cannot determine CFG weight. No meta data for entry node exists!"),
        }
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

impl CFGOperations for CFG {
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
                let nw: Weight = match self.nodes_meta.get(&neigh) {
                    Some(neigh_info) => neigh_info.weight,
                    None => panic!("Neighbor node has no meta data."),
                };
                succ_weight.insert(neigh, nw);
            }

            let info: &mut CFGNodeData = match self.nodes_meta.get_mut(&n) {
                Some(info) => info,
                None => panic!("Node is in topological graph, but has no meta information."),
            };
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

impl ICFG {
    pub fn new() -> ICFG {
        ICFG {
            graph: DiGraphMap::new(),
            procedures: HashMap::new(),
            rev_topograph: Vec::new(),
        }
    }

    pub fn get_procedure_weight(&self, proc_addr: Address) -> Weight {
        let w = match self.procedures.get(&proc_addr) {
            Some(p) => p.cfg.get_weight(),
            None => panic!("Procedure not known."),
        };

        w
    }

    fn get_call_weights(&self, procedure: Address) -> HashMap<Address, Weight> {
        let mut p_weights: HashMap<Address, Weight> = HashMap::new();
        for n in self.graph.neighbors_directed(procedure, Outgoing) {
            let n_weight: Weight = match self.procedures.get(&n) {
                Some(neighbor) => neighbor.cfg.get_weight(),
                None => panic!("No procedure was added in the iCFG for procedure."),
            };
            p_weights.insert(n, n_weight);
        }
        p_weights
    }

    fn get_successor_weights(&self, procedure: &Address) -> HashMap<Address, Weight> {
        let mut succ_weight: HashMap<Address, Weight> = HashMap::new();
        for neigh in self.graph.neighbors_directed(*procedure, Outgoing) {
            let nw: Weight = match self.procedures.get(&neigh) {
                Some(successor) => successor.cfg.get_weight(),
                None => panic!("Neighbor node has no meta data."),
            };
            succ_weight.insert(neigh, nw);
        }
        succ_weight
    }

    /// Adds an edge to the graph.
    /// The edge is only added once.
    pub fn add_edge(&mut self, from: (Address, Procedure), to: (Address, Procedure)) {
        if !self.procedures.contains_key(&from.0) {
            self.procedures.insert(from.0, from.1);
        }
        if !self.procedures.contains_key(&to.0) {
            self.procedures.insert(to.0, to.1);
        }
        if !self.graph.contains_edge(from.0, to.0) {
            self.graph.add_edge(from.0, to.0, SamplingBias::new_unset());
        }
    }
}

impl CFGOperations for ICFG {
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
            let procedure: &mut Procedure = match self.procedures.get_mut(paddr) {
                Some(p) => p,
                None => panic!("Procedure is in iCFG but not in procedure list."),
            };
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
}

// - Translate graph
//   - Check for malloc in graph
// - Check for malloc in arguments
// - Warn if no malloc given with sleep
// - Check and mark loops/recursions.
//   - Resolve loops?
//
