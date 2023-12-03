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

pub struct CFGNodeData {
    pub weight: Weight,
    pub ntype: NodeType,
    pub call_target: Address,
    /// Weight of the procedure called.
    pub call_weight: Weight,
}

impl CFGNodeData {
    fn get_call_weight(&self) -> Weight {
        match self.ntype {
            NodeType::Call => {
                if self.call_weight == INVALID_WEIGHT {
                    panic!("Weight from called procedure is not yet set! This should have been done before.");
                }
                self.call_weight
            }
            _ => 0,
        }
    }
}

impl CFGNodeData {
    pub fn new(ntype: NodeType) -> CFGNodeData {
        CFGNodeData {
            weight: INVALID_WEIGHT,
            ntype,
            call_target: INVALID_ADDRESS,
            call_weight: INVALID_WEIGHT,
        }
    }
    pub fn new_call(call_target: Address) -> CFGNodeData {
        CFGNodeData {
            weight: UNDETERMINED_WEIGHT,
            ntype: NodeType::Call,
            call_target,
            call_weight: INVALID_WEIGHT,
        }
    }
}

/// A control-flow graph of a procedure
pub struct CFG {
    /// The graph. Nodes are the addresses of instruction words
    pub graph: DiGraphMap<Address, SamplingBias>,
    /// Meta data for every node. Indexed by address.
    pub nodes_meta: HashMap<Address, CFGNodeData>,
    /// Total weight of the CFG at the entry point.
    pub weight: Weight,
    /// Topoloical sorted graph
    rev_topograph: Vec<Address>,
}

impl CFG {
    pub fn new() -> CFG {
        CFG {
            graph: DiGraphMap::new(),
            nodes_meta: HashMap::new(),
            weight: INVALID_WEIGHT,
            rev_topograph: Vec::new(),
        }
    }

    /// Adds a edge to the graph.
    /// The edge is only added once and never twice.
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

    fn sort(&mut self) {
        // Remove cycles
        self.rev_topograph = match toposort(&self.graph, None) {
            Ok(graph) => graph,
            Err(_) => panic!("Graph contains cycles. Cannot sort it to topological order."),
        };
        self.rev_topograph.reverse();
    }

    pub fn calc_weight(&mut self) {
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
                NodeType::Call => sum_succ_weight * info.get_call_weight(),
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
    }
}

/// A node in an iCFG describing a procedure.
pub struct Procedure {
    /// The address of the procedure.
    address: Address,
    /// Flag if this procedure is malloc.
    is_malloc: bool,
    // The CFG of the procedure
    cfg: CFG,
}

/// An inter-procedual control flow graph.
pub struct ICFG {
    /// The actual graph. Nodes are indexed by address of the procedures.
    graph: DiGraphMap<Address, SamplingBias>,
    /// Map of procedures in the CFG. Indexed by entry point address.
    procedures: HashMap<Address, Procedure>,
}

pub trait CFGOperations {
    /// Removes cycles in the CFG.
    fn make_acyclic(&mut self) -> &Self {
        todo!()
    }

    /// Compute the initial weights of the CFG nodes.
    fn compute_weights(&mut self) -> &Self {
        todo!()
    }

    /// Update weights of graph starting at [node_id]
    fn update_weights(&mut self, node_id: Address) -> &Self {
        todo!()
    }
}

// - Translate graph
//   - Check for malloc in graph
// - Check for malloc in arguments
// - Warn if no malloc given with sleep
// - Check and mark loops/recursions.
//   - Resolve loops?
//
