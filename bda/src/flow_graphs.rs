// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use petgraph::algo::tarjan_scc;
use petgraph::prelude::DiGraphMap;
use petgraph::Direction::{Incoming, Outgoing};

use core::panic;
use std::collections::HashSet;

pub type FlowGraph = DiGraphMap<NodeId, SamplingBias>;

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
pub const UNDETERMINED_WEIGHT: Weight = 1;

pub type Address = u64;

pub const MAX_ADDRESS: Address = u64::MAX;

/// Each node in an iCFG or CFG gets assigned an ID.
/// This id, which is part of a loop, gets duplicated
/// up to i times to resolve cycles. [^2.4.3]
///
///
/// [^2.4.3] https://doi.org/10.25394/PGS.23542014.v1
#[derive(Clone, Copy, Debug, Hash, Eq, Ord, PartialEq, PartialOrd)]
/// A node identifier in a iCFG and CFG
pub struct NodeId {
    /// The i'th iCFG clone this node belongs to.
    /// If 0 it is the original node, i means it is part of the i'th clone.
    pub icfg_clone_id: u32,
    /// The i'th CFG clone this node belongs to.
    /// If 0 it is the original node, i means it is part of the i'th clone.
    pub cfg_clone_id: u32,
    /// The memory address of the procedure or instruction word this node represents.
    pub address: Address,
}

impl std::convert::From<Address> for NodeId {
    fn from(value: u64) -> NodeId {
        NodeId::new(0, 0, value)
    }
}

pub const INVALID_NODE_ID: NodeId = NodeId {
    icfg_clone_id: u32::MAX,
    cfg_clone_id: u32::MAX,
    address: u64::MAX,
};

impl NodeId {
    pub fn new(icfg_clone_id: u32, cfg_clone_id: u32, address: u64) -> NodeId {
        NodeId {
            icfg_clone_id,
            cfg_clone_id,
            address,
        }
    }

    pub fn new_original(address: Address) -> NodeId {
        NodeId {
            icfg_clone_id: 0,
            cfg_clone_id: 0,
            address,
        }
    }

    pub fn get_orig_node_id(&self) -> NodeId {
        NodeId {
            icfg_clone_id: 0,
            cfg_clone_id: 0,
            address: self.address,
        }
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "({}:{}:{:#x})",
            self.icfg_clone_id, self.cfg_clone_id, self.address
        )
    }
}

impl std::cmp::PartialEq<u128> for NodeId {
    fn eq(&self, other: &u128) -> bool {
        self.icfg_clone_id == (*other >> 96) as u32
            && self.cfg_clone_id == ((*other >> 64) as u32 & u32::MAX)
            && self.address == *other as u64
    }
}

/// Minimum times nodes of a loop get duplicated in a graph
/// to make it loop free.
pub const MIN_DUPLICATE_BOUND: u32 = 3;

/// Sampling bias of each path. Used as edge weight.
///
/// # Example
/// If from node A 6000 paths can be reached and the outgoing
/// edge (A, B) leads to 40 of those, the sampling bias is 40/6000
/// for edge (A, B)
#[derive(Debug, Clone)]
pub struct SamplingBias {
    pub numerator: Weight,
    pub denominator: Weight,
}

impl std::fmt::Display for SamplingBias {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.numerator == INVALID_WEIGHT && self.denominator == INVALID_WEIGHT {
            return write!(f, "invalid/invalid");
        } else if self.numerator == INVALID_WEIGHT {
            return write!(f, "invalid/{:#x}", self.denominator);
        } else if self.denominator == INVALID_WEIGHT {
            return write!(f, "{:#x}/invalid", self.numerator);
        }
        write!(f, "{:#x}/{:#x}", self.numerator, self.denominator)
    }
}

impl std::cmp::PartialEq for SamplingBias {
    fn eq(&self, other: &Self) -> bool {
        self.numerator == other.numerator && self.denominator == other.denominator
    }
}

impl std::cmp::PartialEq<(Weight, Weight)> for SamplingBias {
    fn eq(&self, other: &(Weight, Weight)) -> bool {
        self.numerator == other.0 && self.denominator == other.1
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
    fn add_cloned_edge(&mut self, from: NodeId, to: NodeId);

    fn get_edge_weight(&self, from: NodeId, to: NodeId) -> &SamplingBias {
        match self.get_graph().edge_weight(from, to) {
            Some(w) => w,
            None => panic!("Edge {} => {} does not exist.", from, to),
        }
    }

    /// Returns the next (incremented) clone of [id] by returning a copy of [id].
    fn get_next_node_id_clone(increment: u32, nid: NodeId) -> NodeId;

    /// Adds clones of an edge to the graph of [self].
    /// The edge [from] -> [to] is duplicated [dup_bound] times.
    /// It depends on [flow] how the edge is cloned.
    /// For edges within the SCC, [from] and [to] are duplicated and the original edge is removed.
    /// For all others, one node ([fixed_node]) is not cloned. Instead edges between the [fixed_node]
    /// from/to the cloned node are added.
    fn add_clones_to_graph(
        &mut self,
        from: &NodeId,
        to: &NodeId,
        fix_node: &NodeId,
        flow: EdgeFlow,
        dup_bound: u32,
    ) {
        assert!(
            from == fix_node
                || to == fix_node
                || (*fix_node == INVALID_NODE_ID && flow != EdgeFlow::Outsider)
        );

        for i in 0..=dup_bound {
            if flow == EdgeFlow::BackEdge && i == dup_bound {
                break;
            }
            let new_edge: (NodeId, NodeId) = match flow {
                EdgeFlow::Outsider => {
                    if *from == *fix_node {
                        (*from, Self::get_next_node_id_clone(i, *to))
                    } else {
                        (Self::get_next_node_id_clone(i, *from), *to)
                    }
                }
                EdgeFlow::BackEdge => (
                    Self::get_next_node_id_clone(i, *from),
                    Self::get_next_node_id_clone(i + 1, *to),
                ),
                EdgeFlow::ForwardEdge => (
                    Self::get_next_node_id_clone(i, *from),
                    Self::get_next_node_id_clone(i, *to),
                ),
            };
            self.add_cloned_edge(new_edge.0, new_edge.1);
        }
    }

    /// Determines if the edge (from, to) is a back edge in the graph.
    /// Currently it implies, that the flow is from the lower
    /// to the higher address.
    /// This function is only valid, if both nodes
    /// are part of the same strongly connected component.
    fn is_back_edge(&self, from: &NodeId, to: &NodeId) -> bool {
        from.address >= to.address
    }

    /// Remove an edge from the graph.
    fn remove_edge(&mut self, from: &NodeId, to: &NodeId) {
        self.get_graph_mut().remove_edge(*from, *to);
    }

    /// Clones the nodes of an SCC within the graph of [self].
    /// Edges are added or removed so the SCC is afterwards cycle free.
    fn clone_nodes(&mut self, scc: &Vec<NodeId>, scc_edges: &HashSet<(NodeId, NodeId)>) {
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
                    &INVALID_NODE_ID,
                    EdgeFlow::BackEdge,
                    MIN_DUPLICATE_BOUND,
                );
                self.remove_edge(from, to);
            } else {
                self.add_clones_to_graph(
                    &from,
                    &to,
                    &INVALID_NODE_ID,
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
        let mut scc_groups: Vec<(Vec<NodeId>, HashSet<(NodeId, NodeId)>)> = Vec::new();

        // SCCs are in reverse topological order. The nodes in each SCC are arbitrary
        for scc in sccs {
            let mut edges: HashSet<(NodeId, NodeId)> = HashSet::new();
            if scc.len() == 1 {
                // Only add edges if they self refernce the node
                let node = match scc.get(0) {
                    Some(n) => n,
                    None => panic!("Rust is broken. Vector size changed inbetween."),
                };
                for incomming in self.get_graph().neighbors_directed(*node, Incoming) {
                    if incomming == *node {
                        edges.insert((incomming, *node));
                    }
                }
                if edges.is_empty() {
                    // Not a self referencing SCC
                    continue;
                }
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
        self.clean_up_acyclic()
    }

    /// Specific clean up tasks after making the graph acyclic.
    fn clean_up_acyclic(&mut self);

    /// Update weights of graph
    fn update_weights(&mut self) {
        self.calc_weight();
    }

    /// Calculate the node and edge weights over the whole graph.
    fn calc_weight(&mut self) -> Weight;

    /// Sort the graph in reverse topological order.
    fn sort(&mut self);

    fn get_graph_mut(&mut self) -> &mut FlowGraph;

    fn get_graph(&self) -> &FlowGraph;
}

// - Translate graph
//   - Check for malloc in graph
// - Check for malloc in arguments
// - Warn if no malloc given with sleep
// - Check and mark loops/recursions.
//   - Resolve loops?
//
