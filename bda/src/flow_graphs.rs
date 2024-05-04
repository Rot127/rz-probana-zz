// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use helper::spinner::Spinner;
use petgraph::algo::{is_cyclic_directed, kosaraju_scc};
use petgraph::prelude::DiGraphMap;
use petgraph::Direction::{Incoming, Outgoing};

use core::panic;
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use crate::icfg::Procedure;
use crate::weight::{WeightID, WeightMap};

pub type FlowGraph = DiGraphMap<NodeId, usize>;

pub struct ProcedureMap {
    map: HashMap<NodeId, RwLock<Procedure>>,
}

impl ProcedureMap {
    pub fn new() -> ProcedureMap {
        ProcedureMap {
            map: HashMap::new(),
        }
    }

    pub fn get(&self, nid: &NodeId) -> Option<&RwLock<Procedure>> {
        self.map.get(nid)
    }

    pub fn insert(&mut self, nid: NodeId, p: RwLock<Procedure>) {
        self.map.insert(nid, p);
    }

    pub fn contains_key(&self, nid: &NodeId) -> bool {
        self.map.contains_key(nid)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn iter(&self) -> std::collections::hash_map::Iter<'_, NodeId, RwLock<Procedure>> {
        self.map.iter()
    }

    pub fn values(&self) -> std::collections::hash_map::Values<'_, NodeId, RwLock<Procedure>> {
        self.map.values()
    }

    pub fn keys(&self) -> std::collections::hash_map::Keys<'_, NodeId, RwLock<Procedure>> {
        self.map.keys()
    }
}

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

    pub fn is_invalid_call_target(&self) -> bool {
        self.address == MAX_ADDRESS
    }

    /// Returns the NodeId with an incremented icfg_clone_id.
    pub fn get_next_icfg_clone(&self) -> NodeId {
        let mut clone = self.clone();
        clone.icfg_clone_id += 1;
        clone
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
    /// Checks if the flow graph is acyclic.
    fn is_acyclic(&self) -> bool {
        !is_cyclic_directed(self.get_graph())
    }

    /// Add a cloned edge to the graph.
    /// The CFG and iCFG have to add the meta information to the cloned edge
    /// and add it afterwards to the real graph object.
    fn add_cloned_edge(&mut self, from: NodeId, to: NodeId, wmap: &RwLock<WeightMap>);

    /// Returns the next (incremented) clone of [id] by returning a copy of [id].
    fn get_next_node_id_clone(increment: u32, nid: NodeId) -> NodeId;

    /// Adds clones of an edge to the graph of [self].
    /// The edge [from] -> [to] is duplicated [dup_bound] times.
    /// It depends on [flow] how the edge is cloned.
    /// For edges within the SCC, [from] and [to] are duplicated and the original edge is removed.
    /// For all others, one node ([fixed_node]) is not cloned. Instead edges between the [fixed_node]
    /// from/to the cloned node are added.
    ///
    /// It returns the last clone of the edge.
    fn add_clones_to_graph(
        &mut self,
        from: &NodeId,
        to: &NodeId,
        fix_node: &NodeId,
        flow: EdgeFlow,
        dup_bound: u32,
        wmap: &RwLock<WeightMap>,
    ) -> (NodeId, NodeId) {
        assert!(
            from == fix_node
                || to == fix_node
                || (*fix_node == INVALID_NODE_ID && flow != EdgeFlow::Outsider)
        );

        let mut new_edge: (NodeId, NodeId) = (INVALID_NODE_ID, INVALID_NODE_ID);
        for i in 0..=dup_bound {
            if flow == EdgeFlow::BackEdge && i == dup_bound {
                break;
            }
            new_edge = match flow {
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
            self.add_cloned_edge(new_edge.0, new_edge.1, wmap);
        }
        new_edge
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

    /// Checks if the edge [from] -> [to] is a self-referenceing edge where [from] == [to]
    /// and no outgoing edge from [to] exists.
    /// This indicates that the instruction is a hold/self-referencing jump instruction.
    /// The last clone of this node should be marked as Exit, because the program
    /// won't return from it.
    fn check_self_ref_hold(
        scc_edges: &HashSet<(NodeId, NodeId)>,
        from: &NodeId,
        to: &NodeId,
    ) -> bool {
        if from != to {
            return false;
        }

        if !(scc_edges.contains(&(*from, *to)) && scc_edges.contains(&(*to, *from))) {
            return false;
        }

        // Check if there are other outgoing edges originating from [to]
        !scc_edges
            .iter()
            .any(|edge| edge.0 == *to && edge.1 != *from)
    }

    /// Clones the nodes of an SCC within the graph of [self].
    /// Edges are added or removed so the SCC was resolved to a cycle free sub-graph.
    ///
    /// [scc_edges] must contain all edges into, out of and within the SCC.
    /// [scc] must contain all nodes within the SCC.
    fn clone_nodes(
        &mut self,
        scc: &Vec<NodeId>,
        scc_edges: &HashSet<(NodeId, NodeId)>,
        wmap: &RwLock<WeightMap>,
    ) {
        for (from, to) in scc_edges {
            if !scc.contains(&from) {
                // Edge into the SCC
                self.add_clones_to_graph(
                    &from,
                    &to,
                    &from,
                    EdgeFlow::Outsider,
                    MIN_DUPLICATE_BOUND,
                    wmap,
                );
            } else if !scc.contains(&to) {
                // Edge out of the SCC
                self.add_clones_to_graph(
                    &from,
                    &to,
                    &to,
                    EdgeFlow::Outsider,
                    MIN_DUPLICATE_BOUND,
                    wmap,
                );
            } else if self.is_back_edge(&from, &to) {
                // Back edge. remove the original and connect it to the clone
                self.add_clones_to_graph(
                    &from,
                    &to,
                    &INVALID_NODE_ID,
                    EdgeFlow::BackEdge,
                    MIN_DUPLICATE_BOUND,
                    wmap,
                );
                self.remove_edge(from, to);
                if Self::check_self_ref_hold(scc_edges, from, to) {
                    self.mark_exit_node(to);
                }
            } else {
                self.add_clones_to_graph(
                    &from,
                    &to,
                    &INVALID_NODE_ID,
                    EdgeFlow::ForwardEdge,
                    MIN_DUPLICATE_BOUND,
                    wmap,
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
    fn make_acyclic(&mut self, wmap: &RwLock<WeightMap>, spinner_text: Option<String>) {
        // Strongly connected components
        let sccs = kosaraju_scc(self.get_graph());
        // The SCC and Edges from, to and within the SCC
        let mut scc_groups: Vec<(Vec<NodeId>, HashSet<(NodeId, NodeId)>)> = Vec::new();
        let mut spinner = Spinner::new(if spinner_text.is_some() {
            spinner_text.clone().unwrap()
        } else {
            "".to_owned()
        });

        // SCCs are in reverse topological order. The nodes in each SCC are arbitrary
        for scc in sccs {
            if spinner_text.is_some() {
                spinner.update(None);
            }
            let mut edges: HashSet<(NodeId, NodeId)> = HashSet::new();
            if scc.len() == 1 {
                // Only add edges if they self refernce the node
                let node = match scc.get(0) {
                    Some(n) => n,
                    None => panic!("Race condition? Vector size changed inbetween."),
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
            self.clone_nodes(&group.0, &group.1, wmap);
        }
        self.clean_up_acyclic(wmap);
        self.sort();
        if spinner_text.is_some() {
            spinner.done(spinner_text.clone().unwrap());
        }
    }

    /// Specific clean up tasks after making the graph acyclic.
    fn clean_up_acyclic(&mut self, wmap: &RwLock<WeightMap>);

    /// Update weights of graph
    fn update_weights(&mut self, _wmap: &RwLock<WeightMap>) {
        todo!()
    }

    /// Calculates and returns the weight of the node. And if it wasn't determined yet, it calculates it.
    fn calc_node_weight(
        &mut self,
        nid: &NodeId,
        proc_map: &ProcedureMap,
        wmap: &RwLock<WeightMap>,
        recalc: bool,
    ) -> WeightID;

    /// Sort the graph in reverse topological order.
    fn sort(&mut self);

    fn get_graph_mut(&mut self) -> &mut FlowGraph;

    fn get_graph(&self) -> &FlowGraph;

    /// Marks the node with [nid] as an Exit node (if applicable).
    fn mark_exit_node(&mut self, _nid: &NodeId) {}
}
