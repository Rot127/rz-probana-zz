// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use helper::spinner::Spinner;
use petgraph::algo::{is_cyclic_directed, kosaraju_scc, toposort};
use petgraph::dot::{Config, Dot};
use petgraph::prelude::DiGraphMap;
use petgraph::Direction::{Incoming, Outgoing};
use rand::{thread_rng, Rng};

use core::panic;
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use crate::cfg::Procedure;
use crate::weight::{WeightID, WeightMap};

pub type FlowGraph = DiGraphMap<NodeId, usize>;

#[macro_export]
macro_rules! proc_map_get_cfg {
    ($pmap:expr, $nid:expr) => {
        $pmap.get($nid).unwrap().read().unwrap().get_cfg()
    };
}

pub use proc_map_get_cfg;

#[macro_export]
macro_rules! proc_map_get_cfg_mut {
    ($pmap:expr, $nid:expr) => {
        $pmap.get($nid).unwrap().write().unwrap().get_cfg_mut()
    };
}

pub use proc_map_get_cfg_mut;

pub struct ProcedureMap {
    /// Map of CFG entry node IDs and their procedure objects.
    map: HashMap<NodeId, RwLock<Procedure>>,
}

impl ProcedureMap {
    pub fn new() -> ProcedureMap {
        ProcedureMap {
            map: HashMap::new(),
        }
    }

    /// Returns the procedure with the [nid] if any exists.
    pub fn get(&self, nid: &NodeId) -> Option<&RwLock<Procedure>> {
        self.map.get(nid)
    }

    pub fn insert(&mut self, nid: NodeId, p: RwLock<Procedure>) {
        let entry = p.read().unwrap().get_cfg().get_entry();
        if entry != INVALID_NODE_ID {
            assert_eq!(
                nid, entry,
                "Can't add procedure. Index and entry node address miss-match: index({}) != entry({})",
                nid, entry
            );
        }
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

    pub fn iter_mut(
        &mut self,
    ) -> std::collections::hash_map::IterMut<'_, NodeId, RwLock<Procedure>> {
        self.map.iter_mut()
    }

    pub fn values(&self) -> std::collections::hash_map::Values<'_, NodeId, RwLock<Procedure>> {
        self.map.values()
    }

    pub fn keys(&self) -> std::collections::hash_map::Keys<'_, NodeId, RwLock<Procedure>> {
        self.map.keys()
    }

    pub fn test_remove(&mut self, nid: &NodeId) {
        self.map.remove(nid);
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
#[derive(Clone, Copy, Hash, Eq, Ord, PartialEq, PartialOrd)]
/// A node identifier in a iCFG and CFG
pub struct NodeId {
    /// The i'th iCFG clone this node belongs to.
    /// If 0 it is the original node, i means it is part of the i'th clone.
    pub icfg_clone_id: i32,
    /// The i'th CFG clone this node belongs to.
    /// If 0 it is the original node, i means it is part of the i'th clone.
    pub cfg_clone_id: i32,
    /// The memory address of the procedure or instruction word this node represents.
    pub address: Address,
}

impl std::convert::From<Address> for NodeId {
    fn from(value: u64) -> NodeId {
        NodeId::new(0, 0, value)
    }
}

impl std::convert::From<(i32, i32, u64)> for NodeId {
    fn from(v: (i32, i32, u64)) -> NodeId {
        NodeId::new(v.0, v.1, v.2)
    }
}

impl std::fmt::Debug for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

pub const INVALID_NODE_ID: NodeId = NodeId {
    icfg_clone_id: i32::MAX,
    cfg_clone_id: i32::MAX,
    address: u64::MAX,
};

impl NodeId {
    pub fn new(icfg_clone_id: i32, cfg_clone_id: i32, address: u64) -> NodeId {
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

    /// Returns a clone of the node id. If one of the given clone ids is smaller 0,
    /// it sets the clone ID of the original node.
    pub fn get_clone(&self, icfg_clone_id: i32, cfg_clone_id: i32) -> NodeId {
        NodeId {
            icfg_clone_id: if icfg_clone_id < 0 {
                self.icfg_clone_id
            } else {
                icfg_clone_id
            },
            cfg_clone_id: if cfg_clone_id < 0 {
                self.cfg_clone_id
            } else {
                cfg_clone_id
            },
            address: self.address,
        }
    }

    pub fn set_next_icfg_clone_id(&mut self) {
        self.icfg_clone_id += 1;
    }

    pub fn reset_to_original(&mut self) {
        self.icfg_clone_id = 0;
        self.cfg_clone_id = 0;
    }

    pub fn get_cfg_clone_id(&self) -> i32 {
        self.cfg_clone_id
    }

    pub fn get_icfg_clone_id(&self) -> i32 {
        self.icfg_clone_id
    }

    /// Returns true if either clone id is greate than [limit].
    pub fn is_clone_over_limit(&self, limit: i32) -> bool {
        self.icfg_clone_id > limit || self.cfg_clone_id > limit
    }

    pub fn get_dot_style(&self) -> String {
        match self.icfg_clone_id {
            0 => "style=filled fillcolor=\"blue\"".to_string(),
            1 => "style=filled fillcolor=\"yellow;0.3:blue\"".to_string(),
            2 => "style=filled fillcolor=\"yellow;0.6:blue\"".to_string(),
            3 => "style=filled fillcolor=\"yellow\"".to_string(),
            _ => panic!("No color defined."),
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
        self.icfg_clone_id == (*other >> 96) as i32
            && self.cfg_clone_id == ((*other >> 64) as i32 & i32::MAX)
            && self.address == *other as u64
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct NodeIdSet {
    /// The nodes
    vec: Vec<NodeId>,
}

impl NodeIdSet {
    pub fn get_clone(&self, icfg_clone_id: i32, cfg_clone_id: i32) -> NodeIdSet {
        let mut clone = NodeIdSet::new();
        for n in self.vec.iter() {
            clone.vec.push(n.get_clone(icfg_clone_id, cfg_clone_id));
        }
        clone
    }

    pub fn from_nid(nid: NodeId) -> NodeIdSet {
        let mut nid_vec = NodeIdSet { vec: Vec::new() };
        nid_vec.insert(nid);
        nid_vec
    }

    pub fn contains(&self, nid: &NodeId) -> bool {
        self.vec.contains(nid)
    }

    /// Adds a node to the set.
    /// But only nodes with a valid id, address and if the node is not already added.
    pub fn insert(&mut self, nid: NodeId) {
        if nid != INVALID_NODE_ID && nid.address != MAX_ADDRESS && !self.vec.contains(&nid) {
            if nid.cfg_clone_id > 0 {
                print!("ASD");
            }
            self.vec.push(nid);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.vec.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, NodeId> {
        self.vec.iter()
    }

    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, NodeId> {
        self.vec.iter_mut()
    }

    pub fn clear(&mut self) {
        self.vec.clear();
    }

    pub fn set_next_icfg_clone_id(&mut self) {
        for ct in self.vec.iter_mut() {
            ct.icfg_clone_id = ct.icfg_clone_id + 1;
        }
    }

    /// Returns true if any call target has a icfg or cfg clone id > 0.
    /// This indicates that the node was cloned before.
    pub fn contains_any_clone(&self) -> bool {
        self.vec
            .iter()
            .any(|ct| ct.icfg_clone_id > 0 || ct.cfg_clone_id > 0)
    }

    /// Returns true if it contains any clone or original node of
    /// [nid].
    pub fn contains_any_variant_of(&self, nid: &NodeId) -> bool {
        self.vec.iter().any(|ct| ct.address == nid.address)
    }

    /// Samples a NodeId uniformily at random from the vector
    /// If the list is empty, it returns an INVALID_NODE_ID
    pub fn sample(&self) -> NodeId {
        if self.vec.is_empty() {
            return INVALID_NODE_ID;
        }
        let s = self
            .vec
            .get(thread_rng().gen_range(0..self.vec.len()))
            .expect("Schroedingers bug encountered.")
            .clone();
        s
    }

    pub fn new() -> NodeIdSet {
        NodeIdSet { vec: Vec::new() }
    }

    pub fn clone(&self) -> NodeIdSet {
        NodeIdSet {
            vec: self.vec.clone(),
        }
    }

    /// The runtime is bad if it is used on non constant set lengths.
    pub fn retain_mut<F>(&mut self, f: F)
    where
        F: FnMut(&mut NodeId) -> bool,
    {
        self.vec.retain_mut(f);
    }

    pub(crate) fn len(&self) -> usize {
        self.vec.len()
    }

    pub(crate) fn get(&self, call_index: usize) -> Option<&NodeId> {
        self.vec.get(call_index)
    }
}

/// Categories of edges for cycle removement by cloning
/// strongly connected components.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum EdgeFlow {
    /// Edge into a strongly connected component.
    /// The From node is outside of the SCC and should not be cloned.
    /// The outsider node is also a SCC of size one.
    OutsiderFixedFrom,
    /// Edge out of a strongly connected component.
    /// The To node is outside of the SCC and should not be cloned.
    /// The outsider node is also a SCC of size one.
    OutsiderFixedTo,
    /// Edge into a strongly connected component.
    /// The From node is outside of the SCC.
    /// The outsider node is also part of another SCC of size > 1.
    /// The From node will be cloned.
    OutsiderLooseFrom,
    /// Edge out of a strongly connected component.
    /// The To node is outside of the SCC.
    /// The outsider node is also part of another SCC of size > 1.
    /// The To node will be cloned.
    OutsiderLooseTo,
    /// A back edge within the SCC (from.address >= to.address).
    BackEdge,
    /// A forward edge within the SCC (from.address < to.address).
    ForwardEdge,
}

impl std::fmt::Display for EdgeFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EdgeFlow::OutsiderFixedFrom => write!(f, "OutsiderFixedFrom"),
            EdgeFlow::OutsiderFixedTo => write!(f, "OutsiderFixedTo"),
            EdgeFlow::OutsiderLooseFrom => write!(f, "OutsiderLooseFrom"),
            EdgeFlow::OutsiderLooseTo => write!(f, "OutsiderLooseTo"),
            EdgeFlow::BackEdge => write!(f, "BackEdge"),
            EdgeFlow::ForwardEdge => write!(f, "ForwardEdge"),
        }
    }
}

/// Traits of the CFG and iCFG.
pub trait FlowGraphOperations {
    /// Set the number of duplications for none static loops.
    fn set_node_dup_count(&mut self, dup_cnt: usize);

    /// Get the number of duplications for none static loops.
    fn get_node_dup_count(&self) -> usize;

    /// Checks if the flow graph is acyclic.
    fn is_acyclic(&self) -> bool {
        !is_cyclic_directed(self.get_graph())
    }

    /// Add a cloned edge to the graph.
    /// The CFG and iCFG have to add the meta information to the cloned edge
    /// and add it afterwards to the real graph object.
    fn add_cloned_edge(&mut self, from: NodeId, to: NodeId, flow: &EdgeFlow);

    /// Does clean up tasks for the edge which is __not__ added
    /// to the iCFG.
    /// [from] is the last clone in the graph. Finishing an iteration.
    /// The given [non_existent_node] is the node id which must not be in the graph.
    fn handle_last_clone(&mut self, from: &NodeId, non_existent_node: &NodeId);

    /// Returns the next (incremented) clone of [id] by returning a copy of [id].
    fn get_next_node_id_clone(increment: i32, nid: NodeId) -> NodeId;

    fn product_dup_bound(dup_bound: i32) -> Vec<(i32, i32)> {
        let mut prod = Vec::<(i32, i32)>::new();
        for j in 0..=dup_bound {
            for i in 0..=dup_bound {
                prod.push((i, j));
            }
        }
        prod
    }

    /// Adds clones of an edge to the graph of [self].
    /// The edge [from] -> [to] is duplicated [dup_bound] times.
    /// It depends on [flow] how the edge is cloned.
    ///
    /// - Edges within the SCC: are cloned [dup_bound] times.
    /// - Edges reaching outside to/from a fixed node: are cloned [dup_bound] times.
    /// - Edges reaching outside to/from a loose node: are cloned [dup_bound] x [dup_bound] times.
    ///   Each of clone (0..=dup_bound) to the targeted (0..=dup_bound) clones.
    fn add_clones_to_graph(&mut self, from: &NodeId, to: &NodeId, flow: &EdgeFlow, dup_bound: i32) {
        let mut new_edge: (NodeId, NodeId);
        for (i, j) in Self::product_dup_bound(dup_bound) {
            if j > 0 && (*flow != EdgeFlow::OutsiderLooseFrom && *flow != EdgeFlow::OutsiderLooseTo)
            {
                // Done for them.
                break;
            }
            new_edge = match flow {
                EdgeFlow::OutsiderFixedFrom => (*from, Self::get_next_node_id_clone(i, *to)),
                EdgeFlow::OutsiderFixedTo => (Self::get_next_node_id_clone(i, *from), *to),
                EdgeFlow::BackEdge => (
                    Self::get_next_node_id_clone(i, *from),
                    Self::get_next_node_id_clone(i + 1, *to),
                ),
                EdgeFlow::ForwardEdge => (
                    Self::get_next_node_id_clone(i, *from),
                    Self::get_next_node_id_clone(i, *to),
                ),
                EdgeFlow::OutsiderLooseFrom | EdgeFlow::OutsiderLooseTo => (
                    Self::get_next_node_id_clone(i, *from),
                    Self::get_next_node_id_clone(j, *to),
                ),
            };
            if *flow == EdgeFlow::BackEdge && i == dup_bound {
                self.handle_last_clone(&new_edge.0, &new_edge.1);
                break;
            }
            if new_edge.0.is_clone_over_limit(dup_bound)
                || new_edge.1.is_clone_over_limit(dup_bound)
            {
                // We don't handle any edge pointint outside of the limit. Can happen if
                // resolve loop is called multiple times.
                break;
            }
            self.add_cloned_edge(new_edge.0, new_edge.1, flow);
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
    fn remove_edge(&mut self, from: &NodeId, to: &NodeId);

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
    fn clone_nodes(&mut self, sccs_edge_flows: Vec<HashSet<((NodeId, NodeId), EdgeFlow)>>) {
        let dup_bound = self.get_node_dup_count() as i32;
        for scc_flows in sccs_edge_flows {
            for ((from, to), flow) in scc_flows {
                self.add_clones_to_graph(&from, &to, &flow, dup_bound);
                if flow != EdgeFlow::BackEdge {
                    continue;
                }
                // Back edge: remove the original. Check if last node
                self.remove_edge(&from, &to);
            }
        }
    }

    fn clear_scc_member_map(&mut self);

    fn set_scc_membership(&mut self, nid: &NodeId, scc_idx: usize);

    fn share_scc_membership(&self, nid_a: &NodeId, nid_b: &NodeId) -> bool;

    fn get_scc_idx(&self, nid: &NodeId) -> &usize;

    fn push_scc(&mut self, scc: Vec<NodeId>);

    fn scc_size_of(&self, nid: &NodeId) -> usize;

    fn get_sccs(&self) -> &Vec<Vec<NodeId>>;

    fn get_scc_edge_flow(&self, from: &NodeId, to: &NodeId, center: &NodeId) -> EdgeFlow {
        assert!(from == center || to == center);
        if self.share_scc_membership(from, to) {
            return if from.address < to.address {
                EdgeFlow::ForwardEdge
            } else {
                EdgeFlow::BackEdge
            };
        }
        let from_scc_size = self.scc_size_of(from);
        let to_scc_size = self.scc_size_of(to);
        if center == from {
            // Outgoing edge.
            return if to_scc_size > 1 {
                EdgeFlow::OutsiderLooseTo
            } else {
                EdgeFlow::OutsiderFixedTo
            };
        }
        // Incoming edge
        return if from_scc_size > 1 {
            EdgeFlow::OutsiderLooseFrom
        } else {
            EdgeFlow::OutsiderFixedFrom
        };
    }

    /// Moves the SCCs into a hashmap which maps NodeId -> SCC index.
    /// The SCC member map is cleaned before.
    fn fill_scc_map(&mut self, sccs: Vec<Vec<NodeId>>) {
        self.clear_scc_member_map();
        for (scc_idx, scc) in sccs.into_iter().enumerate() {
            for nid in scc.iter() {
                self.set_scc_membership(&nid, scc_idx);
            }
            self.push_scc(scc);
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
    fn make_acyclic(&mut self, spinner_text: Option<String>) {
        // Strongly connected components
        let sccs = kosaraju_scc(self.get_graph());
        self.fill_scc_map(sccs);
        // The SCC edges, each vector element contains the edges from a single SCC: from, to and within it.
        let mut sccs_edge_flows: Vec<HashSet<((NodeId, NodeId), EdgeFlow)>> = Vec::new();

        // SCCs are in reverse topological order. The nodes in each SCC are arbitrary
        for scc in self.get_sccs() {
            let mut edge_flows: HashSet<((NodeId, NodeId), EdgeFlow)> = HashSet::new();
            if scc.len() == 1 {
                // Normally SCCs with one node won't be duplicated. Except they have a self-referencing edge.
                // Because this edge is a loop.
                let node = scc.get(0).unwrap();
                let mut self_ref = false;
                for incoming in self.get_graph().neighbors_directed(*node, Incoming) {
                    if incoming == *node {
                        // Continue with edge cloning.
                        self_ref = true;
                        break;
                    }
                }
                if !self_ref {
                    // Single node SCC without a self referencing edge.
                    // No edges to clone for this one.
                    continue;
                }
            }
            // Accumulate all edges of an SCC
            for node in scc.iter() {
                for incoming in self.get_graph().neighbors_directed(*node, Incoming) {
                    edge_flows.insert((
                        (incoming, *node),
                        self.get_scc_edge_flow(&incoming, node, node),
                    ));
                }
                for outgoing in self.get_graph().neighbors_directed(*node, Outgoing) {
                    edge_flows.insert((
                        (*node, outgoing),
                        self.get_scc_edge_flow(node, &outgoing, node),
                    ));
                }
            }
            sccs_edge_flows.push(edge_flows);
        }
        // WITHIN a SCC:
        // Remove any edge which points to the previous clone (smaller clone id).
        // These are back-edges, which have been already resolved, and should not be added again.
        // They are not detected as back-edges in `clone_nodes`, but as Outsider edges
        // (due to the different clone id). Due to this, they remain in the graph
        // and produce a loop.
        for edge_flows in sccs_edge_flows.iter_mut() {
            edge_flows.retain(|((f, t), _)| {
                f.icfg_clone_id >= t.icfg_clone_id && f.cfg_clone_id >= t.cfg_clone_id
            })
        }
        // Resolve loops for each SCC
        self.clone_nodes(sccs_edge_flows);
        self.clean_up_acyclic();
        self.sort();
    }

    /// Specific clean up tasks after making the graph acyclic.
    fn clean_up_acyclic(&mut self);

    /// Calculates and returns the weight of the node. And if it wasn't determined yet, it calculates it.
    fn calc_node_weight(
        &mut self,
        nid: &NodeId,
        proc_map: &ProcedureMap,
        wmap: &RwLock<WeightMap>,
    ) -> WeightID;

    fn set_topograph_mut(&mut self, topograph: Vec<NodeId>);

    /// Sort the graph in reverse topological order.
    fn sort(&mut self) {
        // Check if all cycles are gone
        let topograph = match toposort(&self.get_graph(), None) {
            Ok(graph) => graph,
            Err(_) => panic!("Graph contains cycles. Cannot sort it to topological order."),
        };
        self.set_topograph_mut(topograph);
    }

    fn get_graph_mut(&mut self) -> &mut FlowGraph;

    fn get_graph(&self) -> &FlowGraph;

    /// Marks the last cloned node with [nid] as an Exit node (if applicable).
    fn mark_exit_node(&mut self, _nid: &NodeId) {}

    fn get_name(&self) -> String;

    fn dot_graph_to_stdout(&self) {
        println!(
            "{:?}",
            Dot::with_attr_getters(
                &self.get_graph(),
                &[Config::NodeNoLabel, Config::EdgeNoLabel],
                &|_graph, edge| { format!("label = \"{} -> {}\"", edge.0, edge.1) },
                &|_graph, node| {
                    format!(
                        "label = \"{}\" {} layer = {}",
                        node.1,
                        node.1.get_dot_style(),
                        node.1.icfg_clone_id
                    )
                },
            )
        );
    }
}
