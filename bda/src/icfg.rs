// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::{
    collections::{HashMap, HashSet},
    sync::RwLock,
    thread::{self, ScopedJoinHandle},
};

use helper::progress::ProgressBar;
use petgraph::Direction::Outgoing;

use crate::{
    cfg::Procedure,
    flow_graphs::{EdgeFlow, FlowGraph, FlowGraphOperations, NodeId, ProcedureMap},
    weight::{WeightID, WeightMap},
};

/// An inter-procedual control flow graph.
pub struct ICFG {
    /// The actual graph. Nodes are indexed by the entry node id of the procedures.
    graph: FlowGraph,
    /// Map of procedures in the CFG. Indexed by entry point node id.
    pub procedures: ProcedureMap,
    /// Topoloical sorted graph
    topograph: Vec<NodeId>,
    /// Number of node duplications for loop resolvement
    dup_cnt: usize,
    /// SCC map. Mapping NodeId to it's SCC member.
    scc_members: HashMap<NodeId, usize>,
    /// The strongly connected compononets of the cyclical graph
    sccs: Vec<Vec<NodeId>>,
}

impl ICFG {
    pub fn new() -> ICFG {
        ICFG {
            graph: FlowGraph::new(),
            procedures: ProcedureMap::new(),
            topograph: Vec::new(),
            dup_cnt: 3,
            scc_members: HashMap::new(),
            sccs: Vec::new(),
        }
    }

    pub fn new_graph(graph: FlowGraph) -> ICFG {
        ICFG {
            graph,
            procedures: ProcedureMap::new(),
            topograph: Vec::new(),
            dup_cnt: 3,
            scc_members: HashMap::new(),
            sccs: Vec::new(),
        }
    }

    pub fn is_procedure(&self, node_id: &NodeId) -> bool {
        self.procedures.contains_key(node_id)
    }

    pub fn is_malloc(&self, node_id: &NodeId) -> bool {
        self.procedures
            .get(node_id)
            .is_some_and(|p| p.read().expect("").is_malloc())
    }

    pub fn is_unmapped(&self, node_id: &NodeId) -> bool {
        self.procedures
            .get(node_id)
            .is_some_and(|p| p.read().expect("").is_unmapped())
            || !self.has_procedure(node_id)
    }

    pub fn is_input(&self, node_id: &NodeId) -> bool {
        if !self.is_procedure(node_id) {
            return false;
        }
        false
    }

    pub fn print_stats(&self) {
        println!("iCFG stats");
        println!("\tCFGs: {}", self.graph.node_count());
        println!("\tEdges: {}", self.graph.edge_count());
    }

    pub fn has_malloc(&self) -> bool {
        for p in self.procedures.keys() {
            if self.get_procedure(p).read().unwrap().is_malloc() {
                return true;
            }
        }
        false
    }

    pub fn has_procedure(&self, pid: &NodeId) -> bool {
        self.procedures.contains_key(pid)
    }

    pub fn get_procedure(&self, pid: &NodeId) -> &RwLock<Procedure> {
        let p = match self.procedures.get(pid) {
            Some(p) => p,
            None => panic!("The iCFG has no procedure for {}.", pid),
        };
        p
    }

    pub fn get_procedures(&self) -> &ProcedureMap {
        &self.procedures
    }

    pub fn add_procedure(&mut self, node_id: NodeId, mut proc: Procedure) -> bool {
        if self.has_procedure(&node_id) {
            return false;
        }
        proc.get_cfg_mut().set_node_dup_count(self.dup_cnt);
        self.procedures.insert(node_id, RwLock::new(proc));
        return true;
    }

    /// Adds an edge [from] -> [to]. The procedures can be passed optionally. If a procedure given
    /// is None, it is expected that the iCFG already contains it.
    /// Otherwise it panics.
    /// If [addr_to_update] is Some, it is assume that the newly added edge was discovered
    /// via an indirect call/jump. The instruction at [addr_to_update] is updated accordingly.
    /// Returns true if the edge was contained in the iCFG.
    pub fn add_edge(
        &mut self,
        from_proc_tuple: (NodeId, Option<Procedure>),
        to_proc_tuple: (NodeId, Option<Procedure>),
        call_insn_addr: Option<NodeId>,
    ) -> bool {
        if self.has_edge(from_proc_tuple.0, to_proc_tuple.0) {
            return true;
        }
        if self.has_edge(to_proc_tuple.0, from_proc_tuple.0) {
            // Don't add an edge if the reverse of it exits already. Because it has been resolved before.
            return true;
        }
        let from_proc_nid = from_proc_tuple.0;
        let to_proc_nid = to_proc_tuple.0;
        if !self.has_procedure(&from_proc_nid) {
            if from_proc_tuple.1.is_none() {
                panic!(
                    "Cannot add edge ({} -> {}), no procedure given",
                    from_proc_nid, to_proc_nid
                );
            }
            self.add_procedure(from_proc_nid, from_proc_tuple.1.unwrap());
        }
        if let Some(call_addr) = call_insn_addr {
            self.get_procedure(&from_proc_nid)
                .write()
                .unwrap()
                .insert_call_target(&call_addr, -1, &to_proc_nid);
        }
        if !self.has_procedure(&to_proc_nid) {
            if to_proc_tuple.1.is_none() {
                panic!(
                    "Cannot add edge ({} -> {}), no procedure given",
                    from_proc_nid, to_proc_nid
                );
            }
            self.add_procedure(to_proc_nid, to_proc_tuple.1.unwrap());
        }

        // Add actual edge
        if self.graph.contains_edge(from_proc_nid, to_proc_nid) {
            return true;
        }
        self.graph.add_edge(from_proc_nid, to_proc_nid, 0);
        return false;
    }

    /// Adds an edge to the graph.
    /// The edge is only added once.
    pub fn add_edge_test(&mut self, from: (NodeId, Procedure), to: (NodeId, Procedure)) {
        // Check if a procedure is located at the actual address.
        if !self.procedures.contains_key(&from.0) {
            if !from.1.is_cfg_set() {
                panic!("If a new node is added to the iCFG, the procedure has no CFG.");
            }
            self.add_procedure(from.0, from.1);
        }
        if !self.procedures.contains_key(&to.0) {
            if !to.1.is_cfg_set() {
                panic!("If a new node is added to the iCFG, the procedure has no CFG.");
            }
            self.add_procedure(to.0, to.1);
        }

        // Add actual edge
        if !self.graph.contains_edge(from.0, to.0) {
            self.graph.add_edge(from.0, to.0, 0);
        }
    }

    pub fn num_procedures(&self) -> usize {
        self.procedures.len()
    }

    /// Resolve all loops in the iCFG and all its CFGs.
    /// Ensure to run WeightMap.proagate_cfg_edits() after this one!
    pub fn resolve_loops(&mut self, num_threads: usize) {
        let mut progress = ProgressBar::new("Resolving loops".to_owned(), self.num_procedures());
        let mut resolved: usize = 0;
        let mut todo: Vec<NodeId> = self.procedures.keys().cloned().collect();
        let num_procedures = self.num_procedures();

        thread::scope(|s| {
            let mut threads: HashMap<usize, ScopedJoinHandle<_>> = HashMap::new();
            loop {
                progress.update_print(resolved, None);
                if resolved == num_procedures {
                    while !threads.is_empty() {
                        for tid in 0..num_threads {
                            if threads.get(&tid).is_some_and(|t| t.is_finished()) {
                                resolved += 1;
                                threads.remove(&tid);
                            }
                        }
                    }
                    break;
                }

                for tid in 0..num_threads {
                    if todo.is_empty() {
                        break;
                    }
                    if threads.get(&tid).is_some() {
                        // This one is busy
                        continue;
                    }
                    let next: NodeId = todo.pop().unwrap().to_owned();
                    let next_proc: &RwLock<Procedure> = self.procedures.get(&next).unwrap();

                    threads.insert(
                        tid,
                        s.spawn(move || {
                            let mut writeable_proc = match next_proc.write() {
                                Ok(r) => r,
                                _PoisonError => {
                                    panic!("Got poisoned write lock for procedure {}.", next)
                                }
                            };
                            writeable_proc.get_cfg_mut().make_acyclic(None);
                        }),
                    );
                }

                for tid in 0..num_threads {
                    if threads.get(&tid).is_some_and(|t| t.is_finished()) {
                        resolved += 1;
                        threads.remove(&tid);
                    }
                }
            }
        });
        self.make_acyclic(Some("Make iCFG acyclic".to_owned()));
    }

    /// Check if the call targets are alligned to the actual iCFG.
    /// And if the iCFG only contains edges by calls
    pub(crate) fn icfg_consistency_check(&self) -> bool {
        let mut seen_call_edges = HashSet::<(NodeId, NodeId)>::new();
        for (pid, proc) in self.get_procedures().iter() {
            for ct in proc.read().unwrap().get_cfg().nodes_meta.ct_iter() {
                if !self.get_graph().contains_edge(*pid, *ct) {
                    self.get_graph()
                        .neighbors_directed(pid.clone(), Outgoing)
                        .for_each(|n| println!("{} -> {}", *pid, n));
                }
                seen_call_edges.insert((*pid, *ct));
                debug_assert!(self.has_procedure(pid), "iCFG misses procedure {}", pid);
                debug_assert!(self.has_procedure(&ct), "iCFG misses procedure {}", ct);
                debug_assert!(
                    self.get_graph().contains_edge(*pid, *ct),
                    "Call target {} -> {} not in iCFG",
                    pid,
                    ct
                )
            }
        }
        if self.get_graph().edge_count() == seen_call_edges.len() {
            let mut graph_edges = HashSet::<(NodeId, NodeId)>::new();
            self.get_graph().all_edges().for_each(|(f, t, _)| {
                graph_edges.insert((f, t));
            });
            let diff = seen_call_edges.difference(&graph_edges);
            debug_assert_eq!(
                self.get_graph().edge_count(),
                seen_call_edges.len(),
                "iCFG edge count is off: iCFG edges: {} expected edge count (by call targets): {} | diff: {:?}",
                self.get_graph().edge_count(),
                seen_call_edges.len(),
                diff
            );
        }
        true
    }

    /// Removes all iCFG edges which have no calls in the CFGs.
    /// See: https://github.com/Rot127/rz-probana-zz/issues/28
    pub(crate) fn make_icfg_consistent(&mut self) {
        let mut to_keep = HashSet::<(NodeId, NodeId)>::new();
        for (pid, proc) in self.get_procedures().iter() {
            for ct in proc.read().unwrap().get_cfg().nodes_meta.ct_iter() {
                to_keep.insert((*pid, *ct));
            }
        }
        let mut to_remove = HashSet::<(NodeId, NodeId)>::new();
        for e in self.get_graph().all_edges() {
            if !to_keep.contains(&(e.0, e.1)) {
                to_remove.insert((e.0, e.1));
            }
        }
        for (from, to) in to_remove {
            self.get_graph_mut().remove_edge(from, to);
        }
    }

    pub fn has_edge(&self, from: NodeId, to: NodeId) -> bool {
        self.get_graph().contains_edge(from, to)
    }

    pub fn cfg_contains_edge(&self, cfg_entry: &NodeId, from: &NodeId, to: &NodeId) -> bool {
        self.get_procedure(cfg_entry)
            .read()
            .unwrap()
            .get_cfg()
            .get_graph()
            .contains_edge(*from, *to)
    }

    pub fn cfg_contains_node(&self, cfg_entry: &NodeId, nid: &NodeId) -> bool {
        self.get_procedure(cfg_entry)
            .read()
            .unwrap()
            .get_cfg()
            .get_graph()
            .contains_node(*nid)
    }
}

impl FlowGraphOperations for ICFG {
    fn get_name(&self) -> String {
        "ICFG".to_owned()
    }

    fn set_node_dup_count(&mut self, dup_cnt: usize) {
        self.dup_cnt = dup_cnt;
    }

    fn get_node_dup_count(&self) -> usize {
        self.dup_cnt
    }

    fn get_graph_mut(&mut self) -> &mut FlowGraph {
        &mut self.graph
    }

    fn clean_up_acyclic(&mut self) {
        // Assert that all call_target point to an existing CFG.
        debug_assert!(self.icfg_consistency_check());
    }

    fn get_graph(&self) -> &FlowGraph {
        &self.graph
    }

    fn set_topograph_mut(&mut self, topograph: Vec<NodeId>) {
        self.topograph = topograph;
    }

    /// Increments [nid.icfg_clone_count] by [increment].
    fn get_next_node_id_clone(increment: i32, nid: NodeId) -> NodeId {
        let mut clone: NodeId = nid.clone();
        clone.icfg_clone_id += increment;
        clone
    }

    fn remove_edge(&mut self, from: &NodeId, to: &NodeId) {
        self.get_graph_mut().remove_edge(*from, *to);
        // Delete call targets
        self.get_procedure(from)
            .write()
            .unwrap()
            .for_each_cinsn(|i| {
                i.call_targets.retain_mut(|ct| {
                    if ct == to {
                        return false;
                    }
                    return true;
                })
            });
    }

    fn handle_last_clone(&mut self, from: &NodeId, non_existent_node: &NodeId) {
        if !self.has_procedure(from) {
            // Happens sometimes, if the edge 3rd -> 4th clone is handled (going over the duplicate limit),
            // before any edge towards the 3rd is added.
            // Due to this the 3rd clone is not yet in the iCFG.
            // We need to clone the procedure here in this case.
            // Otherwise we don't get another chance to fix it's call targets.
            let cloned_proc = self
                .get_procedure(&from.get_orig_node_id())
                .read()
                .unwrap()
                .get_clone(from.icfg_clone_id);
            self.add_procedure(*from, cloned_proc);
        }
        // Remove any call to the non existing node.
        self.get_procedure(from)
            .write()
            .unwrap()
            .for_each_cinsn(|i| {
                if !i.itype.is_call() {
                    return;
                }
                i.call_targets.retain_mut(|ct| {
                    if ct.address == non_existent_node.address
                        && ct.icfg_clone_id < non_existent_node.icfg_clone_id
                    {
                        return false;
                    }
                    return true;
                });
                if i.call_targets.is_empty() {
                    i.itype.is_normal();
                }
            });
    }

    fn add_cloned_edge(&mut self, from: NodeId, to: NodeId, flow: &EdgeFlow) {
        if !self.graph.contains_edge(from, to) {
            self.graph.add_edge(from, to, 0);
        }
        if !self.procedures.contains_key(&from) {
            let cloned_proc = self
                .get_procedure(&from.get_orig_node_id())
                .read()
                .unwrap()
                .get_clone(from.icfg_clone_id);
            self.add_procedure(from, cloned_proc);
        }
        self.get_procedure(&from)
            .write()
            .unwrap()
            .update_call_edge(flow, &from, &to, false);

        if !self.procedures.contains_key(&to) {
            let cloned_proc = self
                .get_procedure(&to.get_orig_node_id())
                .read()
                .unwrap()
                .get_clone(to.icfg_clone_id);
            self.add_procedure(to, cloned_proc);
        }
        self.get_procedure(&to)
            .write()
            .unwrap()
            .update_call_edge(flow, &from, &to, true);
    }

    /// Returns the WeightID for [nid].
    /// [nid] must point to a valid CFG. Otherwise the function panics.
    fn calc_node_weight(
        &mut self,
        nid: &NodeId,
        proc_map: &ProcedureMap,
        wmap: &RwLock<WeightMap>,
    ) -> WeightID {
        assert!(
            self.procedures.contains_key(nid),
            "iCFG doesn't have a procedure for {}",
            nid
        );
        let proc = self.procedures.get(nid).unwrap();
        proc.write()
            .unwrap()
            .get_cfg_mut()
            .get_entry_weight_id(proc_map, wmap)
            .unwrap()
    }

    fn clear_scc_member_map(&mut self) {
        self.scc_members.clear();
        self.sccs.clear();
    }

    fn set_scc_membership(&mut self, nid: &NodeId, scc_idx: usize) {
        self.scc_members.insert(*nid, scc_idx);
    }

    fn share_scc_membership(&self, nid_a: &NodeId, nid_b: &NodeId) -> bool {
        self.scc_members
            .get(nid_a)
            .expect("nid_a should be in member list")
            == self
                .scc_members
                .get(nid_b)
                .expect("nid_b should be in member list")
    }

    fn get_scc_idx(&self, nid: &NodeId) -> &usize {
        self.scc_members
            .get(nid)
            .expect("nid should be in member list.")
    }

    fn push_scc(&mut self, scc: Vec<NodeId>) {
        self.sccs.push(scc);
    }

    fn scc_size_of(&self, nid: &NodeId) -> usize {
        self.sccs
            .get(*self.get_scc_idx(nid))
            .expect("Should be in boundary")
            .len()
    }

    fn get_sccs(&self) -> &Vec<Vec<NodeId>> {
        &self.sccs
    }
}
