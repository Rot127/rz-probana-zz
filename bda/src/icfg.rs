// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::{
    collections::{HashMap, HashSet},
    sync::RwLock,
    thread::{self, ScopedJoinHandle},
};

use helper::progress::ProgressBar;

use crate::{
    cfg::{InsnNodeWeightType, Procedure},
    flow_graphs::{FlowGraph, FlowGraphOperations, NodeId, ProcedureMap, INVALID_NODE_ID},
    weight::{WeightID, WeightMap},
};

/// An inter-procedual control flow graph.
pub struct ICFG {
    /// The actual graph. Nodes are indexed by the entry node id of the procedures.
    graph: FlowGraph,
    /// Map of procedures in the CFG. Indexed by entry point node id.
    pub procedures: ProcedureMap,
    /// Reverse topoloical sorted graph
    rev_topograph: Vec<NodeId>,
    /// Number of node duplications for loop resolvement
    dup_cnt: usize,
}

impl ICFG {
    pub fn new() -> ICFG {
        ICFG {
            graph: FlowGraph::new(),
            procedures: ProcedureMap::new(),
            rev_topograph: Vec::new(),
            dup_cnt: 3,
        }
    }

    pub fn new_graph(graph: FlowGraph) -> ICFG {
        ICFG {
            graph,
            procedures: ProcedureMap::new(),
            rev_topograph: Vec::new(),
            dup_cnt: 3,
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

    pub fn add_procedure(&mut self, node_id: NodeId, proc: Procedure) {
        self.procedures.insert(node_id, RwLock::new(proc));
    }

    /// Adds an edge [from] -> [to]. The procedures can be passed optionally. If a procedure given
    /// is None, it is expected that the iCFG already contains it.
    /// Otherwise it panics.
    /// If [addr_to_update] is Some, it is assume that the newly added edge was discovered
    /// via an indirect call/jump. The instruction at [addr_to_update] is updated accordingly.
    pub fn add_edge(
        &mut self,
        from: (NodeId, Option<Procedure>),
        to: (NodeId, Option<Procedure>),
        addr_to_update: Option<NodeId>,
    ) {
        let from_nid = from.0;
        let to_nid = to.0;
        if !self.has_procedure(&from_nid) {
            if from.1.is_none() {
                panic!(
                    "Cannot add edge ({} -> {}), no procedure given",
                    from_nid, to_nid
                );
            }
            let mut from_proc = from.1.unwrap();
            if addr_to_update.is_some() {
                from_proc.update_call_target(&from_nid, -1, &to_nid);
            }
            self.add_procedure(from_nid, from_proc);
        }
        if !self.has_procedure(&to_nid) {
            if to.1.is_none() {
                panic!(
                    "Cannot add edge ({} -> {}), no procedure given",
                    from_nid, to_nid
                );
            }
            self.add_procedure(to_nid, to.1.unwrap());
        }

        // Add actual edge
        if self.graph.contains_edge(from_nid, to_nid) {
            return;
        }
        self.graph.add_edge(from_nid, to_nid, 0);
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
    pub fn resolve_loops(&mut self, num_threads: usize, wmap: &RwLock<WeightMap>) {
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
                            writeable_proc.get_cfg_mut().make_acyclic(wmap, None);
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
        self.make_acyclic(wmap, Some("Make iCFG acyclic".to_owned()));
    }
}

impl FlowGraphOperations for ICFG {
    fn set_node_dup_count(&mut self, dup_cnt: usize) {
        self.dup_cnt = dup_cnt;
    }

    fn get_node_dup_count(&self) -> usize {
        self.dup_cnt
    }

    fn get_graph_mut(&mut self) -> &mut FlowGraph {
        &mut self.graph
    }

    /// If we have cloned several CFGs, we need to update the calls in each of them.
    /// Since a call node has the target address attached in its meta data, we might need to update
    /// it to a cloned or not cloned procedure CFG.
    fn clean_up_acyclic(&mut self, _wmap: &RwLock<WeightMap>) {
        // Runtime: |V_icfg| * |V_cfg| + |E_icfg|
        let mut to_update = HashSet::<NodeId>::new();
        // O(E_icfg)
        for (from_id, to_id, _) in self.get_graph().all_edges() {
            if !to_update.contains(&from_id) {
                to_update.insert(from_id);
            }
            if !to_update.contains(&to_id) {
                to_update.insert(to_id);
            }
        }

        // O(V_icfg)
        for cfg_id in to_update.iter() {
            // O(V_cfg)
            for nmeta in self
                .get_procedure(cfg_id)
                .write()
                .unwrap()
                .get_cfg_mut()
                .nodes_meta
                .values_mut()
            {
                // O(1) - instruction words have a constant length
                for i in nmeta.insns.iter_mut() {
                    // Either the call target is within the same CFG, it is
                    // in the next CFG clone or has no edge in the iCFG.
                    if i.itype.weight_type != InsnNodeWeightType::Call {
                        continue;
                    }
                    // The call target cannot point backwards to a previous clone.
                    i.call_target.icfg_clone_id = cfg_id.icfg_clone_id;
                    // Call target edge is within the original CFG.
                    if self.get_graph().contains_edge(*cfg_id, i.call_target) {
                        continue;
                    }
                    // Call target edge points to the next CFG clone in the iCFG.
                    let clone = i.call_target.get_next_icfg_clone();
                    if self.get_graph().contains_edge(*cfg_id, clone) {
                        i.call_target = clone;
                        continue;
                    }
                    // This is the special case of the last clone.
                    // Its call edge was not not duplicated in the iCFG
                    // so we need to transform the node to a normal node.
                    i.call_target = INVALID_NODE_ID;
                    i.itype.weight_type = InsnNodeWeightType::Normal;
                }
            }
        }
    }

    fn get_graph(&self) -> &FlowGraph {
        &self.graph
    }

    fn set_rev_topograph_mut(&mut self, rev_topograph: Vec<NodeId>) {
        self.rev_topograph = rev_topograph;
    }

    /// Increments [nid.icfg_clone_count] by [increment].
    fn get_next_node_id_clone(increment: u32, nid: NodeId) -> NodeId {
        let mut clone: NodeId = nid.clone();
        clone.icfg_clone_id += increment;
        clone
    }

    fn add_cloned_edge(&mut self, from: NodeId, to: NodeId, wmap: &RwLock<WeightMap>) {
        if !self.graph.contains_edge(from, to) {
            self.graph.add_edge(from, to, 0);
        }
        if !self.procedures.contains_key(&from) {
            let mut cloned_proc = self
                .get_procedure(&from.get_orig_node_id())
                .read()
                .unwrap()
                .get_clone(from.icfg_clone_id);
            cloned_proc.get_cfg_mut().make_acyclic(wmap, None);
            self.add_procedure(from, cloned_proc);
        }

        if !self.procedures.contains_key(&to) {
            let mut cloned_proc = self
                .get_procedure(&to.get_orig_node_id())
                .read()
                .unwrap()
                .get_clone(to.icfg_clone_id);
            cloned_proc.get_cfg_mut().make_acyclic(wmap, None);
            self.add_procedure(to, cloned_proc);
        }
    }

    /// Returns the WeightID for [nid].
    /// [nid] must point to a valid CFG. Otherwise the function panics.
    fn calc_node_weight(
        &mut self,
        nid: &NodeId,
        proc_map: &ProcedureMap,
        wmap: &RwLock<WeightMap>,
        recalc: bool,
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
            .calc_node_weight(nid, proc_map, wmap, recalc)
    }
}
