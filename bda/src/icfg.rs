// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::{
    collections::{HashMap, HashSet},
    sync::RwLock,
    thread::{self, ScopedJoinHandle},
};

use helper::{progress::ProgressBar, spinner::Spinner};
use petgraph::algo::toposort;

use crate::{
    cfg::{InsnNodeType, InsnNodeWeightType, CFG},
    flow_graphs::{FlowGraph, FlowGraphOperations, NodeId, ProcedureMap, INVALID_NODE_ID},
    weight::{WeightID, WeightMap},
};

/// A node in an iCFG describing a procedure.
pub struct Procedure {
    // The CFG of the procedure. Must be None if already added.
    cfg: Option<CFG>,
    /// Flag if this procedure is malloc.
    is_malloc: bool,
}

impl Procedure {
    pub fn new(cfg: Option<CFG>, is_malloc: bool) -> Procedure {
        Procedure { cfg, is_malloc }
    }

    pub fn get_cfg(&self) -> &CFG {
        match &self.cfg {
            Some(cfg) => &cfg,
            None => panic!("Procedure has no CFG defined."),
        }
    }

    pub fn get_cfg_mut(&mut self) -> &mut CFG {
        match &mut self.cfg {
            Some(ref mut cfg) => cfg,
            None => panic!("Procedure has no CFG defined."),
        }
    }

    pub fn get_clone(&self, icfg_clone_id: u32) -> Procedure {
        Procedure {
            cfg: Some(self.get_cfg().get_clone(icfg_clone_id)),
            is_malloc: self.is_malloc,
        }
    }
}

/// An inter-procedual control flow graph.
pub struct ICFG {
    /// The actual graph. Nodes are indexed by the entry node id of the procedures.
    graph: FlowGraph,
    /// Map of procedures in the CFG. Indexed by entry point node id.
    pub procedures: ProcedureMap,
    /// Reverse topoloical sorted graph
    rev_topograph: Vec<NodeId>,
}

impl ICFG {
    pub fn new() -> ICFG {
        ICFG {
            graph: FlowGraph::new(),
            procedures: ProcedureMap::new(),
            rev_topograph: Vec::new(),
        }
    }

    pub fn new_graph(graph: FlowGraph) -> ICFG {
        ICFG {
            graph,
            procedures: ProcedureMap::new(),
            rev_topograph: Vec::new(),
        }
    }

    pub fn print_stats(&self) {
        println!("iCFG stats");
        println!("\tCFGs: {}", self.graph.node_count());
        println!("\tEdges: {}", self.graph.edge_count());
    }

    pub fn has_malloc(&self) -> bool {
        for p in self.procedures.keys() {
            if self.get_procedure(p).read().unwrap().is_malloc {
                return true;
            }
        }
        false
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

    /// Adds an edge to the graph.
    /// The edge is only added once.
    pub fn add_edge(&mut self, from: (NodeId, Procedure), to: (NodeId, Procedure)) {
        // Check if a procedure is located at the actual address.
        if !self.procedures.contains_key(&from.0) {
            if from.1.cfg.is_none() {
                panic!("If a new node is added to the iCFG, the procedure can not be None.");
            }
            self.add_procedure(from.0, from.1);
        }
        if !self.procedures.contains_key(&to.0) {
            if to.1.cfg.is_none() {
                panic!("If a new node is added to the iCFG, the procedure can not be None.");
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

    fn sort(&mut self) {
        // Remove cycles
        self.rev_topograph = match toposort(&self.graph, None) {
            Ok(graph) => graph,
            Err(_) => panic!("Graph contains cycles. Cannot sort it to topological order."),
        };
        self.rev_topograph.reverse();
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
