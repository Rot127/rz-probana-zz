// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::{
    collections::{HashMap, HashSet},
    sync::RwLock,
    thread::{self, ScopedJoinHandle},
};

use helper::progress::ProgressBar;
use petgraph::{
    algo::toposort,
    Direction::{Incoming, Outgoing},
};

use crate::{
    cfg::{InsnNodeWeightType, CFG},
    flow_graphs::{
        FlowGraph, FlowGraphOperations, NodeId, SamplingBias, Weight, UNDETERMINED_WEIGHT,
    },
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
    procedures: HashMap<NodeId, RwLock<Procedure>>,
    /// Reverse topoloical sorted graph
    rev_topograph: Vec<NodeId>,
}

macro_rules! get_procedure_mut {
    ($self:ident, $pid:expr) => {
        match $self.procedures.get_mut($pid) {
            Some(p) => p.get_mut().unwrap(),
            None => panic!("The iCFG has no procedure for {}.", $pid),
        }
    };
}

impl ICFG {
    pub fn new() -> ICFG {
        ICFG {
            graph: FlowGraph::new(),
            procedures: HashMap::new(),
            rev_topograph: Vec::new(),
        }
    }

    pub fn new_graph(graph: FlowGraph) -> ICFG {
        ICFG {
            graph,
            procedures: HashMap::new(),
            rev_topograph: Vec::new(),
        }
    }

    pub fn has_malloc(&self) -> bool {
        for p in self.procedures.keys() {
            if self.get_procedure(p).read().unwrap().is_malloc {
                return true;
            }
        }
        false
    }

    pub fn get_procedure_mut(&mut self, pid: &NodeId) -> &mut Procedure {
        get_procedure_mut!(self, pid)
    }

    pub fn get_procedure(&self, pid: &NodeId) -> &RwLock<Procedure> {
        match self.procedures.get(pid) {
            Some(p) => p,
            None => panic!("The iCFG has no procedure for {}.", pid),
        }
    }

    pub fn get_procedure_weight(&self, proc_nid: NodeId) -> Weight {
        self.get_procedure(&proc_nid)
            .read()
            .unwrap()
            .get_cfg()
            .get_weight()
    }

    pub fn add_procedure(&mut self, node_id: NodeId, proc: Procedure) {
        self.procedures.insert(node_id, RwLock::new(proc));
    }

    fn get_successor_weights(&self, procedure: &NodeId) -> HashMap<NodeId, Weight> {
        let mut succ_weight: HashMap<NodeId, Weight> = HashMap::new();
        for neigh in self.graph.neighbors_directed(*procedure, Outgoing) {
            let nw: Weight = self.get_procedure_weight(neigh);
            succ_weight.insert(neigh, nw);
        }
        succ_weight
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
            self.graph.add_edge(from.0, to.0, SamplingBias::new_unset());
        }
    }

    pub fn num_procedures(&self) -> usize {
        self.procedures.len()
    }

    /// Resolve all loops in the iCFG and all its CFGs.
    pub fn resolve_loops(&mut self, num_threads: usize) {
        let mut progress = ProgressBar::new(
            format!("Resolving loops ({} threads)", num_threads),
            self.num_procedures(),
        );
        let mut resolved: usize = 0;
        let mut todo: Vec<NodeId> = self.procedures.keys().cloned().collect();
        let num_procedures = self.num_procedures();

        thread::scope(|s| {
            let mut threads: HashMap<usize, ScopedJoinHandle<_>> = HashMap::new();
            loop {
                progress.update_print(resolved);
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
                            writeable_proc.get_cfg_mut().make_acyclic();
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
        println!("Make ICFG acyclic");
        self.make_acyclic();
    }
}

impl FlowGraphOperations for ICFG {
    fn get_graph_mut(&mut self) -> &mut FlowGraph {
        &mut self.graph
    }

    /// If we have cloned several CFGs, we need to update the calls in each of them.
    /// Since a call node has the target address attached in its meta data, we might need to update
    /// it to a cloned or not cloned procedure CFG.
    /// This deletes saved weights. So calc_weight() must be run again.
    /// TODO Replace this with a HashMap. So we do not iterate over it. This is horrible inefficient
    fn clean_up_acyclic(&mut self) {
        // |V| * |E| * |V_cfg| elements all the time.
        let mut to_update = HashSet::new();
        for (from_id, to_id, _) in self.get_graph().all_edges() {
            to_update.insert((from_id, to_id));
        }
        for (p_id, proc_lock) in self.procedures.iter_mut() {
            let proc = proc_lock.get_mut().unwrap();
            proc.get_cfg_mut().call_target_weights.clear();
            for (from, to) in to_update.iter() {
                if from != p_id {
                    continue;
                }
                proc.get_cfg_mut().set_call_weight(*to, UNDETERMINED_WEIGHT);
                for nmeta in proc.get_cfg_mut().nodes_meta.values_mut() {
                    if !nmeta.has_type(InsnNodeWeightType::Call) {
                        continue;
                    }
                    nmeta.update_call_target(*to);
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

    /// Calculate the weight of the whole iCFG and all CFGs part of it.
    fn calc_weight(&mut self) -> Weight {
        self.sort();
        for (i, pid) in self.rev_topograph.iter().enumerate() {
            // Get weight of all successor procedures (procedures at outgoing edges)
            let succ_weights = self.get_successor_weights(pid);
            let procedure: &mut Procedure = get_procedure_mut!(self, pid);
            // Update the weights of the called procedures.
            for (target_proc_nid, target_proc_weight) in succ_weights.iter() {
                procedure
                    .get_cfg_mut()
                    .set_call_weight(*target_proc_nid, *target_proc_weight);
            }
            let pweight = procedure.get_cfg_mut().calc_weight();

            // Update weight of outgoing edges
            for (neighbor_nid, neighbor_weight) in succ_weights.iter() {
                let bias: SamplingBias = SamplingBias {
                    numerator: *neighbor_weight,
                    denominator: procedure.get_cfg().get_weight(),
                };
                self.graph.add_edge(*pid, *neighbor_nid, bias);
            }

            // Now we know the weight of the procedure at pid.
            // Every CFG which calls this procedure, needs to be update with its weight.
            for i in self.graph.neighbors_directed(*pid, Incoming) {
                get_procedure_mut!(self, &i)
                    .get_cfg_mut()
                    .update_procedure_weight(*pid, pweight);
            }
            print!(
                "\rCalculated {}/{} CFG weights.",
                i,
                self.rev_topograph.len()
            );
        }
        println!();
        if self.num_procedures() == 0 {
            return UNDETERMINED_WEIGHT;
        }
        self.get_procedure(match self.rev_topograph.last() {
            Some(a) => a,
            None => panic!("Can not return a weight if no CFG was added."),
        })
        .read()
        .unwrap()
        .get_cfg()
        .get_weight()
    }

    fn add_cloned_edge(&mut self, from: NodeId, to: NodeId) {
        if !self.graph.contains_edge(from, to) {
            self.graph.add_edge(from, to, SamplingBias::new_unset());
        }
        if !self.procedures.contains_key(&from) {
            let orig_proc = self
                .get_procedure(&from.get_orig_node_id())
                .read()
                .unwrap()
                .get_clone(from.icfg_clone_id);
            self.add_procedure(from, orig_proc);
        }

        if !self.procedures.contains_key(&to) {
            let orig_proc = self
                .get_procedure(&to.get_orig_node_id())
                .read()
                .unwrap()
                .get_clone(to.icfg_clone_id);
            self.add_procedure(to, orig_proc);
        }
    }
}
