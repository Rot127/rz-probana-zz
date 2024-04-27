// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::{
    collections::{HashMap, HashSet},
    sync::RwLock,
    thread::{self, ScopedJoinHandle},
};

use helper::{
    progress::{ProgressBar, Task, TaskStatus},
    spinner::Spinner,
};
use petgraph::{algo::toposort, Direction::Outgoing};

use crate::{
    cfg::{InsnNodeWeightType, CFG},
    flow_graphs::{FlowGraph, FlowGraphOperations, NodeId},
    weight::{NodeWeightIDMap, WeightID, WeightMap, UNDETERMINED_WEIGHT},
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

type ProcedureMap = HashMap<NodeId, RwLock<Procedure>>;

/// An inter-procedual control flow graph.
pub struct ICFG {
    /// The actual graph. Nodes are indexed by the entry node id of the procedures.
    graph: FlowGraph,
    /// Map of procedures in the CFG. Indexed by entry point node id.
    procedures: ProcedureMap,
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

    pub fn get_procedure_mut(&mut self, pid: &NodeId) -> &mut Procedure {
        get_procedure_mut!(self, pid)
    }

    pub fn get_procedure(&self, pid: &NodeId) -> &RwLock<Procedure> {
        let p = match self.procedures.get(pid) {
            Some(p) => p,
            None => panic!("The iCFG has no procedure for {}.", pid),
        };
        p
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

        let mut spinner = Spinner::new();
        thread::scope(|s| {
            spinner.update("Make iCFG acyclic".to_owned());
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
                            writeable_proc.get_cfg_mut().make_acyclic(wmap);
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
        self.make_acyclic(wmap);
        spinner.done(format!(
            "Result: CFGs: {} Edges: {}",
            self.graph.node_count(),
            self.graph.edge_count()
        ));
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
    fn clean_up_acyclic(&mut self, wmap: &RwLock<WeightMap>) {
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
                proc.get_cfg_mut()
                    .set_call_weight(*to, UNDETERMINED_WEIGHT!(wmap));
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

    fn calc_weight(&mut self, wmap: &RwLock<WeightMap>) -> Option<&WeightID> {
        if self.num_procedures() == 0 {
            return None;
        }

        self.sort();
        let topo = &self.rev_topograph;
        assert!(!topo.is_empty());

        let mut k_max: u32 = 0;
        let mut k_acc = 0;
        let mut k_cnt = 1;
        let graph = &self.graph;
        let procs = &mut self.procedures;
        let mut progress = ProgressBar::new("Calc weight".to_string(), procs.len());
        for (i, pid) in topo.iter().enumerate() {
            let num_weights = wmap.read().unwrap().num_weights();
            progress.update_print(
                i + 1,
                Some(format!(
                    "k = avg.: {} max: {} - num weights = {}",
                    k_acc / k_cnt,
                    k_max,
                    num_weights
                )),
            );
            // Proc: Get weight of successors
            let succ = get_succ_weights(graph, pid, procs);
            let mut proc = {
                match procs.get_mut(pid) {
                    Some(p) => p.write().unwrap(),
                    None => panic!("The iCFG has no procedure for {}.", pid),
                }
            };
            // Proc: Update call targets with the weight of successors
            for (target_proc_nid, target_proc_weight) in succ.iter() {
                proc.get_cfg_mut()
                    .set_call_weight(*target_proc_nid, target_proc_weight.to_owned());
            }
            // Proc: Calc CFG weight
            let weight_id = proc.get_cfg_mut().calc_weight(wmap).unwrap();
            if wmap.read().unwrap().get_weight(weight_id).is_some() {
                let sig_bits = wmap
                    .read()
                    .unwrap()
                    .get_weight(weight_id)
                    .unwrap()
                    .significant_bits();
                k_acc += sig_bits as usize;
                k_cnt += 1;
                if sig_bits > k_max {
                    k_max = sig_bits
                }
            }
        }
        None
    }

    fn add_cloned_edge(&mut self, from: NodeId, to: NodeId, _wmap: &RwLock<WeightMap>) {
        if !self.graph.contains_edge(from, to) {
            self.graph.add_edge(from, to, 0);
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

fn get_succ_weights(
    graph: &FlowGraph,
    pid: &NodeId,
    procs: &mut ProcedureMap,
) -> HashMap<NodeId, WeightID> {
    let mut succ_weight: NodeWeightIDMap = HashMap::new();
    for neigh in graph.neighbors_directed(*pid, Outgoing) {
        succ_weight.insert(
            neigh,
            procs
                .get(&neigh)
                .unwrap()
                .read()
                .unwrap()
                .get_cfg()
                .get_weight_id()
                .to_owned(),
        );
    }
    succ_weight
}
