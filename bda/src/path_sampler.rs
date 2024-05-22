// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::{
    collections::{HashMap, VecDeque},
    sync::RwLock,
};

use binding::{log_rizin, log_rz, LOG_DEBUG};
use petgraph::Direction::Outgoing;
use rand::{thread_rng, Rng};
use rzil_abstr::interpreter::{AddrInfo, IntrpPath};

use crate::{
    cfg::CFG,
    flow_graphs::{Address, FlowGraphOperations, NodeId},
    icfg::ICFG,
    weight::{WeightID, WeightMap},
};

#[derive(Debug)]
pub struct PathNodeInfo {
    is_proc_entry: bool,
}

#[derive(Debug)]
pub struct Path {
    path: Vec<NodeId>,
    node_info: HashMap<NodeId, PathNodeInfo>,
}

impl std::hash::Hash for Path {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.path.hash(state);
    }
}

impl Eq for Path {}

impl PartialEq for Path {
    fn eq(&self, other: &Self) -> bool {
        PartialEq::eq(&self.path, &other.path)
    }
}

impl Path {
    pub fn new() -> Path {
        Path {
            path: Vec::new(),
            node_info: HashMap::new(),
        }
    }

    // Function only used in macro and is not detected as used.
    #[allow(dead_code)]
    pub fn from(path: Vec<NodeId>) -> Path {
        Path {
            path,
            node_info: HashMap::new(),
        }
    }

    pub fn push(&mut self, nid: NodeId, info: Option<PathNodeInfo>) {
        self.path.push(nid);
        if info.is_some() {
            self.node_info.insert(nid, info.unwrap());
        }
    }

    /// Translates the path to an interpreter path.
    pub fn to_addr_path(&self) -> IntrpPath {
        let mut ipath: IntrpPath = IntrpPath::new();
        for n in self.path.iter() {
            ipath.push(n.address);
        }
        for (n, i) in self.node_info.iter() {
            if i.is_proc_entry {
                ipath.push_info(n.address, AddrInfo::IsProcEntry)
            }
        }
        ipath
    }
}

impl std::fmt::Display for Path {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut res = write!(f, "p[");
        for (i, n) in self.path.iter().enumerate() {
            if i != 0 {
                res = res.or(write!(f, " -> {}", n));
            } else {
                res = res.or(write!(f, "{}", n));
            }
        }
        res.or(write!(f, "]"))
    }
}

#[derive(Clone)]
struct ApproxW {
    pub exp: u64,
    pub sig: u64,
}

impl ApproxW {
    fn new() -> ApproxW {
        ApproxW { exp: 0, sig: 0 }
    }
}

/// Returns a the approximated weight of the given weights.
/// If [weights] contains more then one element, they are summed and then approximated.
fn approximate_weights(weights: &VecDeque<WeightID>, wmap: &RwLock<WeightMap>) -> ApproxW {
    assert!(weights.len() > 0, "No weights given.");
    let mut sum: WeightID = wmap.read().unwrap().get_zero();
    for w in weights {
        sum = sum.add(w, wmap);
    }
    let mut aw = ApproxW::new();
    aw.exp = u64::max(sum.log2(wmap), 63) - 63;
    aw.sig = sum.get_msbs(wmap, 64 as u32);
    aw
}

/// Selects a branch based on the given weights.
/// Returns the index into [weights]. So the node which has the weight [weights]\[i\] should be taken.
/// Implementation after Algorithm 2 [2] modified for n weights.
///
/// Modifications:
///
/// We let the different weights compete against each other.
/// We always compare the weights of a candidate node against the sum of weights
/// of all the rest.
/// If the candiate wins, its index is returned.
/// If the rest is selected, the current candidate is dropped and a new candiadate is
/// taken from the rest and the comparision is done again.
/// The algorithm terminates if either one of candiates was chosen, all candidates
/// lost, in which case the last index is returned.
///
/// [^2] https://doi.org/10.25394/PGS.23542014.v1
fn select_branch(mut weights: VecDeque<WeightID>, wmap: &RwLock<WeightMap>) -> usize {
    if weights.len() == 1 {
        return 0;
    }
    let mut rng = thread_rng();
    let mut candidate = 0;
    let mut next_cnd = 1;
    loop {
        if weights.len() == 1 {
            break;
        }
        // Sample with one branches weight and the sum of the rest.
        let mut choice_app = VecDeque::new();
        choice_app.push_back(weights.pop_front().unwrap());
        let w_choice = approximate_weights(&choice_app, wmap);
        let w_rest = approximate_weights(&weights, wmap);
        let n = w_choice.exp - w_rest.exp;
        if n >= 64 {
            for _ in 0..n {
                if rng.gen_bool(0.5) {
                    return candidate;
                }
            }
            let r: usize = rng.gen_range(0..w_choice.sig as usize);
            if r >= w_rest.sig as usize {
                return candidate;
            }
        } else {
            let r: usize = rng
                .gen_range(0..(w_choice.sig * u64::pow(2, n as u32) + w_rest.sig as u64) as usize);
            if r >= w_rest.sig as usize {
                return candidate;
            }
        }
        candidate = next_cnd;
        next_cnd += 1;
    }
    candidate
}

fn sample_cfg_path(
    icfg: &ICFG,
    cfg: &mut CFG,
    start: NodeId,
    path: &mut Path,
    i: usize,
    wmap: &RwLock<WeightMap>,
) {
    let mut cur = start;
    loop {
        path.push(
            cur,
            Some(PathNodeInfo {
                is_proc_entry: icfg.is_procedure(&cur),
            }),
        );
        log_rz!(LOG_DEBUG, None, format!("{} -> {}", " ".repeat(i), cur));
        if cfg.nodes_meta.get(&cur).is_some_and(|meta| {
            meta.insns
                .iter()
                .any(|i| !i.call_target.is_invalid_call_target())
        }) {
            // The instr. word has a call.
            // First visit this procedure and add it to the path
            let call_targets = cfg
                .nodes_meta
                .get(&cur)
                .unwrap()
                .insns
                .iter()
                .filter_map(|i| {
                    if !i.call_target.is_invalid_call_target() {
                        Some(i.call_target)
                    } else {
                        None
                    }
                });
            call_targets.for_each(|ct| {
                let entry = icfg
                    .get_procedure(&ct)
                    .read()
                    .unwrap()
                    .get_cfg()
                    .get_entry();
                sample_cfg_path(
                    icfg,
                    icfg.get_procedure(&ct).write().unwrap().get_cfg_mut(),
                    entry,
                    path,
                    i + 1,
                    wmap,
                )
            });
        }

        // Visit all neighbors and decide which one to add to the path
        let mut neigh_ids: Vec<NodeId> = Vec::new();
        let mut neigh_weights: VecDeque<WeightID> = VecDeque::new();
        for n in cfg.graph.neighbors_directed(cur, Outgoing) {
            neigh_ids.push(n);
        }
        for n in neigh_ids.iter() {
            let recalc = cfg.needs_recalc(icfg.get_procedures());
            neigh_weights.push_back(cfg.calc_node_weight(&n, icfg.get_procedures(), wmap, recalc));
        }
        if neigh_ids.is_empty() {
            // Leaf node. We are done
            break;
        }
        let picked_neighbor = *neigh_ids.get(select_branch(neigh_weights, wmap)).unwrap();
        if picked_neighbor == cur {
            panic!("Unresolved loop in CFG detected at node {}.", cur);
        }
        cur = picked_neighbor;
    }
}

/// Sample a path from the given [icfg] and return it as vector.
pub fn sample_path(icfg: &ICFG, entry_point: Address, wmap: &RwLock<WeightMap>) -> Path {
    let mut entry_proc = icfg
        .get_procedure(&NodeId::new_original(entry_point))
        .write()
        .unwrap();
    let mut path = Path::new();
    let entry_node = entry_proc.get_cfg().get_entry();
    sample_cfg_path(
        icfg,
        entry_proc.get_cfg_mut(),
        entry_node,
        &mut path,
        0,
        wmap,
    );
    path
}
