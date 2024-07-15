// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::{collections::VecDeque, sync::RwLock};

use petgraph::Direction::Outgoing;
use rand::{thread_rng, Rng};
use rzil_abstr::interpreter::{AddrInfo, IntrpPath};

use crate::{
    cfg::{InsnNodeWeightType, CFG},
    flow_graphs::{Address, FlowGraphOperations, NodeId},
    icfg::ICFG,
    weight::{WeightID, WeightMap},
};

#[derive(Debug)]
pub struct PathNodeInfo {
    /// True if the iword calls another procedure.
    is_call: bool,
    /// True if the iword calls malloc.
    calls_malloc: bool,
    /// True if the iword calls an input function.
    calls_input: bool,
    /// True if the iword calls an unmapped function.
    calls_unmapped: bool,
    /// True if the iword is executed after a call from a subroutine.
    is_return_point: bool,
}

impl PathNodeInfo {
    fn as_addr_info(&self) -> AddrInfo {
        AddrInfo::new(
            self.is_call,
            self.calls_malloc,
            self.calls_input,
            self.calls_unmapped,
            self.is_return_point,
        )
    }
}

#[derive(Debug)]
pub struct Path {
    path: Vec<NodeId>,
    node_info: Vec<PathNodeInfo>,
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
            node_info: Vec::new(),
        }
    }

    // Function only used in macro and is not detected as used.
    #[allow(dead_code)]
    pub fn from(path: Vec<NodeId>) -> Path {
        Path {
            path,
            node_info: Vec::new(),
        }
    }

    pub fn push(&mut self, nid: NodeId, info: PathNodeInfo) {
        self.path.push(nid);
        self.node_info.push(info);
    }

    /// Translates the path to an interpreter path.
    pub fn to_addr_path(self) -> IntrpPath {
        assert!(
            self.path.len() == self.node_info.len(),
            "Length of node and info vector don't match"
        );
        let mut ipath: IntrpPath = IntrpPath::new();
        for (n, info) in self.path.into_iter().zip(self.node_info) {
            ipath.push(n.address, Some(info.as_addr_info()));
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
        let n = if w_choice.exp < w_rest.exp {
            0
        } else {
            w_choice.exp - w_rest.exp
        };
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
            let r: u64 = rng.gen_range(
                0..(w_choice
                    .sig
                    .saturating_mul(u64::pow(2, n as u32))
                    .saturating_add(w_rest.sig)),
            );
            if r >= w_rest.sig {
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
    addr_ranges: &Vec<(Address, Address)>,
) {
    // Flag if the instruction at the previous neighbor address was a call.
    let mut node_follows_call = false;
    let mut cur = start;
    loop {
        if !addr_ranges.is_empty()
            && addr_ranges
                .iter()
                .all(|r| cur.address < r.0 || r.1 < cur.address)
        {
            return;
        }
        let mut ninfo = PathNodeInfo {
            is_call: false,
            calls_malloc: false,
            calls_input: false,
            calls_unmapped: false,
            is_return_point: node_follows_call,
        };
        if node_follows_call {
            node_follows_call = false;
        }

        // println!("{}", format!("{}-> {}", " ".repeat(i), cur));
        if cfg.nodes_meta.get(&cur).is_some_and(|meta| {
            meta.insns
                .iter()
                .any(|i| i.itype.weight_type == InsnNodeWeightType::Call)
        }) {
            // For indirect calls without an set address we do not recuse into it to sample a path.
            // Put we set the meta information for the path node (marking it as call).
            ninfo.is_call = true;
            node_follows_call = true;
            // The instr. word has a call.
            // First visit these procedures and add it to the path
            let call_targets = cfg
                .nodes_meta
                .get(&cur)
                .unwrap()
                .insns
                .iter()
                .filter_map(|i| {
                    if !i.call_targets.is_empty() {
                        Some(i.call_targets.clone())
                    } else {
                        None
                    }
                });
            // Only works for iwords with a single call instructions
            if let Some(cts) = call_targets.last() {
                let ct = cts.sample();
                if icfg.is_malloc(&ct) {
                    ninfo.calls_malloc = true;
                }
                if icfg.is_input(&ct) {
                    ninfo.calls_input = true;
                }
                if icfg.is_unmapped(&ct) {
                    ninfo.calls_unmapped = true;
                }

                if ninfo.calls_unmapped || ninfo.calls_malloc || ninfo.calls_input {
                    // Either a dynamically linked procedure (without CFG)
                    // or a malloc/input call. We don't recurse in those.
                    path.push(cur, ninfo);
                } else {
                    // recurse into CFG to sample a new path.
                    path.push(cur, ninfo);
                    sample_cfg_path(
                        icfg,
                        icfg.get_procedure(&ct).write().unwrap().get_cfg_mut(),
                        ct,
                        path,
                        i + 1,
                        wmap,
                        addr_ranges,
                    );
                }
            } else {
                path.push(cur, ninfo);
            }
        } else {
            path.push(cur, ninfo);
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
pub fn sample_path(
    icfg: &ICFG,
    entry_point: Address,
    wmap: &RwLock<WeightMap>,
    addr_ranges: &Vec<(Address, Address)>,
) -> Path {
    let entry_node: NodeId;
    let mut path = Path::new();
    let mut entry_proc: std::sync::RwLockWriteGuard<'_, crate::cfg::Procedure>;
    entry_proc = icfg
        .get_procedure(&NodeId::new_original(entry_point))
        .write()
        .unwrap();
    entry_node = entry_proc.get_cfg().get_entry();
    sample_cfg_path(
        icfg,
        entry_proc.get_cfg_mut(),
        entry_node,
        &mut path,
        0,
        wmap,
        addr_ranges,
    );
    path
}
