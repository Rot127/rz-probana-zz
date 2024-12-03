// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::{collections::VecDeque, sync::RwLock};

use petgraph::Direction::Outgoing;
use rand::{thread_rng, Rng};
use rzil_abstr::interpreter::{IWordInfo, IntrpPath};

use crate::{
    cfg::CFG,
    flow_graphs::{Address, NodeId, NodeIdSet, INVALID_NODE_ID},
    icfg::ICFG,
    weight::{WeightID, WeightMap},
};

#[derive(Debug)]
pub struct Path {
    path: Vec<NodeId>,
    node_info: Vec<IWordInfo>,
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

    pub fn push(&mut self, nid: NodeId, info: IWordInfo) {
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
            ipath.push(n.address, info);
        }
        ipath
    }

    pub(crate) fn len(&self) -> usize {
        self.path.len()
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

fn node_in_ranges(nid: &NodeId, addr_ranges: &Vec<(Address, Address)>) -> bool {
    addr_ranges.is_empty()
        || addr_ranges
            .iter()
            .any(|r| r.0 <= nid.address && nid.address <= r.1)
}

fn filter_call_targets(
    cfg: &mut CFG,
    cur: NodeId,
    addr_ranges: Option<&Vec<(Address, Address)>>,
) -> NodeIdSet {
    let mut call_targets = NodeIdSet::new();
    for i in cfg.nodes_meta.get(&cur).unwrap().insns.iter() {
        if i.call_targets.is_empty() {
            continue;
        }
        i.call_targets.iter().for_each(|ct| {
            if addr_ranges.is_some_and(|ar| node_in_ranges(ct, ar)) {
                call_targets.insert(ct.clone());
            }
        });
    }
    call_targets
}

fn filter_jump_targets(
    cfg: &mut CFG,
    cur: NodeId,
    addr_ranges: &Vec<(Address, Address)>,
) -> NodeIdSet {
    let mut jump_targets = NodeIdSet::new();
    for i in cfg.nodes_meta.get(&cur).unwrap().insns.iter() {
        if i.orig_jump_targets.is_empty() {
            continue;
        }
        i.orig_jump_targets.iter().for_each(|ct| {
            if node_in_ranges(ct, addr_ranges) {
                jump_targets.insert(ct.clone());
            }
        });
    }
    jump_targets
}

#[derive(PartialEq, Eq)]
enum SamplingState {
    Continue,
    Exit,
}

fn sample_cfg_path(
    icfg: &ICFG,
    cfg: &mut CFG,
    start: NodeId,
    path: &mut Path,
    i: usize,
    wmap: &RwLock<WeightMap>,
    addr_ranges: &Vec<(Address, Address)>,
) -> SamplingState {
    let entry = &cfg.get_entry();
    let cfg_needs_recalc = wmap.read().unwrap().needs_recalc(entry);
    if cfg_needs_recalc {
        // Getting the entry point requires to calculate the whole CFG.
        cfg.get_entry_weight_id(&icfg.procedures, wmap)
            .expect("Invalid CFG");
    }
    // Flag if the instruction at the previous neighbor address was a call.
    let mut node_follows_call = false;
    let mut cur = start;
    loop {
        if !node_in_ranges(&cur, addr_ranges) {
            return SamplingState::Continue;
        }
        let ninfo = get_node_info(cur, &mut node_follows_call, icfg, cfg);
        if ninfo.is_exit() {
            // Last node in path
            path.push(cur, ninfo);
            return SamplingState::Exit;
        }

        let mut res = SamplingState::Continue;
        // println!("{}", format!("{}-> {}", " ".repeat(i), cur));
        if ninfo.is_call() {
            let call_targets = filter_call_targets(cfg, cur, Some(addr_ranges));

            if ninfo.calls_unmapped() || ninfo.calls_malloc() || ninfo.calls_input() {
                // Either a dynamically linked procedure (without CFG)
                // a malloc/input call or indirect call with unknown addresses.
                // We don't recurse in those.
                path.push(cur, ninfo);
                // These calls are effectively not followed.
                // So the next instruction does not follow a semantic call.
                node_follows_call = false;
            } else {
                node_follows_call = true;
                // recurse into CFG to sample a new path.
                path.push(cur, ninfo);
                let ct = call_targets.sample();
                if ct != INVALID_NODE_ID {
                    if sample_cfg_path(
                        icfg,
                        icfg.get_procedure(&ct).write().unwrap().get_cfg_mut(),
                        ct,
                        path,
                        i + 1,
                        wmap,
                        addr_ranges,
                    ) == SamplingState::Exit
                    {
                        // Stop sampling if exit was reached deeper in the tree.
                        return SamplingState::Exit;
                    }
                }
                // Go to following node
            }
        } else if is_tail_call(cfg, cur) {
            path.push(cur, ninfo);
            let jump_targets = filter_jump_targets(cfg, cur, addr_ranges);
            let jt = jump_targets.sample();
            if jt != INVALID_NODE_ID {
                res = sample_cfg_path(
                    icfg,
                    icfg.get_procedure(&jt).write().unwrap().get_cfg_mut(),
                    jt,
                    path,
                    i + 1,
                    wmap,
                    addr_ranges,
                );
            }
            // This is not quite correct. Because the jump_target list is already filterd.
            // But for now it is a nice debug test.
            // A better test can follow, once we hit this one.
            debug_assert_eq!(
                cfg.graph.neighbors_directed(cur, Outgoing).count(),
                jump_targets.len(),
                "The instruction word at {:#x} is marked as tail jump but as other outgoing edges which are no jumps.", cur.address
            );
            return res;
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
            neigh_weights.push_back(
                cfg.get_node_weight_id(&n)
                    .expect(format!("CFG {} should have been calculated before.", n).as_str()),
            );
        }
        if neigh_ids.is_empty() {
            // Leaf node. We are done
            return SamplingState::Continue;
        }
        let picked_neighbor = *neigh_ids.get(select_branch(neigh_weights, wmap)).unwrap();
        if picked_neighbor == cur {
            panic!("Unresolved loop in CFG detected at node {}.", cur);
        }
        cur = picked_neighbor;
    }
}

fn get_node_info(
    nid: NodeId,
    node_follows_call: &mut bool,
    icfg: &ICFG,
    cfg: &mut CFG,
) -> IWordInfo {
    let mut ninfo = IWordInfo::None;
    if *node_follows_call {
        ninfo |= IWordInfo::IsReturnPoint;
        *node_follows_call = false;
    }
    if is_jump(cfg, nid) {
        ninfo |= IWordInfo::IsJump;
    }
    if is_tail_call(cfg, nid) {
        ninfo |= IWordInfo::IsTailCall;
    }
    if is_exit(cfg, nid) {
        ninfo |= IWordInfo::IsExit;
    }
    if is_call(cfg, nid) {
        // Put we set the meta information for the path node (marking it as call).
        ninfo |= IWordInfo::IsCall;

        let unfiltered_call_targets = filter_call_targets(cfg, nid, None);
        if unfiltered_call_targets.iter().any(|ct| icfg.is_malloc(ct)) {
            ninfo |= IWordInfo::CallsMalloc;
        }
        if unfiltered_call_targets.iter().any(|ct| icfg.is_input(ct)) {
            ninfo |= IWordInfo::CallsInput;
        }
        if unfiltered_call_targets
            .iter()
            .any(|ct| icfg.is_unmapped(ct))
        {
            ninfo |= IWordInfo::CallsUnmapped;
        }
    }
    ninfo
}

fn is_call(cfg: &mut CFG, cur: NodeId) -> bool {
    cfg.nodes_meta
        .get(&cur)
        .is_some_and(|meta| meta.insns.iter().any(|i| i.itype.is_call()))
}

fn is_jump(cfg: &mut CFG, cur: NodeId) -> bool {
    cfg.nodes_meta
        .get(&cur)
        .is_some_and(|meta| meta.insns.iter().any(|i| i.itype.is_jump()))
}

fn is_tail_call(cfg: &mut CFG, cur: NodeId) -> bool {
    cfg.nodes_meta
        .get(&cur)
        .is_some_and(|meta| meta.node_type.is_tail_call())
}

fn is_exit(cfg: &mut CFG, cur: NodeId) -> bool {
    cfg.nodes_meta
        .get(&cur)
        .is_some_and(|meta| meta.node_type.is_exit())
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
    if !node_in_ranges(&entry_node, addr_ranges) {
        panic!(
            "Entry point {} outside of allowed ranges: {:?}",
            entry_node, addr_ranges
        );
    }
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

#[allow(dead_code)]
/// Translate given addresses to a Path.
/// Expects the first node to be an entry node of an CFG.
pub fn testing_addresses_to_path(icfg: &ICFG, addresses: &mut VecDeque<Address>, path: &mut Path) {
    let proc = icfg.get_procedure(&&NodeId::new_original(*addresses.get(0).unwrap()));
    let mut node_follows_call = false;
    while let Some(addr) = addresses.pop_front() {
        let nid = NodeId::new_original(addr);
        let ninfo = get_node_info(
            nid,
            &mut node_follows_call,
            icfg,
            proc.write().unwrap().get_cfg_mut(),
        );
        path.push(nid, ninfo);

        if ninfo.is_call() {
            if !(ninfo.calls_unmapped() || ninfo.calls_malloc() || ninfo.calls_input()) {
                let next = NodeId::new_original(*addresses.get(0).unwrap());
                node_follows_call = true;
                if icfg.has_procedure(&next) {
                    testing_addresses_to_path(icfg, addresses, path);
                }
            }
        }
        if addresses.is_empty()
            || !proc
                .read()
                .unwrap()
                .get_cfg()
                .has_node(NodeId::new_original(*addresses.get(0).unwrap()))
        {
            return;
        }
    }
}
