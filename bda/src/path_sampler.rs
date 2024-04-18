// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::collections::HashMap;

use petgraph::Direction::Outgoing;
use rand::{thread_rng, Rng};

use crate::{
    cfg::CFG,
    flow_graphs::{Address, NodeId, Weight, INVALID_NODE_ID},
    icfg::{Procedure, ICFG},
};

type Path = Vec<NodeId>;

#[derive(Clone)]
struct ApproxW {
    pub exp: u32,
    pub sig: u32,
}

impl ApproxW {
    fn new() -> ApproxW {
        ApproxW { exp: 0, sig: 0 }
    }
}

/// Return hsig, expi = sig × 2exp = w
fn approximate_weights(weights: &Vec<Weight>, out: &mut Vec<ApproxW>) {
    for w in weights.iter() {
        let w_32 = *w as u32;
        let mut aw = ApproxW::new();
        aw.exp = u32::max(w_32.ilog2(), 63) - 63;
        aw.sig = w_32 / u32::pow(2, aw.exp);
        out.push(aw);
    }
}

macro_rules! get_w {
    ($v:ident, $i:expr) => {
        match $v.get($i) {
            Some(w) => w,
            None => panic!("Index out of range"),
        }
    };
}

/// Selects a branch based on the given weights.
/// Returns the index of the branch to take.
/// Implementation after Algorithm 2 [2] modified for n weights.
///
/// [^2] https://doi.org/10.25394/PGS.23542014.v1
fn select_branch(weights: &Vec<Weight>) -> usize {
    if weights.len() == 1 {
        return 0;
    }
    let mut rng = thread_rng();
    let mut approx_w: Vec<ApproxW> = Vec::new();
    approximate_weights(&weights, &mut approx_w);
    let mut choice = 0;
    let mut opponent = 1;
    // Let the different weights compete against each other.
    loop {
        if opponent < weights.len() {
            break;
        }
        let w_cho = get_w!(approx_w, choice);
        let w_opp = get_w!(approx_w, choice);
        let n = w_cho.exp - w_opp.exp;
        if n >= 64 {
            let b = choice;
            let r: u32 = rng.gen_range(0..w_cho.sig);
            choice = if r < w_opp.sig { choice } else { opponent };
            for _ in 0..n {
                if rng.gen_bool(0.5) {
                    choice = b;
                    break;
                }
            }
        } else {
            let r: u32 = rng.gen_range(0..w_cho.sig * u32::pow(2, n) + w_opp.sig);
            choice = if r < w_opp.sig { choice } else { opponent };
        }
        opponent += 1;
    }
    choice
}

fn sample_cfg_path(icfg: &ICFG, cfg_id: NodeId, path: &mut Path) {
    let cfg = icfg.get_procedure(cfg_id).get_cfg();
    path.push(cfg.get_entry());
    let cur = cfg.get_entry();
    let mut neigh_ids: Vec<NodeId> = Vec::new();
    let mut neigh_weights: Vec<Weight> = Vec::new();
    loop {
        if cfg.nodes_meta.get(&cur).is_some_and(|meta| {
            meta.insns
                .iter()
                .any(|i| !i.call_target.is_invalid_call_target())
        }) {
            // The instr. word has a call. First visit this procedure.
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
            call_targets.for_each(|ct| sample_cfg_path(icfg, ct, path));
        }

        cfg.graph.neighbors_directed(cur, Outgoing).for_each(|n| {
            neigh_ids.push(n);
            neigh_weights.push(cfg.get_node_weight(n));
        });
        path.push(*neigh_ids.get(select_branch(&neigh_weights)).unwrap());
    }
}

/// Sample a path from the given [icfg] and return it as vector.
pub fn sample_path(icfg: &ICFG, entry_point: Address) -> Path {
    let entry_proc = icfg.get_procedure(NodeId::new_original(entry_point));
    let mut path = Path::new();
    sample_cfg_path(icfg, entry_proc.get_cfg().get_entry(), &mut path);
    path
}
