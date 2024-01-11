// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use rand::{thread_rng, Rng};

use crate::flow_graphs::Weight;

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
pub fn select_branch(weights: Vec<Weight>) -> usize {
    let mut rng = thread_rng();
    let mut approx_w: Vec<ApproxW> = Vec::new();
    approximate_weights(&weights, &mut approx_w);
    let mut choice = 0;
    let mut opponent = 1;
    // Let the different weights compete against each other.
    'outer: loop {
        if opponent < weights.len() {
            break 'outer;
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
