// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

// get function list
// get icfg
// mark malloc calls in between
// get every cfg
// Remove all loops
// Sampling
// pass path to abstract interpr.
// ...

use std::{
    collections::HashMap,
    thread::{self, JoinHandle},
    time::{Duration, SystemTime},
};

use binding::{RzAnalysis, RzCore};
use rand::{thread_rng, Rng};

use crate::{
    abstr_int::{interpret, InterpreterProducts, MemVal},
    bda_binding::get_bin_entries,
    icfg::ICFG,
    path_sampler::sample_path,
};

struct BDAState {
    /// Tiemstamp when the analysis started.
    analysis_start: SystemTime,
    /// Maximum duration the analysis is allowed to run.
    timeout: Duration,
    /// Counter how many threads can be dispatched for interpretation.
    num_threads: usize,
}

impl BDAState {
    fn new(num_threads: usize) -> BDAState {
        BDAState {
            analysis_start: SystemTime::now(),
            timeout: Duration::new(10, 0),
            num_threads,
        }
    }
}

fn run_condition_fulfilled(state: &BDAState) -> bool {
    state
        .analysis_start
        .elapsed()
        .is_ok_and(|elap| elap < state.timeout)
}

fn report_mem_vals_to_rz(rz_analysis: *mut RzAnalysis, mem_vals: &Vec<MemVal>) {
    todo!()
}

/// Runs the BDA analysis by sampleing paths within the iCFG and performing
/// abstract execution on them.
/// Memory references get directly added to Rizin via Rizin's API.
pub fn run_bda(rz_core: *mut RzCore, rz_analysis: *mut RzAnalysis, icfg: &mut ICFG) {
    // Check for presence of malloc
    // Resolve loops and calc weight

    let state = BDAState::new(4);
    let mut rng = thread_rng();
    let mut products: Vec<InterpreterProducts> = Vec::new();
    let mut threads: HashMap<usize, JoinHandle<InterpreterProducts>> = HashMap::new();
    let bin_entries = get_bin_entries(rz_core);
    while run_condition_fulfilled(&state) {
        // Dispatch interpretation into threads
        for tid in 0..state.num_threads {
            let path = sample_path(
                icfg,
                // Choose a random entry point.
                *bin_entries
                    .get(rng.gen_range(0..bin_entries.len()))
                    .unwrap(),
            );
            if threads.get(&tid).is_none() {
                threads.insert(tid, thread::spawn(move || interpret(&path)));
            }
        }

        for tid in 0..state.num_threads {
            if !threads.get(&tid).is_none() && threads.get(&tid).as_ref().unwrap().is_finished() {
                let thread = threads.remove(&tid).unwrap();
                products.push(thread.join().unwrap());
            }
        }
        for product in products.iter() {
            // Update iCFG with resolved calls
            // Recalculate weight.
            // Report mem vals
        }
        products.clear();
    }
}
