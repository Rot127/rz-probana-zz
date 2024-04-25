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
};

use binding::{log_rizn, log_rz, rz_notify_done, RzAnalysis, RzCore, LOG_WARN};
use helper::user::ask_yes_no;
use rand::{thread_rng, Rng};

use crate::{
    abstr_int::{interpret, InterpreterProducts, MemVal},
    bda_binding::get_bin_entries,
    flow_graphs::FlowGraphOperations,
    icfg::ICFG,
    path_sampler::sample_path,
    state::{run_condition_fulfilled, BDAState},
};

fn report_mem_vals_to_rz(rz_analysis: *mut RzAnalysis, mem_vals: &Vec<MemVal>) {
    todo!()
}

fn malloc_present(icfg: &ICFG) -> bool {
    if !icfg.has_malloc() {
        log_rz!(
            LOG_WARN,
            Some("BDA".to_string()),
            "\nThe binary has no memory allocating function symbol.\n\
            This means BDA will NOT be able to deduct values on the heap.\n\
            It is highly advisable to identify and name malloc() functions first in the binary.\n"
                .to_string()
        );
        if ask_yes_no("Abort?") {
            return false;
        }
    }
    true
}

/// Runs the BDA analysis by sampleing paths within the iCFG and performing
/// abstract execution on them.
/// Memory references get directly added to Rizin via Rizin's API.
pub fn run_bda(rz_core: *mut RzCore, icfg: &mut ICFG, state: &BDAState) {
    let bin_entries = get_bin_entries(rz_core);
    if !malloc_present(icfg) {
        return;
    }
    icfg.resolve_loops(state.num_threads, state.get_weight_map());
    icfg.print_stats();
    icfg.calc_weight(state.get_weight_map());

    // Run abstract interpretation
    let mut rng = thread_rng();
    let mut products: Vec<InterpreterProducts> = Vec::new();
    let mut threads: HashMap<usize, JoinHandle<InterpreterProducts>> = HashMap::new();
    while run_condition_fulfilled(&state) {
        // Dispatch interpretation into threads
        for tid in 0..state.num_threads {
            let path = sample_path(
                icfg,
                // Choose a random entry point.
                *bin_entries
                    .get(rng.gen_range(0..bin_entries.len()))
                    .unwrap(),
                state.get_weight_map(),
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
    let mut term_reason = "";
    if state.timed_out() {
        term_reason = "timeout";
    }
    rz_notify_done(rz_core, format!("Finished BDA analysis ({})", term_reason));
}
