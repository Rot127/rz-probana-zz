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
    time::Instant,
};

use binding::{log_rizin, log_rz, rz_notify_done, GRzCore, LOG_WARN};
use helper::{spinner::Spinner, user::ask_yes_no};
use rand::{thread_rng, Rng};
use rzil_abstr::interpreter::{interpret, IntrpByProducts};

use crate::{
    bda_binding::get_bin_entries,
    icfg::ICFG,
    path_sampler::sample_path,
    state::{run_condition_fulfilled, BDAState},
};

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

fn get_bda_status(state: &BDAState, num_bda_products: usize) -> String {
    let mut passed = (Instant::now() - state.bda_start).as_secs();
    let hours = passed / 3600;
    passed -= hours * 3600;
    let minutes = passed / 60;
    passed -= minutes * 60;
    // Separated at the thousands mark
    let formatted_path_num = num_bda_products
        .to_string()
        .as_bytes()
        .rchunks(3)
        .rev()
        .map(std::str::from_utf8)
        .collect::<Result<Vec<&str>, _>>()
        .unwrap()
        .join(",");

    format!(
        "Threads: {} - Runtime: {:02}:{:02}:{:02} - Paths interpreted: {}",
        state.num_threads, hours, minutes, passed, formatted_path_num
    )
}

/// Runs the BDA analysis by sampleing paths within the iCFG and performing
/// abstract execution on them.
/// Memory references get directly added to Rizin via Rizin's API.
pub fn run_bda(core: GRzCore, icfg: &mut ICFG, state: &BDAState) {
    let bin_entries = get_bin_entries(core.clone());
    if !malloc_present(icfg) {
        return;
    }
    icfg.resolve_loops(state.num_threads, state.get_weight_map());

    // Run abstract interpretation
    let mut spinner = Spinner::new("".to_string());
    let mut paths_walked = 0;
    let mut rng = thread_rng();
    let mut products: Vec<IntrpByProducts> = Vec::new();
    let mut threads: HashMap<usize, JoinHandle<IntrpByProducts>> = HashMap::new();
    while run_condition_fulfilled(&state) {
        spinner.update(Some(get_bda_status(state, paths_walked)));
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
                let core_ref = core.clone();
                threads.insert(
                    tid,
                    thread::spawn(move || interpret(core_ref, path.to_addr_path())),
                );
            }
        }

        for tid in 0..state.num_threads {
            if !threads.get(&tid).is_none() && threads.get(&tid).as_ref().unwrap().is_finished() {
                let thread = threads.remove(&tid).unwrap();
                match thread.join() {
                    Err(_) => panic!("Thread failed."),
                    Ok(r) => products.push(r),
                };
            }
        }
        for _product in products.iter() {
            paths_walked += 1;
            // Update iCFG with resolved calls
            // Recalculate weight.
            // Report mem vals
        }
        products.clear();
    }
    spinner.done(get_bda_status(state, paths_walked));
    let mut term_reason = "";
    if state.bda_timed_out() {
        term_reason = "timeout";
    }
    rz_notify_done(
        core.clone(),
        format!("Finished BDA analysis ({})", term_reason),
    );
}
