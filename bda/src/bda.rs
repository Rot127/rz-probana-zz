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

use binding::{log_rizin, log_rz, rz_notify_done, rz_notify_error, GRzCore, LOG_WARN};
use helper::{spinner::Spinner, user::ask_yes_no};
use rand::{thread_rng, Rng};
use rzil_abstr::interpreter::{interpret, IntrpByProducts};

use crate::{
    bda_binding::get_bin_entries,
    flow_graphs::{Address, NodeId},
    icfg::ICFG,
    path_sampler::sample_path,
    state::{run_condition_fulfilled, BDAState},
};

fn malloc_present(icfg: &ICFG) -> bool {
    if !icfg.has_malloc() {
        log_rz!(
            LOG_WARN,
            Some("BDA"),
            "The binary has no memory allocating function symbol.\n\
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
        "Threads: {} - Runtime: {:02}:{:02}:{:02} - Paths interpreted: {} Discovered icalls: {}",
        state.num_threads,
        hours,
        minutes,
        passed,
        formatted_path_num,
        state.icalls.len()
    )
}

fn get_entry_point_list(core: &GRzCore, icfg: &ICFG) -> Option<Vec<Address>> {
    let user_defined_entries = core
        .lock()
        .expect("Should not be locked")
        .get_bda_analysis_entries()
        .expect("Failed to get user defined entries.");
    if !user_defined_entries.is_empty() {
        for entry in user_defined_entries.iter() {
            if !icfg.has_procedure(&NodeId::new_original(*entry)) {
                log_rz!(
                    LOG_WARN,
                    Some("BDA"),
                    format!(
                        "User defined entry point {:#x} doesn't point to a procedure.",
                        entry
                    )
                );
                return None;
            }
        }
        return Some(user_defined_entries);
    }
    let bin_entries = get_bin_entries(core.clone());
    if bin_entries.len() == 0 {
        log_rz!(
            LOG_WARN,
            Some("BDA"),
            "Binary file has no entry point set. You can set custom ones with 'e plugins.bda.entries'"
                .to_string()
        );
        return None;
    }
    Some(bin_entries)
}

/// Runs the BDA analysis by sampleing paths within the iCFG and performing
/// abstract execution on them.
/// Memory references get directly added to Rizin via Rizin's API.
pub fn run_bda(core: GRzCore, icfg: &mut ICFG, state: &mut BDAState) {
    let ranges = core
        .lock()
        .expect("Should not be locked")
        .get_bda_analysis_range()
        .expect("Failed to get analysis ranges.");
    let entry_points = match get_entry_point_list(&core, icfg) {
        Some(ep) => ep,
        None => {
            rz_notify_error(core.clone(), "BDA analysis failed with an error".to_owned());
            return;
        }
    };

    if !malloc_present(icfg) {
        return;
    }
    icfg.resolve_loops(state.num_threads, state.get_weight_map());

    let mut nothing_happened = 0;
    let mut handled_thread = 0;
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
                *entry_points
                    .get(rng.gen_range(0..entry_points.len()))
                    .unwrap(),
                state.get_weight_map(),
                &ranges,
            );
            if threads.get(&tid).is_none() {
                let core_ref = core.clone();
                threads.insert(
                    tid,
                    thread::spawn(move || interpret(core_ref, path.to_addr_path())),
                );
            }
        }

        let mut nothing = true;
        for tid in 0..state.num_threads {
            if !threads.get(&tid).is_none() && threads.get(&tid).as_ref().unwrap().is_finished() {
                nothing = false;
                handled_thread += 1;
                let thread = threads.remove(&tid).unwrap();
                match thread.join() {
                    Err(_) => panic!("Thread failed."),
                    Ok(r) => products.push(r),
                };
            }
        }
        if nothing {
            nothing_happened += 1;
        }
        for product in products.iter() {
            paths_walked += 1;
            state.update_icalls(&product.resolved_icalls);
            state.update_mem_xrefs(&product.mem_xrefs);
            state.update_stack_xrefs(&product.stack_xrefs);
            // Update iCFG with resolved calls
            // Recalculate weight.
            // Report mem vals
        }
        products.clear();
    }
    spinner.done(get_bda_status(state, paths_walked));
    println!(
        "Lazy factor: {}/{} = {}",
        nothing_happened,
        handled_thread,
        nothing_happened as f64 / handled_thread as f64
    );
    println!("Calls");
    for ic in state.icalls.iter() {
        println!("{}", ic);
    }
    println!("Mem xrefs");
    for ic in state.mem_xrefs.iter() {
        println!("{}", ic);
    }
    println!("Stack xrefs");
    for ic in state.stack_xrefs.iter() {
        println!("{}", ic);
    }
    let mut term_reason = "";
    if state.bda_timed_out() {
        term_reason = "timeout";
    }
    rz_notify_done(
        core.clone(),
        format!("Finished BDA analysis ({})", term_reason),
    );
}
