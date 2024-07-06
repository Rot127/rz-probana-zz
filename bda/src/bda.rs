// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::{
    collections::HashMap,
    sync::mpsc::{channel, Receiver, Sender},
    thread::{self, JoinHandle},
    time::Instant,
};

use binding::{log_rizin, log_rz, rz_notify_done, rz_notify_error, GRzCore, LOG_WARN};
use helper::{spinner::Spinner, user::ask_yes_no};
use rand::{thread_rng, Rng};
use rzil_abstr::interpreter::{interpret, IntrpProducts};

use crate::{
    bda_binding::{get_bin_entries, setup_procedure_at_addr},
    cfg::Procedure,
    flow_graphs::{Address, NodeId},
    icfg::ICFG,
    path_sampler::sample_path,
    state::{run_condition_fulfilled, BDAState},
};

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
        state.calls.len()
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

fn move_products_to_state(state: &mut BDAState, products: &mut Vec<IntrpProducts>) {
    for product in products.iter() {
        state.update_calls(&product.concrete_calls);
        state.update_mem_xrefs(&product.mem_xrefs);
        state.update_stack_xrefs(&product.stack_xrefs);
    }
    products.clear();
}

/// Updates the iCFG with newly discovered calls.
fn update_icfg(core: GRzCore, state: &mut BDAState, icfg: &mut ICFG, products: &[IntrpProducts]) {
    let mut call_added = false;
    products.iter().for_each(|prod| {
        for code_xref in prod.concrete_calls.iter() {
            let proc_addr = NodeId::from(code_xref.get_proc_addr());
            let from = NodeId::from(code_xref.get_from());
            let to = NodeId::from(code_xref.get_to());
            let procedure_from: Option<Procedure> = if icfg.has_procedure(&proc_addr) {
                None
            } else {
                setup_procedure_at_addr(&core.lock().unwrap(), proc_addr.address)
            };
            if procedure_from.is_none() && !icfg.has_procedure(&proc_addr) {
                panic!("Could not initialize procedure at {}", proc_addr);
            }
            let procedure_to: Option<Procedure> = if icfg.has_procedure(&to) {
                None
            } else {
                setup_procedure_at_addr(&core.lock().unwrap(), to.address)
            };
            if procedure_to.is_none() && !icfg.has_procedure(&to) {
                panic!("Could not initialize procedure at {}", to);
            }
            if !icfg.add_edge((proc_addr, procedure_from), (to, procedure_to), Some(from)) {
                call_added = true;
            }
        }
    });
    if call_added {
        icfg.resolve_loops(1, state.get_weight_map());
    }
}

/// Runs the BDA analysis by sampling paths within the iCFG and performing
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

    if !icfg.has_malloc() {
        log_rz!(
            LOG_WARN,
            Some("BDA"),
            "The binary has no memory allocating function symbol.\n\
            This means BDA will NOT be able to deduct values on the heap.\n\
            It is highly advisable to identify and define malloc() functions first in the binary.\n\
            Use the 'af+' command to define the functions."
                .to_string()
        );
        if !core
            .lock()
            .expect("Should not be locked")
            .get_bda_skip_questions()
            && ask_yes_no("Abort?")
        {
            return;
        }
    }

    icfg.resolve_loops(state.num_threads, state.get_weight_map());

    let mut nothing_happened = 0;
    let mut handled_thread = 0;
    // Run abstract interpretation
    let mut spinner = Spinner::new("".to_string());
    let mut paths_walked = 0;
    let mut rng = thread_rng();
    let mut products: Vec<IntrpProducts> = Vec::new();
    let mut threads: HashMap<usize, JoinHandle<_>> = HashMap::new();
    let (tx, rx): (Sender<IntrpProducts>, Receiver<IntrpProducts>) = channel();
    loop {
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
                let thread_tx = tx.clone();
                threads.insert(
                    tid,
                    thread::spawn(move || interpret(core_ref, path.to_addr_path(), thread_tx)),
                );
            }
        }

        let mut nothing = true;
        for tid in 0..state.num_threads {
            if !threads.get(&tid).is_none() && threads.get(&tid).as_ref().unwrap().is_finished() {
                nothing = false;
                handled_thread += 1;
                let thread = threads.remove(&tid).unwrap();
                if let Err(_) = thread.join() {
                    panic!("Thread failed.");
                }
            }
        }
        if nothing {
            nothing_happened += 1;
        } else {
            paths_walked += 1;
        }
        if let Ok(prods) = rx.try_recv() {
            products.push(prods);
        }
        update_icfg(core.clone(), state, icfg, &products);
        move_products_to_state(state, &mut products);
        if !run_condition_fulfilled(&state) {
            for tid in 0..state.num_threads {
                if !threads.get(&tid).is_none() {
                    let thread = threads.remove(&tid).unwrap();
                    if let Err(_) = thread.join() {
                        panic!("Thread failed.");
                    }
                }
            }
            if let Ok(prods) = rx.try_recv() {
                products.push(prods);
                move_products_to_state(state, &mut products);
            }
            break;
        }
    }
    // Report mem values to Rizin
    spinner.done(get_bda_status(state, paths_walked));
    println!(
        "Lazy factor (nothing/thread_handled): {}/{} = {}",
        nothing_happened,
        handled_thread,
        nothing_happened as f64 / handled_thread as f64
    );
    println!("Calls");
    for ic in state.calls.iter() {
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
    println!("MOS");
    for ic in state.mos.iter() {
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
