// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::mpsc::{channel, Receiver, Sender},
    thread::{self, JoinHandle},
    time::Instant,
};

use binding::{
    log_rizin, log_rz, rz_notify_begin, rz_notify_done, rz_notify_error, GRzCore, LOG_WARN,
};
use helper::{spinner::Spinner, user::ask_yes_no};
use rand::{thread_rng, Rng};
use rzil_abstr::interpreter::{interpret, CodeXrefType, ConcreteCodeXref, IntrpProducts};

use crate::{
    bda_binding::{get_bin_entries, setup_procedure_at_addr},
    cfg::Procedure,
    flow_graphs::{Address, FlowGraphOperations, NodeId},
    icfg::ICFG,
    path_sampler::{sample_path, testing_addresses_to_path, Path},
    post_analysis::posterior_dependency_analysis,
    state::{run_condition_fulfilled, BDAState, StatisticID},
};

fn get_bda_status(state: &BDAState, num_bda_products: usize) -> String {
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

    let sample_time = state
        .runtime_stats
        .get_avg_duration_str(StatisticID::SampleTime);
    let interp_time = state
        .runtime_stats
        .get_avg_duration_str(StatisticID::InterpretTime);
    format!(
        "Threads: {} - Runtime: {} - Paths interp.: {} - Avg. sampling time: {} - Avg. interp. time: {} - Max path len: {} - iCFG update in: {} / {}/{} xrefs",
        state.num_threads,
        state.bda_timer.time_passed_str(),
        formatted_path_num,
        sample_time,
        interp_time,
        state.runtime_stats.get_max_path_len(),
        state.icfg_update_timer.time_left_str(),
        state.unhandled_code_xrefs.len(),
        state.icfg_update_threshold
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
    for _ in 0..products.len() {
        let p = products.pop().unwrap();
        state.update_iword_info(p.iword_info);
        state.update_calls(p.concrete_calls);
        state.update_jumps(p.concrete_jumps);
        state.update_mem_xrefs(p.mem_xrefs);
        state.update_stack_xrefs(p.stack_xrefs);
        state.update_mos(p.mos);
    }
}

/// Updates the iCFG with newly discovered calls.
fn update_icfg(core: GRzCore, state: &mut BDAState, icfg: &mut ICFG) {
    let mut cxref_added = false;
    let mut edited_procs = Vec::<NodeId>::new();
    let mut xrefs_to_handle: BTreeSet<ConcreteCodeXref> = BTreeSet::new();
    // Poor mans drain() for BTreeSet (which doesn't exist in current Rust toolchain).
    // I just hope the compiler figures the to_owned() doesn't need a clone().
    state.unhandled_code_xrefs.retain(|xref| {
        xrefs_to_handle.insert(xref.to_owned());
        false
    });
    for code_xref in xrefs_to_handle.into_iter() {
        let from_proc_addr = NodeId::from(code_xref.get_proc_addr());
        let xref_insn_addr = NodeId::from(code_xref.get_from());
        let xref_to_addr = NodeId::from(code_xref.get_to());
        let mut from_edited = false;
        match code_xref.get_xtype() {
            CodeXrefType::IndirectCall => {
                if !icfg.has_edge(from_proc_addr, xref_to_addr) {
                    let procedure_from: Option<Procedure> = if icfg.has_procedure(&from_proc_addr) {
                        None
                    } else {
                        setup_procedure_at_addr(&core.lock().unwrap(), from_proc_addr.address)
                    };
                    if procedure_from.is_none() && !icfg.has_procedure(&from_proc_addr) {
                        panic!("Could not initialize procedure at {}", from_proc_addr);
                    }
                    let procedure_to: Option<Procedure> = if icfg.has_procedure(&xref_to_addr) {
                        None
                    } else {
                        setup_procedure_at_addr(&core.lock().unwrap(), xref_to_addr.address)
                    };
                    if procedure_to.is_none() && !icfg.has_procedure(&xref_to_addr) {
                        panic!("Could not initialize procedure at {}", xref_to_addr);
                    }
                    from_edited = !icfg.add_edge(
                        (from_proc_addr, procedure_from),
                        (xref_to_addr, procedure_to),
                        Some(xref_insn_addr),
                    );
                }
                state.calls.insert(code_xref);
            }
            CodeXrefType::IndirectJump => {
                if icfg.has_procedure(&from_proc_addr)
                    && !icfg.cfg_contains_edge(&from_proc_addr, &xref_insn_addr, &xref_to_addr)
                {
                    if !icfg.cfg_contains_node(&from_proc_addr, &xref_to_addr) {
                        // A tail call.
                        if !icfg.has_edge(from_proc_addr, xref_to_addr) {
                            println!("\n[Unimplemented] Skip adding tail call: {}", code_xref);
                        }
                    } else {
                        from_edited = !icfg.cfg_contains_edge(
                            &from_proc_addr,
                            &xref_insn_addr,
                            &xref_to_addr,
                        );
                        icfg.get_procedure(&from_proc_addr)
                            .write()
                            .unwrap()
                            .insert_jump_target(&xref_insn_addr, &xref_to_addr);
                    }
                }
                state.jumps.insert(code_xref);
            }
        }
        if from_edited {
            edited_procs.push(from_proc_addr);
            cxref_added = true;
        }
    }
    if cxref_added {
        icfg.resolve_loops(4);
        state
            .get_weight_map()
            .write()
            .unwrap()
            .propagate_cfg_edits(icfg, edited_procs);
    }
    state.icfg_update_timer.reset_start();
}

/// Runs the BDA analysis by sampling paths within the iCFG and performing
/// abstract execution on them.
/// Memory references get directly added to Rizin via Rizin's API.
pub fn run_bda(
    core: GRzCore,
    icfg: &mut ICFG,
    state: &mut BDAState,
) -> Option<BTreeSet<(Address, Address)>> {
    state.bda_timer.start();
    state.icfg_update_timer.start();
    state.set_ranges(
        core.lock()
            .expect("Should not be locked")
            .get_bda_analysis_range()
            .expect("Failed to get analysis ranges."),
    );
    let entry_points = match get_entry_point_list(&core, icfg) {
        Some(ep) => ep,
        None => {
            rz_notify_error(core.clone(), "BDA analysis failed with an error".to_owned());
            return None;
        }
    };
    icfg.set_entries(&entry_points);

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
            return None;
        }
    }

    icfg.resolve_loops(state.num_threads);

    let mut nothing_happened = 0;
    let mut handled_thread = 0;
    // Run abstract interpretation
    let mut spinner = Spinner::new("".to_string());
    let mut paths_walked = 0;
    let path_buf_limit = core.lock().unwrap().get_bda_path_buf_limit();
    let mut path_buffer = VecDeque::<Path>::new();
    let mut rng = thread_rng();
    let mut products: Vec<IntrpProducts> = Vec::new();
    let mut threads: BTreeMap<usize, JoinHandle<_>> = BTreeMap::new();
    let mut threads_stats: BTreeMap<usize, Instant> = BTreeMap::new();
    let (tx, rx): (Sender<IntrpProducts>, Receiver<IntrpProducts>) = channel();
    loop {
        spinner.update(Some(get_bda_status(state, paths_walked)));
        // Dispatch interpretation into threads
        for tid in 0..state.num_threads {
            sample_path_into_buffer(
                &mut path_buffer,
                path_buf_limit,
                icfg,
                &entry_points,
                &mut rng,
                state,
            );

            if threads.get(&tid).is_some() {
                // Busy
                continue;
            }
            let next_path = path_buffer
                .pop_front()
                .expect("Path generation before failed.");
            if threads.get(&tid).is_none() {
                let core_ref = core.clone();
                let thread_tx = tx.clone();
                threads_stats.insert(tid, Instant::now());
                threads.insert(
                    tid,
                    thread::spawn(move || {
                        interpret(tid, core_ref, next_path.to_addr_path(), thread_tx)
                    }),
                );
            }
        }

        let mut nothing = true;
        for tid in 0..state.num_threads {
            if !threads.get(&tid).is_none() && threads.get(&tid).as_ref().unwrap().is_finished() {
                nothing = false;
                handled_thread += 1;
                state.runtime_stats.add_dp(
                    StatisticID::InterpretTime,
                    Instant::now()
                        .duration_since(threads_stats.remove(&tid).expect("Should be set")),
                );
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
        move_products_to_state(state, &mut products);
        if state.update_icfg_check() {
            update_icfg(core.clone(), state, icfg);
        }

        if !run_condition_fulfilled(&state) {
            // End of run. Collect the rest of all products.
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
    // println!("Calls");
    // for ic in state.calls.iter() {
    //     println!("{}", ic);
    // }
    // println!("Mem xrefs");
    // for ic in state.mem_xrefs.iter() {
    //     println!("{}", ic);
    // }
    // println!("Stack xrefs");
    // for ic in state.stack_xrefs.iter() {
    //     println!("{}", ic);
    // }
    // println!("MOS");
    // for ic in state.mos.iter() {
    //     println!("{}", ic);
    // }
    let mut term_reason = "not reason specified";
    if state.bda_timed_out() {
        term_reason = "timeout";
    }
    rz_notify_done(
        core.clone(),
        format!("Finished BDA sampling ({})", term_reason),
    );
    rz_notify_begin(core.clone(), format!("BDA post-analysis"));
    let dip = posterior_dependency_analysis(state, icfg);
    rz_notify_done(core.clone(), format!("Finished BDA post-analysis"));
    Some(dip)
}

fn sample_path_into_buffer(
    path_buffer: &mut VecDeque<Path>,
    path_buf_limit: usize,
    icfg: &mut ICFG,
    entry_points: &Vec<u64>,
    rng: &mut rand::prelude::ThreadRng,
    state: &mut BDAState,
) {
    if path_buffer.len() < path_buf_limit {
        let ts_sampling_start = Instant::now();
        let path = sample_path(
            icfg,
            // Choose a random entry point.
            *entry_points
                .get(rng.gen_range(0..entry_points.len()))
                .unwrap(),
            state.get_weight_map(),
            state.get_ranges(),
        );
        state.runtime_stats.add_dp(
            StatisticID::SampleTime,
            Instant::now().duration_since(ts_sampling_start),
        );
        state.runtime_stats.add_path_len(path.len());
        path_buffer.push_back(path);
    }
}

#[allow(dead_code)]
pub fn testing_bda_on_paths(
    core: GRzCore,
    icfg: &mut ICFG,
    state: &mut BDAState,
    paths: Vec<VecDeque<Address>>,
) -> Option<BTreeSet<(Address, Address)>> {
    state.set_ranges(
        core.lock()
            .expect("Should not be locked")
            .get_bda_analysis_range()
            .expect("Failed to get analysis ranges."),
    );
    state.bda_timer.start();
    state.icfg_update_timer.start();
    let entry_points = match get_entry_point_list(&core, icfg) {
        Some(ep) => ep,
        None => {
            rz_notify_error(core.clone(), "BDA analysis failed with an error".to_owned());
            return None;
        }
    };
    icfg.set_entries(&entry_points);
    icfg.resolve_loops(state.num_threads);

    // Run abstract interpretation
    let mut products: Vec<IntrpProducts> = Vec::new();
    let (tx, rx): (Sender<IntrpProducts>, Receiver<IntrpProducts>) = channel();
    for mut path_addresses in paths.into_iter() {
        let mut path = Path::new();
        testing_addresses_to_path(icfg, &mut path_addresses, &mut path);
        let addr_path = path.to_addr_path();
        // println!("InterPath: {addr_path}");
        interpret(0, core.clone(), addr_path, tx.clone());

        if let Ok(prods) = rx.try_recv() {
            products.push(prods);
        }
        move_products_to_state(state, &mut products);
        if state.update_icfg_check() {
            update_icfg(core.clone(), state, icfg);
        }
    }
    let dip = posterior_dependency_analysis(state, icfg);
    Some(dip)
}
