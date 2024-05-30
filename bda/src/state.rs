// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::{
    collections::HashSet,
    sync::RwLock,
    time::{Duration, Instant},
};

use rzil_abstr::interpreter::{ConcreteCall, MemXref, StackXref};

use crate::weight::WeightMap;

pub fn run_condition_fulfilled(state: &BDAState) -> bool {
    !state.bda_timed_out()
}

pub struct BDAState {
    /// Tiemstamp when the analysis started.
    pub bda_start: Instant,
    /// Maximum duration the analysis is allowed to run.
    pub timeout: Duration,
    /// Counter how many threads can be dispatched for interpretation.
    pub num_threads: usize,
    /// The weight map for every node in all graphs.
    weight_map: RwLock<WeightMap>,
    /// Discovered icalls
    pub icalls: HashSet<ConcreteCall>,
    /// Discovered mem_xrefs
    pub mem_xrefs: HashSet<MemXref>,
    /// Discovered stacK_xrefs
    pub stack_xrefs: HashSet<StackXref>,
}

impl BDAState {
    pub fn new(num_threads: usize, timeout: u64) -> BDAState {
        BDAState {
            bda_start: Instant::now(),
            timeout: Duration::new(timeout, 0),
            num_threads,
            weight_map: WeightMap::new(),
            icalls: HashSet::new(),
            mem_xrefs: HashSet::new(),
            stack_xrefs: HashSet::new(),
        }
    }

    pub fn bda_timed_out(&self) -> bool {
        self.bda_start.elapsed() >= self.timeout
    }

    pub fn reset_bda_timeout(&mut self) {
        self.bda_start = Instant::now();
    }

    pub fn get_weight_map(&self) -> &RwLock<WeightMap> {
        &self.weight_map
    }

    pub fn update_icalls(&mut self, icalls: &HashSet<ConcreteCall>) {
        icalls.iter().for_each(|c| {
            self.icalls.insert(c.clone());
        });
    }

    pub fn update_mem_xrefs(&mut self, xrefs: &HashSet<MemXref>) {
        xrefs.iter().for_each(|c| {
            self.mem_xrefs.insert((*c).clone());
        });
    }

    pub fn update_stack_xrefs(&mut self, xrefs: &HashSet<StackXref>) {
        xrefs.iter().for_each(|c| {
            self.stack_xrefs.insert((*c).clone());
        });
    }
}
