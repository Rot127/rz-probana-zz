// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::{
    collections::{HashMap, HashSet},
    sync::RwLock,
    time::{Duration, Instant},
};

use rzil_abstr::interpreter::{ConcreteCall, MemOpSeq, MemXref, StackXref};

use crate::weight::WeightMap;

pub fn run_condition_fulfilled(state: &BDAState) -> bool {
    !state.bda_timed_out()
}

#[derive(PartialEq, Eq, Hash)]
pub enum StatisticID {
    /// Data points of the path sampler, time it takes to sample a single path.
    PSSampleTime,
}

pub struct RuntimeStats {
    /// Measured durations of the PathSampler sampling a single path
    stats: HashMap<StatisticID, Vec<Duration>>,
    /// Maximal path length seen so far.
    max_path_len: usize,
}

impl RuntimeStats {
    pub fn new() -> RuntimeStats {
        RuntimeStats {
            stats: HashMap::new(),
            max_path_len: 0,
        }
    }

    /// Add a data point.
    pub fn add_dp(&mut self, set_id: StatisticID, dp: Duration) {
        if let Some(v) = self.stats.get_mut(&set_id) {
            v.push(dp);
            return;
        }
        let mut v = Vec::<Duration>::new();
        v.push(dp);
        self.stats.insert(set_id, v);
    }

    /// Returns the average duration of the requested statistic.
    pub fn get_avg_duration(&self, stat_id: StatisticID) -> Option<Duration> {
        if let Some(set) = self.stats.get(&stat_id) {
            let mut sum = Duration::ZERO;
            set.iter().for_each(|d| sum += *d);
            return Some(sum / set.len() as u32);
        }
        None
    }

    pub fn add_path_len(&mut self, path_len: usize) {
        if self.max_path_len < path_len {
            self.max_path_len = path_len;
        }
    }

    pub fn get_max_path_len(&self) -> usize {
        self.max_path_len
    }
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
    pub calls: HashSet<ConcreteCall>,
    /// Discovered mem_xrefs
    pub mem_xrefs: HashSet<MemXref>,
    /// Discovered stacK_xrefs
    pub stack_xrefs: HashSet<StackXref>,
    /// Memory op sequences
    pub mos: MemOpSeq,
    /// Runtime statistics
    pub runtime_stats: RuntimeStats,
}

impl BDAState {
    pub fn new(num_threads: usize, timeout: u64) -> BDAState {
        BDAState {
            bda_start: Instant::now(),
            timeout: Duration::new(timeout, 0),
            num_threads,
            weight_map: WeightMap::new(),
            calls: HashSet::new(),
            mem_xrefs: HashSet::new(),
            stack_xrefs: HashSet::new(),
            mos: MemOpSeq::new(),
            runtime_stats: RuntimeStats::new(),
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

    pub fn update_calls(&mut self, icalls: HashSet<ConcreteCall>) {
        self.calls.extend(icalls);
    }

    pub fn update_mem_xrefs(&mut self, xrefs: HashSet<MemXref>) {
        self.mem_xrefs.extend(xrefs);
    }

    pub fn update_stack_xrefs(&mut self, xrefs: HashSet<StackXref>) {
        self.stack_xrefs.extend(xrefs);
    }

    pub fn update_mos(&mut self, mos: MemOpSeq) {
        self.mos.extend(mos);
    }
}
