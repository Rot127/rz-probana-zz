// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::RwLock,
    time::Duration,
};

use helper::timer::Timer;
use rzil_abstr::interpreter::{ConcreteCodeXref, IWordInfo, MemOpSeq, MemXref, StackXref};

use crate::{flow_graphs::Address, weight::WeightMap};

pub fn run_condition_fulfilled(state: &BDAState) -> bool {
    !state.bda_timed_out()
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub enum StatisticID {
    /// Data points of the path sampler, time it takes to sample a single path.
    SampleTime,
    /// Data points of abstract interpreters, time it takes to execute a single path.
    InterpretTime,
}

pub struct RuntimeStats {
    /// Measured durations of the PathSampler sampling a single path
    stats: BTreeMap<StatisticID, Vec<Duration>>,
    /// Maximal path length seen so far.
    max_path_len: usize,
}

impl RuntimeStats {
    pub fn new() -> RuntimeStats {
        RuntimeStats {
            stats: BTreeMap::new(),
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

    /// Returns the average duration of the requested statistic.
    pub fn get_avg_duration_str(&self, stat_id: StatisticID) -> String {
        let Some(mean) = self.get_avg_duration(stat_id) else {
            return "NAN".to_string();
        };
        let mean_ms = mean.as_millis();
        if mean_ms > 1000 {
            format!("{}s", mean_ms / 1000)
        } else {
            format!("{}ms", mean_ms)
        }
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
    /// Timer for the BDA total runtime.
    pub bda_timer: Timer,
    /// Timer for the iCFG update check. A iCFG update is enforced after the timeout.
    pub icfg_update_timer: Timer,
    /// Number of new code xrefs which trigger an iCFG update.
    pub icfg_update_threshold: usize,
    /// Counter how many threads can be dispatched for interpretation.
    pub num_threads: usize,
    /// The weight map for every node in all graphs.
    weight_map: RwLock<WeightMap>,
    /// Discovered indirect calls. Already in the iCFG.
    pub calls: BTreeSet<ConcreteCodeXref>,
    /// Discovered indirect jumps. Already in the iCFG.
    pub jumps: BTreeSet<ConcreteCodeXref>,
    /// Code xrefs not yet added to the iCFG.
    pub unhandled_code_xrefs: BTreeSet<ConcreteCodeXref>,
    /// Discovered mem_xrefs
    pub mem_xrefs: BTreeSet<MemXref>,
    /// Discovered stacK_xrefs
    pub stack_xrefs: BTreeSet<StackXref>,
    /// Memory op sequences
    pub mos: Option<BTreeSet<MemOpSeq>>,
    /// Meta information collected about each instruction word executed.
    pub iword_info: Option<BTreeMap<Address, IWordInfo>>,
    /// Runtime statistics
    pub runtime_stats: RuntimeStats,
}

impl BDAState {
    pub fn new(
        num_threads: usize,
        timeout: u64,
        icfg_update_timeout: u64,
        icfg_update_threshold: usize,
    ) -> BDAState {
        BDAState {
            bda_timer: Timer::new(Duration::from_secs(timeout)),
            icfg_update_timer: Timer::new(Duration::from_secs(icfg_update_timeout)),
            icfg_update_threshold,
            num_threads,
            weight_map: WeightMap::new(),
            iword_info: Some(BTreeMap::new()),
            calls: BTreeSet::new(),
            jumps: BTreeSet::new(),
            unhandled_code_xrefs: BTreeSet::new(),
            mem_xrefs: BTreeSet::new(),
            stack_xrefs: BTreeSet::new(),
            mos: Some(BTreeSet::new()),
            runtime_stats: RuntimeStats::new(),
        }
    }

    pub fn take_moses(&mut self) -> BTreeSet<MemOpSeq> {
        self.mos.take().unwrap()
    }

    pub fn take_iword_info(&mut self) -> BTreeMap<Address, IWordInfo> {
        self.iword_info.take().unwrap()
    }

    pub fn bda_timed_out(&self) -> bool {
        self.bda_timer.timed_out()
    }

    pub fn get_weight_map(&self) -> &RwLock<WeightMap> {
        &self.weight_map
    }

    pub fn update_calls(&mut self, icalls: BTreeSet<ConcreteCodeXref>) {
        for xref in icalls.into_iter() {
            if self.calls.contains(&xref) {
                // Already added to call set during iCFG update.
                continue;
            }
            self.unhandled_code_xrefs.insert(xref);
        }
    }

    pub fn update_jumps(&mut self, ijumps: BTreeSet<ConcreteCodeXref>) {
        for xref in ijumps.into_iter() {
            if self.jumps.contains(&xref) {
                // Already added to jump set during iCFG update.
                continue;
            }
            self.unhandled_code_xrefs.insert(xref);
        }
    }

    pub fn update_mem_xrefs(&mut self, xrefs: BTreeSet<MemXref>) {
        self.mem_xrefs.extend(xrefs);
    }

    pub fn update_stack_xrefs(&mut self, xrefs: BTreeSet<StackXref>) {
        self.stack_xrefs.extend(xrefs);
    }

    pub fn update_mos(&mut self, mos: MemOpSeq) {
        self.mos.as_mut().unwrap().insert(mos);
    }

    pub fn update_iword_info(&mut self, iword_info: BTreeMap<Address, IWordInfo>) {
        self.iword_info.as_mut().unwrap().extend(iword_info);
    }

    pub(crate) fn update_icfg_check(&self) -> bool {
        (self.icfg_update_timer.timed_out() && self.unhandled_code_xrefs.len() > 0)
            || self.unhandled_code_xrefs.len() >= self.icfg_update_threshold
    }
}
