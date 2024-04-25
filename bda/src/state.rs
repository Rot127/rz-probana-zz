// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::{
    sync::RwLock,
    time::{Duration, SystemTime},
};

use crate::weight::WeightMap;

pub fn run_condition_fulfilled(state: &BDAState) -> bool {
    !state.timed_out()
}

pub struct BDAState {
    /// Tiemstamp when the analysis started.
    pub analysis_start: SystemTime,
    /// Maximum duration the analysis is allowed to run.
    pub timeout: Duration,
    /// Counter how many threads can be dispatched for interpretation.
    pub num_threads: usize,
    /// The weight map for every node in all graphs.
    weight_map: RwLock<WeightMap>,
}

impl BDAState {
    pub fn new(num_threads: usize) -> BDAState {
        BDAState {
            analysis_start: SystemTime::now(),
            timeout: Duration::new(10, 0),
            num_threads,
            weight_map: WeightMap::new(),
        }
    }

    pub fn timed_out(&self) -> bool {
        self.analysis_start
            .elapsed()
            .is_ok_and(|elap| elap >= self.timeout)
    }

    pub fn get_weight_map(&self) -> &RwLock<WeightMap> {
        &self.weight_map
    }
}
