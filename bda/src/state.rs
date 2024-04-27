// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::{
    sync::RwLock,
    time::{Duration, Instant},
};

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
}

impl BDAState {
    pub fn new(num_threads: usize) -> BDAState {
        BDAState {
            bda_start: Instant::now(),
            timeout: Duration::new(10, 0),
            num_threads,
            weight_map: WeightMap::new(),
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
}
