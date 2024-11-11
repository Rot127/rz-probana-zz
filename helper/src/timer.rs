// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::time::{Duration, Instant};

pub struct Timer {
    start_time: Option<Instant>,
    duration: Duration,
}

impl Timer {
    pub fn new(duration: Duration) -> Timer {
        Timer {
            start_time: None,
            duration,
        }
    }

    pub fn timed_out(&self) -> bool {
        if let Some(start_time) = self.start_time {
            return start_time.elapsed() >= self.duration;
        }
        false
    }

    /// Returns if the timer timed out.
    /// If yes, it restarts the timer.
    pub fn timed_out_restart(&mut self) -> bool {
        let timed_out = self.timed_out();
        if timed_out {
            self.reset();
        }
        timed_out
    }

    pub fn reset(&mut self) {
        self.start_time = None;
    }

    pub fn start(&mut self) {
        self.start_time = Some(Instant::now());
    }

    pub fn passed_seconds(&self) -> u64 {
        if let Some(start_time) = self.start_time {
            return (Instant::now() - start_time).as_secs();
        }
        0
    }
}
