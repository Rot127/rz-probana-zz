// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::time::{Duration, Instant};

pub const SECONDS_PER_MINUTE: u64 = 60;
pub const SECONDS_PER_HOUR: u64 = SECONDS_PER_MINUTE * 60;
pub const SECONDS_PER_DAY: u64 = SECONDS_PER_HOUR * 24;

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

    pub fn reset_start(&mut self) {
        self.reset();
        self.start();
    }

    pub fn start(&mut self) {
        self.start_time = Some(Instant::now());
    }

    pub fn time_passed_seconds(&self) -> u64 {
        if let Some(start_time) = self.start_time {
            return (Instant::now() - start_time).as_secs();
        }
        0
    }

    pub fn time_left_seconds(&self) -> u64 {
        let d = self.duration.as_secs();
        if self.time_passed_seconds() > d {
            0
        } else {
            d - self.time_passed_seconds()
        }
    }

    pub fn seconds_to_str(seconds: u64) -> String {
        let mut sec = seconds;
        let days = sec / SECONDS_PER_DAY;
        sec -= days * SECONDS_PER_DAY;
        let hours = sec / SECONDS_PER_HOUR;
        sec -= hours * SECONDS_PER_HOUR;
        let minutes = sec / SECONDS_PER_MINUTE;
        sec -= minutes * SECONDS_PER_MINUTE;
        if days > 0 {
            format!(
                "{} day{} {:02}:{:02}:{:02}",
                days,
                if days == 1 { "" } else { "s" },
                hours,
                minutes,
                sec
            )
        } else {
            format!("{:02}:{:02}:{:02}", hours, minutes, sec)
        }
    }

    pub fn time_passed_str(&self) -> String {
        Self::seconds_to_str(self.time_passed_seconds())
    }

    pub fn time_left_str(&self) -> String {
        Self::seconds_to_str(self.time_left_seconds())
    }
}
