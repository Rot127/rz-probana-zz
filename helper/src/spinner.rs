// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::{
    io::Write,
    time::{Duration, Instant},
};

pub struct Spinner {
    spin_interval: Duration,
    last_spin_change: Instant,
    spin_symbols: Vec<String>,
    spin_idx: usize,
}

impl Spinner {
    pub fn new() -> Spinner {
        let spin_elem = vec!["-", "+", "#", "+"];
        Spinner {
            spin_interval: Duration::new(0, 50e6 as u32),
            last_spin_change: Instant::now(),
            spin_symbols: Vec::<String>::from_iter(spin_elem.into_iter().map(str::to_owned)),
            spin_idx: 0,
        }
    }

    pub fn update(&mut self, status: String) {
        let now = Instant::now();
        if now - self.last_spin_change > self.spin_interval {
            self.spin_idx = (self.spin_idx + 1) % self.spin_symbols.len();
            self.last_spin_change = now;
        }

        print!(
            "\r[{}] {}",
            self.spin_symbols.get(self.spin_idx).unwrap(),
            status
        );
        std::io::stdout().flush().unwrap();
    }

    pub fn done(&self, status: String) {
        println!("\r[x] {}", status);
    }
}
