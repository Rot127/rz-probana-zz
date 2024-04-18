// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::io::Write;

pub fn sleep(sec: usize, notify: bool) {
    for _ in 0..sec {
        if notify {
            std::io::stdout().flush().unwrap();
            print!(".");
        }
        std::thread::sleep(std::time::Duration::new(1, 0));
    }
    if notify {
        println!();
    }
}
