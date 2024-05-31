// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

pub fn subscript(mut n: u64) -> String {
    let sub_n = vec!['₀', '₁', '₂', '₃', '₄', '₅', '₆', '₇', '₈', '₉'];
    let mut s = String::from("");
    while n > 0 {
        let i = n % 10;
        s.push(*sub_n.get(i as usize).expect("out of bounds"));
        n = (n - i) / 10;
    }
    String::from_iter(s.chars().into_iter().rev())
}
