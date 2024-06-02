// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

pub fn subscript(mut n: u64) -> String {
    if n == 0 {
        return "₀".to_string();
    }
    let sub_n = vec!['₀', '₁', '₂', '₃', '₄', '₅', '₆', '₇', '₈', '₉'];
    let mut s = String::from("");
    while n > 0 {
        let i = n % 10;
        s.push(*sub_n.get(i as usize).expect("out of bounds"));
        n = (n - i) / 10;
    }
    String::from_iter(s.chars().into_iter().rev())
}

pub fn superscript_hex(mut n: u64) -> String {
    if n == 0 {
        return "⁰ˣ⁰".to_string();
    }
    let sub_n = vec![
        '⁰', 'ⁱ', '²', '³', '⁴', '⁵', '⁶', '⁷', '⁸', '⁹', 'ᵃ', 'ᵇ', 'ᶜ', 'ᵈ', 'ᵉ', 'ᶠ',
    ];
    let mut s = String::from("");
    while n > 0 {
        let i = n % 0x10;
        s.push(*sub_n.get(i as usize).expect("out of bounds"));
        n = n >> 4;
    }
    s.push_str("ˣ⁰");
    String::from_iter(s.chars().into_iter().rev())
}
