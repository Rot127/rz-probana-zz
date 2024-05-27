// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

pub fn parse_bda_range_conf_val(val: String) -> Option<Vec<(u64, u64)>> {
    let mut vec = Vec::new();
    for s in val.split(',') {
        let r = s.trim();
        let mut range: (u64, u64) = (0, 0);
        if !s.contains('-') {
            println!(
                "Range list must be of the form: '<hex_num>-<hex_num>, <hex_num>-<hex_num>, ...'"
            );
            return None;
        }
        for (i, n) in r.split("-").enumerate() {
            if i > 1 {
                println!("Range list must be of the form: '<hex_num>-<hex_num>, <hex_num>-<hex_num>, ...'");
                return None;
            }
            if let Ok(n) = u64::from_str_radix(n.trim_start_matches("0x"), 16) {
                if i == 0 {
                    range.0 = n;
                } else if i == 1 {
                    range.1 = n;
                }
            } else {
                println!("Failed to parse '{}'", n);
                return None;
            }
        }
        if range.0 > range.1 {
            println!(
                "Invalid range: [{:#x},{:#x}] - (begin > end)",
                range.0, range.1
            );
            return None;
        }

        vec.push(range);
    }
    Some(vec)
}

pub fn parse_bda_entry_list(val: String) -> Option<Vec<u64>> {
    let mut vec = Vec::new();
    if val.is_empty() {
        return Some(vec);
    }
    for str in val.split(',') {
        if let Ok(n) = u64::from_str_radix(str.trim().trim_start_matches("0x"), 16) {
            vec.push(n);
        } else {
            println!("Failed to parse '{}'", str);
            return None;
        }
    }

    Some(vec)
}
