// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::io::Write;

/// Asks the user a yes and no question and returns true if they answered yes or false if the answer was no.
pub fn ask_yes_no(question: &str) -> bool {
    print!("{}", question);
    let mut answer = String::from("invalid");
    let valid_answers = vec![
        String::from("y"),
        String::from("n"),
        String::from("no"),
        String::from("yes"),
    ];
    while !valid_answers.iter().any(|va| *va == answer.to_lowercase()) {
        print!(" [y/n] > ");
        std::io::stdout().flush().unwrap();
        answer.clear();
        std::io::stdin()
            .read_line(&mut answer)
            .expect("Failed to read line");
        answer = answer.trim_end().to_owned();
    }
    answer == "y" || answer == "yes"
}
