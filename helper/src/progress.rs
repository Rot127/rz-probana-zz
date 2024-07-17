// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::{io::Write, time::Duration};

pub fn sleep(sec: usize, notify: bool) {
    for _ in 0..sec {
        if notify {
            std::io::stdout().flush().unwrap();
            print!(".");
        }
        std::thread::sleep(Duration::new(1, 0));
    }
    if notify {
        println!();
    }
}

pub struct ProgressBar {
    task_name: String,
    total: usize,
    current: usize,
    max_bar_width: usize,
}

impl ProgressBar {
    pub fn new(task_name: String, total_steps: usize) -> ProgressBar {
        ProgressBar {
            task_name,
            total: total_steps,
            current: 0,
            max_bar_width: 99, // Hard code for now
        }
    }

    fn update(&mut self, new_current: usize) {
        self.current = new_current;
    }

    fn print(&self, msg: Option<String>) {
        let is_done = self.current == self.total;
        let prefix = format!(
            "{} {}: ",
            if is_done { "[x]" } else { "[ ]" },
            self.task_name
        );
        let postfix = format!(
            " - {}/{}{}",
            self.current,
            self.total,
            if msg.is_some() {
                format!(" - {}", msg.unwrap())
            } else {
                "".to_owned()
            }
        );
        let progress_width = self.max_bar_width - prefix.len() - postfix.len() - 2;
        let done = self.current as f32 / self.total as f32;
        let todo = 1 as f32 - done;

        let bar_content = format!(
            "{}{}",
            "▒".repeat((done * progress_width as f32) as usize),
            "-".repeat((todo * progress_width as f32) as usize)
        );
        print!("{}|{}|{} \r", prefix, bar_content, postfix);
        std::io::stdout().flush().unwrap();
        if is_done {
            // We assume no one calls this function afterwards.
            println!();
        }
    }

    /// Updates the progress bar and prints it.
    pub fn update_print(&mut self, new_current: usize, msg: Option<String>) {
        self.update(new_current);
        self.print(msg);
    }
}

pub enum TaskStatus {
    Begin,
    Fail,
    Done,
}

pub struct Task {
    task_text: String,
    status: TaskStatus,
}

impl Task {
    pub fn new(task_text: String) -> Task {
        Task {
            task_text,
            status: TaskStatus::Begin,
        }
    }

    pub fn print(&self, msg: String) {
        print!("\r[");
        match self.status {
            TaskStatus::Begin => print!(" "),
            TaskStatus::Fail => print!("!"),
            TaskStatus::Done => print!("x"),
        }
        print!(
            "] {}{}",
            self.task_text,
            if msg.is_empty() {
                "".to_owned()
            } else {
                format!(" - {}", msg)
            }
        );
        std::io::stdout().flush().unwrap();
        match self.status {
            TaskStatus::Begin => {}
            _ => println!(),
        };
    }

    pub fn set_print(&mut self, status: TaskStatus, msg: String) {
        self.status = status;
        self.print(msg);
    }
}
