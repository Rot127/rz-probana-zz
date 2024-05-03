// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

/// Operations of an expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operation {
    CONST,
    ADD,
    MUL,
}

// An expression with up to two operands.
#[derive(Clone, Debug)]
pub struct Expr<T> {
    pub operation: Operation,
    pub lhs: Option<T>,
    pub rhs: Option<T>,
}

impl<T> Expr<T> {
    pub fn get_lhs(&self) -> &T {
        self.lhs
            .as_ref()
            .expect("For non constant values this must have been set.")
    }

    pub fn get_rhs(&self) -> &T {
        self.rhs
            .as_ref()
            .expect("For non constant values this must have been set.")
    }
}
