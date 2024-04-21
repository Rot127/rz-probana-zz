// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use rug::Integer;
use std::fmt::LowerHex;
use std::ops::AddAssign;

#[derive(Debug, Clone)]
pub struct Weight {
    val: Integer,
}

impl std::ops::Mul for Weight {
    type Output = Weight;

    fn mul(self, rhs: Self) -> Weight {
        Weight {
            val: self.val * rhs.val,
        }
    }
}

macro_rules! w {
    ($v:expr) => {
        Weight::new($v)
    };
}

/// The undetermined weight value.
macro_rules! UNDETERMINED_WEIGHT {
    () => {
        Weight::new(0)
    };
}
pub(crate) use w;
pub(crate) use UNDETERMINED_WEIGHT;

impl PartialEq<usize> for Weight {
    fn eq(&self, other: &usize) -> bool {
        self.val == Integer::from(*other)
    }
}

impl PartialEq<Integer> for Weight {
    fn eq(&self, other: &Integer) -> bool {
        self.val == *other
    }
}

impl PartialEq<Weight> for Weight {
    fn eq(&self, other: &Weight) -> bool {
        self.val == other.val
    }
}

impl LowerHex for Weight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#x}", self.val)
    }
}

impl Weight {
    pub fn new(v: usize) -> Weight {
        Weight {
            val: Integer::from(v),
        }
    }

    pub fn log2(&self) -> u32 {
        self.val.significant_bits()
    }

    pub fn div32(&self, rhs: Weight) -> u32 {
        self.val.div_exact(&rhs.val).to_owned().to_u32().unwrap()
    }

    pub fn add_assign(&mut self, rhs: &Weight) {
        self.val.add_assign(&rhs.val);
    }
}
