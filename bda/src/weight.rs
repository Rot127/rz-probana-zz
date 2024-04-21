// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use rug::Integer;
use std::collections::HashMap;
use std::fmt::LowerHex;
use std::ops::AddAssign;

pub type NodeWeightMap = HashMap<NodeId, Weight>;
pub type NodeWeightRefMap<'a> = HashMap<NodeId, &'a Weight>;
pub type WeightRefVec<'a> = Vec<&'a Weight>;

#[derive(Debug, Clone)]
pub struct Weight {
    val: Integer,
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

use crate::flow_graphs::NodeId;

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

    pub fn log2(&self) -> usize {
        self.val.significant_bits() as usize
    }

    pub fn div32(&self, rhs: &Weight) -> usize {
        self.val.clone().div_exact(&rhs.val).to_usize().unwrap()
    }

    pub fn div32usize(&self, rhs: usize) -> usize {
        self.val.clone().div_exact(&w!(rhs).val).to_usize().unwrap()
    }

    pub fn add_assign(&mut self, rhs: &Weight) {
        self.val.add_assign(&rhs.val);
    }

    pub fn mul(&self, rhs: &Weight) -> Weight {
        Weight {
            val: self.val.clone() * rhs.val.clone(),
        }
    }
}
