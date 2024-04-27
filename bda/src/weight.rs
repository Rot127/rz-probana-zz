// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use rug::integer::{IntegerExt64, MiniInteger};
use rug::Integer;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::fmt::LowerHex;
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::sync::RwLock;

#[derive(Debug, Copy, Clone, Eq)]
pub struct WeightID {
    id: u64,
}

impl Hash for WeightID {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl Deref for WeightID {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        &self.id
    }
}

impl PartialEq<WeightID> for WeightID {
    fn eq(&self, other: &WeightID) -> bool {
        self.id == other.id
    }
}

impl std::fmt::Display for WeightID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if WeightMap::is_weight_id_of_usize(self, 0) {
            return write!(f, "wid(0)");
        } else if WeightMap::is_weight_id_of_usize(self, 1) {
            return write!(f, "wid(1)");
        }
        return write!(f, "wid({:#x})", self.id);
    }
}

impl WeightID {
    pub fn log2(&self, wmap: &RwLock<WeightMap>) -> usize {
        let lhs_value = wmap
            .read()
            .unwrap()
            .map
            .get(self)
            .unwrap()
            .val
            .significant_bits() as usize;
        lhs_value
    }

    pub fn div32(&self, rhs: &WeightID, wmap: &RwLock<WeightMap>) -> usize {
        let map = wmap.read().unwrap();
        let lhs_value = &map.map.get(self).unwrap().val;
        let rhs_value = &map.map.get(rhs).unwrap().val;
        lhs_value.clone().div_exact(rhs_value).to_usize_wrapping()
    }

    pub fn div32usize(&self, rhs: usize, wmap: &RwLock<WeightMap>) -> usize {
        let lhs_value = wmap.read().unwrap().map.get(self).unwrap().val.clone();
        lhs_value.div_exact_u64(rhs as u64).to_usize_wrapping()
    }

    pub fn add(&mut self, rhs: &WeightID, wmap: &RwLock<WeightMap>) -> WeightID {
        let lhs_value = wmap.read().unwrap().map.get(self).unwrap().val.clone();
        let rhs_value = wmap.read().unwrap().map.get(rhs).unwrap().val.clone();
        let sum = lhs_value + rhs_value;
        Weight::new_w(sum, wmap)
    }

    pub fn mul(&self, rhs: &WeightID, wmap: &RwLock<WeightMap>) -> WeightID {
        let lhs_value = wmap.read().unwrap().map.get(self).unwrap().val.clone();
        let rhs_value = wmap.read().unwrap().map.get(rhs).unwrap().val.clone();
        Weight::new_w(lhs_value * rhs_value, wmap)
    }

    fn new(id: u64) -> WeightID {
        WeightID { id }
    }

    pub fn eq_w(&self, other: &WeightID, wmap: &RwLock<WeightMap>) -> bool {
        if wmap.read().unwrap().map.contains_key(self)
            && wmap.read().unwrap().map.contains_key(other)
        {
            return wmap.read().unwrap().map.get(self).unwrap()
                == wmap.read().unwrap().map.get(other).unwrap();
        }
        panic!("Cannot compare WeightIDs which are not stored in the WeightMap");
    }

    pub fn eq_usize(&self, other: usize, wmap: &RwLock<WeightMap>) -> bool {
        if !wmap.read().unwrap().map.contains_key(self) {
            panic!("Cannot compare a WeightID which is not stored in the WeightMap");
        }

        return wmap.read().unwrap().map.get(self).unwrap() == &MiniInteger::from(other);
    }
}

pub struct WeightMap {
    map: HashMap<WeightID, Weight>,
    unde_weight_id: WeightID,
    const_one: WeightID,
    const_zero: WeightID,
}

impl WeightMap {
    fn hash_and_add_usize(&mut self, v: usize) -> WeightID {
        let val = Integer::from(v);
        let mut hasher = DefaultHasher::new();
        val.hash(&mut hasher);
        let wid = WeightID::new(hasher.finish());
        if self.map.get(&wid).is_none() {
            self.map.insert(wid, Weight { val, _id: wid });
        }
        wid
    }

    pub fn new() -> RwLock<WeightMap> {
        let mut wm = WeightMap {
            map: HashMap::new(),
            unde_weight_id: WeightID { id: 0 },
            const_one: WeightID { id: 0 },
            const_zero: WeightID { id: 0 },
        };
        wm.unde_weight_id = wm.hash_and_add_usize(0);
        wm.const_zero = wm.hash_and_add_usize(0);
        wm.const_one = wm.hash_and_add_usize(1);
        RwLock::new(wm)
    }

    pub fn get_undetermand_weight_id(&self) -> WeightID {
        self.unde_weight_id
    }

    /// Returns the Weight in the map for the given [id].
    /// Or None if there is no weight present.
    pub fn get_weight(&self, id: &WeightID) -> Option<&Weight> {
        self.map.get(id)
    }

    /// Get the wight id a weight of 1.
    pub fn get_one(&self) -> WeightID {
        self.const_one
    }

    /// Get the wight id a weight of 0.
    pub fn get_zero(&self) -> WeightID {
        self.const_zero
    }

    /// Checks if the [wid] is the id for the value [v].
    pub fn is_weight_id_of_usize(wid: &WeightID, v: usize) -> bool {
        let val = Integer::from(v);
        let mut hasher = DefaultHasher::new();
        val.hash(&mut hasher);
        WeightID::new(hasher.finish()) == *wid
    }

    pub fn num_weights(&self) -> usize {
        self.map.len()
    }
}

pub type NodeWeightIDMap = HashMap<NodeId, WeightID>;
pub type NodeWeightIDRefMap<'a> = HashMap<NodeId, &'a WeightID>;
pub type WeightRefVec<'a> = Vec<&'a WeightID>;

#[derive(Debug, Clone)]
pub struct Weight {
    val: Integer,
    _id: WeightID,
}

macro_rules! wu {
    ($v:expr, $map:expr) => {
        Weight::new_u($v, $map)
    };
}

/// The undetermined weight value.
macro_rules! UNDETERMINED_WEIGHT {
    ($wmap:expr) => {
        $wmap.read().unwrap().get_undetermand_weight_id()
    };
}
pub(crate) use wu;
pub(crate) use UNDETERMINED_WEIGHT;

use crate::flow_graphs::NodeId;

impl PartialEq<usize> for Weight {
    fn eq(&self, other: &usize) -> bool {
        self.val == MiniInteger::from(*other)
    }
}

impl PartialEq<Integer> for Weight {
    fn eq(&self, other: &Integer) -> bool {
        self.val == *other
    }
}

impl PartialEq<MiniInteger> for Weight {
    fn eq(&self, other: &MiniInteger) -> bool {
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
    /// Creates a new weight and adds it to the weight map [wmap].
    /// It returns the id of the weight, under which it is stored in the WeightMap.
    pub fn new_u(v: usize, wmap: &RwLock<WeightMap>) -> WeightID {
        let mut map = wmap.write().unwrap();
        let mut hasher = DefaultHasher::new();
        let val = Integer::from(v);
        val.hash(&mut hasher);
        let wid = WeightID::new(hasher.finish());
        if map.map.get(&wid).is_none() {
            map.map.insert(wid, Weight { val, _id: wid });
        }
        wid
    }

    /// Creates a new weight and adds it to the weight map [wmap].
    /// It returns the id of the weight, under which it is stored in the WeightMap.
    pub fn new_w(int_val: Integer, wmap: &RwLock<WeightMap>) -> WeightID {
        let mut hasher = DefaultHasher::new();
        let mut map = wmap.write().unwrap();
        int_val.hash(&mut hasher);
        let wid = WeightID::new(hasher.finish());
        if map.map.get(&wid).is_none() {
            map.map.insert(
                wid,
                Weight {
                    val: int_val,
                    _id: wid,
                },
            );
        }
        wid
    }

    pub fn significant_bits(&self) -> u32 {
        self.val.significant_bits()
    }
}
