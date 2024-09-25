// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use helper::expression::{Expr, Operation};
use rug::integer::{MiniInteger, Order, UnsignedPrimitive};
use rug::{Complete, Integer};
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::sync::RwLock;
use std::time::Instant;

/// An weight expression which can be evaluated to a constant value.
type WeightExpr = Expr<WeightID>;

/// An identifier for a weight. It is an index into the weight map,
/// which stores the actual Integers for each weight.
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

macro_rules! get_const {
    ($wmap:expr, $wid:expr) => {
        $wmap.write().unwrap().get_const($wid)
    };
}

impl WeightID {
    pub fn log2(&self, wmap: &RwLock<WeightMap>) -> u64 {
        let lhs_value = wmap.write().unwrap().significant_bits(self) as u64;
        lhs_value
    }

    /// Returns the n most significant bits.
    pub fn get_msbs(&self, wmap: &RwLock<WeightMap>, n: u32) -> u64 {
        let shift = u32::max(get_const!(wmap, self).significant_bits(), n - 1) - (n - 1);
        let msbs = (get_const!(wmap, self) >> shift).complete();
        msbs.to_u64()
            .expect("This operation should always produce a 64bit value.")
    }

    pub fn add(&self, rhs: &WeightID, wmap: &RwLock<WeightMap>) -> WeightID {
        let expr = WeightExpr {
            operation: Operation::ADD,
            lhs: Some(self.clone()),
            rhs: Some(rhs.clone()),
        };
        wmap.try_write().unwrap().touch_const(self);
        wmap.try_write().unwrap().touch_const(rhs);
        let res = (wmap.try_read().unwrap().get_const(self)
            + wmap.try_read().unwrap().get_const(rhs))
        .complete();
        let wid = wmap.try_write().unwrap().add_expr(res.clone(), expr);
        wid
    }

    pub fn mul(&self, rhs: &WeightID, wmap: &RwLock<WeightMap>) -> WeightID {
        let expr = WeightExpr {
            operation: Operation::MUL,
            lhs: Some(self.clone()),
            rhs: Some(rhs.clone()),
        };
        wmap.try_write().unwrap().touch_const(self);
        wmap.try_write().unwrap().touch_const(rhs);
        let res = (wmap.try_read().unwrap().get_const(self)
            * wmap.try_read().unwrap().get_const(rhs))
        .complete();
        let wid = wmap.try_write().unwrap().add_expr(res, expr);
        wid
    }

    fn new(id: u64) -> WeightID {
        WeightID { id }
    }

    /// Compares the constant values of the given WeightIDs.
    /// This performs a clone on the first left hand side constant.
    pub fn eq_w(&self, other: &WeightID, wmap: &RwLock<WeightMap>) -> bool {
        let c0 = get_const!(wmap, self).clone();
        return &c0 == get_const!(wmap, other);
    }

    pub fn eq_usize(&self, other: usize, wmap: &RwLock<WeightMap>) -> bool {
        if !wmap.read().unwrap().wmap.contains_key(self) {
            panic!("Cannot compare a WeightID which is not stored in the WeightMap");
        }

        *get_const!(wmap, self) == MiniInteger::from(other)
    }

    /// Returns the constant of the weight identified by this WeightID.
    /// It will evaluate the weight and clone it. So it might be expensive.
    pub fn get_weight_const(&self, wmap: &RwLock<WeightMap>) -> Integer {
        wmap.write().unwrap().get_weight_const(self)
    }
}

/// Map to save all weights of nodes in the graphs.
pub struct WeightMap {
    /// The map to match weight identifiers to their abstract (possibly not evaluated) weights.
    wmap: HashMap<WeightID, Weight>,
    /// Constant values map. Buffers the constant values of weights.
    cmap: HashMap<WeightID, Integer>,
    /// The weight identifier for a weight of 1
    const_one_id: WeightID,
    /// The weight identifier for a weight of 0
    const_zero_id: WeightID,
    /// Root constant ids. All expressions in [wmap] can be calculated by these
    /// constants. The root constants are never cleaned from the
    /// [cmap].
    root_constants: HashSet<WeightID>,
    /// CFG last calculated timestamps
    /// If the value is None, it must be recalculated.
    cfg_last_calc: HashMap<NodeId, Option<Instant>>,
}

impl WeightMap {
    pub fn new() -> RwLock<WeightMap> {
        let mut wm = WeightMap {
            wmap: HashMap::new(),
            cmap: HashMap::new(),
            const_one_id: WeightID { id: 0 },
            const_zero_id: WeightID { id: 0 },
            root_constants: HashSet::new(),
            cfg_last_calc: HashMap::new(),
        };
        wm.const_zero_id = wm.add_root_const_usize(0);
        wm.const_one_id = wm.add_root_const_usize(1);
        RwLock::new(wm)
    }

    pub fn needs_recalc(&self, cfg_id: &NodeId) -> bool {
        let timestamp = self.cfg_last_calc.get(cfg_id);
        return timestamp.is_none() || timestamp.unwrap().is_none();
    }

    /// Set the "needs recalculation" property for all CFGs dependend on [edited_cfg].
    /// This should be done after every loop removal of the CFG!
    pub fn propagate_cfg_edits(&mut self, icfg: &ICFG, edited_cfgs: Vec<NodeId>) {
        // We need to track the seen nodes, because at this stage the graph is not acyclic.
        let mut seen: HashSet<NodeId> = HashSet::new();
        let mut todo = Vec::<NodeId>::new();
        for ecfg in edited_cfgs {
            // For now:
            // If this cfg was part of a recursive loop, we automatically assume the last clone was edited
            // (and update all the dependent, which includes the original).
            // In the future we can check which edge was actual affected and maybe don't update everything.
            let last_clone = ecfg.get_clone(icfg.get_node_dup_count() as i32, 0);
            if icfg.has_procedure(&last_clone) {
                todo.push(last_clone.clone());
                seen.insert(last_clone);
            } else {
                todo.push(ecfg.clone());
                seen.insert(ecfg.clone());
            }
        }
        while todo.len() > 0 {
            let n = todo.pop().unwrap();
            self.cfg_last_calc.insert(n, None);
            for incoming in icfg
                .get_graph()
                .neighbors_directed(n, petgraph::Direction::Incoming)
            {
                if seen.contains(&incoming) {
                    continue;
                }
                seen.insert(incoming);
                todo.push(incoming);
            }
        }
    }

    pub fn print(&self) {
        println!("| Weight map:");
        println!("| Constants");
        for w in self.cmap.values() {
            println!("| {}", w);
        }
        println!("| \n| Expressions");
        for w in self.wmap.values() {
            println!("| {:?}", w.expr);
        }
        println!("| \n| update map");
        for (id, lc) in self.cfg_last_calc.iter() {
            println!("| {}: {:?}", id, lc);
        }
        println!();
    }

    pub fn set_calc_timestamp(&mut self, cfg_id: &NodeId) {
        self.cfg_last_calc.insert(*cfg_id, Some(Instant::now()));
    }

    pub fn add_root_const_digits<T: UnsignedPrimitive>(
        &mut self,
        v: &[T],
        order: Order,
    ) -> WeightID {
        let (const_val, wid) = digits_to_integer_wid(v, order);
        self.root_constants.insert(wid);
        if !self.wmap.contains_key(&wid) {
            let weight = Weight::new_const(wid);
            self.wmap.insert(wid, weight);
        }
        if !self.cmap.contains_key(&wid) {
            self.cmap.insert(wid, const_val.to_owned());
        }
        wid
    }

    /// Adds the constant value [v] to the weight map.
    /// Note: The value added here will NOT be deleted when the
    /// constant map is cleared. It is considered a root value from which all
    /// expressions can be calculated.
    pub fn add_root_const_usize(&mut self, v: usize) -> WeightID {
        let (const_val, wid) = u128_to_integer_wid(v as u128);
        self.root_constants.insert(wid);
        if !self.wmap.contains_key(&wid) {
            let weight = Weight::new_const(wid);
            self.wmap.insert(wid, weight);
        }
        if !self.cmap.contains_key(&wid) {
            self.cmap.insert(wid, const_val.to_owned());
        }
        wid
    }

    pub fn add_expr(&mut self, expr_val: Integer, expr: WeightExpr) -> WeightID {
        let mut hasher = DefaultHasher::new();
        expr_val.hash(&mut hasher);
        let wid = WeightID::new(hasher.finish());
        if !self.wmap.contains_key(&wid) {
            let weight = Weight::new(wid, expr);
            self.wmap.insert(wid, weight);
        }
        if !self.cmap.contains_key(&wid) {
            self.cmap.insert(wid, expr_val.to_owned());
        }
        wid
    }

    /// Evaluate the weight if it is not in the constant map.
    fn touch_const(&mut self, wid: &WeightID) {
        if self.cmap.contains_key(wid) {
            return;
        }

        let weight = self
            .wmap
            .get(wid)
            .expect("WeightMap is inconsistent! WeightID should have been in the map.")
            .clone();
        self.eval_w(&weight);
    }

    fn get_const(&self, wid: &WeightID) -> &Integer {
        return self.cmap.get(wid).expect("Did not contain weight");
    }

    /// Returns the constant value for the given Weight id.
    /// If the Weight needs to be evaluated, it is done so.
    /// It will panic, if there is no weight for the given weight id.
    fn touch_get_const(&mut self, wid: &WeightID) -> &Integer {
        if self.cmap.contains_key(wid) {
            return self.cmap.get(wid).unwrap();
        }

        let weight = self
            .wmap
            .get(wid)
            .expect("WeightMap is inconsistent! WeightID should have been in the map.")
            .clone();
        self.eval_w(&weight);
        self.cmap.get(wid).unwrap()
    }

    /// Get the wight id a weight of 1.
    pub fn get_one(&self) -> WeightID {
        self.const_one_id
    }

    pub fn significant_bits(&mut self, wid: &WeightID) -> u32 {
        self.touch_get_const(wid).significant_bits()
    }

    /// Get the wight id a weight of 0.
    pub fn get_zero(&self) -> WeightID {
        self.const_zero_id
    }

    /// Checks if the [wid] is the id for the value [v].
    pub fn is_weight_id_of_usize(wid: &WeightID, v: usize) -> bool {
        let val = Integer::from(v);
        let mut hasher = DefaultHasher::new();
        val.hash(&mut hasher);
        WeightID::new(hasher.finish()) == *wid
    }

    pub fn num_weights(&self) -> usize {
        self.wmap.len()
    }

    pub fn num_constants(&self) -> usize {
        self.cmap.len()
    }

    /// Deletes all constant values from the map, except root constants.
    pub fn clear_derived_constants(&mut self) {
        self.cmap.retain(|wid, _| {
            if self.root_constants.contains(wid) {
                return true;
            }
            return false;
        })
    }

    /// Evaluates a weight recursively and returns it's constant value.
    fn eval_w(&mut self, weight: &Weight) -> &Integer {
        if weight.expr.operation == Operation::CONST {
            return self
                .cmap
                .get(&weight.id)
                .expect("Constant should have been added at this point.");
        }
        let lhs: &Weight = &self
            .wmap
            .get(weight.expr.get_lhs())
            .expect("Weight should have been added at this point.")
            .clone();
        let rhs: &Weight = &self
            .wmap
            .get(&weight.expr.get_rhs())
            .expect("Weight should have been added at this point.")
            .clone();
        let const_val = match weight.expr.operation {
            Operation::ADD => {
                self.eval_w(lhs);
                self.eval_w(rhs);
                (self.cmap.get(&lhs.id).unwrap() + self.cmap.get(&rhs.id).unwrap()).complete()
            }
            Operation::MUL => {
                self.eval_w(lhs);
                self.eval_w(rhs);
                (self.cmap.get(&lhs.id).unwrap() * self.cmap.get(&rhs.id).unwrap()).complete()
            }
            Operation::CONST => panic!("CONST case should have been covered earlier."),
        };
        self.cmap.insert(weight.id, const_val);
        self.cmap.get(&weight.id).expect("We just added it?!")
    }

    /// Returns the constant number of the WeightID.
    pub fn get_weight_const(&mut self, wid: &WeightID) -> Integer {
        self.touch_get_const(wid).clone()
    }

    pub fn contains_wid(&self, wid: &WeightID) -> bool {
        self.wmap.contains_key(wid)
    }

    pub fn contains_const(&self, wid: &WeightID) -> bool {
        self.wmap.contains_key(wid)
    }

    /// Returns the weight id of the given number if it is in the map.
    pub fn get_wid_of_u128(&self, n: u128) -> Option<WeightID> {
        let (_, wid) = u128_to_integer_wid(n);
        if self.wmap.get(&wid).is_some() {
            return Some(wid);
        }
        return None;
    }

    /// Returns the weight id of the given digits if it is in the map.
    pub fn get_wid_of_digits<T: UnsignedPrimitive>(
        &self,
        v: &[T],
        order: Order,
    ) -> Option<WeightID> {
        let (_, wid) = digits_to_integer_wid(v, order);
        if self.wmap.get(&wid).is_some() {
            return Some(wid);
        }
        return None;
    }
}

/// PUBLICLY USABLE BY TESTING MODULE ONLY.
pub fn digits_to_integer_wid<T: UnsignedPrimitive>(v: &[T], order: Order) -> (Integer, WeightID) {
    let const_val = Integer::from_digits(v, order);
    let mut hasher = DefaultHasher::new();
    const_val.hash(&mut hasher);
    let wid = WeightID::new(hasher.finish());
    (const_val, wid)
}

/// PUBLICLY USABLE BY TESTING MODULE ONLY.
pub fn u128_to_integer_wid(v: u128) -> (Integer, WeightID) {
    let const_val = Integer::from(v);
    let mut hasher = DefaultHasher::new();
    const_val.hash(&mut hasher);
    let wid = WeightID::new(hasher.finish());
    (const_val, wid)
}

// /// Evaluates a weight recursively and returns it's constant value.
// fn eval_w_EXPR(wmap: &RwLock<WeightMap>, weight: &Weight) -> &Integer {
//     if weight.expr.operation == Operation::CONST {
//         return wmap
//             .read()
//             .unwrap()
//             .cmap
//             .get(&weight.id)
//             .expect("Constant should have been added at this point.");
//     }
//     let lhs: &Weight = &wmap
//         .read()
//         .unwrap()
//         .wmap
//         .get(weight.expr.get_lhs())
//         .expect("Weight should have been added at this point.")
//         .clone();
//     let rhs: &Weight = &wmap
//         .read()
//         .unwrap()
//         .wmap
//         .get(&weight.expr.get_rhs())
//         .expect("Weight should have been added at this point.")
//         .clone();
//     let const_val = match weight.expr.operation {
//         Operation::ADD => (eval_w(wmap, lhs) + eval_w(wmap, rhs)).complete(),
//         Operation::MUL => (eval_w(wmap, lhs) * eval_w(wmap, rhs)).complete(),
//         Operation::CONST => panic!("CONST case should have been covered earlier."),
//     };
//     wmap.write().unwrap().cmap.insert(weight.id, const_val);
//     wmap.read()
//         .unwrap()
//         .cmap
//         .get(&weight.id)
//         .expect("We just added it?!")
// }

pub type NodeWeightIDMap = HashMap<NodeId, Option<WeightID>>;
pub type NodeWeightIDRefMap<'a> = HashMap<NodeId, &'a Option<WeightID>>;

/// A weight of a node in a graph. The weight of a node is equivalent to
/// the reachable paths from a given node.
/// WIth the exception of the constant weights `1` and `0`, weights are not
/// calculated until the user requests it.
/// Instead a weight is an expression which uses other weight identifiers as
/// their operands.
/// If the scalar value of the weight is requested, it evaluates this expression.
#[derive(Debug, Clone)]
struct Weight {
    /// The identifier of this weight.
    id: WeightID,
    /// The value of the weight. Represented as an expression.
    expr: WeightExpr,
}

use crate::flow_graphs::{FlowGraphOperations, NodeId};
use crate::icfg::ICFG;

impl Weight {
    fn new_const(id: WeightID) -> Weight {
        Weight {
            expr: WeightExpr {
                operation: Operation::CONST,
                lhs: None,
                rhs: None,
            },
            id,
        }
    }

    fn new(id: WeightID, expr: WeightExpr) -> Weight {
        Weight { id, expr }
    }
}
