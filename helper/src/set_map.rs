// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
};

/// KeyType -> { CellType } data structure
#[derive(Clone)]
pub struct SetMap<KeyType, CellType>
where
    KeyType: Ord,
{
    map: BTreeMap<KeyType, BTreeSet<CellType>>,
}

impl<KeyType, CellType> Display for SetMap<KeyType, CellType>
where
    KeyType: Ord,
    KeyType: Display,
    CellType: Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (k, set) in self.map.iter() {
            let Ok(_) = write!(f, "{}\n", k) else {
                return std::fmt::Result::Err(std::fmt::Error);
            };
            for v in set.iter() {
                let Ok(_) = write!(f, "\t->{}\n", v) else {
                    return std::fmt::Result::Err(std::fmt::Error);
                };
            }
        }
        write!(f, "\n")
    }
}

impl<KeyType, CellType> SetMap<KeyType, CellType>
where
    KeyType: Ord,
    CellType: Ord,
{
    pub fn new() -> SetMap<KeyType, CellType> {
        SetMap {
            map: BTreeMap::new(),
        }
    }

    pub fn get<'a>(&'a self, id: &KeyType) -> Option<&'a BTreeSet<CellType>> {
        self.map.get(id)
    }

    pub fn insert(&mut self, id: KeyType, val: CellType) {
        if let Some(id_set) = self.map.get_mut(&id) {
            id_set.insert(val);
            return;
        }
        let mut new_set = BTreeSet::<CellType>::new();
        new_set.insert(val);
        self.map.insert(id, new_set);
    }

    pub fn remove(&mut self, id: &KeyType, val: &CellType) {
        if let Some(id_set) = self.map.get_mut(id) {
            id_set.remove(val);
        }
    }

    pub fn reset_to(&mut self, id: KeyType, val: CellType) {
        self.map.remove(&id);
        self.insert(id, val);
    }

    pub fn extend(&mut self, id: KeyType, set: BTreeSet<CellType>) {
        if let Some(id_set) = self.map.get_mut(&id) {
            id_set.extend(set);
            return;
        }
        self.map.insert(id, set);
    }

    pub fn assign_difference(&mut self, id: &KeyType, exclude: &BTreeSet<CellType>) {
        if let Some(id_set) = self.map.get_mut(id) {
            id_set.retain(|v| !exclude.contains(v));
        }
    }

    pub fn len_of(&self, id: &KeyType) -> usize {
        if let Some(set) = self.map.get(id) {
            return set.len();
        }
        return 0;
    }

    pub fn set_iter<'a>(
        &'a self,
        id: &KeyType,
    ) -> Option<std::collections::btree_set::Iter<'a, CellType>> {
        if let Some(set) = self.map.get(id) {
            return Some(set.iter());
        }
        None
    }
}

impl<KeyType, CellType> PartialEq for SetMap<KeyType, CellType>
where
    KeyType: Ord,
    CellType: Ord,
{
    fn eq(&self, other: &Self) -> bool {
        self.map == other.map
    }
}
