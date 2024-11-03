// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::collections::BTreeMap;

/// KeyType -> [ CellType ] data structure
#[derive(Clone)]
pub struct VecMap<KeyType, CellType>
where
    KeyType: Ord,
{
    map: BTreeMap<KeyType, Vec<CellType>>,
}

impl<KeyType, CellType> VecMap<KeyType, CellType>
where
    KeyType: Ord,
    CellType: Ord,
{
    pub fn new() -> VecMap<KeyType, CellType> {
        VecMap {
            map: BTreeMap::new(),
        }
    }

    pub fn push(&mut self, id: KeyType, cell_val: CellType) {
        if let Some(id_vec) = self.map.get_mut(&id) {
            id_vec.push(cell_val);
            return;
        }
        let mut vec = Vec::<CellType>::new();
        vec.push(cell_val);
        self.map.insert(id, vec);
    }

    pub fn reset_to(&mut self, id: KeyType, val: CellType) {
        self.map.remove(&id);
        self.push(id, val);
    }

    pub fn remove(&mut self, id: KeyType, val: CellType) {
        if let Some(id_vec) = self.map.get_mut(&id) {
            // TODO: Not cool. Should be a set to save iterations.
            id_vec.retain(|v| v != &val);
            return;
        }
    }

    pub fn extend(&mut self, id: KeyType, vec: Vec<CellType>) {
        if let Some(id_vec) = self.map.get_mut(&id) {
            id_vec.extend(vec);
            return;
        }
        self.map.insert(id, vec);
    }

    pub fn len_of(&self, id: &KeyType) -> usize {
        if let Some(vec) = self.map.get(id) {
            return vec.len();
        }
        return 0;
    }

    pub fn vec_iter<'a>(&'a self, id: &KeyType) -> Option<std::slice::Iter<'a, CellType>> {
        if let Some(vec) = self.map.get(id) {
            return Some(vec.iter());
        }
        None
    }

    pub fn vec_iter_mut<'a>(
        &'a mut self,
        id: &KeyType,
    ) -> Option<std::slice::IterMut<'a, CellType>> {
        if let Some(vec) = self.map.get_mut(id) {
            return Some(vec.iter_mut());
        }
        None
    }
}

impl<KeyType, CellType> PartialEq for VecMap<KeyType, CellType>
where
    KeyType: Ord,
    CellType: Ord,
{
    fn eq(&self, other: &Self) -> bool {
        self.map == other.map
    }
}
