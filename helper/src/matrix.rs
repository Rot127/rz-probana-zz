// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::collections::BTreeMap;

pub struct CellIter<'a, KeyType, CellType>
where
    KeyType: Ord,
    KeyType: 'a,
    CellType: 'a,
{
    x_row_iter: Option<std::collections::btree_map::Iter<'a, KeyType, CellType>>,
}

impl<'a, KeyType, CellType> Iterator for CellIter<'a, KeyType, CellType>
where
    KeyType: Ord,
    KeyType: 'a,
    CellType: 'a,
{
    type Item = &'a CellType;

    fn next(&mut self) -> Option<Self::Item> {
        if self.x_row_iter.is_none() {
            return None;
        }
        let x_row_iter = self.x_row_iter.as_mut().unwrap();
        if let Some(next_y) = x_row_iter.next() {
            return Some(next_y.1);
        }
        return None;
    }
}

pub struct KeyIter<'a, KeyType, CellType>
where
    KeyType: Ord,
    KeyType: 'a,
    CellType: 'a,
{
    x_row_iter: Option<std::collections::btree_map::Iter<'a, KeyType, CellType>>,
    cell_check: &'a dyn Fn(&CellType) -> bool,
}

impl<'a, KeyType, CellType> Iterator for KeyIter<'a, KeyType, CellType>
where
    KeyType: Ord,
    KeyType: 'a,
    CellType: 'a,
{
    type Item = &'a KeyType;

    fn next(&mut self) -> Option<Self::Item> {
        if self.x_row_iter.is_none() {
            return None;
        }
        let x_row_iter = self.x_row_iter.as_mut().unwrap();
        loop {
            let next_y = x_row_iter.next();
            if next_y.is_none() {
                return None;
            }
            let cell = next_y.unwrap().1;
            let cell_check = self.cell_check;
            if cell_check(cell) {
                return Some(next_y.unwrap().0);
            }
        }
    }
}

pub struct Matrix<KeyType, CellType>
where
    KeyType: Ord,
{
    map: BTreeMap<KeyType, BTreeMap<KeyType, CellType>>,
}

impl<'a, KeyType, CellType> Matrix<KeyType, CellType>
where
    KeyType: Ord,
{
    pub fn new() -> Matrix<KeyType, CellType> {
        Matrix {
            map: BTreeMap::new(),
        }
    }

    pub fn set_cell(&mut self, x: KeyType, y: KeyType, cell_val: CellType) -> Option<CellType> {
        let x_cells = self.map.get_mut(&x);
        if x_cells.is_none() {
            let mut y_cell = BTreeMap::new();
            y_cell.insert(y, cell_val);
            self.map.insert(x, y_cell);
            return None;
        }
        x_cells.unwrap().insert(y, cell_val)
    }

    pub fn x_row_cell_iter(&self, x: &KeyType) -> CellIter<KeyType, CellType> {
        CellIter {
            x_row_iter: if let Some(x_row) = self.map.get(x) {
                Some(x_row.iter())
            } else {
                None
            },
        }
    }

    /// Oterates over the x-row, but yields the y values if [cell_check] returns true for them.
    pub fn x_row_key_iter(
        &'a self,
        x: &KeyType,
        cell_check: &'a dyn Fn(&CellType) -> bool,
    ) -> KeyIter<'a, KeyType, CellType> {
        let iter = KeyIter {
            x_row_iter: if let Some(x_row) = self.map.get(x) {
                Some(x_row.iter())
            } else {
                None
            },
            cell_check,
        };
        iter
    }
}
