// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use crate::flow_graphs::{Address, NodeId};

struct IndirectCall {
    from: NodeId,
    to: NodeId,
}

enum MemRegionClass {
    /// Global memory region. E.g. static variables and the like
    Global,
    /// The stacck memory region.
    Stack,
    /// The Heap memory region.
    Heap,
}

/// A memory region.
pub struct MemRegion {
    /// Memory region class
    class: MemRegionClass,
    /// Base address of the region.
    base: Address,
    /// The c-th invocation this region was allocated/used.
    c: u64,
    /// For Heap regions: The address of the allocating instruction.
    /// For Stack regions: The address of the function this stack frame was used.
    addr: Address,
}

pub struct MemVal {
    /// The memory region of this variable
    region: MemRegion,
    /// The offset of this variable from the base of the region.
    offset: i64,
}

/// Resulting products of the abstract interpretation.
pub struct InterpreterProducts {
    /// Indirect calls resolved during interpretation
    pub resolved_icalls: Vec<IndirectCall>,
    /// Memory values discovered during interpretation
    pub mem_values: Vec<MemVal>,
}

impl InterpreterProducts {
    pub fn new() -> InterpreterProducts {
        InterpreterProducts {
            resolved_icalls: Vec::new(),
            mem_values: Vec::new(),
        }
    }
}

pub fn interpret(_path: &Vec<NodeId>) -> InterpreterProducts {
    todo!()
}
