// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use binding::GRzCore;

type Address = u64;
type Const = u64;

pub struct IntrpPath {
    path: Vec<Address>,
}

impl IntrpPath {
    pub fn new() -> IntrpPath {
        IntrpPath { path: Vec::new() }
    }

    pub fn push(&mut self, addr: Address) {
        self.path.push(addr);
    }
}

/// A concretely resolved indirect call.
/// Those can be discovered, if only constant value were used to define the call target.
pub struct ConcreteIndirectCall {
    /// The caller
    from: Address,
    /// The callee
    to: Address,
}

/// Memory region classes: Global, Stack, Heap
enum MemRegionClass {
    /// Global memory region. E.g. .data, .rodata, .bss
    Global,
    /// The stacck memory region.
    Stack,
    /// The Heap memory region.
    Heap,
}

/// A memory region. Either of Global, Stack or Heap.
pub struct MemRegion {
    /// Memory region class
    class: MemRegionClass,
    /// Base address of the region.
    base: Address,
    /// The c-th invocation this region was allocated/used.
    /// For stack regions this is the c'th invocation of the function.
    /// For heap regions this is the c'th invocation of the instruction.
    /// This is a mere theoretical distinction. Because the invocation count
    /// for the entry point instruction of a function, is always equal to the
    /// function invocation. So it always counts the c'th invocation of an instruction.
    /// This might change though in the future, if someone
    /// invents "multiple-entry" functions or something.
    c: u64,
    /// For Heap regions: The address of the allocating instruction.
    /// For Stack regions: The function address this stack frame was used.
    addr: Address,
}

/// An abstract value
pub struct AbstrVal {
    /// The memory region of this value
    region: MemRegion,
    /// The offset of this variable from the base of the region.
    offset: i64,
}

/// Resulting by-products of the abstract interpretation.
pub struct IntrpByProducts {
    /// Indirect calls resolved during interpretation
    pub resolved_icalls: Vec<ConcreteIndirectCall>,
}

impl IntrpByProducts {
    pub fn new() -> IntrpByProducts {
        IntrpByProducts {
            resolved_icalls: Vec::new(),
        }
    }
}

/// An abstract interpreter VM. It will perform the abstract execution.
pub struct InterpreterVM {}

impl InterpreterVM {
    pub fn new() -> InterpreterVM {
        InterpreterVM {}
    }
}

/// Interprets the given path with the given interpeter VM.
pub fn interpret(rz_core: GRzCore, vm: &mut InterpreterVM, path: IntrpPath) -> IntrpByProducts {
    let _ = rz_core;
    let _ = path;
    let _ = vm;
    IntrpByProducts {
        resolved_icalls: Vec::new(),
    }
}
