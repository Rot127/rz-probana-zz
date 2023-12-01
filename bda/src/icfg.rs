// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::collections::HashMap;

use petgraph::prelude::DiGraphMap;

/// A node in an iCFG describing a procedure.
pub struct Procedure {
    /// The address of the procedure.
    address: u64,
    /// Name of the procedure (if any).
    name: String,
    /// Flag if this procedure allocates memory on the heap.
    is_alloc: bool,
    /// Weight of the node. Equivalent to number outgoing edges.
    weight: u64,
    // The cfg of the procedure
    // cfg: GraphMap<>
}

/// And edge in an iCFG.
pub struct ICFGEdge<'a> {
    from: &'a Procedure,
    to: &'a Procedure,
}

/// An inter-procedual control flow graph.
pub struct ICFG<'a> {
    /// Name of the binary this iCFG describes.
    bin_name: String,
    /// The actual graph. Nodes are indexed by address of the procedures.
    graph: &'a DiGraphMap<&'a Procedure, &'a Procedure>,
    /// Map off allocation procedures.
    allocs: HashMap<u64, &'a Procedure>,
}

// - Translate graph
//   - Check for malloc in graph
// - Check for malloc in arguments
// - Warn if no malloc given with sleep
// - Check and mark loops/recursions.
//   - Resolve loops?
//
