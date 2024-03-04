<!-- SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org> -->
<!-- SPDX-License-Identifier: LGPL-3.0-only -->

# Graphs

We argue over two different graphs in these algorithms.

1. The inter-procedural control flow graph (iCFG) - Flow between procedures.
2. The control flow graph (CFG) - Flow between instruction words.

# Graph nodes

A node in an iCFG is a procedure. The edges of an iCFG depict calls from one to another procedure.
If procedure A calls procedure B, we have an edge from `A -> B`.
But no back edge for `return`.

A node in an CFG (the graph of a single procedure), has instruction words as nodes.
An instruction word is an atomically executed number of instructions.
This is important, because very long instruction word processors might execute multiple instructions in parallel.
Hence, we need to consider a full instruction word, an atomically unit.

If an instruction word contains two conditional jumps to other instruction words, it has three outgoing edges.
One for each conditional jump instruction in the word, and one edge for the following instruction.

Calls are not modelled as edges.

Because for resolving loops we need to duplicate nodes.
Because a node in our graph always depicts either a procedure (for an iCFG) or
an instruction word (in the CFG), we pick the address where the instruction word or procedure is located as identifier.

But the address is not enough. Because we duplicate nodes when resolving loops, we need additional fields.

```rust
/// A node identifier in a iCFG and CFG
pub struct NodeId {
    /// The i'th iCFG clone this node belongs to.
    /// If 0 it is the original node, i means it is part of the i'th clone.
    pub icfg_clone_id: u32,
    /// The i'th CFG clone this node belongs to.
    /// If 0 it is the original node, i means it is part of the i'th clone.
    pub cfg_clone_id: u32,
    /// The memory address of the procedure or instruction word this node represents.
    pub address: Address,
}
```

If we have duplicated a node of an iCFG (by cloning the complete CFG), we increment the `icfg_clone_id`.
If an instruction word node is duplicated in an CFG, we increment the `cfg_node_id`.
This way we can always identify each node, if clone or not, uniquely.

Also by aligning the struct to 128bit, we should be able to take advantage of processor vector extensions.
