// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use core::panic;
use std::{
    collections::{hash_map, hash_set, HashMap, HashSet, VecDeque},
    sync::RwLock,
};

use binding::{log_rizin, log_rz, LOG_DEBUG};
use petgraph::Direction::Outgoing;

use crate::{
    flow_graphs::{
        Address, EdgeFlow, FlowGraph, FlowGraphOperations, NodeId, NodeIdSet, ProcedureMap,
        INVALID_NODE_ID,
    },
    weight::{NodeWeightIDRefMap, WeightID, WeightMap},
};

/// The type of a node which determines the weight calculation of it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum InsnNodeWeightType {
    /// A node without any special meaning in the graph.
    /// It's weight is:
    ///
    ///   foreach s in addr.successors:
    ///     W\[iaddr\] = W\[iaddr\] + W\[s\]
    ///
    Normal,
    /// A node which calls a procedure.
    /// Its weight is defined as:
    ///
    ///   W\[iaddr\] = W\[ret_addr\] × W\[callee\]
    ///
    Call,
    /// A return node. This is always a leaf and always has
    ///
    ///   W\[iaddr\] = 1
    ///
    Return,
    /// A node which exits the procedure without return.
    /// Its weight is defined by:
    ///
    ///   W\[iaddr\] = 1
    ///
    Exit,
}

/// The node type of a instruction.
#[derive(Clone, Debug, PartialEq)]
pub struct InsnNodeType {
    pub is_entry: bool,
    pub weight_type: InsnNodeWeightType,
}

impl InsnNodeType {
    pub fn new(weight_type: InsnNodeWeightType, is_entry: bool) -> InsnNodeType {
        InsnNodeType {
            is_entry,
            weight_type,
        }
    }
}

/// An instruction node which is always part of an
/// instruction word node.
#[derive(Clone, Debug, PartialEq)]
pub struct InsnNodeData {
    /// The memory address the instruction is located.
    pub addr: Address,
    /// Instruction type. Determines weight calculation.
    pub itype: InsnNodeType,
    /// Node this instruction calls. The NodeIds point to other CFGs.
    /// Multiple call targets are possible, if a call target is dynamically calculated.
    pub call_targets: NodeIdSet,
    /// Node this instruction jumps to.
    /// It always points to the original NodeId. It is not updated if a cloned edge is added.
    pub orig_jump_target: NodeId,
    /// Follwing instruction address.
    /// It always points to the original NodeId. It is not updated if a cloned edge is added.
    pub orig_next: NodeId,
    /// Flag if this instruction is an indirect call.
    pub is_indirect_call: bool,
}

impl InsnNodeData {
    pub fn new_call(
        addr: Address,
        call_targets: NodeIdSet,
        is_indirect_call: bool,
        jump_target: NodeId,
        next: NodeId,
    ) -> InsnNodeData {
        InsnNodeData {
            addr,
            itype: InsnNodeType::new(InsnNodeWeightType::Call, false),
            call_targets,
            orig_jump_target: jump_target,
            orig_next: next,
            is_indirect_call,
        }
    }

    pub fn new(
        addr: Address,
        itype: InsnNodeType,
        call_target: NodeId,
        orig_jump_target: NodeId,
        orig_next: NodeId,
        is_indirect_call: bool,
    ) -> InsnNodeData {
        InsnNodeData {
            addr,
            itype,
            call_targets: NodeIdSet::from_nid(call_target),
            orig_jump_target,
            orig_next,
            is_indirect_call,
        }
    }

    pub fn get_clone(&self, _icfg_clone_id: i32, _cfg_clone_id: i32) -> InsnNodeData {
        InsnNodeData {
            addr: self.addr,
            itype: self.itype.clone(),
            call_targets: self.call_targets.get_clone(-1, 0),
            orig_jump_target: self.orig_jump_target,
            orig_next: self.orig_next,
            is_indirect_call: self.is_indirect_call,
        }
    }

    /// Calculate the weight of the instruction node from the successor node weights.
    pub fn insn_calc_weight(
        &self,
        iword_succ_weights: &NodeWeightIDRefMap,
        procedure_map: &ProcedureMap,
        wmap: &RwLock<WeightMap>,
    ) -> WeightID {
        let mut sum_succ_weights: WeightID = wmap.read().unwrap().get_zero();
        for (target_id, target_weight) in iword_succ_weights.iter() {
            if self.call_targets.contains(target_id)
                || self.orig_jump_target.address == target_id.address
                || self.orig_next.address == target_id.address
            {
                if target_weight.is_none() {
                    continue;
                }
                let tw = target_weight.unwrap();
                sum_succ_weights = sum_succ_weights.add(&tw, wmap);
            }
        }
        let const_one = &wmap.read().unwrap().get_one();
        if sum_succ_weights == wmap.read().unwrap().get_zero()
            && self.itype.weight_type == InsnNodeWeightType::Normal
        {
            // This indicates the CFG has an endless loop of normal instructions
            // without any Return or Exit nodes.
            // Because they can still be a part of a valid path, we
            // need to assign at least one node a weight of 1.
            // Otherwise the whole weight of the CFG would be 0.
            // Which doesn't match the reality.
            return const_one.clone();
        }
        let weight = match self.itype.weight_type {
            InsnNodeWeightType::Return => const_one.clone(),
            InsnNodeWeightType::Exit => const_one.clone(),
            InsnNodeWeightType::Normal => sum_succ_weights,
            InsnNodeWeightType::Call => {
                // This sampling step breaks the promise of path insensitivity of the algorithm.
                // But due to the design decission, to seperate path sampling from
                // abstract interpretation, I can't come up with a better method then this for now.
                // Because, if a single call instruction computes its targets
                // dynamically, we do not know at this sampling stage, where it will
                // jump to.
                // The interpreter would know, but the sample does not.
                let ct_nid = &self.call_targets.sample();
                let p: Option<&RwLock<Procedure>> = procedure_map.get(ct_nid);
                let mut has_procedure = p.is_some();
                if has_procedure {
                    // malloc, input and unmapped CFGs always have a weight of 1
                    has_procedure &= !p
                        .unwrap()
                        .try_read()
                        .expect(format!("Read Locked for {}", ct_nid).as_str())
                        .wont_execute();
                }
                let cw: WeightID = if has_procedure {
                    procedure_map
                        .get(ct_nid)
                        .expect(
                            "The call target must be set, even if no weight is associated with it.",
                        )
                        .try_write()
                        .expect(format!("Write Locked for {}", ct_nid).as_str())
                        .get_cfg_mut()
                        .get_entry_weight_id(procedure_map, wmap)
                        .expect("Entry has a weight.")
                } else {
                    *const_one
                };
                sum_succ_weights.mul(&cw, wmap)
            }
        };
        weight
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct InsnNodeDataVec {
    vec: Vec<InsnNodeData>,
}

impl InsnNodeDataVec {
    pub fn new() -> InsnNodeDataVec {
        InsnNodeDataVec { vec: Vec::new() }
    }

    pub fn push(&mut self, idata: InsnNodeData) {
        self.vec.push(idata);
    }

    pub fn len(&self) -> usize {
        self.vec.len()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, InsnNodeData> {
        self.vec.iter()
    }

    pub fn get(&self, i: usize) -> Option<&InsnNodeData> {
        self.vec.get(i)
    }

    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, InsnNodeData> {
        self.vec.iter_mut()
    }

    pub fn last_mut(&mut self) -> Option<&mut InsnNodeData> {
        self.vec.last_mut()
    }

    pub fn get_clone(&self, icfg_clone_id: i32, cfg_clone_id: i32) -> InsnNodeDataVec {
        let mut clone = InsnNodeDataVec { vec: Vec::new() };
        self.iter()
            .for_each(|idata| clone.push(idata.get_clone(icfg_clone_id, cfg_clone_id)));
        clone
    }
}

/// A CFG node. This is equivalent to an instruction word.
/// For most architectures this instruction word
/// contains one instruction.
/// For a few (e.g. Hexagon) it can contain more.
#[derive(Clone, Debug, PartialEq)]
pub struct CFGNodeData {
    pub nid: NodeId,
    weight_id: Option<WeightID>,
    pub insns: InsnNodeDataVec,
}

impl std::fmt::Display for CFGNodeData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "iw({})", self.nid)
    }
}

impl CFGNodeData {
    pub fn new(nid: NodeId) -> CFGNodeData {
        CFGNodeData {
            nid,
            weight_id: None,
            insns: InsnNodeDataVec::new(),
        }
    }

    /// Initialize an CFG node with a single instruction.
    pub fn new_test_single(
        addr: Address,
        ntype: InsnNodeType,
        jump_target: NodeId,
        next: NodeId,
    ) -> CFGNodeData {
        let mut node = CFGNodeData {
            nid: NodeId::from(addr),
            weight_id: None,
            insns: InsnNodeDataVec::new(),
        };
        node.insns.push(InsnNodeData {
            addr,
            itype: ntype,
            call_targets: NodeIdSet::new(),
            orig_jump_target: jump_target,
            orig_next: next,
            is_indirect_call: false,
        });
        node
    }

    /// Calulcates the weights of all instructions part of this instruction word
    /// and returns it as vector
    pub fn iword_calc_weight(
        &self,
        successor_weights: &NodeWeightIDRefMap,
        procedures: &ProcedureMap,
        wmap: &RwLock<WeightMap>,
    ) -> Vec<WeightID> {
        assert_ne!(
            self.insns.len(),
            0,
            "The instruction word at {} has no instructions.",
            self
        );
        let mut insn_weights = Vec::<WeightID>::new();
        for insn in self.insns.iter() {
            insn_weights.push(insn.insn_calc_weight(successor_weights, procedures, wmap));
        }
        insn_weights
    }

    /// Initialize an CFG node with a single call instruction.
    pub fn new_test_single_call(
        addr: Address,
        call_target: NodeId,
        is_indirect_call: bool,
        next: NodeId,
    ) -> CFGNodeData {
        let mut node = CFGNodeData {
            nid: NodeId::from(addr),
            weight_id: None,
            insns: InsnNodeDataVec::new(),
        };
        node.insns.push(InsnNodeData::new_call(
            addr,
            NodeIdSet::from_nid(call_target),
            is_indirect_call,
            INVALID_NODE_ID,
            next,
        ));
        node
    }

    pub fn get_clone(&self, icfg_clone_id: i32, cfg_clone_id: i32) -> CFGNodeData {
        let mut clone = CFGNodeData {
            nid: self.nid,
            weight_id: self.weight_id,
            insns: self.insns.get_clone(icfg_clone_id, cfg_clone_id),
        };
        clone.nid.icfg_clone_id = icfg_clone_id;
        clone.nid.cfg_clone_id = cfg_clone_id;
        clone
    }

    pub fn has_type(&self, wtype: InsnNodeWeightType) -> bool {
        for i in self.insns.iter() {
            if i.itype.weight_type == wtype {
                return true;
            }
        }
        false
    }

    pub fn has_entry(&self) -> bool {
        for i in self.insns.iter() {
            if i.itype.is_entry {
                return true;
            }
        }
        false
    }
}

pub struct CFGNodeDataMap {
    map: HashMap<NodeId, CFGNodeData>,
    /// Tracks the NodeIds of call instructions for faster iteration.
    call_insns_idx: HashSet<NodeId>,
}

pub struct InsnNodeDataIterator<'a> {
    node_data_iter: hash_map::Iter<'a, NodeId, CFGNodeData>,
    cur_node_data: Option<(&'a NodeId, &'a CFGNodeData)>,
    insn_index: usize,
}

impl<'a> Iterator for InsnNodeDataIterator<'a> {
    type Item = &'a InsnNodeData;
    fn next(&mut self) -> Option<&'a InsnNodeData> {
        if self.cur_node_data.is_none() {
            self.cur_node_data = self.node_data_iter.next();
            if self.cur_node_data.is_none() {
                // End of iteration. Last node data handled
                return None;
            }
            // First iteration
        }
        let nd = self.cur_node_data.expect("Check before failed.");
        if self.insn_index < nd.1.insns.len() {
            // Return next instruction
            let insn = nd.1.insns.get(self.insn_index);
            self.insn_index += 1;
            return insn;
        }
        self.insn_index = 0;
        self.cur_node_data = self.node_data_iter.next();
        if self.cur_node_data.is_none() {
            // End reached
            return None;
        }
        let insn = self.cur_node_data.unwrap().1.insns.get(self.insn_index);
        assert!(
            insn.is_some(),
            "CFGNodeData without any instructions should not exist."
        );
        self.insn_index += 1;

        return insn;
    }
}

pub struct CallInsnIterator<'a> {
    map: &'a HashMap<NodeId, CFGNodeData>,
    call_insns_idx: hash_set::Iter<'a, NodeId>,
    cur_node_data: Option<&'a CFGNodeData>,
    insn_index: usize,
}

impl<'a> Iterator for CallInsnIterator<'a> {
    type Item = &'a InsnNodeData;

    fn next(&mut self) -> Option<&'a InsnNodeData> {
        if self.cur_node_data.is_none() {
            let next_ci = self.call_insns_idx.next();
            if next_ci.is_none() {
                // No call instruction in map or end
                return None;
            }
            self.cur_node_data = self.map.get(next_ci.unwrap());
            // First iteration
        }
        let nd = self.cur_node_data.expect("Check before failed.");
        if self.insn_index < nd.insns.len() {
            // Return next instruction
            let insn = nd.insns.get(self.insn_index);
            self.insn_index += 1;
            return insn;
        }
        self.insn_index = 0;
        let next_ci = self.call_insns_idx.next();
        if next_ci.is_none() {
            // No call instrution left
            return None;
        }
        self.cur_node_data = self.map.get(next_ci.unwrap());
        let insn = self
            .cur_node_data
            .expect("Check before failed.")
            .insns
            .get(self.insn_index);
        assert!(
            insn.is_some(),
            "CFGNodeData without any instructions should not exist."
        );
        self.insn_index += 1;
        return insn;
    }
}

pub struct CallTargetIterator<'a> {
    call_insn_iter: CallInsnIterator<'a>,
    cur_cts: Option<&'a NodeIdSet>,
    call_index: usize,
}

impl<'a> Iterator for CallTargetIterator<'a> {
    type Item = &'a NodeId;

    fn next(&mut self) -> Option<&'a NodeId> {
        if self.cur_cts.is_none() {
            let next_ci = self.call_insn_iter.next();
            if next_ci.is_none() {
                // No call instruction in map or end
                return None;
            }
            self.cur_cts = Some(&next_ci.unwrap().call_targets);
            // First iteration
        }

        loop {
            let cts = self.cur_cts.unwrap();
            if self.call_index < cts.len() {
                // Return next instruction
                let ct = cts.get(self.call_index);
                self.call_index += 1;
                return ct;
            }
            self.call_index = 0;
            let next_ci = self.call_insn_iter.next();
            if next_ci.is_none() {
                // No call instruction left
                return None;
            }
            self.cur_cts = Some(&next_ci.unwrap().call_targets);
            let insn = self.cur_cts.unwrap().get(self.call_index);
            self.call_index += 1;
            if insn.is_some() {
                return insn;
            }
        }
    }
}

impl CFGNodeDataMap {
    pub fn new() -> CFGNodeDataMap {
        CFGNodeDataMap {
            map: HashMap::new(),
            call_insns_idx: HashSet::new(),
        }
    }

    pub fn insn_iter(&self) -> InsnNodeDataIterator {
        InsnNodeDataIterator {
            node_data_iter: self.map.iter(),
            cur_node_data: None,
            insn_index: 0,
        }
    }

    pub fn cinsn_iter(&self) -> CallInsnIterator {
        CallInsnIterator {
            map: &self.map,
            call_insns_idx: self.call_insns_idx.iter(),
            cur_node_data: None,
            insn_index: 0,
        }
    }

    pub fn ct_iter(&self) -> CallTargetIterator {
        CallTargetIterator {
            call_insn_iter: self.cinsn_iter(),
            cur_cts: None,
            call_index: 0,
        }
    }

    pub fn get_clone(&self, icfg_clone_id: i32, cfg_clone_id: i32) -> CFGNodeDataMap {
        let mut clone = CFGNodeDataMap::new();
        for (k, v) in self.map.iter() {
            clone.map.insert(
                k.get_clone(icfg_clone_id, cfg_clone_id),
                v.get_clone(icfg_clone_id, cfg_clone_id),
            );
        }
        for k in self.call_insns_idx.iter() {
            clone
                .call_insns_idx
                .insert(k.get_clone(icfg_clone_id, cfg_clone_id));
        }
        clone
    }

    /// For each call target
    /// O(|call instr.|)
    pub fn for_each_ct_mut<F>(&mut self, mut f: F)
    where
        Self: Sized,
        F: FnMut(&mut NodeId),
    {
        for cid in self.call_insns_idx.iter() {
            let call_insn_data: &mut CFGNodeData = self
                .map
                .get_mut(cid)
                .expect("CFG node meta data out of sync.");
            for insn in call_insn_data.insns.iter_mut() {
                for ct in insn.call_targets.iter_mut() {
                    f(ct);
                }
            }
        }
    }

    /// For each instruction
    /// O(|instr.|)
    pub fn for_each_insn_mut<F>(&mut self, mut f: F)
    where
        Self: Sized,
        F: FnMut(&mut InsnNodeData),
    {
        for ndata in self.map.values_mut() {
            for insn in ndata.insns.iter_mut() {
                f(insn)
            }
        }
    }

    /// For each call instruction
    /// O(|call instr.|)
    pub fn for_each_cinsn_mut<F>(&mut self, mut f: F)
    where
        Self: Sized,
        F: FnMut(&mut InsnNodeData),
    {
        for cid in self.call_insns_idx.iter() {
            let call_insn_data: &mut CFGNodeData = self
                .map
                .get_mut(cid)
                .expect("CFG node meta data out of sync.");
            for insn in call_insn_data.insns.iter_mut() {
                f(insn)
            }
        }
    }

    pub fn iter(&self) -> std::collections::hash_map::Iter<'_, NodeId, CFGNodeData> {
        self.map.iter()
    }

    pub fn iter_mut(&mut self) -> std::collections::hash_map::IterMut<'_, NodeId, CFGNodeData> {
        self.map.iter_mut()
    }

    pub fn values(&self) -> std::collections::hash_map::Values<'_, NodeId, CFGNodeData> {
        self.map.values()
    }

    pub fn values_mut(&mut self) -> std::collections::hash_map::ValuesMut<'_, NodeId, CFGNodeData> {
        self.map.values_mut()
    }

    pub fn insert(&mut self, key: NodeId, value: CFGNodeData) {
        if value.has_type(InsnNodeWeightType::Call) {
            self.call_insns_idx.insert(key);
        }
        self.map.insert(key, value);
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn contains_key(&self, key: &NodeId) -> bool {
        self.map.contains_key(key)
    }

    pub fn get(&self, nid: &NodeId) -> Option<&CFGNodeData> {
        self.map.get(nid)
    }

    pub fn get_mut(&mut self, nid: &NodeId) -> Option<&mut CFGNodeData> {
        self.map.get_mut(nid)
    }

    pub fn clear(&mut self) {
        self.call_insns_idx.clear();
        self.map.clear();
    }

    pub fn extend(&mut self, other: CFGNodeDataMap) {
        for ndata in other.iter() {
            if ndata.1.has_type(InsnNodeWeightType::Call) {
                self.call_insns_idx.insert(ndata.0.clone());
            }
        }
        self.map.extend(other.map);
    }
}

/// A control-flow graph of a procedure
pub struct CFG {
    /// The graph.
    pub graph: FlowGraph,
    /// Meta data for every node.
    pub nodes_meta: CFGNodeDataMap,
    /// Set of exit nodes, discovered while building the CFG.
    discovered_exits: NodeIdSet,
    /// Reverse topoloical sorted graph
    rev_topograph: Vec<NodeId>,
    /// The node id of the entry node
    entry: NodeId,
    /// Number of node duplications for loop resolvement
    dup_cnt: usize,
}

impl std::fmt::Display for CFG {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (nid, info) in self.nodes_meta.iter() {
            if info.has_entry() {
                return write!(f, "CFG({})", nid);
            }
        }
        write!(f, "CFG(empty)")
    }
}

impl CFG {
    pub fn new() -> CFG {
        CFG {
            graph: FlowGraph::new(),
            nodes_meta: CFGNodeDataMap::new(),
            rev_topograph: Vec::new(),
            discovered_exits: NodeIdSet::new(),
            entry: INVALID_NODE_ID,
            dup_cnt: 3,
        }
    }

    pub fn new_graph(graph: FlowGraph) -> CFG {
        CFG {
            graph,
            nodes_meta: CFGNodeDataMap::new(),
            rev_topograph: Vec::new(),
            discovered_exits: NodeIdSet::new(),
            entry: INVALID_NODE_ID,
            dup_cnt: 3,
        }
    }

    pub fn get_nodes_meta_mut(&mut self, nid: &NodeId) -> &mut CFGNodeData {
        match self.nodes_meta.get_mut(nid) {
            Some(m) => m,
            None => panic!("The CFG has no meta info for node {}.", nid),
        }
    }

    pub fn get_nodes_meta(&self, nid: &NodeId) -> &CFGNodeData {
        match self.nodes_meta.get(nid) {
            Some(m) => m,
            None => panic!("The CFG has no meta info for node {}.", nid),
        }
    }

    pub fn get_entry(&self) -> NodeId {
        self.entry
    }

    /// Clones itself and updates the node IDs with the given iCFG clone id
    pub fn get_clone(&self, icfg_clone_id: i32) -> CFG {
        let mut cloned_cfg: CFG = CFG {
            graph: FlowGraph::new(),
            nodes_meta: self.nodes_meta.get_clone(icfg_clone_id, -1),
            discovered_exits: self.discovered_exits.get_clone(icfg_clone_id, -1),
            rev_topograph: self.rev_topograph.clone(),
            entry: self.entry.get_clone(icfg_clone_id, -1),
            dup_cnt: self.dup_cnt.clone(),
        };

        // Lastly update the graph nodes.
        for (from, to, bias) in self.graph.all_edges() {
            let mut from_new: NodeId = from;
            from_new.icfg_clone_id = icfg_clone_id;
            let mut to_new: NodeId = to;
            to_new.icfg_clone_id = icfg_clone_id;
            cloned_cfg.graph.add_edge(from_new, to_new, *bias);
        }
        cloned_cfg
            .rev_topograph
            .iter_mut()
            .for_each(|n| n.icfg_clone_id = icfg_clone_id);

        cloned_cfg
    }

    /// Get the WeightID of the node.
    pub fn get_node_weight_id(&self, node: &NodeId) -> Option<WeightID> {
        if self.graph.node_count() == 0 {
            panic!("The graph have no nodes.");
        }
        self.get_nodes_meta(&node).weight_id
    }

    /// Get the WeightID of the CFG which saves the total CFG weight.
    pub fn get_entry_weight_id(
        &mut self,
        procedures: &ProcedureMap,
        wmap: &RwLock<WeightMap>,
    ) -> Option<WeightID> {
        if self.graph.node_count() == 0 {
            return None;
        }
        let entry_nid = match self.rev_topograph.last() {
            Some(first) => first.to_owned(),
            None => {
                panic!("If get_weight_id() is called on a CFG, the graph has to be made acyclic before.")
            }
        };
        let cfg_wid: Option<WeightID>;
        let recalc = wmap.read().unwrap().needs_recalc(&entry_nid);
        if !recalc && self.get_node_weight_id(&entry_nid).is_some() {
            cfg_wid = self.get_node_weight_id(&entry_nid);
        } else {
            cfg_wid = Some(self.calc_node_weight(&entry_nid, procedures, wmap));
            wmap.write().unwrap().set_calc_timestamp(&entry_nid);
        }
        cfg_wid
    }

    /// Get the total weight of the CFG.
    pub fn node_weight_eq_usize(&self, node: NodeId, rhs: usize, wmap: &RwLock<WeightMap>) -> bool {
        self.get_node_weight_id(&node)
            .is_some_and(|lhs| lhs.eq_usize(rhs, wmap))
    }

    /// Get the total weight of the CFG.
    pub fn weight_eq_usize(
        &mut self,
        rhs: usize,
        procedures: &ProcedureMap,
        wmap: &RwLock<WeightMap>,
    ) -> bool {
        self.get_entry_weight_id(procedures, wmap)
            .is_some_and(|lhs| lhs.eq_usize(rhs, wmap))
    }

    /// Adds an edge to the graph.
    /// The edge is only added once.
    pub fn add_edge(&mut self, from: (NodeId, CFGNodeData), to: (NodeId, CFGNodeData)) {
        if from.0 == to.0 {
            assert_eq!(from.1, to.1);
        }
        if from.1.has_entry() {
            self.entry = from.0;
            // The entry of a CFG is always the original CFG node.
            // Never a clone.
            self.entry.cfg_clone_id = 0;
        }
        if !self.nodes_meta.contains_key(&from.0) {
            self.nodes_meta.insert(from.0, from.1);
        }
        if !self.nodes_meta.contains_key(&to.0) {
            self.nodes_meta.insert(to.0, to.1);
        }
        if !self.graph.contains_edge(from.0, to.0) {
            self.graph.add_edge(from.0, to.0, 0);
        }
    }

    /// Adds an node to the graph.
    /// If the node was present before, it nothing is done.
    pub fn add_node(&mut self, node: (NodeId, CFGNodeData)) {
        if self.nodes_meta.contains_key(&node.0) && self.graph.contains_node(node.0) {
            return;
        }
        self.nodes_meta.insert(node.0, node.1);
        self.graph.add_node(node.0);
    }

    pub fn add_node_data(&mut self, node_id: NodeId, data: CFGNodeData) {
        assert!(self.graph.contains_node(node_id));
        if data.insns.iter().any(|i| i.itype.is_entry) {
            self.entry = node_id;
        }
        self.nodes_meta.insert(node_id, data);
    }

    /// Insert a call target at instruction [i] of the node [nid].
    /// If the node is not a call instruction, it returns silently.
    /// If [i] is -1, it panics if there are more than one call instructions part of the node.
    /// Otherwise it assigns the new call target.
    fn insert_call_target(&mut self, nid: &NodeId, i: isize, call_target: &NodeId) {
        let ninfo = self
            .nodes_meta
            .get_mut(nid)
            .expect(&format!("{} has no information saved.", nid));
        let mut call_set = false;
        for (j, insn) in ninfo.insns.iter_mut().enumerate() {
            if i >= 0 && i != j as isize {
                continue;
            }
            if insn.itype.weight_type == InsnNodeWeightType::Call {
                if call_set {
                    panic!("Two calls exist, but it wasn't specifies which one to update.");
                }
                insn.call_targets.insert(*call_target);
                call_set = true;
            }
        }
        if !call_set {
            panic!("Call target was not updated, either because no call exist or the instruction index is off.");
        }
    }
}

impl FlowGraphOperations for CFG {
    fn get_name(&self) -> String {
        self.to_string()
    }

    fn set_node_dup_count(&mut self, dup_cnt: usize) {
        self.dup_cnt = dup_cnt;
    }

    fn get_node_dup_count(&self) -> usize {
        self.dup_cnt
    }

    fn get_graph_mut(&mut self) -> &mut FlowGraph {
        &mut self.graph
    }

    fn clean_up_acyclic(&mut self) {
        // Update the node types for Exit nodes.
        for n in self.discovered_exits.iter() {
            let exit: &mut InsnNodeData = self
                .nodes_meta
                .get_mut(&n)
                .unwrap()
                .insns
                .last_mut()
                .unwrap();
            exit.itype.weight_type = InsnNodeWeightType::Exit;
        }
    }

    fn get_graph(&self) -> &FlowGraph {
        &self.graph
    }

    fn set_rev_topograph_mut(&mut self, rev_topograph: Vec<NodeId>) {
        self.rev_topograph = rev_topograph;
    }

    /// Increments [nid.cfg_clone_count] by [increment].
    fn get_next_node_id_clone(increment: i32, nid: NodeId) -> NodeId {
        let mut clone: NodeId = nid.clone();
        clone.cfg_clone_id += increment;
        clone
    }

    fn add_cloned_edge(&mut self, cloned_from: NodeId, cloned_to: NodeId, _flow: &EdgeFlow) {
        log_rz!(
            LOG_DEBUG,
            None,
            format!("Add cloned edge: {} -> {}", cloned_from, cloned_to)
        );
        if self.nodes_meta.contains_key(&cloned_from)
            && self.nodes_meta.contains_key(&cloned_to)
            && self.graph.contains_edge(cloned_from, cloned_to)
        {
            return;
        }
        self.add_edge(
            (
                cloned_from,
                self.get_nodes_meta(&cloned_from.get_orig_node_id())
                    .get_clone(cloned_from.icfg_clone_id, cloned_from.cfg_clone_id),
            ),
            (
                cloned_to,
                self.get_nodes_meta(&cloned_to.get_orig_node_id())
                    .get_clone(cloned_to.icfg_clone_id, cloned_to.cfg_clone_id),
            ),
        );
    }

    fn remove_edge(&mut self, from: &NodeId, to: &NodeId) {
        self.get_graph_mut().remove_edge(*from, *to);
    }

    fn handle_last_clone(&mut self, _from: &NodeId, _non_existent_node: &NodeId) {}

    fn mark_exit_node(&mut self, nid: &NodeId) {
        self.discovered_exits.insert(*nid);
    }

    /// Calculates the weight of the node with [nid].
    /// This function will re-calculate the weight of the node, if called again.
    /// If a CFG needs to be recalculated can be checked with CFG::needs_recalc().
    /// So make sure to check the weight map before for already calculated values.
    /// For just getting the current (possibly outdated) weight id of a node,
    /// use get_node_weight_id()
    /// This function assumes that all weights of called procedures are correctly calculated before.
    fn calc_node_weight(
        &mut self,
        nid: &NodeId,
        proc_map: &ProcedureMap,
        wmap: &RwLock<WeightMap>,
    ) -> WeightID {
        if self.rev_topograph.is_empty() {
            panic!("The CFG must be made acyclic before querying for node weights.")
        }
        let graph = &mut self.graph;
        let nodes_data = &mut self.nodes_meta;
        let mut done = HashSet::<NodeId>::new();
        let mut prev_nids = VecDeque::<NodeId>::new();
        let mut curr_nid = *nid;
        loop {
            let mut unvisited = VecDeque::<NodeId>::new();
            // First check all neighbor if their weights are already calculated.
            for succ_n in graph.neighbors_directed(curr_nid, Outgoing) {
                if done.contains(&succ_n) || unvisited.contains(&succ_n) {
                    continue;
                }
                unvisited.push_back(succ_n);
            }
            if !unvisited.is_empty() {
                // Calculate successors' node weights.
                let succ = unvisited.pop_back().unwrap();
                debug_assert!(
                    curr_nid != succ
                        && !prev_nids.contains(&succ)
                        && !prev_nids.contains(&curr_nid),
                    "Loops should have been resolved."
                );
                prev_nids.push_back(curr_nid);
                curr_nid = succ;
                continue;
            }
            // All childs' weights were determined or we arrived at a leaf node.
            // Get the weight ids of the successors, if any.
            let mut succ_weights: NodeWeightIDRefMap = HashMap::new();
            for neigh in graph.neighbors_directed(curr_nid, Outgoing) {
                assert!(
                    nodes_data.get(&neigh).is_some(),
                    "The weight should be calculated at this point."
                );
                succ_weights.insert(neigh, &nodes_data.get(&neigh).unwrap().weight_id);
            }

            // Sum up the weights of the successor weights and assign them to the current node.
            let mut total_weight: WeightID = wmap.read().unwrap().get_zero();
            match nodes_data.get(&curr_nid) {
                Some(n) => n
                    .iword_calc_weight(&succ_weights, proc_map, wmap)
                    .into_iter()
                    .for_each(|w| {
                        total_weight = total_weight.add(&w, wmap);
                    }),
                None => {
                    panic!("The CFG has no meta info for node {}.", curr_nid)
                }
            };
            nodes_data
                .get_mut(&curr_nid)
                .expect("Node id not in meta.")
                .weight_id = Some(total_weight);

            // Check if we calculated the weight which was actually requested.
            if curr_nid == *nid || prev_nids.is_empty() {
                assert!(
                    self.get_node_weight_id(nid).is_some(),
                    "The node {} as an invalid weight, although we just calculated it.",
                    nid
                );
                return self
                    .get_node_weight_id(nid)
                    .expect("Logic error: Weight was just calculated")
                    .clone();
            }
            // If not, go a level higher in the tree
            done.insert(curr_nid);
            curr_nid = prev_nids
                .pop_back()
                .expect("Logic error: There is no parent, but there should be");
        }
    }
}

/// A node in an iCFG describing a procedure.
pub struct Procedure {
    // The CFG of the procedure. Must be None if already added.
    cfg: Option<CFG>,
    /// Flag if this procedure is malloc.
    is_malloc: bool,
    /// Flag if this procedure provides unpredictable input.
    is_input: bool,
    /// Procedure is not mapped, likely because it is dynamically linked.
    is_unmapped: bool,
}

impl Procedure {
    pub fn new(cfg: Option<CFG>, is_malloc: bool, is_input: bool, is_unmapped: bool) -> Procedure {
        Procedure {
            cfg,
            is_malloc,
            is_input,
            is_unmapped,
        }
    }

    pub fn is_cfg_set(&self) -> bool {
        match &self.cfg {
            Some(_) => true,
            None => false,
        }
    }

    pub fn get_cfg(&self) -> &CFG {
        match &self.cfg {
            Some(cfg) => &cfg,
            None => panic!("Procedure has no CFG defined."),
        }
    }

    /// Reutrns the mutable CFG.
    pub fn get_cfg_mut(&mut self) -> &mut CFG {
        match &mut self.cfg {
            Some(ref mut cfg) => cfg,
            None => panic!("Procedure has no CFG defined."),
        }
    }

    pub fn get_clone(&self, icfg_clone_id: i32) -> Procedure {
        Procedure {
            cfg: Some(self.get_cfg().get_clone(icfg_clone_id)),
            is_malloc: self.is_malloc,
            is_input: self.is_input,
            is_unmapped: self.is_unmapped,
        }
    }

    /// Updates the call target address according to the [edge_flow] and if it is the from node.
    pub(crate) fn update_call_edge(
        &mut self,
        edge_flow: &EdgeFlow,
        from_nid: &NodeId,
        to_nid: &NodeId,
        is_to_node: bool,
    ) {
        if is_to_node {
            return;
        }
        match edge_flow {
            EdgeFlow::OutsiderFixedFrom => {
                self.get_cfg_mut().nodes_meta.for_each_cinsn_mut(|insn| {
                    if insn.call_targets.contains_any_variant_of(to_nid) {
                        insn.call_targets.insert(to_nid.clone());
                    }
                });
            }
            EdgeFlow::OutsiderFixedTo => {
                // Is from: Don't update ct
                return;
            }
            EdgeFlow::BackEdge => {
                // is from: Update ct to icfg clone id
                self.get_cfg_mut().nodes_meta.for_each_cinsn_mut(|ci| {
                    // Prevent duplication of call targets.
                    let mut seen = HashSet::<NodeId>::new();
                    ci.call_targets.retain_mut(|ct| {
                        if ct.address == to_nid.address {
                            ct.icfg_clone_id = to_nid.icfg_clone_id;
                            if seen.contains(ct) {
                                return false;
                            }
                            seen.insert(*ct);
                            return true;
                        }
                        seen.insert(*ct);
                        return true;
                    });
                });
            }
            EdgeFlow::ForwardEdge => {
                self.get_cfg_mut().nodes_meta.for_each_ct_mut(|ct| {
                    if ct.address == to_nid.address {
                        ct.icfg_clone_id = from_nid.icfg_clone_id;
                    }
                });
                return;
            }
        }
    }

    /// True if this procedure is considered a memory allocating functions.
    /// False otherwise.
    pub fn is_malloc(&self) -> bool {
        self.is_malloc
    }

    /// True if this procedure is not mapped in memory.
    /// False otherwise.
    pub fn is_unmapped(&self) -> bool {
        self.is_unmapped
    }

    /// True if this procedure is not executed.
    /// False otherwise.
    pub fn wont_execute(&self) -> bool {
        self.is_malloc || self.is_input || self.is_unmapped
    }

    /// Insert call target at instruction [i] of the node [nid] in the procedures CFG.
    /// If [i] is -1, it panics if there are more than one call instructions part of the node.
    /// Otherwise it updates the single call.
    /// It panics if no call was updated.
    pub fn insert_call_target(&mut self, nid: &NodeId, i: isize, call_target: &NodeId) {
        self.get_cfg_mut().insert_call_target(nid, i, call_target);
    }

    /// For each call target
    /// O(|call instr.|)
    pub fn for_each_ct<F>(&mut self, f: F)
    where
        Self: Sized,
        F: FnMut(&mut NodeId),
    {
        self.get_cfg_mut().nodes_meta.for_each_ct_mut(f);
    }

    /// For each instruction
    /// O(|instr.|)
    pub fn _for_each_insn<F>(&mut self, f: F)
    where
        Self: Sized,
        F: FnMut(&mut InsnNodeData),
    {
        self.get_cfg_mut().nodes_meta.for_each_insn_mut(f);
    }

    /// For each call instruction
    /// O(|call instr.|)
    pub fn for_each_cinsn<F>(&mut self, f: F)
    where
        Self: Sized,
        F: FnMut(&mut InsnNodeData),
    {
        self.get_cfg_mut().nodes_meta.for_each_cinsn_mut(f);
    }
}
