// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#![allow(dead_code)]

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt::LowerHex,
    ops::RangeInclusive,
};

use helper::matrix::Matrix;
use helper::set_map::SetMap;
use rzil_abstr::interpreter::{AbstrVal, IWordInfo, MemOpSeq};

use crate::{
    flow_graphs::{Address, FlowGraphOperations, NodeId},
    icfg::ICFG,
    state::BDAState,
};

type U8Cell = u8;

/// No edge.
const NO_EDGE: U8Cell = 0x00;
/// Non-Call edge.
const IEDGE: U8Cell = 0x01;
/// Call edge
const CEDGE: U8Cell = 0x02;

fn is_iedge_cell(cell: &U8Cell) -> bool {
    *cell == IEDGE
}

fn is_cedge_cell(cell: &U8Cell) -> bool {
    *cell == CEDGE
}

fn is_c_or_iedge_cell(cell: &U8Cell) -> bool {
    *cell == IEDGE || *cell == CEDGE
}

type CallStack = VecDeque<NodeId>;

/// M2I -> Map abstract value to its defining instructions (mem writes)
/// One abstract value can have multiple definitions (writes).
/// Here we map abstract values to their defining instructions (mem writes).
#[derive(Clone)]
struct MemDefMap {
    map: SetMap<AbstrVal, Address>,
}

impl MemDefMap {
    fn new() -> MemDefMap {
        MemDefMap { map: SetMap::new() }
    }

    fn merge(&mut self, other: MemDefMap) {
        for (maddr, addr_set) in other.map.into_iter() {
            self.map.extend(maddr, addr_set);
        }
    }

    fn strong_update(&mut self, maddr: AbstrVal, iaddr: Address) {
        self.map.reset_to(maddr, iaddr);
    }

    fn insert(&mut self, maddr: AbstrVal, iaddr: Address) {
        self.map.insert(maddr, iaddr);
    }

    fn strong_kill(&mut self, maddr: &AbstrVal, addr_set: Option<&BTreeSet<u64>>) {
        if addr_set.is_none() {
            return;
        }
        self.map.assign_difference(maddr, addr_set.unwrap());
    }

    fn get<'a>(&'a self, aval: &AbstrVal) -> Option<&'a BTreeSet<u64>> {
        self.map.get(aval)
    }

    // Return if [self] contains [other]
    fn contains(&self, other: &MemDefMap) -> bool {
        for (aval_key, addr_set) in other.map.iter() {
            if let Some(set) = self.map.get(aval_key) {
                if addr_set == set {
                    continue;
                }
                return false;
            }
            return false;
        }
        true
    }
}

impl LowerHex for MemDefMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}", self.map)
    }
}

/// A state index is the address of the instruction and
/// the index of the call stack this instruction is executed under.
type StateIdx = (usize, NodeId);

#[derive(Debug)]
struct WorkList {
    /// Work list for each call stack.
    stack: BTreeMap<usize, VecDeque<NodeId>>,
    head: usize,
}

impl WorkList {
    fn new(procedure_entry: Address) -> WorkList {
        let mut list = WorkList {
            stack: BTreeMap::new(),
            head: 0,
        };
        list.stack.insert(
            0,
            VecDeque::from_iter([NodeId::new_original(procedure_entry)]),
        );
        list
    }

    fn push_back(&mut self, state_idx: StateIdx) {
        let (cs_idx, addr) = state_idx;
        if let Some(queue) = self.stack.get_mut(&cs_idx) {
            queue.push_back(addr);
        } else {
            self.stack.insert(cs_idx, VecDeque::from([addr]));
        }
        self.head = cs_idx;
    }

    fn pop_front(&mut self) -> StateIdx {
        let mut queue = self
            .stack
            .get_mut(&self.head)
            .expect("Work list out of sync wih program state. Likely an unmarked return or call instruction messed up the stack.");
        if queue.is_empty() {
            self.head -= 1;
            queue = self
                .stack
                .get_mut(&self.head)
                .expect("Work list out of sync.");
        }
        (
            self.head,
            queue
                .pop_front()
                .expect("Work list out of sync wih program state. Likely an unmarked return or call instruction messed up the stack."),
        )
    }

    fn is_empty(&self) -> bool {
        if self.head > 0 {
            return false;
        }
        self.stack.get(&0).expect("Unreachable").is_empty()
    }
}

struct AbstractProgramState {
    /// Set of unique CallStacks.
    call_stacks: Vec<CallStack>,
    /// Maps single states (call stack X addr. of insn.) to the memory definitions.
    /// CallStack references point to the values in [Self::call_stacks]
    state: BTreeMap<StateIdx, MemDefMap>,
}

impl AbstractProgramState {
    fn new(entry: Address) -> AbstractProgramState {
        let mut new_state = AbstractProgramState {
            call_stacks: Vec::new(),
            state: BTreeMap::new(),
        };
        // Insert initial empty call stack entry.
        new_state.call_stacks.push(CallStack::new());
        // Entry state points to an invalid call stack index.
        new_state
            .state
            .insert((0, NodeId::new_original(entry)), MemDefMap::new());
        new_state
    }

    fn get_mut(&mut self, idx: &StateIdx) -> Option<&mut MemDefMap> {
        if let Some(mem_defs) = self.state.get_mut(idx) {
            return Some(mem_defs);
        }
        None
    }

    fn get(&self, idx: &StateIdx) -> Option<&MemDefMap> {
        if let Some(mem_defs) = self.state.get(idx) {
            return Some(mem_defs);
        }
        None
    }

    fn m2i_contains(&self, succ: &StateIdx, iaddr: &StateIdx) -> bool {
        let succ_m2i = self.state.get(succ);
        let iaddr_m2i = self.state.get(iaddr);
        if iaddr_m2i.is_none() || succ_m2i.is_none() {
            return false;
        }
        succ_m2i.unwrap().contains(iaddr_m2i.unwrap())
    }

    /// Sets the maps of [a] to `a.DEF = a.DEF ∪  b.DEF`
    fn merge_maps(&mut self, a: &StateIdx, b: &StateIdx) {
        if self.state.get(b).is_none() {
            return;
        }
        let b_clone = self.state.get(b).unwrap().clone();

        if let Some(map) = self.state.get_mut(a) {
            map.merge(b_clone);
        } else {
            self.state.insert(*a, b_clone);
        }
    }

    fn push_to_cs(&mut self, cs_idx: usize, addr: NodeId) {
        if let Some(call_stack) = self.call_stacks.get_mut(cs_idx) {
            call_stack.push_back(addr);
            return;
        }
        let mut new_call_stack = CallStack::new();
        new_call_stack.push_back(addr);
        self.call_stacks.insert(cs_idx, new_call_stack);
    }

    fn pop_from_cs(&mut self, cs_idx: usize) -> NodeId {
        self.call_stacks
            .get_mut(cs_idx)
            .expect("Call stack was not initiaized.")
            .pop_back()
            .expect("Call stack has no entry left.")
    }

    fn add_empty_map(&mut self, state_idx: &StateIdx) {
        self.state.insert(*state_idx, MemDefMap::new());
    }
}

pub struct PostAnalyzer {
    /// Entry addresses into iCFG.
    icfg_entries: Vec<Address>,
    /// The complete flow graph of the whole program.
    /// The rows are offsets from the minimal address sampled.
    programm_graph: Matrix<NodeId, U8Cell>,
    /// Instruction meta data (instruction type etc.)
    insn_meta_data: BTreeMap<Address, IWordInfo>,
    /// Dependent instruction pairs. If set, there is a dependency between the instructions.
    DIP: BTreeSet<(Address, Address)>,
}

impl PostAnalyzer {
    pub fn new(icfg: &ICFG, iword_info: BTreeMap<Address, IWordInfo>) -> PostAnalyzer {
        let mut edge_matrix = Matrix::new();
        for cfg in icfg.get_procedures().iter() {
            for (x_insn, y_insn, _) in cfg.1.read().unwrap().get_cfg().get_graph().all_edges() {
                edge_matrix.set_cell(x_insn, y_insn, IEDGE);
            }
            let icfg_clone_id = cfg.0.icfg_clone_id;
            for call_insn in cfg.1.read().unwrap().get_cfg().nodes_meta.cinsn_iter() {
                call_insn.call_targets.iter().for_each(|ct| {
                    edge_matrix.set_cell(NodeId::new(icfg_clone_id, 0, call_insn.addr), *ct, CEDGE);
                });
            }
        }
        PostAnalyzer {
            icfg_entries: icfg.get_entry_points().clone(),
            programm_graph: edge_matrix,
            insn_meta_data: iword_info,
            DIP: BTreeSet::new(),
        }
    }

    fn is_mem_write(&self, addr: &Address) -> bool {
        if let Some(info) = self.insn_meta_data.get(addr) {
            return info.iter().any(|i| i.is_mem_write());
        }
        false
    }

    fn is_mem_read(&self, addr: &Address) -> bool {
        if let Some(info) = self.insn_meta_data.get(addr) {
            return info.iter().any(|i| i.is_mem_read());
        }
        false
    }

    fn is_call(&self, addr: &Address) -> bool {
        if let Some(info) = self.insn_meta_data.get(addr) {
            return info.iter().any(|i| i.is_call());
        }
        false
    }

    fn is_call_to_skip(&self, addr: &Address) -> bool {
        if let Some(info) = self.insn_meta_data.get(addr) {
            return info
                .iter()
                .any(|i| i.calls_malloc() || i.calls_input() || i.calls_unmapped());
        }
        false
    }

    fn is_return(&self, addr: &Address) -> bool {
        if let Some(info) = self.insn_meta_data.get(addr) {
            return info.iter().any(|i| i.is_return());
        }
        false
    }

    fn addr_info(&self, addr: &Address) -> String {
        if let Some(info) = self.insn_meta_data.get(addr) {
            let mut info_str = "<".to_string();
            info.iter()
                .for_each(|i| info_str.push_str(format!("{}", i).as_str()));
            info_str.push_str(">");
            return info_str;
        }
        "<>".to_string()
    }

    fn per_sample_analysis(
        &self,
        MOS: MemOpSeq,
        I2M: &mut SetMap<Address, AbstrVal>,
        DEP: &mut SetMap<Address, Address>,
        KILL: &mut SetMap<Address, Address>,
    ) {
        // println!("MOS: {:?}", self.insn_meta_data);
        debug_assert!(
            MOS.iter()
                .all(|mop| { self.insn_meta_data.get(&mop.ref_addr).is_some() }),
            "Some MemOps have no iword meta data."
        );
        let mut DEF = BTreeMap::<AbstrVal, Address>::new();

        for mem_op in MOS.into_iter() {
            let iaddr = mem_op.ref_addr;
            let aval = mem_op.aval;
            if self.is_mem_write(&iaddr) {
                if let Some(def_addr) = DEF.get(&aval) {
                    KILL.insert(iaddr, *def_addr);
                }
                DEF.insert(aval.clone(), iaddr);
            }
            if self.is_mem_read(&iaddr) {
                if let Some(def_addr) = DEF.get(&aval) {
                    DEP.insert(iaddr, *def_addr);
                }
            }
            I2M.insert(iaddr, aval);
        }
        // println!("DEF:");
        // for (k, v) in DEF.iter() {
        //     println!("{} -> {:#x}", k, v);
        // }
    }

    fn handle_memory_write(
        iaddr: Address,
        state: &mut AbstractProgramState,
        curr_state_idx: &StateIdx,
        GI2M: &SetMap<Address, AbstrVal>,
        _GKILL: &SetMap<Address, Address>,
    ) {
        let mut curr_m2i = state.get_mut(curr_state_idx);
        if curr_m2i.is_none() {
            state.add_empty_map(curr_state_idx);
            curr_m2i = state.get_mut(curr_state_idx);
        }
        let Some(m2i) = curr_m2i.as_mut() else {
            panic!("It was just initialized");
        };
        let Some(i2m_iter) = GI2M.set_iter(&iaddr) else {
            return;
        };
        for maddr in i2m_iter {
            if m2i.get(maddr).is_some() {
                // This instruction overwrites the previous defintion
                // at the current abstract program state.
                m2i.strong_update(maddr.clone(), iaddr);
            } else {
                m2i.insert(maddr.clone(), iaddr);
                // Why is kill necessary again?
                // if GKILL.len_of(&iaddr) == 1 {
                //     m2i.strong_kill(maddr, GKILL.get(&iaddr))
                // }
            }
        }
    }

    fn handle_memory_read(
        DIP: &mut BTreeSet<(Address, Address)>,
        iaddr: Address,
        state: &AbstractProgramState,
        curr_state_idx: &StateIdx,
        GI2M: &SetMap<Address, AbstrVal>,
        _GDEP: &SetMap<Address, Address>,
    ) {
        // TODO: Why again taking the DEP deendencies, when we can have the abstract value based one?
        // if GDEP.len_of(&iaddr) == 1 {
        //     let Some(iter) = GDEP.set_iter(&iaddr) else {
        //         return;
        //     };
        //     for def in iter {
        //         DIP.insert((iaddr, *def));
        //     }
        // } else {
        let Some(i2m_iter) = GI2M.set_iter(&iaddr) else {
            return;
        };
        let Some(m2i) = state.get(curr_state_idx) else {
            return;
        };
        for maddr in i2m_iter {
            let Some(m2i_iter) = m2i.map.set_iter(maddr) else {
                continue;
            };
            for def in m2i_iter {
                DIP.insert((iaddr, *def));
            }
        }
        // }
    }

    fn next_icfg_entry(&mut self) -> Option<u64> {
        self.icfg_entries.pop()
    }

    fn iter_successors(
        &self,
        iaddr: &NodeId,
        successor_type: U8Cell,
    ) -> helper::matrix::KeyIter<NodeId, U8Cell> {
        if successor_type == CEDGE {
            return self.programm_graph.x_row_key_iter(iaddr, &is_cedge_cell);
        } else if successor_type == IEDGE {
            return self.programm_graph.x_row_key_iter(iaddr, &is_iedge_cell);
        } else if successor_type == (IEDGE | CEDGE) {
            return self
                .programm_graph
                .x_row_key_iter(iaddr, &is_c_or_iedge_cell);
        }
        panic!("Edge type not handled: {}", successor_type);
    }

    fn get_dip_mut(&mut self) -> &mut BTreeSet<(Address, Address)> {
        &mut self.DIP
    }

    fn clone_dip(&self) -> BTreeSet<(Address, Address)> {
        self.DIP.clone()
    }

    // Returns true if any of the call targets is followed.
    // False otherwise.
    fn call_is_followed(&self, addr_ranges: &Vec<RangeInclusive<Address>>, iaddr: &NodeId) -> bool {
        if self.is_call_to_skip(&iaddr.address) {
            return false;
        }
        for call_target in self.iter_successors(iaddr, CEDGE) {
            if addr_ranges
                .iter()
                .any(|range| range.contains(&call_target.address))
            {
                return true;
            }
        }
        false
    }
}

pub fn posterior_dependency_analysis(
    state: &mut BDAState,
    icfg: &ICFG,
) -> BTreeSet<(Address, Address)> {
    let mut analyzer = PostAnalyzer::new(icfg, state.take_iword_info());
    // TODO: Handle all entries
    let icfg_entry = analyzer.next_icfg_entry();
    let mut abstr_prog_state =
        AbstractProgramState::new(icfg_entry.expect("No icfg_entry defined."));

    let mut I2M = SetMap::<Address, AbstrVal>::new();
    let mut DEP = SetMap::<Address, Address>::new();
    let mut KILL = SetMap::<Address, Address>::new();
    for mos in state.take_moses() {
        analyzer.per_sample_analysis(mos, &mut I2M, &mut DEP, &mut KILL);
    }
    // println!("I2M:\n{:x}", I2M);
    // println!("DEP:\n{:x}", DEP);
    // println!("KILL:\n{:x}", KILL);

    let mut work_list: WorkList = WorkList::new(icfg_entry.unwrap());
    let mut succ_type;
    while !work_list.is_empty() {
        let state_idx = work_list.pop_front();
        let mut iaddr = state_idx.1;
        let mut cs_idx = state_idx.0;
        println!(
            "CS-idx: {cs_idx} - Address: {iaddr} - {}",
            analyzer.addr_info(&iaddr.address)
        );
        println!("{work_list:?}");
        // Handle references
        if analyzer.is_mem_write(&iaddr.address) {
            PostAnalyzer::handle_memory_write(
                iaddr.address,
                &mut abstr_prog_state,
                &state_idx,
                &I2M,
                &KILL,
            );
        }
        if analyzer.is_mem_read(&iaddr.address) {
            PostAnalyzer::handle_memory_read(
                analyzer.get_dip_mut(),
                iaddr.address,
                &abstr_prog_state,
                &state_idx,
                &I2M,
                &DEP,
            );
        }

        // Choose which neighbor to follow.
        if analyzer.is_call(&iaddr.address) && analyzer.call_is_followed(state.get_ranges(), &iaddr)
        {
            // Go into a procedure
            abstr_prog_state.push_to_cs(cs_idx, iaddr);
            cs_idx += 1;
            succ_type = CEDGE;
        } else if analyzer.is_return(&iaddr.address) {
            // Return from a procedure. Select a neighbor from the call we return to.
            if cs_idx == 0 {
                // Don't return from main though.
                // Just go to the next node in the work list if any left.
                continue;
            }
            cs_idx -= 1;
            iaddr = abstr_prog_state.pop_from_cs(cs_idx);
            succ_type = IEDGE;
        } else {
            // Normal instruction.
            succ_type = IEDGE
        }

        // if let Some(m2i) = abstr_prog_state.get(&state_idx) {
        //     println!("M2I:\n{m2i:x}");
        // } else {
        //     println!("M2I: None");
        // }
        for succ in analyzer.iter_successors(&iaddr, succ_type) {
            let succ_state_id = (cs_idx, *succ);
            if !abstr_prog_state.m2i_contains(&succ_state_id, &state_idx) {
                abstr_prog_state.merge_maps(&succ_state_id, &state_idx);
                work_list.push_back(succ_state_id);
            }
        }
    }
    analyzer.clone_dip()
}
