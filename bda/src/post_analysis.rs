// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use helper::matrix::Matrix;
use helper::set_map::SetMap;
use rzil_abstr::interpreter::{AbstrVal, IWordInfo, MemOpSeq};

use crate::{
    flow_graphs::{Address, FlowGraphOperations},
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

type CallStack = VecDeque<Address>;

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
}

/// A state index is the address of the instruction and
/// the index of the call stack this instruction is executed under.
type StateIdx = (usize, Address);

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
        new_state.state.insert((0, entry), MemDefMap::new());
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

    fn def_maps_equal(&self, succ: &StateIdx, iaddr: &StateIdx) -> bool {
        let succ_m2i = self.state.get(succ);
        let iaddr_m2i = self.state.get(iaddr);
        if succ_m2i.is_none() || iaddr_m2i.is_none() {
            return false;
        }
        succ_m2i.unwrap().map == iaddr_m2i.unwrap().map
    }

    /// Sets the maps of [a] to `a.DEF = a.DEF ∪  b.DEF`
    fn merge_maps(&mut self, a: &StateIdx, b: &StateIdx) {
        let Some(b_m2i) = self.state.get(b) else {
            return;
        };
        self.state.insert(*a, b_m2i.clone());
    }

    fn push_to_cs(&mut self, cs_idx: usize, addr: Address) {
        if let Some(call_stack) = self.call_stacks.get_mut(cs_idx) {
            call_stack.push_back(addr);
            return;
        }
        let mut new_call_stack = CallStack::new();
        new_call_stack.push_back(addr);
        self.call_stacks.insert(cs_idx, new_call_stack);
    }

    fn pop_from_cs(&mut self, cs_idx: usize) -> Address {
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
    programm_graph: Matrix<Address, U8Cell>,
    /// Instruction meta data (instruction type etc.)
    insn_meta_data: SetMap<Address, IWordInfo>,
    /// Dependent instruction pairs. If set, there is a dependency between the instructions.
    DIP: BTreeSet<(Address, Address)>,
}

impl PostAnalyzer {
    pub fn new(icfg: &ICFG, iword_info: SetMap<Address, IWordInfo>) -> PostAnalyzer {
        let mut edge_matrix = Matrix::new();
        for cfg in icfg.get_procedures().iter() {
            for (x_insn, y_insn, _) in cfg.1.read().unwrap().get_cfg().get_graph().all_edges() {
                edge_matrix.set_cell(x_insn.address, y_insn.address, IEDGE);
            }
            for call_insn in cfg.1.read().unwrap().get_cfg().nodes_meta.cinsn_iter() {
                call_insn.call_targets.iter().for_each(|ct| {
                    edge_matrix.set_cell(call_insn.addr, ct.address, CEDGE);
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

    fn is_return(&self, addr: &Address) -> bool {
        if let Some(info) = self.insn_meta_data.get(addr) {
            return info.iter().any(|i| i.is_return());
        }
        false
    }

    fn per_sample_analysis(
        &self,
        MOS: MemOpSeq,
        I2M: &mut SetMap<Address, AbstrVal>,
        DEP: &mut SetMap<Address, Address>,
        KILL: &mut SetMap<Address, Address>,
    ) {
        let mut DEF = BTreeMap::<AbstrVal, Address>::new();

        for mem_op in MOS.into_iter() {
            let iaddr = mem_op.ref_addr;
            let aval = mem_op.aval;
            if self.is_mem_write(&iaddr) {
                if let Some(def_iaddr) = DEF.get(&aval) {
                    // Kills previous definition, because it overwrits it.
                    KILL.insert(iaddr, *def_iaddr);
                } else {
                    // Set last address which wrote to aval.
                    DEF.insert(aval.clone(), iaddr);
                }
            }
            if self.is_mem_read(&iaddr) {
                if let Some(def_iaddr) = DEF.get(&aval) {
                    DEP.insert(iaddr, *def_iaddr);
                }
            }
            I2M.insert(iaddr, aval);
        }
    }

    fn handle_memory_write(
        iaddr: Address,
        state: &mut AbstractProgramState,
        curr_state_idx: &StateIdx,
        GI2M: &SetMap<Address, AbstrVal>,
        GKILL: &SetMap<Address, Address>,
    ) {
        let mut curr_m2i = state.get_mut(curr_state_idx);
        if curr_m2i.is_none() {
            state.add_empty_map(curr_state_idx);
            curr_m2i = state.get_mut(curr_state_idx);
        }
        let Some(i2m_iter) = GI2M.set_iter(&iaddr) else {
            return;
        };
        for maddr in i2m_iter {
            if GI2M.len_of(&iaddr) == 1 {
                curr_m2i
                    .as_mut()
                    .unwrap()
                    .strong_update(maddr.clone(), iaddr);
            } else {
                curr_m2i.as_mut().unwrap().insert(maddr.clone(), iaddr);
                if GKILL.len_of(&iaddr) == 1 {
                    curr_m2i
                        .as_mut()
                        .unwrap()
                        .strong_kill(maddr, GKILL.get(&iaddr))
                }
            }
        }
    }

    fn handle_memory_read(
        DIP: &mut BTreeSet<(Address, Address)>,
        iaddr: Address,
        state: &AbstractProgramState,
        curr_state_idx: &StateIdx,
        GI2M: &SetMap<Address, AbstrVal>,
        GDEP: &SetMap<Address, Address>,
    ) {
        if GDEP.len_of(&iaddr) == 1 {
            let Some(iter) = GDEP.set_iter(&iaddr) else {
                return;
            };
            for def in iter {
                DIP.insert((iaddr, *def));
            }
        } else {
            let Some(i2m_iter) = GI2M.set_iter(&iaddr) else {
                return;
            };
            for maddr in i2m_iter {
                let Some(m2i) = state.get(curr_state_idx) else {
                    continue;
                };
                let Some(m2i_iter) = m2i.map.set_iter(maddr) else {
                    continue;
                };
                for def in m2i_iter {
                    DIP.insert((iaddr, *def));
                }
            }
        }
    }

    fn next_icfg_entry(&mut self) -> Option<u64> {
        self.icfg_entries.pop()
    }

    fn iter_successors(
        &self,
        iaddr: Address,
        successor_type: U8Cell,
    ) -> helper::matrix::KeyIter<Address, U8Cell> {
        if successor_type == CEDGE {
            return self.programm_graph.x_row_key_iter(&iaddr, &is_cedge_cell);
        } else if successor_type == IEDGE {
            return self.programm_graph.x_row_key_iter(&iaddr, &is_iedge_cell);
        }
        panic!("Edge type not handled: {}", successor_type);
    }

    fn get_dip_mut(&mut self) -> &mut BTreeSet<(Address, Address)> {
        &mut self.DIP
    }
}

pub fn posterior_dependency_analysis(
    state: &mut BDAState,
    icfg: &ICFG,
) -> SetMap<Address, Address> {
    let mut analyzer = PostAnalyzer::new(icfg, state.take_iword_info());
    // TODO: Handle all entries
    let icfg_entry = analyzer.next_icfg_entry();
    let mut abstr_prog_state =
        AbstractProgramState::new(icfg_entry.expect("No icfg_entry defined."));

    let mut I2M = SetMap::<Address, AbstrVal>::new();
    let mut DEP = SetMap::<Address, Address>::new();
    let mut KILL = SetMap::<Address, Address>::new();
    analyzer.per_sample_analysis(state.take_mos(), &mut I2M, &mut DEP, &mut KILL);

    let mut work_list: VecDeque<StateIdx> = VecDeque::new();
    work_list.push_back((0, icfg_entry.unwrap()));
    let mut succ_edge_type;
    while !work_list.is_empty() {
        let state_idx = work_list.pop_front().unwrap();
        let mut iaddr = state_idx.1;
        let cs_idx = state_idx.0;
        if analyzer.is_call(&iaddr) {
            abstr_prog_state.push_to_cs(cs_idx, iaddr);
            succ_edge_type = CEDGE;
        } else {
            if analyzer.is_return(&iaddr) {
                iaddr = abstr_prog_state.pop_from_cs(cs_idx);
            }
            succ_edge_type = IEDGE;
        }
        if analyzer.is_mem_write(&iaddr) {
            PostAnalyzer::handle_memory_write(
                iaddr,
                &mut abstr_prog_state,
                &state_idx,
                &I2M,
                &KILL,
            );
        } else if analyzer.is_mem_read(&iaddr) {
            PostAnalyzer::handle_memory_read(
                analyzer.get_dip_mut(),
                iaddr,
                &abstr_prog_state,
                &state_idx,
                &I2M,
                &DEP,
            );
        }
        for succ in analyzer.iter_successors(iaddr, succ_edge_type) {
            let succ_state_id = (cs_idx, *succ);
            if !abstr_prog_state.def_maps_equal(&succ_state_id, &state_idx) {
                abstr_prog_state.merge_maps(&succ_state_id, &state_idx);
                work_list.push_back(succ_state_id);
            }
        }
    }
    DEP
}
