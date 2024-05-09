// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only
#![allow(unused)]

use std::collections::{HashMap, VecDeque};

use binding::{null_check, pderef, GRzCore, RzILOpEffect, RzILOpPure, RzILTypePure};

use crate::op_handler::{
    rz_il_handler_add, rz_il_handler_append, rz_il_handler_bitv, rz_il_handler_blk,
    rz_il_handler_bool_and, rz_il_handler_bool_false, rz_il_handler_bool_inv,
    rz_il_handler_bool_or, rz_il_handler_bool_true, rz_il_handler_bool_xor, rz_il_handler_branch,
    rz_il_handler_cast, rz_il_handler_div, rz_il_handler_empty, rz_il_handler_eq,
    rz_il_handler_fabs, rz_il_handler_fadd, rz_il_handler_fbits, rz_il_handler_fcast_float,
    rz_il_handler_fcast_int, rz_il_handler_fcast_sfloat, rz_il_handler_fcast_sint,
    rz_il_handler_fcompound, rz_il_handler_fconvert, rz_il_handler_fdiv, rz_il_handler_fhypot,
    rz_il_handler_float, rz_il_handler_fmad, rz_il_handler_fmod, rz_il_handler_fmul,
    rz_il_handler_fneg, rz_il_handler_forder, rz_il_handler_fpow, rz_il_handler_fpown,
    rz_il_handler_fpred, rz_il_handler_frequal, rz_il_handler_frootn, rz_il_handler_fround,
    rz_il_handler_frsqrt, rz_il_handler_fsqrt, rz_il_handler_fsub, rz_il_handler_fsucc,
    rz_il_handler_goto, rz_il_handler_is_finite, rz_il_handler_is_fneg, rz_il_handler_is_fpos,
    rz_il_handler_is_fzero, rz_il_handler_is_inf, rz_il_handler_is_nan, rz_il_handler_is_zero,
    rz_il_handler_ite, rz_il_handler_jmp, rz_il_handler_let, rz_il_handler_load,
    rz_il_handler_loadw, rz_il_handler_logical_and, rz_il_handler_logical_not,
    rz_il_handler_logical_or, rz_il_handler_logical_xor, rz_il_handler_lsb, rz_il_handler_mod,
    rz_il_handler_msb, rz_il_handler_mul, rz_il_handler_neg, rz_il_handler_nop,
    rz_il_handler_repeat, rz_il_handler_sdiv, rz_il_handler_seq, rz_il_handler_set,
    rz_il_handler_shiftl, rz_il_handler_shiftr, rz_il_handler_sle, rz_il_handler_smod,
    rz_il_handler_store, rz_il_handler_storew, rz_il_handler_sub, rz_il_handler_ule,
    rz_il_handler_var, IL_OP_ADD, IL_OP_AND, IL_OP_APPEND, IL_OP_B0, IL_OP_B1, IL_OP_BITV,
    IL_OP_BLK, IL_OP_BRANCH, IL_OP_CAST, IL_OP_DIV, IL_OP_EMPTY, IL_OP_EQ, IL_OP_FABS, IL_OP_FADD,
    IL_OP_FBITS, IL_OP_FCAST_FLOAT, IL_OP_FCAST_INT, IL_OP_FCAST_SFLOAT, IL_OP_FCAST_SINT,
    IL_OP_FCOMPOUND, IL_OP_FCONVERT, IL_OP_FDIV, IL_OP_FHYPOT, IL_OP_FLOAT, IL_OP_FMAD, IL_OP_FMOD,
    IL_OP_FMUL, IL_OP_FNEG, IL_OP_FORDER, IL_OP_FPOW, IL_OP_FPOWN, IL_OP_FPRED, IL_OP_FREQUAL,
    IL_OP_FROOTN, IL_OP_FROUND, IL_OP_FRSQRT, IL_OP_FSQRT, IL_OP_FSUB, IL_OP_FSUCC, IL_OP_GOTO,
    IL_OP_INV, IL_OP_IS_FINITE, IL_OP_IS_FNEG, IL_OP_IS_FPOS, IL_OP_IS_FZERO, IL_OP_IS_INF,
    IL_OP_IS_NAN, IL_OP_IS_ZERO, IL_OP_ITE, IL_OP_JMP, IL_OP_LET, IL_OP_LOAD, IL_OP_LOADW,
    IL_OP_LOGAND, IL_OP_LOGNOT, IL_OP_LOGOR, IL_OP_LOGXOR, IL_OP_LSB, IL_OP_MOD, IL_OP_MSB,
    IL_OP_MUL, IL_OP_NEG, IL_OP_NOP, IL_OP_OR, IL_OP_PURE_MAX, IL_OP_REPEAT, IL_OP_SDIV, IL_OP_SEQ,
    IL_OP_SET, IL_OP_SHIFTL, IL_OP_SHIFTR, IL_OP_SLE, IL_OP_SMOD, IL_OP_STORE, IL_OP_STOREW,
    IL_OP_SUB, IL_OP_ULE, IL_OP_VAR, IL_OP_XOR,
};

type Address = u64;
type Const = u64;
type PC = Address;
type Register = u64;

pub struct IntrpPath {
    path: VecDeque<Address>,
}

impl IntrpPath {
    pub fn new() -> IntrpPath {
        IntrpPath {
            path: VecDeque::new(),
        }
    }

    pub fn push(&mut self, addr: Address) {
        self.path.push_back(addr);
    }

    pub fn next(&mut self) -> Option<Address> {
        self.path.pop_front()
    }

    pub fn get(&self, i: usize) -> Address {
        self.path
            .get(i)
            .expect(&format!("Index i = {} out of range", i))
            .clone()
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
struct MemRegion {
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
struct AbstrVal {
    /// The memory region of this value
    region: MemRegion,
    /// The offset of this variable from the base of the region.
    offset: i64,
}

struct MemOp {
    /// Address of the memory instruction
    addr: Address,
    /// The abstract memory value which is processed.
    aval: AbstrVal,
}

type MemOpSeq = Vec<MemOp>;

struct CallFrame {
    /// The invocation site
    in_site: Address,
    /// The instance count.
    instance: Const,
    /// The return address
    return_addr: Address,
    /// The abstract value of the SP register
    sp: AbstrVal,
}

type CallStack = VecDeque<CallFrame>;

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
pub struct AbstrVM {
    /// Program counter
    pc: PC,
    /// Instruction sizes map
    is: HashMap<Address, Const>,
    /// Invocation count map
    ic: HashMap<Address, Const>,
    /// Loop predicate map
    lp: HashMap<Address, bool>,
    /// MemStore map
    ms: HashMap<AbstrVal, AbstrVal>,
    /// RegStore map
    rs: HashMap<Register, AbstrVal>,
    /// MemTaint map
    mt: HashMap<AbstrVal, AbstrVal>,
    /// RegTaint map
    rt: HashMap<Register, AbstrVal>,
    /// Path
    pa: IntrpPath,
    /// Random input validation
    rv: fn(Address, Const) -> Const,
    /// Call stack
    cs: CallStack,
    /// The resulting memory operand sequences of the interpretation
    mos: MemOpSeq,
}

fn eval_pure(vm: &mut AbstrVM, pure: *mut RzILOpPure, ptype: &mut RzILTypePure) -> *mut RzILOpPure {
    match pderef!(pure).code {
        IL_OP_VAR => rz_il_handler_var(vm, pure, ptype),
        IL_OP_ITE => rz_il_handler_ite(vm, pure, ptype),
        IL_OP_LET => rz_il_handler_let(vm, pure, ptype),
        IL_OP_B0 => rz_il_handler_bool_false(vm, pure, ptype),
        IL_OP_B1 => rz_il_handler_bool_true(vm, pure, ptype),
        IL_OP_INV => rz_il_handler_bool_inv(vm, pure, ptype),
        IL_OP_AND => rz_il_handler_bool_and(vm, pure, ptype),
        IL_OP_OR => rz_il_handler_bool_or(vm, pure, ptype),
        IL_OP_XOR => rz_il_handler_bool_xor(vm, pure, ptype),
        IL_OP_BITV => rz_il_handler_bitv(vm, pure, ptype),
        IL_OP_MSB => rz_il_handler_msb(vm, pure, ptype),
        IL_OP_LSB => rz_il_handler_lsb(vm, pure, ptype),
        IL_OP_IS_ZERO => rz_il_handler_is_zero(vm, pure, ptype),
        IL_OP_NEG => rz_il_handler_neg(vm, pure, ptype),
        IL_OP_LOGNOT => rz_il_handler_logical_not(vm, pure, ptype),
        IL_OP_ADD => rz_il_handler_add(vm, pure, ptype),
        IL_OP_SUB => rz_il_handler_sub(vm, pure, ptype),
        IL_OP_MUL => rz_il_handler_mul(vm, pure, ptype),
        IL_OP_DIV => rz_il_handler_div(vm, pure, ptype),
        IL_OP_SDIV => rz_il_handler_sdiv(vm, pure, ptype),
        IL_OP_MOD => rz_il_handler_mod(vm, pure, ptype),
        IL_OP_SMOD => rz_il_handler_smod(vm, pure, ptype),
        IL_OP_LOGAND => rz_il_handler_logical_and(vm, pure, ptype),
        IL_OP_LOGOR => rz_il_handler_logical_or(vm, pure, ptype),
        IL_OP_LOGXOR => rz_il_handler_logical_xor(vm, pure, ptype),
        IL_OP_SHIFTR => rz_il_handler_shiftr(vm, pure, ptype),
        IL_OP_SHIFTL => rz_il_handler_shiftl(vm, pure, ptype),
        IL_OP_EQ => rz_il_handler_eq(vm, pure, ptype),
        IL_OP_SLE => rz_il_handler_sle(vm, pure, ptype),
        IL_OP_ULE => rz_il_handler_ule(vm, pure, ptype),
        IL_OP_CAST => rz_il_handler_cast(vm, pure, ptype),
        IL_OP_APPEND => rz_il_handler_append(vm, pure, ptype),
        IL_OP_FLOAT => rz_il_handler_float(vm, pure, ptype),
        IL_OP_FBITS => rz_il_handler_fbits(vm, pure, ptype),
        IL_OP_IS_FINITE => rz_il_handler_is_finite(vm, pure, ptype),
        IL_OP_IS_NAN => rz_il_handler_is_nan(vm, pure, ptype),
        IL_OP_IS_INF => rz_il_handler_is_inf(vm, pure, ptype),
        IL_OP_IS_FZERO => rz_il_handler_is_fzero(vm, pure, ptype),
        IL_OP_IS_FNEG => rz_il_handler_is_fneg(vm, pure, ptype),
        IL_OP_IS_FPOS => rz_il_handler_is_fpos(vm, pure, ptype),
        IL_OP_FNEG => rz_il_handler_fneg(vm, pure, ptype),
        IL_OP_FABS => rz_il_handler_fabs(vm, pure, ptype),
        IL_OP_FCAST_INT => rz_il_handler_fcast_int(vm, pure, ptype),
        IL_OP_FCAST_SINT => rz_il_handler_fcast_sint(vm, pure, ptype),
        IL_OP_FCAST_FLOAT => rz_il_handler_fcast_float(vm, pure, ptype),
        IL_OP_FCAST_SFLOAT => rz_il_handler_fcast_sfloat(vm, pure, ptype),
        IL_OP_FCONVERT => rz_il_handler_fconvert(vm, pure, ptype),
        IL_OP_FREQUAL => rz_il_handler_frequal(vm, pure, ptype),
        IL_OP_FSUCC => rz_il_handler_fsucc(vm, pure, ptype),
        IL_OP_FPRED => rz_il_handler_fpred(vm, pure, ptype),
        IL_OP_FORDER => rz_il_handler_forder(vm, pure, ptype),
        IL_OP_FROUND => rz_il_handler_fround(vm, pure, ptype),
        IL_OP_FSQRT => rz_il_handler_fsqrt(vm, pure, ptype),
        IL_OP_FRSQRT => rz_il_handler_frsqrt(vm, pure, ptype),
        IL_OP_FADD => rz_il_handler_fadd(vm, pure, ptype),
        IL_OP_FSUB => rz_il_handler_fsub(vm, pure, ptype),
        IL_OP_FMUL => rz_il_handler_fmul(vm, pure, ptype),
        IL_OP_FDIV => rz_il_handler_fdiv(vm, pure, ptype),
        IL_OP_FMOD => rz_il_handler_fmod(vm, pure, ptype),
        IL_OP_FHYPOT => rz_il_handler_fhypot(vm, pure, ptype),
        IL_OP_FPOW => rz_il_handler_fpow(vm, pure, ptype),
        IL_OP_FMAD => rz_il_handler_fmad(vm, pure, ptype),
        IL_OP_FROOTN => rz_il_handler_frootn(vm, pure, ptype),
        IL_OP_FPOWN => rz_il_handler_fpown(vm, pure, ptype),
        IL_OP_FCOMPOUND => rz_il_handler_fcompound(vm, pure, ptype),
        IL_OP_LOAD => rz_il_handler_load(vm, pure, ptype),
        IL_OP_LOADW => rz_il_handler_loadw(vm, pure, ptype),
        pt => panic!("Pure type {} not handled.", pt),
    }
}

fn eval_effect(vm: &mut AbstrVM, eff: *mut RzILOpEffect) -> bool {
    match pderef!(eff).code {
        IL_OP_STORE => rz_il_handler_store(vm, eff),
        IL_OP_STOREW => rz_il_handler_storew(vm, eff),
        IL_OP_EMPTY => rz_il_handler_empty(vm, eff),
        IL_OP_NOP => rz_il_handler_nop(vm, eff),
        IL_OP_SET => rz_il_handler_set(vm, eff),
        IL_OP_JMP => rz_il_handler_jmp(vm, eff),
        IL_OP_GOTO => rz_il_handler_goto(vm, eff),
        IL_OP_SEQ => rz_il_handler_seq(vm, eff),
        IL_OP_BLK => rz_il_handler_blk(vm, eff),
        IL_OP_REPEAT => rz_il_handler_repeat(vm, eff),
        IL_OP_BRANCH => rz_il_handler_branch(vm, eff),
        et => panic!("Pure type {} not handled.", et),
    }
}

impl AbstrVM {
    pub fn new(
        pc: PC,
        path: IntrpPath,
        rand_input_valuator: fn(Address, Const) -> Const,
    ) -> AbstrVM {
        AbstrVM {
            pc,
            is: HashMap::new(),
            ic: HashMap::new(),
            lp: HashMap::new(),
            ms: HashMap::new(),
            rs: HashMap::new(),
            mt: HashMap::new(),
            rt: HashMap::new(),
            pa: path,
            rv: rand_input_valuator,
            cs: CallStack::new(),
            mos: MemOpSeq::new(),
        }
    }

    fn step(&mut self) -> bool {
        let iaddr = self.pa.next();
        if iaddr.is_none() {
            return false;
        }
        // Get il op
        // execute
        true
    }
}

/// Interprets the given path with the given interpeter VM.
pub fn interpret(rz_core: GRzCore, path: IntrpPath) -> IntrpByProducts {
    let mut vm = AbstrVM::new(path.get(0), path, |addr, c| addr);

    while vm.step() {}

    // Replace with Channel and send/rcv
    IntrpByProducts {
        resolved_icalls: Vec::new(),
    }
}
