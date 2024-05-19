// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only
#![allow(unused)]

use std::{
    collections::{HashMap, VecDeque},
    ffi::CString,
};

use rug::Integer;

use binding::{
    log_rizin, log_rz, null_check, pderef, rz_analysis_insn_word_free, rz_analysis_op_free,
    GRzCore, RzAnalysisOpMask_RZ_ANALYSIS_OP_MASK_IL, RzILOpEffect, RzILOpPure, RzILTypePure,
    LOG_DEBUG, LOG_ERROR, LOG_WARN,
};

use crate::op_handler::{
    eval_effect, eval_pure, rz_il_handler_add, rz_il_handler_append, rz_il_handler_bitv,
    rz_il_handler_blk, rz_il_handler_bool_and, rz_il_handler_bool_false, rz_il_handler_bool_inv,
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

/// If this plugin is still used, when 128bit address space is a thing, do grep "64".
type Address = u64;

/// A constant value. It is an arbitrary size Integer because it must also
/// be able to hold constant vector values of more then 64/128bit.
pub type Const = Integer;

type PC = Address;

struct Global {
    /// Size in bits
    size: usize,
    /// The current value
    val: AbstrVal,
}

impl Global {
    fn new(size: usize, val: AbstrVal) -> Global {
        Global { size, val }
    }
}

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
#[derive(Clone, PartialEq, Eq)]
enum MemRegionClass {
    /// Global memory region. E.g. .data, .rodata, .bss
    Global,
    /// The stacck memory region.
    Stack,
    /// The Heap memory region.
    Heap,
}

/// A memory region. Either of Global, Stack or Heap.
#[derive(Clone)]
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

/// An abstract value.
/// Constant values are represented a value of the Global memory region
/// and the constant value set in [offset].
#[derive(Clone, Hash, PartialEq, Eq)]
pub struct AbstrVal {
    /// The memory region of this value
    m: MemRegion,
    /// The offset of this variable from the base of the region.
    /// Or, if this is a global value, the constant.
    c: Const,
    /// Name of the global IL variable this abstract value was read from.
    /// If None, it is a memory value.
    /// This is used to decide which taint map to use.
    il_gvar: Option<String>,
}

impl AbstrVal {
    pub fn new_global(c: Const, is_il_gvar: Option<String>) -> AbstrVal {
        let m = MemRegion {
            class: MemRegionClass::Global,
            base: 0,
            c: 0,
            addr: 0,
        };
        AbstrVal {
            m,
            c,
            il_gvar: is_il_gvar,
        }
    }

    pub fn new_true() -> AbstrVal {
        AbstrVal::new_global(Const::ONE.clone(), None)
    }

    pub fn new_false() -> AbstrVal {
        AbstrVal::new_global(Const::ZERO.clone(), None)
    }

    pub fn new(m: MemRegion, c: Const, is_il_gvar: Option<String>) -> AbstrVal {
        AbstrVal {
            m,
            c,
            il_gvar: is_il_gvar,
        }
    }

    /// Checks if the abstract value is equal to global zero (a.k.a False).
    /// This check ignores the invocation count and only checks the memory region
    /// and constant.
    pub fn is_global_zero(&self) -> bool {
        if self.m.class != MemRegionClass::Global {
            return false;
        }
        self.c == Const::ZERO
    }
}

/// An operation on the constant share of abstract values
type AbstrOp = fn(v1: &Const, v2: &Const) -> Const;

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

/// The call stack. With every Call to a procedure another CallFrame is pushed.
/// With every return, a CallFrame is popped.
type CallStack = Vec<CallFrame>;

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
    is: HashMap<Address, u64>,
    /// Invocation count map
    ic: HashMap<Address, u64>,
    /// Loop predicate map
    lp: HashMap<Address, bool>,
    /// MemStore map
    ms: HashMap<AbstrVal, AbstrVal>,
    /// RegStore map
    rs: HashMap<Global, AbstrVal>,
    /// MemTaint map
    mt: HashMap<AbstrVal, AbstrVal>,
    /// RegTaint map
    rt: HashMap<Global, AbstrVal>,
    /// Path
    pa: IntrpPath,
    /// Call stack
    cs: CallStack,
    /// The resulting memory operand sequences of the interpretation
    mos: MemOpSeq,
    /// IL operation buffer
    il_op_buf: HashMap<Address, *mut RzILOpEffect>,
    /// Global variables (mostly registers)
    gvars: HashMap<String, Global>,
    /// Local pure variables. Defined via LET()
    lpures: HashMap<String, AbstrVal>,
    /// Local variables, defined via SETL
    lvars: HashMap<String, AbstrVal>,
}

impl AbstrVM {
    /// Creates a new abstract interpreter VM.
    /// It takes the initial programm counter [pc], the [path] to walk
    /// and the sampling function for generating random values for input values.
    pub fn new(pc: PC, path: IntrpPath) -> AbstrVM {
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
            cs: CallStack::new(),
            mos: MemOpSeq::new(),
            il_op_buf: HashMap::new(),
            gvars: HashMap::new(),
            lvars: HashMap::new(),
            lpures: HashMap::new(),
        }
    }

    pub fn get_varg(&self, name: &str) -> Option<AbstrVal> {
        if self.gvars.get(name).is_none() {
            log_rz!(
                LOG_WARN,
                None,
                format!("Global var '{}' not defined.", name)
            );
            return None;
        }
        Some(self.gvars.get(name).unwrap().val.clone())
    }

    pub fn get_varl(&self, name: &str) -> Option<AbstrVal> {
        if self.lvars.get(name).is_none() {
            log_rz!(LOG_WARN, None, format!("Local var '{}' not defined.", name));
            return None;
        }
        Some(self.lvars.get(name).unwrap().clone())
    }

    pub fn get_lpure(&self, name: &str) -> Option<AbstrVal> {
        if self.lpures.get(name).is_none() {
            log_rz!(LOG_WARN, None, format!("LET var '{}' not defined.", name));
            return None;
        }
        Some(self.lpures.get(name).unwrap().clone())
    }

    pub fn set_lpure(&mut self, name: String, av: AbstrVal) {
        if self.lpures.get(&name).is_some() {
            log_rz!(
                LOG_WARN,
                None,
                format!("LET var '{}' already defined.", name)
            );
            return;
        }
        self.lpures.insert(name.to_owned(), av);
    }

    pub fn set_varg(&mut self, name: &str, mut av: AbstrVal) {
        let global = self.gvars.get(name);
        if global.is_none() {
            log_rz!(
                LOG_ERROR,
                None,
                format!("The global {} was not initialized. Cannot be set.", name)
            );
            return;
        }
        av.il_gvar = Some(name.to_string());
        self.gvars.insert(
            name.to_owned(),
            Global {
                size: global.unwrap().size,
                val: av,
            },
        );
    }

    pub fn set_varl(&mut self, name: &str, av: AbstrVal) {
        self.lvars.insert(name.to_owned(), av);
    }

    pub fn rm_lpure(&mut self, let_name: &str) {
        self.lpures.remove(let_name);
    }

    /// This function samples a random value from its distribution to
    /// simulate input for the program.
    /// It takes the address of an input-functions at [address] and the current
    /// [invocation] of the function.
    fn rv(&self, address: Address, invocation: u64) -> Const {
        todo!()
    }

    fn step(&mut self, rz_core: &GRzCore) -> bool {
        let mut iaddr: Address;
        if let Some(na) = self.pa.next() {
            iaddr = na;
        } else {
            return false;
        }

        *self.ic.entry(iaddr).or_default() += 1;

        let rz_core = rz_core.lock().unwrap();
        let iword_decoder = rz_core.get_iword_decoder();
        let mut effect;
        let result;
        if iword_decoder.is_some() {
            let iword = rz_core.get_iword(iaddr);
            effect = pderef!(iword).il_op;
            result = eval_effect(self, effect);
            unsafe { rz_analysis_insn_word_free(iword) };
        } else {
            let ana_op = rz_core.get_analysis_op(iaddr);
            effect = pderef!(ana_op).il_op;
            result = eval_effect(self, effect);
            unsafe { rz_analysis_op_free(ana_op.cast()) };
        }
        result
    }

    fn init_register_file(&mut self, rz_core: GRzCore) {
        log_rz!(
            LOG_DEBUG,
            None,
            "Init register file for abstract interpreter.".to_string()
        );
        let core = rz_core.lock().unwrap();
        let reg_bindings = core.get_reg_bindings().expect("Could not get reg_bindings");
        let reg_count = pderef!(reg_bindings).regs_count;
        let regs = pderef!(reg_bindings).regs;
        (0..reg_count).for_each(|i| {
            let reg = unsafe { regs.offset(i as isize) };
            let rsize = pderef!(reg).size;
            let rname = pderef!(reg).name;
            let name = unsafe {
                CString::from_raw(rname)
                    .into_string()
                    .expect("CString to String failed.")
            };
            log_rz!(LOG_DEBUG, None, format!("\t-> {}", name));
            self.gvars.insert(
                name.to_owned(),
                Global::new(
                    rsize as usize,
                    AbstrVal::new_global(Integer::from(0), Some(name)),
                ),
            );
        });
    }

    /// Gives the invocation count for a given instruction address.
    fn get_ic(&mut self, iaddr: Address) -> u64 {
        self.ic.entry(iaddr).or_default().clone()
    }

    /// Calculates the result of an operation on two abstract values and their taint flags [^1]
    /// Returns the calculated result as abstract value and the taint flag.
    /// [^1] Figure 2.11 - https://doi.org/10.25394/PGS.23542014.v1
    pub fn calc_value(&mut self, op: AbstrOp, v1: AbstrVal, v2: AbstrVal) -> (AbstrVal, bool) {
        let mut tainted: bool;
        let mut v3: AbstrVal;
        if v1.m.class == MemRegionClass::Global {
            v3 = AbstrVal::new(v2.m.clone(), op(&v1.c, &v2.c), None);
            tainted = false;
        } else if v2.m.class == MemRegionClass::Global {
            v3 = AbstrVal::new(v1.m.clone(), op(&v1.c, &v2.c), None);
            tainted = false;
        } else {
            let pc = self.pc;
            let ic_pc = self.get_ic(pc);
            v3 = AbstrVal::new_global(self.rv(pc, ic_pc), None);
            tainted = true;
        }
        (v3, tainted)
    }

    /// Normilzes the given value. If the value is not a stack memory value,
    /// it returns a clone.
    /// Otherwise, it returns an abtract value with the memory region set to
    /// the enclosing stack frame. [^1]
    /// [^1] Figure 2.11 - https://doi.org/10.25394/PGS.23542014.v1
    pub fn normalize_val(&self, mut v: AbstrVal) -> AbstrVal {
        if v.m.class != MemRegionClass::Stack {
            return v;
        }
        for vt in self.cs.iter().rev() {
            if v.c < 0 {
                break;
            }
            v.m = vt.sp.m.clone();
            v.c += vt.sp.c.clone();
        }
        v
    }
}

/// Interprets the given path with the given interpeter VM.
pub fn interpret(rz_core: GRzCore, path: IntrpPath) -> IntrpByProducts {
    let mut vm = AbstrVM::new(path.get(0), path);
    vm.init_register_file(rz_core.clone());

    while vm.step(&rz_core) {}

    // Replace with Channel and send/rcv
    IntrpByProducts {
        resolved_icalls: Vec::new(),
    }
}
