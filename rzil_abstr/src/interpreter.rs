// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only
#![allow(unused)]

use std::{
    collections::{HashMap, VecDeque},
    ffi::CString,
};

use binding::{
    c_to_str, log_rizin, log_rz, pderef, rz_analysis_insn_word_free, rz_analysis_op_free, GRzCore,
    RzAnalysisOpMask_RZ_ANALYSIS_OP_MASK_IL, RzILOpEffect, RzILOpPure, RzILTypePure, RzRegisterId,
    RzRegisterId_RZ_REG_NAME_BP, RzRegisterId_RZ_REG_NAME_SP, LOG_DEBUG, LOG_ERROR, LOG_WARN,
};

use crate::op_handler::eval_effect;

/// If this plugin is still used, when 128bit address space is a thing, do grep "64".
type Address = u64;

pub type Const = i128;

type PC = Address;

pub enum AddrInfo {
    // Address points to the first instruction in a procedure.
    IsProcEntry,
    // Address points to a memory allocating function.
    IsMalloc,
    // Address points to a function which provides external input.
    IsInput,
}

pub struct IntrpPath {
    /// Execution path of instructions.
    path: VecDeque<Address>,
    /// Function addresses which are in the path.
    addr_info: HashMap<Address, AddrInfo>,
}

impl IntrpPath {
    pub fn new() -> IntrpPath {
        IntrpPath {
            path: VecDeque::new(),
            addr_info: HashMap::new(),
        }
    }

    pub fn push_info(&mut self, addr: Address, info: AddrInfo) {
        self.addr_info.insert(addr, info);
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum MemRegionClass {
    /// Global memory region. E.g. .data, .rodata, .bss
    Global,
    /// The stacck memory region.
    Stack,
    /// The Heap memory region.
    Heap,
}

/// A memory region. Either of Global, Stack or Heap.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct MemRegion {
    /// Memory region class
    class: MemRegionClass,
    /// Base address of the region.
    /// For Heap regions: The address of the allocating instruction.
    /// For Stack regions: The function address this stack frame was used.
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
}

impl std::fmt::Display for MemRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let letter = match self.class {
            MemRegionClass::Global => "G",
            MemRegionClass::Heap => "H",
            MemRegionClass::Stack => "S",
            _ => panic!("Handled mem class."),
        };
        write!(f, "{}({:#x})", letter, self.base)
    }
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

impl std::fmt::Display for AbstrVal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "〈{}, {}〉", self.m, self.c)
    }
}

impl AbstrVal {
    pub fn new_global(c: Const, is_il_gvar: Option<String>) -> AbstrVal {
        let m = MemRegion {
            class: MemRegionClass::Global,
            base: 0,
            c: 0,
        };
        AbstrVal {
            m,
            c,
            il_gvar: is_il_gvar,
        }
    }

    pub fn new_stack(c: Const, is_il_gvar: Option<String>) -> AbstrVal {
        let m = MemRegion {
            class: MemRegionClass::Stack,
            base: 0,
            c: 0,
        };
        AbstrVal {
            m,
            c,
            il_gvar: is_il_gvar,
        }
    }

    pub fn new_true() -> AbstrVal {
        AbstrVal::new_global(1, None)
    }

    pub fn new_false() -> AbstrVal {
        AbstrVal::new_global(0, None)
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
        self.c == 0
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
    /// RegStore map/Global variable store map
    rs: HashMap<String, AbstrVal>,
    /// MemTaint map
    mt: HashMap<AbstrVal, bool>,
    /// RegTaint map
    rt: HashMap<String, bool>,
    /// Path
    pa: IntrpPath,
    /// Call stack
    cs: CallStack,
    /// The resulting memory operand sequences of the interpretation
    mos: MemOpSeq,
    /// IL operation buffer
    il_op_buf: HashMap<Address, *mut RzILOpEffect>,
    /// Global variables (mostly registers)
    gvars: HashMap<String, AbstrVal>,
    /// Local pure variables. Defined via LET()
    lpures: HashMap<String, AbstrVal>,
    /// Local variables, defined via SETL
    lvars: HashMap<String, AbstrVal>,
    /// Register roles (SP, PC, LR, ARG 1, ARG 2 etc)
    /// Role to register name nap.
    reg_roles: HashMap<RzRegisterId, String>,
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
            reg_roles: HashMap::new(),
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
        Some(self.gvars.get(name).unwrap().clone())
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
        let sp_name = self
            .reg_roles
            .get(&RzRegisterId_RZ_REG_NAME_SP)
            .expect("Should have been initialized");
        let bp_name = self
            .reg_roles
            .get(&RzRegisterId_RZ_REG_NAME_BP)
            .expect("Should have been initialized");
        if name == sp_name || name == bp_name {
            assert_eq!(
                av.m.class,
                MemRegionClass::Stack,
                "Only stack values should be written to SP and BP"
            )
        }
        av.il_gvar = Some(name.to_string());
        self.gvars.insert(name.to_owned(), av);
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
        self.lvars.clear();
        result
    }

    /// Initializes the register profile, register alias and their initial
    /// abstract values.
    /// Returns false if it fails.
    fn init_register_file(&mut self, rz_core: GRzCore) -> bool {
        log_rz!(
            LOG_DEBUG,
            None,
            "Init register file for abstract interpreter.".to_string()
        );

        let core = rz_core.lock().unwrap();

        // Set the register alias
        let alias = core.get_reg_alias();
        for ralias in alias {
            let ra = pderef!(ralias);
            if let Some(p) = self.reg_roles.insert(ra.role, c_to_str(ra.reg_name)) {
                log_rz!(
                    LOG_WARN,
                    None,
                    format!(
                        "Duplicate role of register {} detected",
                        c_to_str(ra.reg_name)
                    )
                )
            }
        }
        let sp_name = self.reg_roles.get(&RzRegisterId_RZ_REG_NAME_SP);
        let bp_name = self.reg_roles.get(&RzRegisterId_RZ_REG_NAME_BP);
        if sp_name.is_none() || bp_name.is_none() {
            log_rz!(
                LOG_ERROR,
                None,
                "BP and SP must be set in the register profile for this algorithm to work."
                    .to_string()
            );
            return false;
        }

        // Init complete register file
        let reg_bindings = core.get_reg_bindings().expect("Could not get reg_bindings");
        let reg_count = pderef!(reg_bindings).regs_count;
        let regs = pderef!(reg_bindings).regs;
        (0..reg_count).for_each(|i| {
            let reg = unsafe { regs.offset(i as isize) };
            let rsize = pderef!(reg).size;
            let rname = pderef!(reg).name;
            let name = c_to_str(rname);
            log_rz!(LOG_DEBUG, None, format!("\t-> {}", name));

            let init_val = match &name {
                sp_name => AbstrVal::new_stack(0, Some(name.clone())),
                bp_name => AbstrVal::new_stack(0, Some(name.clone())),
                _ => AbstrVal::new_global(0, Some(name.clone())),
            };
            self.gvars.insert(name.to_owned(), init_val);
        });
        true
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

    pub fn get_taint_flag(&mut self, v: &AbstrVal) -> bool {
        if v.m.class == MemRegionClass::Global && v.il_gvar.is_some() {
            if let Some(t) = self.rt.get(v.il_gvar.as_ref().unwrap()) {
                return *t;
            } else {
                panic!("Has no taint flag set for abstr. global {}", v)
            }
        }
        if let Some(t) = self.mt.get(v) {
            *t
        } else {
            panic!("Has no taint flag set for abstr. memory value {}", v)
        }
    }

    pub fn set_taint_flag(&mut self, v3: &AbstrVal, tainted: bool) {
        if let Some(il_gvar) = v3.il_gvar.clone() {
            if let Some(global) = self.gvars.get(&il_gvar) {
                self.rt.insert(il_gvar, tainted);
                return;
            }
            log_rz!(
                LOG_ERROR,
                None,
                "Global variable is not defined.".to_string()
            );
            return;
        }
        self.mt.insert(v3.clone(), tainted);
    }

    pub fn get_mem_val(&self, key: &AbstrVal) -> AbstrVal {
        if let Some(v) = self.ms.get(key) {
            return v.clone();
        }
        panic!("No value saved for: {}", key);
    }

    pub fn set_mem_val(&mut self, key: &AbstrVal, val: AbstrVal) {
        self.ms.insert(key.clone(), val);
    }

    pub fn get_reg_val(&self, key: &AbstrVal) -> AbstrVal {
        if let Some(rname) = &key.il_gvar {
            self.rs
                .get(rname)
                .expect(&format!("Global var {} not set.", &rname));
        }
        panic!("Abstract value doesn't belong to a global var.");
    }

    pub fn set_reg_val(&mut self, key: &AbstrVal, val: AbstrVal) {
        self.ms.insert(key.clone(), val);
    }

    pub fn enqueue_mos(&mut self, v: &AbstrVal) {
        self.mos.push(MemOp {
            addr: self.pc,
            aval: v.clone(),
        });
    }
}

/// Interprets the given path with the given interpeter VM.
pub fn interpret(rz_core: GRzCore, path: IntrpPath) -> IntrpByProducts {
    // Replace with Channel and send/rcv
    let p = IntrpByProducts {
        resolved_icalls: Vec::new(),
    };

    let mut vm = AbstrVM::new(path.get(0), path);
    if !vm.init_register_file(rz_core.clone()) {
        return p;
    }

    while vm.step(&rz_core) {}

    p
}
