// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use bitflags::bitflags;
use helper::num::subscript;
use log::{debug, error, warn};
use rand::Rng;
use rand_distr::{Distribution, Normal};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt::Display,
    hash::Hash,
    io::Read,
    sync::mpsc::Sender,
};

use binding::{
    c_to_str, effect_to_str, pderef, rz_analysis_insn_word_free, rz_analysis_op_free, GRzCore,
    RzAnalysisInsnWord, RzAnalysisOp, RzRegisterId, RzRegisterId_RZ_REG_NAME_BP,
    RzRegisterId_RZ_REG_NAME_R0, RzRegisterId_RZ_REG_NAME_SP,
};

use crate::{bitvector::BitVector, op_handler::eval_effect};

/// If this plugin is still used, when 128bit address space is a thing, do grep "64".
pub type Address = u64;

const MAX_U64_ADDRESS: u64 = u64::MAX;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum TaintFlag {
    /// The value was known during interpretation.
    Unset,
    /// The value is derived by sampling from a distribution.
    Set,
    /// The value was not set during interpretation.
    /// It is not known if it is an allocated or not constant value.
    Unknown,
}

impl TaintFlag {
    pub fn is_known_const(&self) -> bool {
        *self == TaintFlag::Unset
    }

    pub fn is_unset(&self) -> bool {
        *self == TaintFlag::Unset
    }

    pub fn is_set(&self) -> bool {
        *self == TaintFlag::Set
    }

    pub fn _is_unknown(&self) -> bool {
        *self == TaintFlag::Unknown
    }
}

impl std::ops::BitOr for TaintFlag {
    type Output = TaintFlag;

    fn bitor(self, rhs: Self) -> Self::Output {
        if self == TaintFlag::Set || rhs == TaintFlag::Set {
            TaintFlag::Set
        } else if self == TaintFlag::Unknown || rhs == TaintFlag::Unknown {
            TaintFlag::Unknown
        } else {
            TaintFlag::Unset
        }
    }
}

type PC = Address;

pub const NO_ADDR_INFO: IWordInfo = IWordInfo::None;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct IWordInfo: u64 {
        /// No information provided for this instruction word.
        const None = 0;
        /// The iword has a jump instruction.
        const IsJump = 1 << 0;
        /// The iword has a call instruction.
        const IsCall = 1 << 1;
        /// The iword is a jump or call to another procedure, but has no following instruction.
        const IsTail = 1 << 2;
        /// The iword will exit the program. If the exit happens via a call, jump or due to the iword itself depends on the bits set.
        const IsExit = 1 << 3;
        /// IWord calls an allocating function.
        const CallsMalloc = 1 << 5 | Self::IsCall.bits();
        /// IWord calls an input function.
        const CallsInput = 1 << 6 | Self::IsCall.bits();
        /// True if the iword calls an unmapped function.
        const CallsUnmapped = 1 << 7 | Self::IsCall.bits();
        /// IWord contains an unconditional return instruction.
        const IsReturn = 1 << 8;
        /// IWord contains a memory read
        const IsMemRead = 1 << 9;
        /// IWord contains a memory write
        const IsMemWrite = 1 << 10;
        /// A tail call to another function.
        const IsTailCall = Self::IsTail.bits() | Self::IsJump.bits();
        /// Exits the program by calling a fucntion (e.g. abort, stack_chk_fail).
        const IsExitCall = Self::IsExit.bits() | Self::IsCall.bits();
        /// Exits the program by jumping to a procedure
        const IsExitJump = Self::IsExit.bits() | Self::IsJump.bits();
    }
}

impl IWordInfo {
    pub fn is_none(&self) -> bool {
        *self == IWordInfo::None
    }

    pub fn is_jump(&self) -> bool {
        (*self & IWordInfo::IsJump) == IWordInfo::IsJump
    }

    pub fn is_call(&self) -> bool {
        (*self & IWordInfo::IsCall) == IWordInfo::IsCall
    }

    pub fn is_exit(&self) -> bool {
        (*self & IWordInfo::IsExit) == IWordInfo::IsExit
    }

    pub fn is_tail_call(&self) -> bool {
        (*self & IWordInfo::IsTailCall) == IWordInfo::IsTailCall
    }

    pub fn is_return(&self) -> bool {
        (*self & IWordInfo::IsReturn) == IWordInfo::IsReturn
    }

    pub fn is_mem_read(&self) -> bool {
        (*self & IWordInfo::IsMemRead) == IWordInfo::IsMemRead
    }

    pub fn is_mem_write(&self) -> bool {
        (*self & IWordInfo::IsMemWrite) == IWordInfo::IsMemWrite
    }

    pub fn calls_malloc(&self) -> bool {
        (*self & IWordInfo::CallsMalloc) == IWordInfo::CallsMalloc
    }

    pub fn calls_input(&self) -> bool {
        (*self & IWordInfo::CallsInput) == IWordInfo::CallsInput
    }

    pub fn calls_unmapped(&self) -> bool {
        (*self & IWordInfo::CallsUnmapped) == IWordInfo::CallsUnmapped
    }
}

impl Display for IWordInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_none() {
            return write!(f, "");
        }

        if self.is_jump() {
            if let Err(e) = write!(f, "j") {
                return Err(e);
            }
        }

        if self.is_call() {
            if let Err(e) = write!(f, "c") {
                return Err(e);
            }
        }

        if self.is_exit() {
            if let Err(e) = write!(f, "e") {
                return Err(e);
            }
        }

        if self.is_tail_call() {
            if let Err(e) = write!(f, "t") {
                return Err(e);
            }
        }

        if self.is_return() {
            if let Err(e) = write!(f, "r") {
                return Err(e);
            }
        }

        if self.is_mem_read() {
            if let Err(e) = write!(f, "(mr)") {
                return Err(e);
            }
        }

        if self.is_mem_write() {
            if let Err(e) = write!(f, "(mw)") {
                return Err(e);
            }
        }

        if self.calls_malloc() {
            if let Err(e) = write!(f, "m") {
                return Err(e);
            }
        }

        if self.calls_input() {
            if let Err(e) = write!(f, "i") {
                return Err(e);
            }
        }

        if self.calls_unmapped() {
            if let Err(e) = write!(f, "u") {
                return Err(e);
            }
        }
        write!(f, "")
    }
}

pub struct IntrpPath {
    /// Execution path of instructions.
    path: VecDeque<(Address, IWordInfo)>,
}

impl std::fmt::Display for IntrpPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Err(e) = write!(f, "[") {
            return Err(e);
        }
        for (i, n) in self.path.iter().enumerate() {
            if i != 0 {
                if let Err(e) = write!(f, " -> ") {
                    return Err(e);
                }
            }
            if let Err(e) = write!(f, "{:#x}|", n.0) {
                return Err(e);
            }
            if let Err(e) = write!(f, "{}", n.1) {
                return Err(e);
            }
        }
        write!(f, "]")
    }
}

impl IntrpPath {
    pub fn new() -> IntrpPath {
        IntrpPath {
            path: VecDeque::new(),
        }
    }

    pub fn from(vec: VecDeque<(Address, IWordInfo)>) -> IntrpPath {
        IntrpPath { path: vec }
    }

    pub fn push(&mut self, addr: Address, info: IWordInfo) {
        self.path.push_back((addr, info));
    }

    pub fn next(&mut self) -> Option<(Address, IWordInfo)> {
        self.path.pop_front()
    }

    pub fn peak_next(&self) -> Option<&(Address, IWordInfo)> {
        self.path.get(0)
    }

    pub fn get(&self, i: usize) -> (Address, IWordInfo) {
        self.path
            .get(i)
            .expect(&format!("Index i = {} out of range", i))
            .clone()
    }
}

#[derive(Eq, PartialEq, Hash, Clone, Copy, PartialOrd, Ord, Debug)]
pub enum CodeXrefType {
    IndirectCall,
    IndirectJump,
}

/// A concretely resolved indirect call or jump.
/// Those can be discovered, if only constant value were used to define the call target.
#[derive(Eq, PartialEq, Hash, Clone, PartialOrd, Ord, Debug)]
pub struct ConcreteCodeXref {
    xtype: CodeXrefType,
    /// The address of the procedure this call occurs.
    proc_addr: Address,
    /// The caller
    from: Address,
    /// The callee
    to: Address,
}

impl ConcreteCodeXref {
    pub fn new(xtype: CodeXrefType, proc_addr: Address, from: Address, to: Address) -> Self {
        Self {
            xtype,
            proc_addr,
            from,
            to,
        }
    }

    pub fn get_xtype(&self) -> CodeXrefType {
        self.xtype
    }

    pub fn is_icall(&self) -> bool {
        self.xtype == CodeXrefType::IndirectCall
    }

    pub fn is_ijump(&self) -> bool {
        self.xtype == CodeXrefType::IndirectJump
    }

    pub fn get_proc_addr(&self) -> Address {
        self.proc_addr
    }

    pub fn get_from(&self) -> Address {
        self.from
    }

    pub fn get_to(&self) -> Address {
        self.to
    }
}

impl std::fmt::Display for ConcreteCodeXref {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "icodexref {:#x} : {:#x} -> {:#x}",
            self.proc_addr, self.from, self.to
        )
    }
}

/// A concretely resolved indirect call.
/// Those can be discovered, if only constant value were used to define the call target.
#[derive(Eq, PartialEq, Hash, Clone, Debug, PartialOrd, Ord)]
pub struct MemXref {
    /// The load/store instruction address
    from: Address,
    /// The address referenced
    to: Address,
    /// Number of bytes loaded
    size: u64,
}

impl MemXref {
    pub fn new(from: Address, to: Address, size: u64) -> MemXref {
        MemXref { from, to, size }
    }
}

impl std::fmt::Display for MemXref {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "mem_xref {:#x} -- {} byte --> {:#x}",
            self.from, self.size, self.to
        )
    }
}

/// A concretely resolved indirect call.
/// Those can be discovered, if only constant value were used to define the call target.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct StackXref {
    /// The instruction address
    at: Address,
    /// Abstract value of the stack variable/argument
    var: AbstrVal,
}

impl StackXref {
    /// This functions sets the IC always to 1
    pub fn new(at: Address, offset: BitVector, base: Address) -> StackXref {
        StackXref {
            at,
            var: AbstrVal::new_stack(1, offset, base),
        }
    }
}

impl std::fmt::Display for StackXref {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#x} -> {} ", self.at, self.var)
    }
}

/// Memory region classes: Global, Stack, Heap
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum MemRegionClass {
    /// Global memory region. E.g. .data, .rodata, .bss
    Global,
    /// The stacck memory region.
    Stack,
    /// The Heap memory region.
    Heap,
}

/// A memory region. Either of Global, Stack or Heap.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    ic: u32,
}

impl std::fmt::Display for MemRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let letter = match self.class {
            MemRegionClass::Global => "𝑮",
            MemRegionClass::Heap => "𝑯",
            MemRegionClass::Stack => "𝑺",
        };
        write!(f, "{}{} ⌊{:#x}⌋", subscript(self.ic), letter, self.base)
    }
}

/// An abstract value.
/// Constant values are represented a value of the Global memory region
/// and the constant value set in [offset].
#[derive(Clone, Debug)]
pub struct AbstrVal {
    /// The memory region of this value
    m: MemRegion,
    /// The offset of this variable from the base of the region.
    /// Or, if this is a global value, the constant.
    c: BitVector,
    /// Name of the global IL variable this abstract value was read from.
    /// If None, it is a memory value.
    /// This is used to decide which taint map to use.
    ///
    /// This value is not compared or used for hashing!
    il_gvar: Option<String>,
}

impl Hash for AbstrVal {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.m.hash(state);
        self.c.hash(state);
    }
}

impl Ord for AbstrVal {
    /// The order of abstract values depends on their Memory region and the constant value.
    /// The Memory region is compared (default implementation for enum comparison): self::MemRegion.cmp(other::MemRegion).
    /// If equal, the numerical value is compared.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.eq(other) {
            return std::cmp::Ordering::Equal;
        }
        if self.m != other.m {
            return self.m.cmp(&other.m);
        }
        self.c.cmp(&other.c)
    }
}

impl PartialOrd for AbstrVal {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for AbstrVal {}
impl PartialEq for AbstrVal {
    fn eq(&self, other: &Self) -> bool {
        self.m == other.m && self.c == other.c
    }
}

impl std::fmt::Display for AbstrVal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "〈{}, {}〉",
            self.m,
            if self.m.class == MemRegionClass::Stack {
                self.c.as_signed_str()
            } else {
                format!("{:#x}", self.c)
            }
        )
    }
}

impl std::fmt::LowerHex for AbstrVal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl AbstrVal {
    pub fn new_global(ic: u32, c: BitVector, il_gvar: Option<String>, base: Address) -> AbstrVal {
        let m = MemRegion {
            class: MemRegionClass::Global,
            base,
            ic,
        };
        AbstrVal { m, c, il_gvar }
    }

    pub fn new_stack(ic: u32, offset: BitVector, base: Address) -> AbstrVal {
        let m = MemRegion {
            class: MemRegionClass::Stack,
            base,
            ic,
        };
        AbstrVal {
            m,
            c: offset,
            il_gvar: None,
        }
    }

    pub fn new_heap(ic: u32, offset: BitVector, base: Address) -> AbstrVal {
        let m = MemRegion {
            class: MemRegionClass::Heap,
            base,
            ic,
        };
        AbstrVal {
            m,
            c: offset,
            il_gvar: None,
        }
    }

    pub fn set_il_gvar(&mut self, gvar: Option<String>) {
        self.il_gvar = gvar;
    }

    pub fn get_width(&self) -> u32 {
        self.c.width()
    }

    pub fn new_true() -> AbstrVal {
        AbstrVal::new_global(1, BitVector::new_true(), None, 0)
    }

    pub fn new_false() -> AbstrVal {
        AbstrVal::new_global(1, BitVector::new_false(), None, 0)
    }

    pub fn new(m: MemRegion, c: BitVector, il_gvar: Option<String>) -> AbstrVal {
        AbstrVal { m, c, il_gvar }
    }

    /// Checks if the abstract value is equal to global zero (a.k.a False).
    /// This check ignores the invocation count and only checks the memory region
    /// and constant.
    pub fn is_global_zero(&self) -> bool {
        if self.m.class != MemRegionClass::Global {
            return false;
        }
        self.c.is_zero()
    }

    /// True, if this is a global non-zero value.
    /// False otherwise
    pub fn is_true(&self) -> bool {
        self.m.class == MemRegionClass::Global && self.get_width() == 1 && !self.c.is_zero()
    }

    /// True, if this is a global zero value.
    /// False otherwise
    pub fn is_false(&self) -> bool {
        self.m.class == MemRegionClass::Global && self.get_width() == 1 && self.c.is_zero()
    }

    pub fn is_global(&self) -> bool {
        self.m.class == MemRegionClass::Global
    }

    pub fn is_stack(&self) -> bool {
        self.m.class == MemRegionClass::Stack
    }

    pub fn is_heap(&self) -> bool {
        self.m.class == MemRegionClass::Heap
    }

    pub fn get_mem_region(&self) -> &MemRegion {
        &self.m
    }

    pub fn get_as_addr(&self) -> Address {
        self.c.as_u64()
    }

    pub fn get_const(&self) -> &BitVector {
        &self.c
    }

    /// Consumes the given abstract value [av] and returns a new one of the same type,
    /// but with the constant set to [c].
    pub fn new_from(av: AbstrVal, c: BitVector) -> AbstrVal {
        AbstrVal {
            m: av.m.clone(),
            c,
            il_gvar: av.il_gvar.clone(),
        }
    }

    pub fn set_stack_base(&mut self, new_base: Address) {
        assert_eq!(self.m.class, MemRegionClass::Stack);
        self.m.base = new_base;
    }
}

/// An operation on the constant share of abstract values
type AbstrOp2 = fn(v1: &BitVector, v2: &BitVector) -> BitVector;
type AbstrOp1 = fn(v1: &BitVector) -> BitVector;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MemOp {
    /// Address of the memory instruction which references this value.
    pub ref_addr: Address,
    /// The abstract memory value which is processed.
    pub aval: AbstrVal,
}

impl MemOp {
    pub fn new(ref_addr: Address, aval: AbstrVal) -> MemOp {
        MemOp { ref_addr, aval }
    }

    pub fn is_heap(&self) -> bool {
        self.aval.is_heap()
    }
}

impl std::fmt::Display for MemOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MemOp: {:#x} -> {}", self.ref_addr, self.aval)
    }
}

pub type MemOpSeq = Vec<MemOp>;

#[derive(Debug, Clone)]
pub struct CallFrame {
    /// The invocation site
    in_site: Address,
    /// The instance count.
    instance: u32,
    /// The return address
    return_addr: Address,
    /// The abstract value of the SP register. It can point behind the base pointer, if
    /// after a call the new stac frame wasn't set up yet (new stack base wasn't set).
    sp: AbstrVal,
}

impl std::fmt::Display for CallFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CF(@{:#x}, ic: {}, sp: {}, ret: {:#x})",
            self.in_site, self.instance, self.sp, self.return_addr
        )
    }
}

/// The call stack. With every Call to a procedure another CallFrame is pushed.
/// With every return, a CallFrame is popped.
type CallStack = Vec<CallFrame>;

/// Resulting by-products of the abstract interpretation.
#[derive(Debug)]
pub struct IntrpProducts {
    /// Meta information collected about each instruction word executed.
    pub iword_info: BTreeMap<Address, IWordInfo>,
    /// Indirect calls resolved during interpretation
    pub concrete_calls: BTreeSet<ConcreteCodeXref>,
    pub concrete_jumps: BTreeSet<ConcreteCodeXref>,
    pub mem_xrefs: BTreeSet<MemXref>,
    pub stack_xrefs: BTreeSet<StackXref>,
    pub mos: MemOpSeq,
}

impl IntrpProducts {
    pub fn new() -> IntrpProducts {
        IntrpProducts {
            iword_info: BTreeMap::new(),
            concrete_calls: BTreeSet::new(),
            concrete_jumps: BTreeSet::new(),
            mem_xrefs: BTreeSet::new(),
            stack_xrefs: BTreeSet::new(),
            mos: MemOpSeq::new(),
        }
    }
}

/// An abstract interpreter VM. It will perform the abstract execution.
pub struct AbstrVM {
    /// ID of the thread this VM is executed in.
    pub thread_id: usize,
    /// Program counter
    pc: PC,
    /// Information about the instruction at the current PC
    insn_info: IWordInfo,
    /// PC size in bits
    pc_bit_width: usize,
    /// Instruction sizes map
    is: BTreeMap<Address, u64>,
    /// Invocation count map
    ic: BTreeMap<Address, u32>,
    /// MemTaint map
    mt: BTreeMap<AbstrVal, TaintFlag>,
    /// RegTaint map. Stores taint flags of all global variables.
    rt: BTreeMap<String, TaintFlag>,

    /// MemStore map
    ms: BTreeMap<AbstrVal, AbstrVal>,
    /// Global variables (mostly registers)
    /// This is equivalent to the RS map described in the paper.
    gvars: BTreeMap<String, AbstrVal>,
    /// Call stack
    cs: CallStack,
    /// Entry point of the currerntly executed procedure.
    proc_entry: Vec<Address>,

    /// State backup
    /// Back up from above: (ms, gvars, cs, proc_entry)
    state_backup: VecDeque<(
        BTreeMap<AbstrVal, AbstrVal>,
        BTreeMap<String, AbstrVal>,
        CallStack,
        Vec<Address>,
    )>,

    /// Local variables, defined via SETL
    lvars: BTreeMap<String, AbstrVal>,
    /// The resulting memory operand sequences of the interpretation
    mos: MemOpSeq,
    /// Path
    pa: IntrpPath,
    /// Local pure variables. Defined via LET()
    lpures: BTreeMap<String, AbstrVal>,
    /// Register roles (SP, PC, LR, ARG 1, ARG 2 etc)
    /// Role to register name nap.
    reg_roles: BTreeMap<RzRegisterId, String>,
    /// Register sizes in bits, indexed by name
    reg_sizes: BTreeMap<String, usize>,
    /// Meta information collected about each instruction word executed.
    iword_info: BTreeMap<Address, IWordInfo>,
    /// Const value call targets
    calls_xref: BTreeSet<ConcreteCodeXref>,
    /// Const value jump targets
    jumps_xref: BTreeSet<ConcreteCodeXref>,
    /// Const value memory values loaded or stored.
    mem_xrefs: BTreeSet<MemXref>,
    /// Stack references
    stack_xrefs: BTreeSet<StackXref>,
    /// Rizin Core
    rz_core: GRzCore,
    /// Normal distribution
    dist: Normal<f64>,
    /// Maximum number of REPEAT iteraitions, if they are not static
    limit_repeat: usize,
    /// Buffer for iwords. Indexed by address.
    iword_buffer: BTreeMap<Address, *mut RzAnalysisInsnWord>,
    /// Buffer for iwords. Indexed by address.
    aop_buffer: BTreeMap<Address, *mut RzAnalysisOp>,
}

macro_rules! unlocked_core {
    ($self:expr) => {
        $self.get_rz_core().clone().lock().unwrap()
    };
}

impl AbstrVM {
    /// Creates a new abstract interpreter VM.
    /// It takes the initial programm counter [pc], the [path] to walk
    /// and the sampling function for generating random values for input values.
    pub fn new(rz_core: GRzCore, entry: PC, path: IntrpPath) -> AbstrVM {
        let limit_repeat = rz_core.lock().unwrap().get_bda_max_iterations() as usize;
        let mut vm = AbstrVM {
            thread_id: usize::MAX,
            pc: entry,
            insn_info: NO_ADDR_INFO,
            pc_bit_width: 0,
            is: BTreeMap::new(),
            ic: BTreeMap::new(),
            ms: BTreeMap::new(),
            mt: BTreeMap::new(),
            rt: BTreeMap::new(),
            pa: path,
            proc_entry: Vec::new(),
            cs: CallStack::new(),
            mos: MemOpSeq::new(),
            gvars: BTreeMap::new(),
            lvars: BTreeMap::new(),
            lpures: BTreeMap::new(),
            reg_roles: BTreeMap::new(),
            reg_sizes: BTreeMap::new(),
            iword_info: BTreeMap::new(),
            calls_xref: BTreeSet::new(),
            jumps_xref: BTreeSet::new(),
            mem_xrefs: BTreeSet::new(),
            stack_xrefs: BTreeSet::new(),
            rz_core: rz_core.clone(),
            dist: Normal::new(0.0, 32768.0_f64.powi(2)).unwrap(),
            limit_repeat,
            iword_buffer: BTreeMap::new(),
            aop_buffer: BTreeMap::new(),
            state_backup: VecDeque::new(),
        };
        vm.init_register_file(rz_core);
        vm
    }

    fn free_buffers(&mut self) {
        self.aop_buffer.iter_mut().for_each(|aop| {
            unsafe { rz_analysis_op_free(aop.1.cast()) };
        });
        self.iword_buffer.iter_mut().for_each(|iword| {
            unsafe { rz_analysis_insn_word_free(iword.1.cast()) };
        });
    }

    pub fn peak_next_addr(&self) -> Option<Address> {
        if let Some(next) = self.pa.peak_next() {
            return Some(next.0);
        }
        None
    }

    pub fn peak_next_info(&self) -> Option<IWordInfo> {
        if let Some(next) = self.pa.peak_next() {
            return Some(next.1);
        }
        None
    }

    pub fn peak_next(&self) -> Option<&(Address, IWordInfo)> {
        if let Some(next) = self.pa.peak_next() {
            return Some(next);
        }
        None
    }

    pub fn get_limit_repeat(&self) -> usize {
        self.limit_repeat
    }

    pub fn get_rz_core(&self) -> &GRzCore {
        &self.rz_core
    }

    pub fn add_call_xref(&mut self, proc_addr: Address, to: Address) {
        if self.is_invalid_addr(to) {
            return;
        }
        self.calls_xref.insert(ConcreteCodeXref {
            xtype: CodeXrefType::IndirectCall,
            proc_addr,
            from: self.pc,
            to,
        });
    }

    pub fn add_jump_xref(&mut self, proc_addr: Address, to: Address) {
        if self.is_invalid_addr(to) {
            return;
        }
        self.jumps_xref.insert(ConcreteCodeXref {
            xtype: CodeXrefType::IndirectJump,
            proc_addr,
            from: self.pc,
            to,
        });
    }

    pub fn add_mem_xref(&mut self, to: Address, size: u64) {
        self.mem_xrefs.insert(MemXref {
            from: self.pc,
            to,
            size,
        });
    }

    /// Logs the usage of a stack variable [var] at the current PC.
    pub fn add_stack_xref(&mut self, var: AbstrVal) {
        assert!(var.is_stack());
        assert!(var.get_mem_region().ic != 0);
        self.stack_xrefs.insert(StackXref { at: self.pc, var });
    }

    pub fn get_varg(&self, name: &str) -> Option<AbstrVal> {
        if self.gvars.get(name).is_none() {
            warn!(
                target: "AbstrInterpreter",
                    "TID: {} - Global var '{}' not defined.",
                    self.thread_id,
                    name
            );
            return None;
        }
        Some(self.gvars.get(name).unwrap().clone())
    }

    pub fn get_varl(&self, name: &str) -> Option<AbstrVal> {
        if self.lvars.get(name).is_none() {
            warn!(
                target: "AbstrInterpreter",
                "TID: {} - Local var '{}' not defined.", self.thread_id, name
            );
            return None;
        }
        Some(self.lvars.get(name).unwrap().clone())
    }

    pub fn get_lpure(&self, name: &str) -> Option<AbstrVal> {
        if self.lpures.get(name).is_none() {
            warn!(
                target: "AbstrInterpreter",
                "TID: {} - LET var '{}' not defined.", self.thread_id, name
            );
            return None;
        }
        Some(self.lpures.get(name).unwrap().clone())
    }

    pub fn set_lpure(&mut self, name: String, av: AbstrVal) {
        if self.lpures.get(&name).is_some() {
            warn!(
                target: "AbstrInterpreter",
                    "TID: {} - LET var '{}' already defined.",
                    self.thread_id,
                    name
            );
            return;
        }
        self.lpures.insert(name.to_owned(), av);
    }

    pub fn set_varg(&mut self, name: &str, mut av: AbstrVal) {
        let global = self.gvars.get(name);
        if global.is_none() {
            error!(target: "AbstrInterpreter", "TID: {} - The global {} was not initialized. Cannot be set.", self.thread_id, name);
            return;
        }
        av.il_gvar = Some(name.to_string());
        debug!(target: "AbstrInterpreter", "TID: {} - SET GLOBAL: {} -> {}", self.thread_id, name, av);
        self.gvars
            .insert(name.to_owned(), self.normalize_val(av, false));
    }

    pub fn set_varl(&mut self, name: &str, av: AbstrVal) {
        debug!(target: "AbstrInterpreter", "TID: {} - SET LOCAL: {} -> {}", self.thread_id, name, av);
        self.lvars.insert(name.to_owned(), av);
    }

    pub fn rm_lpure(&mut self, let_name: &str) {
        debug!(target: "AbstrInterpreter", "TID: {} - REMOVE LOCAL: {}", self.thread_id, let_name);
        self.lpures.remove(let_name);
    }

    /// This function samples a random value from its distribution to
    /// simulate input for the program.
    /// It takes the address of an input-functions at [address] and the current
    /// [invocation] of the function.
    pub fn rv(&self, width: u32) -> BitVector {
        if width <= 64 {
            return BitVector::new_from_u64(
                width,
                self.dist.sample(&mut rand::thread_rng()) as u64,
            );
        }
        let samples_cnt = width + 7 >> 3;
        let mut v_buf = Vec::<u8>::new();
        for _ in 0..samples_cnt {
            v_buf.push(self.dist.sample(&mut rand::thread_rng()) as u8);
        }
        BitVector::from_bytes_be(width, v_buf)
    }

    /// Samples with a 0.5 chance a true (1) or false (0) value.
    pub fn rvb(&self) -> BitVector {
        if rand::thread_rng().gen_bool(0.5) {
            BitVector::new_true()
        } else {
            BitVector::new_false()
        }
    }

    /// Initializes the register profile, register alias and their initial
    /// abstract values.
    /// Returns false if it fails.
    fn init_register_file(&mut self, rz_core: GRzCore) {
        debug!(
            target: "AbstrInterpreter",
            "TID: {} - register file for abstract interpreter.",
            self.thread_id
        );

        if rz_core.is_poisoned() {
            rz_core.clear_poison();
        }
        let core = rz_core.lock().unwrap();

        self.pc_bit_width = core.get_arch_bits();

        // Set the register alias
        let alias = core.get_reg_alias();
        for ralias in alias {
            let ra = pderef!(ralias);
            if let Some(_) = self.reg_roles.insert(ra.role, c_to_str(ra.reg_name)) {
                warn!(
                    target: "AbstrInterpreter",
                        "TID: {} - Duplicate role of register {} detected",
                        self.thread_id,
                        c_to_str(ra.reg_name)
                );
            }
        }
        let sp_name = self.get_reg_name_by_role(RzRegisterId_RZ_REG_NAME_SP);
        let bp_name = self.get_reg_name_by_role(RzRegisterId_RZ_REG_NAME_BP);
        // Temp registers for Hexagon. Should be moved to a separated function
        // where other cases are handled as well.
        // Also should be the stack setup properly, depending on the ABI
        let mut sp_name_tmp = sp_name.clone();
        sp_name_tmp.push_str("_tmp");
        let mut bp_name_tmp = bp_name.clone();
        bp_name_tmp.push_str("_tmp");

        // Init complete register file
        let reg_bindings = core.get_reg_bindings().expect("Could not get reg_bindings");
        let reg_count = pderef!(reg_bindings).regs_count;
        let regs = pderef!(reg_bindings).regs;
        let mut stack_access_size = 0;
        for i in 0..reg_count {
            let reg = unsafe { regs.offset(i as isize) };
            let rsize = pderef!(reg).size;
            let rname = pderef!(reg).name;
            let name = c_to_str(rname);
            debug!(
                target: "AbstrInterpreter",
                "TID: {} - \t-> {}", self.thread_id, name
            );

            if name == *bp_name || name == *sp_name || name == sp_name_tmp || name == bp_name_tmp {
                stack_access_size = rsize;
                continue;
            }
            let init_val =
                AbstrVal::new_global(1, BitVector::new_zero(rsize), Some(name.clone()), 0);
            self.reg_sizes.insert(name.clone(), rsize as usize);
            self.gvars.insert(name.clone(), init_val);
            self.rt.insert(name.to_owned(), TaintFlag::Unset);
        }
        self.setup_initial_stack(
            stack_access_size,
            &[sp_name, bp_name, sp_name_tmp, bp_name_tmp],
        );
    }

    /// Gives the invocation count for a given instruction address.
    pub fn get_ic(&mut self, iaddr: Address) -> u32 {
        self.ic.entry(iaddr).or_default().clone()
    }

    /// Calculates the result of an operation on one abstract value and the taint flag [^1]
    /// Returns the calculated result as abstract value and the taint flag.
    /// [^1] Figure 2.11 - https://doi.org/10.25394/PGS.23542014.v1
    pub(crate) fn calc_value_1(
        &mut self,
        op: AbstrOp1,
        v1: AbstrVal,
        sample_bool: bool,
    ) -> (AbstrVal, TaintFlag) {
        let tainted: TaintFlag;
        let v3: AbstrVal;
        if v1.m.class == MemRegionClass::Global {
            v3 = AbstrVal::new(v1.m.clone(), op(&v1.c), None);
            tainted = TaintFlag::Unset;
        } else {
            v3 = AbstrVal::new_global(
                self.get_pc_ic(),
                if sample_bool {
                    self.rvb()
                } else {
                    self.rv(v1.get_width())
                },
                None,
                self.get_pc(),
            );
            tainted = TaintFlag::Set;
        }
        (v3, tainted)
    }

    /// Calculates the result of an operation on two abstract values and their taint flags [^1]
    /// Returns the calculated result as abstract value and the taint flag.
    /// It assumes that [v1] and [v2] are of the same bit width and [op] produces a
    /// value of the same bit width.
    /// [^1] Figure 2.11 - https://doi.org/10.25394/PGS.23542014.v1
    pub(crate) fn calc_value_2(
        &mut self,
        op: AbstrOp2,
        v1: AbstrVal,
        v2: AbstrVal,
        sample_bool: bool,
    ) -> (AbstrVal, TaintFlag) {
        let tainted: TaintFlag;
        let v3: AbstrVal;
        if v1.m.class == MemRegionClass::Global {
            v3 = AbstrVal::new(v2.m.clone(), op(&v1.c, &v2.c), None);
            tainted = TaintFlag::Unset;
        } else if v2.m.class == MemRegionClass::Global {
            v3 = AbstrVal::new(v1.m.clone(), op(&v1.c, &v2.c), None);
            tainted = TaintFlag::Unset;
        } else {
            let pc = self.pc;
            let ic_pc = self.get_ic(pc);
            v3 = AbstrVal::new_global(
                ic_pc,
                if sample_bool {
                    self.rvb()
                } else {
                    self.rv(v1.get_width())
                },
                None,
                self.get_pc(),
            );
            tainted = TaintFlag::Set;
        }
        (v3, tainted)
    }

    /// Normilzes the given value. If the value is not a stack memory value,
    /// it returns a clone.
    /// Otherwise, it returns an abtract value with the memory region set to
    /// the enclosing stack frame. [^1]
    ///
    /// If [norm_zero] is true, it will also normalize values with an offset
    /// of 0.
    ///
    /// [^1] Figure 2.11 - https://doi.org/10.25394/PGS.23542014.v1
    pub fn normalize_val(&self, mut v: AbstrVal, norm_zero: bool) -> AbstrVal {
        if v.m.class != MemRegionClass::Stack {
            return v;
        }
        for vt in self.cs.iter().rev() {
            if v.c.is_neg() || (!norm_zero && v.c.is_zero()) {
                break;
            }
            v.m = vt.sp.m.clone();
            v.c += &vt.sp.c;
        }
        v
    }

    pub(crate) fn get_taint_flag(&mut self, v: &AbstrVal) -> TaintFlag {
        if v.il_gvar.is_some() {
            if let Some(t) = self.rt.get(v.il_gvar.as_ref().unwrap()) {
                return *t;
            } else {
                panic!("Has no taint flag set for abstr. global {}", v)
            }
        }
        if v.is_global() {
            return TaintFlag::Unset;
        }
        if let Some(t) = self.mt.get(v) {
            *t
        } else {
            // If there was not taint flag set, it means the path did not walked over
            // the instruction setting it.
            TaintFlag::Unknown
        }
    }

    pub(crate) fn set_taint_flag(&mut self, v3: &AbstrVal, tainted: TaintFlag) {
        if let Some(il_gvar) = v3.il_gvar.clone() {
            if let Some(_) = self.gvars.get(&il_gvar) {
                self.rt.insert(il_gvar, tainted);
                return;
            }
            error!(
                target: "AbstrInterpreter",
                "TID: {} - variable is not defined.",
                self.thread_id
            );
            return;
        }
        self.mt.insert(v3.clone(), tainted);
    }

    /// Reads a memory value. It first attempts to read an abstract value from the
    /// MS map. If this fails it panics for Heap and Stack values. But attempts to read [n_bytes]
    /// from the memory mapped in Rizins IO.
    /// If [n_bytes] == 0, it panics as well.
    /// Returns the new Abstract value and if it was sampled.
    pub(crate) fn get_mem_val(&mut self, key: &AbstrVal, n_bytes: usize) -> (AbstrVal, TaintFlag) {
        if let Some(v) = self.ms.get(key) {
            debug!(target: "AbstrInterpreter", "TID: {} - LOAD: AT: {} -> {}", self.thread_id, key, v);
            return (v.clone(), TaintFlag::Unset);
        }
        if n_bytes == 0 {
            panic!("Cannot read 0 bytes for: {}", key);
        }
        let mut is_sampled = TaintFlag::Unset;
        if !key.is_global() {
            is_sampled = TaintFlag::Set;
        }
        let gmem_val = BitVector::new_from_u64(
            (n_bytes * 8) as u32,
            self.read_io_at_u64(key.get_as_addr(), n_bytes),
        );
        let v = (
            AbstrVal::new_global(self.get_pc_ic(), gmem_val, None, self.get_pc()),
            is_sampled,
        );
        debug!(target: "AbstrInterpreter", "TID: {} - LOAD: AT: {} -> {}", self.thread_id, key, v.0);
        v
    }

    pub fn set_mem_val(&mut self, key: &AbstrVal, val: AbstrVal) {
        debug!(target: "AbstrInterpreter", "TID: {} - STORE: AT: {} => {}", self.thread_id, key, val);
        self.ms.insert(key.clone(), val);
    }

    pub fn get_reg_val(&self, key: &AbstrVal) -> AbstrVal {
        if let Some(rname) = &key.il_gvar {
            self.gvars
                .get(rname)
                .expect(&format!("Global var {} not set.", &rname));
        }
        panic!("Abstract value doesn't belong to a global var.");
    }

    pub fn enqueue_mos(&mut self, v: &AbstrVal) {
        // We need to normalize the value, because otherwise we can't detect stack pointer
        // dependencies at the stack frame boundaries (usually between call and return instructions).
        //
        // The last value pushed to the stack on a call (usually the return address),
        // has two abstract addresses assigned.
        // One is the abstract address by the caller: 〈₁𝑺 ⌊caller_base⌋, -offset〉
        // and one of the rebased stack pointer for the new callee stack frame: 〈₁𝑺 ⌊callee_base⌋, 0〉
        // But memory ops must be unique, so we normalize the 0 offsets to the last element
        // of the caller stack.
        let normed_v = self.normalize_val(v.clone(), true);
        let mem_op = MemOp {
            ref_addr: self.get_pc(),
            aval: normed_v,
        };
        debug!(target: "AbstrInterpreter", "TID: {} - ENQUEUE MOS: {}", self.thread_id, &mem_op);
        self.mos.push(mem_op);
    }

    fn get_sp(&self) -> AbstrVal {
        let sp_name = self
            .reg_roles
            .get(&RzRegisterId_RZ_REG_NAME_SP)
            .expect("SP not set");
        self.gvars
            .get(sp_name)
            .expect("RS abstract value was not initialized.")
            .clone()
    }

    /// Pushes a functions call frame on the call stack, before it jumps to [proc_addr].
    pub fn call_stack_push(&mut self, proc_addr: Address) {
        debug!(target: "AbstrInterpreter", "TID: {} - Push CS", self.thread_id);
        // For now we just assume that the SP was _not_ updated before the actual jump to the procedure.
        let cf = CallFrame {
            in_site: self.pc,
            instance: *self.ic.get(&self.pc).expect("Should have been set before."),
            return_addr: self.pc + self.is.get(&self.pc).expect("Should have been set before."),
            sp: self.get_sp(),
        };
        self.rebase_sp(proc_addr);
        debug!(target: "AbstrInterpreter", "TID: {} - PUSH: {}", self.thread_id, cf);
        self.proc_entry.push(proc_addr);
        debug!(target: "AbstrInterpreter", "TID: {} - Stack: {:?}", self.thread_id, self.proc_entry);
        self.cs.push(cf);
    }

    /// Pops a call frame from the call stack.
    pub fn call_stack_pop(&mut self) -> Option<CallFrame> {
        let cf = self.cs.pop();
        debug!(target: "AbstrInterpreter", "TID: {} - POP: {}", self.thread_id, cf.as_ref().unwrap());
        self.proc_entry.pop();
        debug!(target: "AbstrInterpreter", "TID: {} - Stack: {:?}", self.thread_id, self.proc_entry);
        cf
    }

    pub fn read_io_at(&self, addr: Address, n_bytes: usize) -> Vec<u8> {
        unlocked_core!(self).read_io_at(addr, n_bytes)
    }

    pub fn read_io_at_u64(&self, addr: Address, n_bytes: usize) -> u64 {
        let data = self.read_io_at(addr, n_bytes);
        let mut buf: [u8; 8] = [0; 8];
        data.as_slice().read_exact(&mut buf[..n_bytes]).unwrap();
        u64::from_le_bytes(buf)
    }

    pub fn read_mem(&self, addr: Address, n_bytes: usize) -> Vec<u8> {
        unlocked_core!(self).read_io_at(addr, n_bytes)
    }

    pub(crate) fn pc_is_call(&self) -> bool {
        self.insn_info.is_call()
    }

    pub(crate) fn pc_is_return(&self) -> bool {
        self.insn_info.is_return()
    }

    pub(crate) fn pc_is_tail_call(&self) -> bool {
        self.insn_info.is_tail_call()
    }

    pub(crate) fn get_pc(&self) -> Address {
        self.pc
    }

    /// Checks if the given register name is the register name of
    /// the stack base pointer.
    fn _is_bp(&self, reg_name: &str) -> bool {
        reg_name
            == self
                .reg_roles
                .get(&RzRegisterId_RZ_REG_NAME_BP)
                .expect("BP must be defined in register profile.")
    }

    fn set_sp(&mut self, av: AbstrVal) {
        let sp_name = self
            .reg_roles
            .get(&RzRegisterId_RZ_REG_NAME_SP)
            .expect("SP must be defined in register profile.")
            .clone();
        self.set_varg(&sp_name, av.clone());
        let sp_tmp = format!("{}_tmp", sp_name);
        if self.gvars.contains_key(&sp_tmp) {
            self.set_varg(&sp_tmp, av);
        }
    }

    /// Resets the stack pointer to a new base.
    fn rebase_sp(&mut self, base: Address) {
        let sp = self.get_sp();
        let ic = self.get_pc_ic();
        debug_assert!(ic != 0);
        self.set_sp(AbstrVal::new_stack(
            ic,
            BitVector::new_zero(sp.get_width()),
            base,
        ));
    }

    /// Initializes the stack for the first two cells of size [stack_cell_size].
    fn setup_initial_stack(&mut self, stack_cell_size: u32, stack_reg_names: &[String]) {
        // Setup all stack base pointer and stack pointer.
        let init_stack_ptr = AbstrVal::new_stack(
            1,
            BitVector::new_from_i32(stack_cell_size, -(stack_cell_size as i32)),
            MAX_U64_ADDRESS,
        );
        for rname in stack_reg_names {
            self.reg_sizes
                .insert(rname.clone(), stack_cell_size as usize);
            self.gvars.insert(rname.clone(), init_stack_ptr.clone());
            self.rt.insert(rname.to_owned(), TaintFlag::Unset);
        }
        self.set_taint_flag(&init_stack_ptr, TaintFlag::Unset);

        // Save dummy values where first stack pointer points to
        self.set_mem_val(
            &init_stack_ptr,
            AbstrVal::new_global(
                1,
                BitVector::new_zero(stack_cell_size),
                None,
                MAX_U64_ADDRESS,
            ),
        );

        // Push initial stack frame
        let mut cf = CallFrame {
            in_site: MAX_U64_ADDRESS,
            instance: 1,
            return_addr: MAX_U64_ADDRESS,
            sp: init_stack_ptr,
        };
        self.proc_entry.push(MAX_U64_ADDRESS);
        self.cs.push(cf);

        // Pretend to call main

        // Set SP.
        // We don't use rebase_sp() here.
        // Because it uses the IC of the PC. Which is 0 at this point.
        self.set_sp(AbstrVal::new_stack(
            1,
            BitVector::new_zero(self.get_sp().get_width()),
            self.pc,
        ));

        // Push initial call frame.
        cf = CallFrame {
            in_site: self.pc,
            instance: 1,
            return_addr: MAX_U64_ADDRESS,
            sp: self.get_sp(),
        };
        self.proc_entry.push(self.pc);
        self.cs.push(cf);
    }

    /// Sets the register which takes return values, to a new Heap abstract value.
    /// This function is usually called after a memory allocating call.
    pub fn move_heap_val_into_ret_reg(&mut self) {
        let rr_name = self.get_reg_name_by_role(RzRegisterId_RZ_REG_NAME_R0);
        let rr_size = self.get_reg_size(&rr_name);
        let hval = AbstrVal::new_heap(
            self.get_ic(self.get_pc()),
            BitVector::new_zero(rr_size as u32),
            self.get_pc(),
        );
        self.set_varg(&rr_name, hval);
    }

    fn get_reg_name_by_role(&self, role: RzRegisterId) -> String {
        self.reg_roles
            .get(&role)
            .expect("Role must be defined in register profile.")
            .clone()
    }

    fn get_reg_size(&self, name: &str) -> usize {
        *self.reg_sizes.get(name).expect("Register has no size set.")
    }

    pub fn get_pc_ic(&mut self) -> u32 {
        self.get_ic(self.get_pc())
    }

    pub fn get_cur_entry(&self) -> u64 {
        return *self.proc_entry.last().expect(
            format!(
                "No entry point on stack, PUSH and POP go out of sync. PC = {:#x}",
                self.pc
            )
            .as_str(),
        );
    }

    fn is_max_addr(&self, to: u64) -> bool {
        to == (u64::MAX >> 64 - self.pc_bit_width)
    }

    fn is_invalid_addr(&self, to: u64) -> bool {
        self.is_max_addr(to) || to == 0x0
    }

    fn get_buffered_aop(&mut self) -> *mut binding::rz_analysis_op_t {
        let ana_op = if self.aop_buffer.get(&self.pc).is_some() {
            *self.aop_buffer.get(&self.pc).unwrap()
        } else {
            let ptr = unlocked_core!(self).get_analysis_op(self.pc);
            self.aop_buffer.insert(self.pc, ptr);
            ptr
        };
        ana_op
    }

    fn get_buffered_iword(&mut self) -> *mut RzAnalysisInsnWord {
        let iword = if self.iword_buffer.get(&self.pc).is_some() {
            *self.iword_buffer.get(&self.pc).unwrap()
        } else {
            let ptr = unlocked_core!(self).get_iword(self.pc);
            self.iword_buffer.insert(self.pc, ptr);
            ptr
        };
        iword
    }

    fn step(&mut self) -> StepResult {
        if let Some((pc, addr_info)) = self.pa.next() {
            self.pc = pc;
            self.insn_info = addr_info;
        } else {
            return StepResult::Done;
        }
        self.add_iword_info(self.insn_info);
        debug!(target: "AbstrInterpreter", "TID: {} - pc = {:#x}", self.thread_id, self.pc);

        *self.ic.entry(self.pc).or_default() += 1;

        if self.insn_info.is_exit() {
            debug_assert!(
                self.pa.next().is_none(),
                "Exit was not the last instruction in the path"
            );
            return StepResult::Exit;
        }

        let iword_decoder = unlocked_core!(self).get_iword_decoder();
        let effect;
        let result;
        if iword_decoder.is_some() {
            // So if the next address in the path is not ht next address, a call is performed.
            let iword = self.get_buffered_iword();
            self.is.insert(self.pc, pderef!(iword).size_bytes as u64);
            effect = pderef!(iword).il_op;
        } else {
            let ana_op = self.get_buffered_aop();
            // So if the next address in the path is not ht next address, a call is performed.
            self.is.insert(self.pc, pderef!(ana_op).size as u64);
            effect = pderef!(ana_op).il_op;
        }
        if self.pc == 0x0800005e {
            println!("");
        }
        let (skip_reason, execute_insn) = if self.insn_info.calls_malloc() {
            // Not yet done for iwords. iwords must only skip the call part.
            ("calls malloc", false)
        } else if self.insn_info.calls_input() {
            ("calls input", false)
        } else if self.insn_info.calls_unmapped() {
            ("calls unmapped", false)
        } else {
            ("none", true)
        };

        // Calls which are not followed, but should be interpreted anyays (to find new call edges) set this flag.
        let dont_commit_to_state = execute_insn && self.pc_is_call() && !self.call_is_taken();
        if dont_commit_to_state {
            self.backup_state();
        }

        if !execute_insn {
            if self.insn_info.calls_malloc() || self.insn_info.calls_input() {
                self.move_heap_val_into_ret_reg();
            }
            debug!(target: "AbstrInterpreter", "TID: {} - Skip call: {}", self.thread_id, skip_reason);
            result = true;
        } else if effect != std::ptr::null_mut() {
            debug!(target: "AbstrInterpreter", "TID: {} - rzil_op: {}", self.thread_id, effect_to_str(effect));
            result = eval_effect(self, effect);
        } else {
            // Otherwise not implemented
            result = true;
        }

        if self.pc_is_tail_call() {
            // Pop CallFrame from stack before jumping to the next one.
            debug!(target: "AbstrInterpreter", "TID: {} - Tail call", self.thread_id);
            if let Some(target) = self.peak_next_addr() {
                self.call_stack_pop();
                self.call_stack_push(target);
            }
        } else if self.pc_is_return() {
            self.call_stack_pop();
        }
        self.lvars.clear();

        if dont_commit_to_state {
            self.restore_state();
        }
        if result {
            return StepResult::Ok;
        }
        return StepResult::Fail;
    }

    pub(crate) fn add_iword_info(&mut self, info: IWordInfo) {
        let pc = self.get_pc();
        if let Some(prev) = self.iword_info.get(&pc) {
            self.iword_info.insert(pc, prev.clone() | info);
            return;
        }
        self.iword_info.insert(pc, info);
    }

    #[allow(dead_code)]
    fn print_machine_state(&self) {
        println!("--------------------------------------------------");
        for (i, reg) in self.rt.iter().enumerate() {
            if reg.0.starts_with(&['S', 'V', 'G', 'C']) {
                continue;
            }
            if i % 3 == 0 {
                println!();
            }
            print!(
                "{} = {}      ",
                reg.0,
                self.get_varg(reg.0).as_ref().unwrap()
            );
        }
        println!();
        println!("--------------------------------------------------");
    }

    pub(crate) fn call_is_taken(&self) -> bool {
        debug_assert!(self.pc_is_call());
        if let Some(next) = self.peak_next_addr() {
            // Assume the call doesn't target the next instruction.
            // So if the next address in the path is not the next address, a call is performed.
            return self.get_pc() + self.is.get(&self.get_pc()).expect("Size unset") != next;
        }
        false
    }

    /// Backup the state of the VM for later restoral.
    /// Used before executing instructions which should be only analysed,
    /// but not commited.
    /// E.g. call instructions to unmapped addresses. They are executed, but should not manipulate
    /// the stack, because they are never followed.
    fn backup_state(&mut self) {
        self.state_backup.push_back((
            self.ms.clone(),
            self.gvars.clone(),
            self.cs.clone(),
            self.proc_entry.clone(),
        ));
    }

    fn restore_state(&mut self) {
        (self.ms, self.gvars, self.cs, self.proc_entry) = self
            .state_backup
            .pop_back()
            .expect("Should not be reached.");
    }
}

#[derive(PartialEq, Eq)]
enum StepResult {
    // Step was executed succesfully.
    Ok,
    // An error occured during effect evaluation.
    Fail,
    // VM walked the whole path
    Done,
    // VM hit an exit.
    Exit,
}

/// Interprets the given path with the given interpreter VM.
pub fn interpret(thread_id: usize, rz_core: GRzCore, path: IntrpPath, tx: Sender<IntrpProducts>) {
    debug!(target: "AbstrInterpreter", "TID: {thread_id}: {}", path);
    println!("\nPath: {path}");
    let mut vm = AbstrVM::new(rz_core, path.get(0).0, path);
    vm.thread_id = thread_id;

    let mut step = StepResult::Ok;
    while step == StepResult::Ok {
        step = vm.step();
        // vm.print_machine_state();
    }
    assert!(
        step == StepResult::Done || step == StepResult::Exit,
        "Emulation failed with an error."
    );

    assert!(
        vm.cs.len() == 1 || step == StepResult::Exit,
        "TID: {} - Call stack invalid. Should only hold the initial frame only or be an exit: {:?}",
        thread_id,
        vm.cs
    );
    vm.free_buffers();

    debug!(target: "AbstrInterpreter", "TID: {} - EXIT\n", vm.thread_id);
    // Replace with Channel and send/rcv
    let products = IntrpProducts {
        iword_info: vm.iword_info.into(),
        concrete_calls: vm.calls_xref.into(),
        concrete_jumps: vm.jumps_xref.into(),
        mem_xrefs: vm.mem_xrefs.into(),
        stack_xrefs: vm.stack_xrefs.into(),
        mos: vm.mos.into(),
    };

    if let Err(_) = tx.send(products) {
        error!(
            target: "AbstrInterpreter",
            "TID: {} - could not send data. Main thread hangs", vm.thread_id
        );
    }
}
