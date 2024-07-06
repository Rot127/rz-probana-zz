// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use helper::num::subscript;
use num_bigint::{BigInt, BigUint, Sign, ToBigInt, ToBigUint};
use rand::Rng;
use rand_distr::{Distribution, Normal};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt::LowerHex,
    hash::{Hash, Hasher},
    io::Read,
    sync::mpsc::Sender,
};

use binding::{
    c_to_str, log_rizin, log_rz, pderef, rz_analysis_insn_word_free, rz_analysis_op_free, GRzCore,
    RzRegisterId, RzRegisterId_RZ_REG_NAME_BP, RzRegisterId_RZ_REG_NAME_R0,
    RzRegisterId_RZ_REG_NAME_SP, LOG_DEBUG, LOG_ERROR, LOG_WARN,
};

use crate::op_handler::eval_effect;

/// If this plugin is still used, when 128bit address space is a thing, do grep "64".
pub type Address = u64;

const MAX_ADDRESS: u64 = u64::MAX;

#[derive(Clone, Debug, Hash)]
pub struct Const {
    v: BigUint,
    /// Width of constant in bits
    width: u64,
}

impl LowerHex for Const {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#x}{}", self.vu(), subscript(self.width))
    }
}

impl Eq for Const {}
impl PartialEq for Const {
    fn eq(&self, other: &Self) -> bool {
        self.v == other.v && self.width() == other.width()
    }
}

impl Const {
    pub fn as_signed_num_str(&self) -> String {
        format!("{:#x}{}", self.v(), subscript(self.width))
    }

    /// Returns a bit mask with all bits set.
    /// The bitmask has a length is always aligned to the next byte.
    pub fn get_maski(width: u64) -> BigInt {
        let v = vec![0xffu8; ((width + 7) >> 3) as usize];
        BigInt::from_bytes_be(Sign::Plus, v.as_slice())
    }

    /// Returns a bit mask with all bits set.
    /// The bitmask has a length is always aligned to the next byte.
    pub fn get_masku(width: u64) -> BigUint {
        let v = vec![0xffu8; ((width + 7) >> 3) as usize];
        BigUint::from_bytes_be(v.as_slice())
    }

    pub fn bigint_to_biguint(v: BigInt, width: u64) -> BigUint {
        if v.sign() == Sign::Minus {
            return (v.into_parts().1 ^ Const::get_masku(width)) + 1.to_biguint().unwrap();
        }
        v.to_biguint().unwrap()
    }

    /// Creates a new Const from an BigInt with a bit width of [width]
    /// Any bits of [v] at [width] onwards are dropped.
    pub fn new(v: BigUint, width: u64) -> Const {
        Const {
            v: v & Const::get_masku(width),
            width,
        }
    }

    pub fn newi(v: BigInt, width: u64) -> Const {
        Const {
            v: Const::bigint_to_biguint(v, width) & Const::get_masku(width),
            width,
        }
    }

    /// Creates a new Const from an BigInt with a bit width of [width]
    /// Any bits of [v] at [width] onwards are dropped.
    pub fn new_i64(v: i64, width: u64) -> Const {
        Const {
            v: Const::bigint_to_biguint(v.to_bigint().expect("to_bigint() failed"), width),
            width,
        }
    }

    pub fn new_i32(v: i32, width: u64) -> Const {
        Const {
            v: Const::bigint_to_biguint(v.to_bigint().expect("to_bigint() failed"), width),
            width,
        }
    }

    /// Returns the BigInt of this constant
    pub fn v(&self) -> BigInt {
        let target_byte_w: usize = ((self.width() + 7) >> 3) as usize;
        if target_byte_w == 0 {
            return BigInt::ZERO;
        }

        let v = self.v.to_bytes_le();
        let mut le_bytes = vec![
            if self.v.bit(self.width() - 1) {
                0xffu8
            } else {
                0x00u8
            };
            target_byte_w
        ];
        for (i, vbyte) in v.iter().enumerate() {
            if let Some(byte) = le_bytes.get_mut(i) {
                *byte = if *byte == 0xffu8 {
                    *byte & *vbyte
                } else {
                    *byte | *vbyte
                }
            }
        }
        let result = BigInt::from_signed_bytes_le(le_bytes.as_slice());
        result
    }

    /// Returns the BigUint representation of this constant
    pub fn vu(&self) -> BigUint {
        self.v.clone()
    }

    pub fn seti(&mut self, v: BigInt) {
        self.v = Const::bigint_to_biguint(v, self.width());
    }

    pub fn msb(&self) -> bool {
        self.v.bit(self.width - 1)
    }

    pub fn lsb(&self) -> bool {
        self.v.bit(0)
    }

    pub fn get_true() -> Const {
        Const {
            v: 1.to_biguint().unwrap(),
            width: 1,
        }
    }

    pub fn get_false() -> Const {
        Const {
            v: 0.to_biguint().unwrap(),
            width: 1,
        }
    }

    pub fn get_zero(width: u64) -> Const {
        Const {
            v: 0.to_biguint().unwrap(),
            width,
        }
    }

    pub fn is_zero(&self) -> bool {
        self.v == BigUint::ZERO
    }

    /// Returns a constant of [width] bits with all bits set to true.
    pub fn get_umax(width: u64) -> Const {
        let mut v = 0.to_biguint().unwrap();
        for i in 0..width {
            v.set_bit(i as u64, true);
        }
        Const { v, width }
    }

    pub fn new_u64(v: u64, width: u64) -> Const {
        Const {
            v: v.to_biguint().unwrap(),
            width,
        }
    }

    pub fn as_u64(&self) -> u64 {
        if self.is_zero() {
            return 0;
        }
        *self.v.to_u64_digits().get(0).expect("Invalid value")
    }

    pub fn width(&self) -> u64 {
        self.width
    }

    /// Returns the a casted value according to [len] and [fill].
    /// Additionally, it returns the taint bit. The taint bit is set, if:
    /// - The [fill] bit was used
    /// AND
    /// - [fill] is not a global true or false value, and has been sampled.
    pub fn cast(&self, len: u64, fill: AbstrVal) -> (Const, bool) {
        if len <= self.width() {
            return (Const::new(self.v.clone(), len), false);
        }
        let (fill_bit, tainted) = if fill.is_true() {
            (true, false)
        } else if fill.is_false() {
            (false, false)
        } else {
            (rand::thread_rng().gen_bool(0.5), true)
        };
        let mut v = self.v.clone();
        if len <= self.width() {
            return (Const::new(v, len), tainted);
        }
        for i in self.width()..len {
            v.set_bit(i, fill_bit);
        }
        (Const::new(v, len), tainted)
    }

    fn _is_neg(&self) -> bool {
        self.v < BigUint::ZERO
    }
}

type PC = Address;

#[derive(PartialEq, Eq)]
pub struct AddrInfo {
    /// IWord calls a procedure.
    is_call: bool,
    /// IWord calls an allocating function.
    calls_malloc: bool,
    /// IWord calls an input function.
    calls_input: bool,
    /// IWord is executed on return of a procedure.
    is_return_point: bool,
}

impl AddrInfo {
    pub fn new(
        is_call: bool,
        calls_malloc: bool,
        calls_input: bool,
        is_return_point: bool,
    ) -> AddrInfo {
        AddrInfo {
            is_call,
            calls_malloc,
            calls_input,
            is_return_point,
        }
    }

    pub fn new_call() -> AddrInfo {
        AddrInfo {
            is_call: true,
            calls_malloc: false,
            calls_input: false,
            is_return_point: false,
        }
    }

    pub fn new_malloc_call() -> AddrInfo {
        AddrInfo {
            is_call: true,
            calls_malloc: true,
            calls_input: false,
            is_return_point: false,
        }
    }

    pub fn new_return_point() -> AddrInfo {
        AddrInfo {
            is_call: false,
            calls_malloc: false,
            calls_input: false,
            is_return_point: true,
        }
    }

    pub fn new_input() -> AddrInfo {
        AddrInfo {
            is_call: true,
            calls_malloc: false,
            calls_input: true,
            is_return_point: false,
        }
    }

    pub fn new_return() -> AddrInfo {
        AddrInfo {
            is_call: false,
            calls_malloc: false,
            calls_input: false,
            is_return_point: true,
        }
    }
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

    pub fn from(vec: VecDeque<Address>) -> IntrpPath {
        IntrpPath {
            path: vec,
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

    pub fn peak_next(&self) -> Option<&Address> {
        self.path.get(0)
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
#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub struct ConcreteCall {
    /// The address of the procedure this call occurs.
    proc_addr: Address,
    /// The caller
    from: Address,
    /// The callee
    to: Address,
}

impl ConcreteCall {
    pub fn new(proc_addr: Address, from: Address, to: Address) -> Self {
        Self {
            proc_addr,
            from,
            to,
        }
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

impl std::fmt::Display for ConcreteCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "icall {:#x} : {:#x} -> {:#x}",
            self.proc_addr, self.from, self.to
        )
    }
}

/// A concretely resolved indirect call.
/// Those can be discovered, if only constant value were used to define the call target.
#[derive(Eq, PartialEq, Hash, Clone, Debug)]
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
#[derive(Eq, PartialEq, Hash, Clone, Debug)]
pub struct StackXref {
    /// The instruction address
    at: Address,
    /// Abstract value of the stack variable/argument
    var: AbstrVal,
}

impl StackXref {
    /// This functions sets the IC always to 1
    pub fn new(at: Address, offset: Const, base: Address) -> StackXref {
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
            MemRegionClass::Global => "𝑮",
            MemRegionClass::Heap => "𝑯",
            MemRegionClass::Stack => "𝑺",
        };
        write!(f, "{}{} ⌊{:#x}⌋", subscript(self.c), letter, self.base)
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
    c: Const,
    /// Name of the global IL variable this abstract value was read from.
    /// If None, it is a memory value.
    /// This is used to decide which taint map to use.
    il_gvar: Option<String>,
}

impl Eq for AbstrVal {}
impl PartialEq for AbstrVal {
    fn eq(&self, other: &Self) -> bool {
        self.m == other.m && self.c == other.c
    }
}

impl Hash for AbstrVal {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        self.m.hash(state);
        self.c.hash(state);
    }
}

impl std::fmt::Display for AbstrVal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "〈{}, {}〉",
            self.m,
            if self.m.class == MemRegionClass::Stack {
                self.c.as_signed_num_str()
            } else {
                format!("{:#x}", self.c)
            }
        )
    }
}

impl AbstrVal {
    pub fn new_global(ic: u64, c: Const, il_gvar: Option<String>, base: Address) -> AbstrVal {
        let m = MemRegion {
            class: MemRegionClass::Global,
            base,
            c: ic,
        };
        AbstrVal { m, c, il_gvar }
    }

    pub fn new_stack(ic: u64, offset: Const, base: Address) -> AbstrVal {
        let m = MemRegion {
            class: MemRegionClass::Stack,
            base,
            c: ic,
        };
        AbstrVal {
            m,
            c: offset,
            il_gvar: None,
        }
    }

    pub fn new_heap(ic: u64, offset: Const, base: Address) -> AbstrVal {
        let m = MemRegion {
            class: MemRegionClass::Heap,
            base,
            c: ic,
        };
        AbstrVal {
            m,
            c: offset,
            il_gvar: None,
        }
    }

    pub fn get_width(&self) -> u64 {
        self.c.width()
    }

    pub fn new_true() -> AbstrVal {
        AbstrVal::new_global(1, Const::get_true(), None, 0)
    }

    pub fn new_false() -> AbstrVal {
        AbstrVal::new_global(1, Const::get_false(), None, 0)
    }

    pub fn new(m: MemRegion, c: Const, il_gvar: Option<String>) -> AbstrVal {
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

    pub fn get_const(&self) -> &Const {
        &self.c
    }

    /// Consumes the given abstract value [av] and returns a new one of the same type,
    /// but with the constant set to [c].
    pub fn new_from(av: AbstrVal, c: Const) -> AbstrVal {
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
type AbstrOp2 = fn(v1: &Const, v2: &Const) -> Const;
type AbstrOp1 = fn(v1: &Const) -> Const;

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct MemOp {
    /// Address of the memory instruction
    addr: Address,
    /// The abstract memory value which is processed.
    aval: AbstrVal,
}

impl MemOp {
    pub fn new(addr: Address, aval: AbstrVal) -> MemOp {
        MemOp { addr, aval }
    }

    pub fn is_heap(&self) -> bool {
        self.aval.is_heap()
    }
}

impl std::fmt::Display for MemOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MemOp: {:#x} -> {}", self.addr, self.aval)
    }
}

pub type MemOpSeq = Vec<MemOp>;

pub struct CallFrame {
    /// The invocation site
    in_site: Address,
    /// The instance count.
    instance: u64,
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
    /// Indirect calls resolved during interpretation
    pub concrete_calls: HashSet<ConcreteCall>,
    pub mem_xrefs: HashSet<MemXref>,
    pub stack_xrefs: HashSet<StackXref>,
    pub mos: MemOpSeq,
}

impl IntrpProducts {
    pub fn new() -> IntrpProducts {
        IntrpProducts {
            concrete_calls: HashSet::new(),
            mem_xrefs: HashSet::new(),
            stack_xrefs: HashSet::new(),
            mos: MemOpSeq::new(),
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
    /// MemStore map
    ms: HashMap<AbstrVal, AbstrVal>,
    /// MemTaint map
    mt: HashMap<AbstrVal, bool>,
    /// RegTaint map. Techincally this stores all global variables.
    rt: HashMap<String, bool>,
    /// Path
    pa: IntrpPath,
    /// Entry point of the currerntly executed procedure.
    proc_entry: Vec<Address>,
    /// Call stack
    cs: CallStack,
    /// The resulting memory operand sequences of the interpretation
    mos: MemOpSeq,
    /// Global variables (mostly registers)
    /// This is equivalent to the RS map described in the paper.
    gvars: HashMap<String, AbstrVal>,
    /// Local pure variables. Defined via LET()
    lpures: HashMap<String, AbstrVal>,
    /// Local variables, defined via SETL
    lvars: HashMap<String, AbstrVal>,
    /// Register roles (SP, PC, LR, ARG 1, ARG 2 etc)
    /// Role to register name nap.
    reg_roles: HashMap<RzRegisterId, String>,
    /// Register sizes in bits, indexed by name
    reg_sizes: HashMap<String, usize>,
    /// Const value jump targets
    calls_xref: HashSet<ConcreteCall>,
    /// Const value memory values loaded or stored.
    mem_xrefs: HashSet<MemXref>,
    /// Stack references
    stack_xrefs: HashSet<StackXref>,
    /// Rizin Core
    rz_core: GRzCore,
    /// Normal distribution
    dist: Normal<f64>,
    /// Maximum number of REPEAT iteraitions, if they are not static
    limit_repeat: usize,
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
    pub fn new(rz_core: GRzCore, pc: PC, path: IntrpPath) -> AbstrVM {
        let limit_repeat = rz_core.lock().unwrap().get_bda_max_iterations() as usize;
        AbstrVM {
            pc,
            is: HashMap::new(),
            ic: HashMap::new(),
            ms: HashMap::new(),
            mt: HashMap::new(),
            rt: HashMap::new(),
            pa: path,
            proc_entry: Vec::new(),
            cs: CallStack::new(),
            mos: MemOpSeq::new(),
            gvars: HashMap::new(),
            lvars: HashMap::new(),
            lpures: HashMap::new(),
            reg_roles: HashMap::new(),
            reg_sizes: HashMap::new(),
            calls_xref: HashSet::new(),
            mem_xrefs: HashSet::new(),
            stack_xrefs: HashSet::new(),
            rz_core,
            dist: Normal::new(0.0, 32768.0_f64.powi(2)).unwrap(),
            limit_repeat,
        }
    }

    pub fn get_limit_repeat(&self) -> usize {
        self.limit_repeat
    }

    pub fn get_rz_core(&self) -> &GRzCore {
        &self.rz_core
    }

    /// Returns true if the instruction at [addr] is calssified as call.
    pub fn is_call(&self, addr: Address) -> bool {
        if let Some(ainfo) = self.pa.addr_info.get(&addr) {
            return ainfo.is_call;
        }
        false
    }

    /// Returns true if the instruction at [addr] is calssified as a call to malloc.
    pub fn calls_malloc(&self, addr: Address) -> bool {
        if let Some(ainfo) = self.pa.addr_info.get(&addr) {
            return ainfo.calls_malloc;
        }
        false
    }

    pub fn calls_input(&self, addr: Address) -> bool {
        if let Some(ainfo) = self.pa.addr_info.get(&addr) {
            return ainfo.calls_input;
        }
        false
    }

    pub fn add_call_xref(&mut self, proc_addr: Address, to: Address) {
        if to == MAX_ADDRESS {
            return;
        }
        self.calls_xref.insert(ConcreteCall {
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
        self.stack_xrefs.insert(StackXref { at: self.pc, var });
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
        av.il_gvar = Some(name.to_string());
        // println!("SET: {} -> {}", name, av);
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
    pub fn rv(&self, width: u64) -> Const {
        if width <= 64 {
            return Const {
                v: (self.dist.sample(&mut rand::thread_rng()) as u64)
                    .to_biguint()
                    .unwrap(),
                width,
            };
        }
        let samples_cnt = width + 7 >> 3;
        let mut v_buf = Vec::<u8>::new();
        for _ in 0..samples_cnt {
            v_buf.push(self.dist.sample(&mut rand::thread_rng()) as u8);
        }
        Const {
            v: BigUint::from_bytes_be(v_buf.as_slice()),
            width,
        }
    }

    /// Samples with a 0.5 chance a true (1) or false (0) value.
    pub fn rvb(&self) -> Const {
        if rand::thread_rng().gen_bool(0.5) {
            Const::get_true()
        } else {
            Const::get_false()
        }
    }

    fn step(&mut self) -> bool {
        if let Some(pc) = self.pa.next() {
            self.pc = pc;
        } else {
            return false;
        }
        println!("pc = {:#x}", self.pc);

        *self.ic.entry(self.pc).or_default() += 1;

        if self.is_return_point() {
            self.call_stack_pop();
        }

        let mut dont_execute = false;
        // Not yet done for iwords. iwords must only skip the call part.
        if self.calls_malloc(self.get_pc()) || self.calls_input(self.get_pc()) {
            dont_execute = true;
        }

        let iword_decoder = unlocked_core!(self).get_iword_decoder();
        let effect;
        let result;
        if iword_decoder.is_some() {
            let iword = unlocked_core!(self).get_iword(self.pc);
            self.is.insert(self.pc, pderef!(iword).size_bytes as u64);
            effect = pderef!(iword).il_op;
            if dont_execute {
                self.call_stack_push(0);
                self.move_heap_val_into_ret_reg();
                result = true;
            } else if effect != std::ptr::null_mut() {
                // Otherwise not implemented
                result = eval_effect(self, effect);
            } else {
                result = true;
            }
            unsafe { rz_analysis_insn_word_free(iword) };
        } else {
            let ana_op = unlocked_core!(self).get_analysis_op(self.pc);
            self.is.insert(self.pc, pderef!(ana_op).size as u64);
            effect = pderef!(ana_op).il_op;
            if dont_execute {
                self.call_stack_push(0);
                self.move_heap_val_into_ret_reg();
                result = true;
            } else if effect != std::ptr::null_mut() {
                // Otherwise not implemented
                result = eval_effect(self, effect);
            } else {
                result = true;
            }
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

        if rz_core.is_poisoned() {
            rz_core.clear_poison();
        }
        let core = rz_core.lock().unwrap();

        // Set the register alias
        let alias = core.get_reg_alias();
        for ralias in alias {
            let ra = pderef!(ralias);
            if let Some(_) = self.reg_roles.insert(ra.role, c_to_str(ra.reg_name)) {
                log_rz!(
                    LOG_WARN,
                    None,
                    format!(
                        "Duplicate role of register {} detected",
                        c_to_str(ra.reg_name)
                    )
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
            log_rz!(LOG_DEBUG, None, format!("\t-> {}", name));

            let init_val = match name == *bp_name
                || name == *sp_name
                || name == sp_name_tmp
                || name == bp_name_tmp
            {
                true => {
                    stack_access_size = rsize;
                    let svar = AbstrVal::new_stack(1, Const::get_zero(rsize as u64), self.get_pc());
                    self.set_taint_flag(&svar, false);
                    svar
                }
                false => {
                    AbstrVal::new_global(1, Const::get_zero(rsize as u64), Some(name.clone()), 0)
                }
            };
            self.reg_sizes.insert(name.clone(), rsize as usize);
            self.gvars.insert(name.clone(), init_val);
            self.rt.insert(name.to_owned(), false);
        }
        self.setup_initial_stack(stack_access_size as u64);
        true
    }

    /// Gives the invocation count for a given instruction address.
    pub fn get_ic(&mut self, iaddr: Address) -> u64 {
        self.ic.entry(iaddr).or_default().clone()
    }

    /// Calculates the result of an operation on one abstract value and the taint flag [^1]
    /// Returns the calculated result as abstract value and the taint flag.
    /// [^1] Figure 2.11 - https://doi.org/10.25394/PGS.23542014.v1
    pub fn calc_value_1(
        &mut self,
        op: AbstrOp1,
        v1: AbstrVal,
        sample_bool: bool,
    ) -> (AbstrVal, bool) {
        let tainted: bool;
        let v3: AbstrVal;
        if v1.m.class == MemRegionClass::Global {
            v3 = AbstrVal::new(v1.m.clone(), op(&v1.c), None);
            tainted = false;
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
            tainted = true;
        }
        (v3, tainted)
    }

    /// Calculates the result of an operation on two abstract values and their taint flags [^1]
    /// Returns the calculated result as abstract value and the taint flag.
    /// It assumes that [v1] and [v2] are of the same bit width and [op] produces a
    /// value of the same bit width.
    /// [^1] Figure 2.11 - https://doi.org/10.25394/PGS.23542014.v1
    pub fn calc_value_2(
        &mut self,
        op: AbstrOp2,
        v1: AbstrVal,
        v2: AbstrVal,
        sample_bool: bool,
    ) -> (AbstrVal, bool) {
        let tainted: bool;
        let v3: AbstrVal;
        if v1.m.class == MemRegionClass::Global {
            v3 = AbstrVal::new(v2.m.clone(), op(&v1.c, &v2.c), None);
            tainted = false;
        } else if v2.m.class == MemRegionClass::Global {
            v3 = AbstrVal::new(v1.m.clone(), op(&v1.c, &v2.c), None);
            tainted = false;
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
            if v.c.v() < BigInt::ZERO {
                break;
            }
            v.m = vt.sp.m.clone();
            let r = v.c.v() + vt.sp.c.v();
            v.c.seti(r);
        }
        v
    }

    pub fn get_taint_flag(&mut self, v: &AbstrVal) -> bool {
        if v.il_gvar.is_some() {
            if let Some(t) = self.rt.get(v.il_gvar.as_ref().unwrap()) {
                return *t;
            } else {
                panic!("Has no taint flag set for abstr. global {}", v)
            }
        }
        if v.is_global() {
            return false;
        }
        if let Some(t) = self.mt.get(v) {
            *t
        } else {
            panic!("Has no taint flag set for abstr. memory value {}", v)
        }
    }

    pub fn set_taint_flag(&mut self, v3: &AbstrVal, tainted: bool) {
        if let Some(il_gvar) = v3.il_gvar.clone() {
            if let Some(_) = self.gvars.get(&il_gvar) {
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

    /// Reads a memory value. It first attempts to read an abstract value from the
    /// MS map. If this fails it panics for Heap and Stack values. But attempts to read [n_bytes]
    /// from the memory mapped in Rizins IO.
    /// If [n_bytes] == 0, it panics as well.
    /// Returns the new Abstract value and if it was sampled.
    pub fn get_mem_val(&mut self, key: &AbstrVal, n_bytes: usize) -> (AbstrVal, bool) {
        if let Some(v) = self.ms.get(key) {
            // println!("LOAD: AT: {} -> {}", key, v);
            return (v.clone(), false);
        }
        if n_bytes == 0 {
            panic!("Cannot read 0 bytes for: {}", key);
        }
        let mut is_sampled = false;
        if !key.is_global() {
            is_sampled = true;
        }
        let gmem_val = Const::new_u64(
            self.read_io_at_u64(key.get_as_addr(), n_bytes),
            (n_bytes * 8) as u64,
        );
        (
            AbstrVal::new_global(self.get_pc_ic(), gmem_val, None, self.get_pc()),
            is_sampled,
        )
    }

    pub fn set_mem_val(&mut self, key: &AbstrVal, val: AbstrVal) {
        // println!("STORE: AT {} => {} ", key, val);
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

    pub fn set_reg_val(&mut self, key: &AbstrVal, val: AbstrVal) {
        self.ms.insert(key.clone(), val);
    }

    pub fn enqueue_mos(&mut self, v: &AbstrVal) {
        self.mos.push(MemOp {
            addr: self.get_pc(),
            aval: v.clone(),
        });
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
        // For now we just assume that the SP was _not_ updated before the actual jump to the procedure.
        let cf = CallFrame {
            in_site: self.pc,
            instance: *self.ic.get(&self.pc).expect("Should have been set before."),
            return_addr: self.pc + self.is.get(&self.pc).expect("Should have been set before."),
            sp: self.get_sp(),
        };
        self.rebase_sp(proc_addr);
        println!("PUSH: {}", cf);
        // self.skip_cs_pop.push(false);
        self.proc_entry.push(proc_addr);
        println!("{:?}", self.proc_entry);
        self.cs.push(cf);
    }

    /// Pops a call frame from the call stack.
    pub fn call_stack_pop(&mut self) -> Option<CallFrame> {
        let cf = self.cs.pop();
        println!("POP: {}", cf.as_ref().unwrap());
        self.proc_entry.pop();
        println!("{:?}", self.proc_entry);
        self.set_sp(cf.as_ref().unwrap().sp.clone());
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
        self.pa.addr_info.get(&self.pc).is_some_and(|i| i.is_call)
    }

    pub(crate) fn peak_next(&self) -> Option<&Address> {
        self.pa.peak_next()
    }

    fn is_return_point(&self) -> bool {
        self.pa
            .addr_info
            .get(&self.pc)
            .is_some_and(|i| i.is_return_point)
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
        self.set_sp(AbstrVal::new_stack(
            ic,
            Const::get_zero(sp.get_width()),
            base,
        ));
    }

    /// Initializes the stack for the first two cells of size [stack_cell_size].
    fn setup_initial_stack(&mut self, stack_cell_size: u64) {
        let zero = Const::get_zero(stack_cell_size);
        // Save dummy values where first stack pointers point to
        self.set_mem_val(
            &AbstrVal::new_stack(1, zero.clone(), self.get_pc()),
            AbstrVal::new_global(1, zero.clone(), None, 0),
        );
        // Push initial stack frame
        let cf = CallFrame {
            in_site: self.pc,
            instance: 0,
            return_addr: MAX_ADDRESS,
            sp: self.get_sp(),
        };
        println!("PUSH: {}", cf);
        // self.skip_cs_pop.push(false);
        self.proc_entry.push(self.pc);
        println!("{:?}", self.proc_entry);
        self.cs.push(cf);
    }

    /// Sets the register which takes return values, to a new Heap abstract value.
    /// This function is usually called after a memory allocating call.
    pub fn move_heap_val_into_ret_reg(&mut self) {
        let rr_name = self.get_reg_name_by_role(RzRegisterId_RZ_REG_NAME_R0);
        let rr_size = self.get_reg_size(&rr_name);
        let hval = AbstrVal::new_heap(
            self.get_ic(self.get_pc()),
            Const::get_zero(rr_size as u64),
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

    pub fn get_pc_ic(&mut self) -> u64 {
        self.get_ic(self.get_pc())
    }

    pub fn get_cur_entry(&self) -> u64 {
        return *self.proc_entry.last().expect("No entry in list");
    }
}

/// Interprets the given path with the given interpreter VM.
pub fn interpret(rz_core: GRzCore, path: IntrpPath, tx: Sender<IntrpProducts>) {
    let mut vm = AbstrVM::new(rz_core, path.get(0), path);
    if !vm.init_register_file(vm.get_rz_core().clone()) {
        return;
    }

    while vm.step() {}

    println!("EXIT\n");
    // Replace with Channel and send/rcv
    let products = IntrpProducts {
        concrete_calls: vm.calls_xref.into(),
        mem_xrefs: vm.mem_xrefs.into(),
        stack_xrefs: vm.stack_xrefs.into(),
        mos: vm.mos.into(),
    };

    if let Err(_) = tx.send(products) {
        log_rz!(
            LOG_ERROR,
            None,
            "Interpreter could not send data. Main thread hangs"
        );
    }
}
