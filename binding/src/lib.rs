// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use helper::rz::{parse_bda_entry_list, parse_bda_range_conf_val, parse_bda_timeout};
use num_bigint::BigUint;
use std::ffi::{CStr, CString};

use core::panic;
use std::{
    env,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex},
};

#[macro_export]
macro_rules! log_rz {
    ($level:ident, $tag:expr, $msg:expr) => {{
        let file = std::ffi::CString::new(file!().to_string()).expect("CString::new() failed");
        let mut m = $msg.to_string();
        m.push('\n');
        let cmsg = std::ffi::CString::new(m).expect("CString::new() failed");
        let t: Option<&str> = $tag;
        let ctag = std::ffi::CString::new(if t == None { "" } else { t.unwrap() })
            .expect("CString::new() failed");
        log_rizin($level, ctag, cmsg, line!(), file);
    }};
}

#[macro_export]
macro_rules! null_check {
    ( $($ptr:expr),* ) => {
        $(
            assert_ne!($ptr, std::ptr::null_mut(), "ptr {:?} == NULL", $ptr);
        )*
    };
}

#[macro_export]
macro_rules! pderef {
    ($ptr:expr) => {{
        assert_ne!($ptr, std::ptr::null_mut(), "{} is NULL", stringify!($ptr));
        unsafe { *$ptr }
    }};
}

#[macro_export]
macro_rules! uderef {
    ($ptr:expr) => {{
        assert_ne!($ptr, std::ptr::null_mut(), "{:?} is NULL", $ptr);
        *$ptr
    }};
}

pub const LOG_DEBUG: u32 = rz_log_level_RZ_LOGLVL_DEBUG;
pub const LOG_VERBOSE: u32 = rz_log_level_RZ_LOGLVL_VERBOSE;
pub const LOG_INFO: u32 = rz_log_level_RZ_LOGLVL_INFO;
pub const LOG_WARN: u32 = rz_log_level_RZ_LOGLVL_WARN;
pub const LOG_ERROR: u32 = rz_log_level_RZ_LOGLVL_ERROR;
pub const LOG_FATAL: u32 = rz_log_level_RZ_LOGLVL_FATAL;

pub fn get_rz_loglevel() -> u32 {
    unsafe { rz_log_get_level() as u32 }
}

/// Write a log message in Rizin style.
pub fn log_rizin(level: rz_log_level, tag: CString, msg: CString, line: u32, filename: CString) {
    unsafe {
        rz_log_str(
            std::ptr::null_mut(),
            filename.as_ptr(),
            line,
            level,
            if tag.is_empty() {
                std::ptr::null_mut()
            } else {
                tag.as_ptr()
            },
            msg.as_ptr(),
        );
    }
}

// We redefine this struct and don't use the auto-generated one.
// Because the .data member is otherwise defined a mutable.
// This is a problem, because we can define the RzAnalysisPlugin struct only
// as const. And hence the assignment fails.
#[doc = " \\brief Represent the content of a plugin\n\n This structure should be pointed by the 'rizin_plugin' symbol found in the\n loaded library (e.g. .so file)."]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rz_lib_struct_t {
    #[doc = "< type of the plugin to load"]
    pub type_: RzLibType,
    #[doc = "< pointer to data handled by plugin handler (e.g. RzBinPlugin, RzAsmPlugin, etc.)"]
    pub data: *const ::std::os::raw::c_void,
    #[doc = "< rizin version this plugin was compiled for"]
    pub version: *const ::std::os::raw::c_char,
    pub free: ::std::option::Option<unsafe extern "C" fn(data: *mut ::std::os::raw::c_void)>,
    pub is_plugin_owned: bool,
}

pub type RzLibStruct = rz_lib_struct_t;

pub fn mpvec_to_vec<T>(pvec: *mut RzPVector) -> Vec<*mut T> {
    let mut vec: Vec<*mut T> = Vec::new();
    if pvec == std::ptr::null_mut() {
        println!("PVector pointer is null.");
        return vec;
    }

    let len = pderef!(pvec).v.len;
    if len <= 0 {
        return vec;
    }
    vec.reserve(len as usize);
    let data_arr: &mut [*mut T] =
        unsafe { std::slice::from_raw_parts_mut(uderef!(pvec).v.a as *mut *mut T, len as usize) };
    for i in 0..len {
        vec.push(data_arr[i]);
    }
    assert_eq!(len, vec.len());
    vec
}

pub fn cpvec_to_vec<T>(pvec: *const RzPVector) -> Vec<*mut T> {
    let mut vec: Vec<*mut T> = Vec::new();
    if pvec == std::ptr::null_mut() {
        println!("PVector pointer is null.");
        return vec;
    }

    let len = pderef!(pvec).v.len;
    if len <= 0 {
        return vec;
    }
    vec.reserve(len as usize);
    let data_arr: &mut [*mut T] =
        unsafe { std::slice::from_raw_parts_mut(uderef!(pvec).v.a as *mut *mut T, len as usize) };
    for i in 0..len {
        vec.push(data_arr[i]);
    }
    assert_eq!(len, vec.len());
    vec
}

pub fn list_to_vec<T>(
    list: *mut RzList,
    elem_conv: fn(*mut ::std::os::raw::c_void) -> T,
) -> Vec<T> {
    let mut vec: Vec<T> = Vec::new();
    if list == std::ptr::null_mut() {
        println!("List pointer is null.");
        return vec;
    }
    let len = pderef!(list).length;
    vec.reserve(len as usize);
    let mut iter: *mut RzListIter = pderef!(list).head;
    if iter == std::ptr::null_mut() {
        assert_eq!(len, vec.len() as u32);
        return vec;
    }
    loop {
        vec.push(elem_conv(pderef!(iter).elem));
        if unsafe { *iter }.next == std::ptr::null_mut() {
            break;
        }
        iter = pderef!(iter).next;
    }
    assert_eq!(len, vec.len() as u32);
    vec
}

pub fn c_to_str(c_str: *const i8) -> String {
    let cstr = unsafe { CStr::from_ptr(c_str) };
    String::from_utf8_lossy(cstr.to_bytes()).to_string()
}

#[macro_export]
macro_rules! str_to_c {
    ($str:expr) => {
        CString::new($str).expect("Conversion failed.").as_ptr()
    };
}

/// Wrapper struct around a *mut rz_core_t
/// Clone and Copy should definitely not be implemented for this struct.
pub struct RzCoreWrapper {
    pub ptr: *mut rz_core_t,
}

/// Guraded RzCore
pub type GRzCore = Arc<Mutex<RzCoreWrapper>>;

impl RzCoreWrapper {
    pub fn new(core: *mut rz_core_t) -> GRzCore {
        Arc::new(Mutex::new(RzCoreWrapper { ptr: core }))
    }

    pub fn set_conf_val(&self, key: &str, val: &str) {
        let k = CString::new(key).expect("Conversion failed.");
        let v = CString::new(val).expect("Conversion failed.");
        unsafe { rz_config_set(uderef!(self.ptr).config, k.as_ptr(), v.as_ptr()) };
    }

    pub fn get_bda_analysis_range(&self) -> Option<Vec<(u64, u64)>> {
        let n = CString::new("plugins.bda.range").expect("Conversion failed.");
        let c = unsafe { rz_config_get(uderef!(self.ptr).config, n.as_ptr()) };
        parse_bda_range_conf_val(c_to_str(c))
    }

    pub fn get_bda_analysis_entries(&self) -> Option<Vec<u64>> {
        let n = CString::new("plugins.bda.entries").expect("Conversion failed.");
        let c = unsafe { rz_config_get(uderef!(self.ptr).config, n.as_ptr()) };
        parse_bda_entry_list(c_to_str(c))
    }

    pub fn get_bda_skip_questions(&self) -> bool {
        let n = CString::new("plugins.bda.skip_questions").expect("Conversion failed.");
        let c = unsafe { rz_config_get_b(uderef!(self.ptr).config, n.as_ptr()) };
        c
    }

    pub fn get_bda_runtime(&self) -> Option<u64> {
        let n = CString::new("plugins.bda.timeout").expect("Conversion failed.");
        let c = unsafe { rz_config_get(uderef!(self.ptr).config, n.as_ptr()) };
        parse_bda_timeout(c_to_str(c))
    }

    pub fn get_bda_max_iterations(&self) -> u64 {
        let n = CString::new("plugins.bda.repeat_iterations").expect("Conversion failed.");
        let c = unsafe { rz_config_get_i(uderef!(self.ptr).config, n.as_ptr()) };
        c
    }

    pub fn get_bda_node_duplicates(&self) -> usize {
        let n = CString::new("plugins.bda.node_duplicates").expect("Conversion failed.");
        let c = unsafe { rz_config_get_i(uderef!(self.ptr).config, n.as_ptr()) };
        c as usize
    }

    pub fn get_analysis_op(&self, addr: u64) -> *mut RzAnalysisOp {
        let iop: *mut RzAnalysisOp = unsafe {
            rz_core_analysis_op(
                self.ptr,
                addr,
                RzAnalysisOpMask_RZ_ANALYSIS_OP_MASK_IL as i32,
            )
        };
        iop
    }

    pub fn read_io_at(&self, addr: u64, len: usize) -> Vec<u8> {
        let mut buf = Vec::<u8>::with_capacity(len);
        unsafe {
            if rz_io_nread_at(self.get_io(), addr, buf.as_mut_ptr(), len) < 0 {
                panic!("rz_io_nread_at() failed reading at address: {:#x}", addr);
            }
            buf.set_len(len);
        }
        buf
    }

    pub fn read_io_mapped_at(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        let mut buf = Vec::<u8>::with_capacity(len);
        unsafe {
            if !rz_io_read_at_mapped(self.get_io(), addr, buf.as_mut_ptr(), len) {
                println!(
                    "rz_io_read_at_mapped() failed reading at address: {:#x}",
                    addr
                );
                return None;
            }
            buf.set_len(len);
        }
        Some(buf)
    }

    pub fn get_iword(&self, addr: u64) -> *mut RzAnalysisInsnWord {
        let iword_decoder = self.get_iword_decoder();
        unsafe {
            let leading_bytes = if addr < 4 { addr } else { 4 };
            let iword = rz_analysis_insn_word_new();
            let mut buf_len = 32;
            let mut buf: Option<Vec<u8>> = None;
            while buf.is_none() {
                if buf_len < 4 {
                    panic!("Could not read the minimum of the required memory to reliably decode an instruction.");
                }
                buf = self.read_io_mapped_at(addr - leading_bytes, buf_len);
                if buf.is_some() {
                    break;
                }
                // The read goes beyond a mapped region. Hence we read until we are in the maped region.
                buf_len -= 4;
            }
            let success = iword_decoder.unwrap()(
                self.get_analysis(),
                iword,
                addr,
                buf.unwrap().as_ptr(),
                buf_len,
                leading_bytes as usize,
            );
            if !success {
                log_rz!(LOG_ERROR, None, "decode_iword failed".to_string());
                return std::ptr::null_mut();
            }

            iword
        }
    }

    pub fn get_io(&self) -> *mut rz_io_t {
        pderef!(self.ptr).io
    }

    pub fn get_analysis(&self) -> *mut rz_analysis_t {
        pderef!(self.ptr).analysis
    }

    pub fn get_rz_cfg(&self, address: u64) -> *mut RzGraph {
        let is_iword_arch = pderef!(self.get_cur()).decode_iword.is_some();
        if is_iword_arch {
            unsafe { rz_core_graph_cfg_iwords(self.ptr, address) }
        } else {
            unsafe { rz_core_graph_cfg(self.ptr, address) }
        }
    }

    pub fn get_cur(&self) -> *mut rz_analysis_plugin_t {
        pderef!(self.get_analysis()).cur
    }

    pub fn get_iword_decoder(
        &self,
    ) -> Option<
        unsafe extern "C" fn(
            *mut rz_analysis_t,
            *mut RzAnalysisInsnWord,
            u64,
            *const u8,
            usize,
            usize,
        ) -> bool,
    > {
        pderef!(self.get_cur()).decode_iword
    }

    pub fn get_reg_alias(&self) -> Vec<*mut RzRegProfileAlias> {
        unsafe {
            list_to_vec::<*mut RzRegProfileAlias>(
                uderef!(uderef!(self.get_analysis()).reg).reg_profile.alias,
                |e| e as *mut RzRegProfileAlias,
            )
        }
    }

    pub fn get_reg_bindings(&self) -> Option<*mut RzILRegBinding> {
        let reg: *mut RzReg = unsafe { rz_reg_new() };
        if reg == std::ptr::null_mut() {
            return None;
        }
        let cur = self.get_cur();
        let get_reg_profile = pderef!(cur)
            .get_reg_profile
            .expect("get_reg_profile not set");
        let profile = unsafe { get_reg_profile(self.get_analysis()) };
        if profile == std::ptr::null_mut() {
            return None;
        }
        let succ = unsafe { rz_reg_set_profile_string(reg, profile) };
        unsafe {
            free(profile.cast());
        }
        if !succ {
            return None;
        }
        let il_config = pderef!(self.get_cur())
            .il_config
            .expect("il_config not set.");
        let cfg = unsafe { il_config(self.get_analysis()) };
        if pderef!(cfg).reg_bindings != std::ptr::null_mut() {
            let mut count = 0;
            let reg_bindings = pderef!(cfg).reg_bindings;
            while unsafe { *reg_bindings.offset(count) } != std::ptr::null_mut() {
                count += 1;
            }
            return Some(unsafe { rz_il_reg_binding_exactly(reg, count as usize, reg_bindings) });
        }
        Some(unsafe { rz_il_reg_binding_derive(reg) })
    }
}

/// This allows us to pass the *mut GRzCore between threads.
/// This is inherintly unsafe. So rz_core should never be used without Mutex.
unsafe impl Send for RzCoreWrapper {}

pub fn get_rz_test_bin_path() -> PathBuf {
    let rz_repo: String = match env::var("RZ_REPO_PATH") {
        Ok(v) => v,
        Err(_e) => {
            println!("RZ_REPO_PATH must be set to Rizins repo path.");
            std::process::exit(1)
        }
    };
    let path = PathBuf::from_str(rz_repo.as_str());
    match path {
        Ok(p) => p.join("test/bins/"),
        Err(_p) => panic!("Could not build path to test bins"),
    }
}

pub fn get_test_bin_path() -> PathBuf {
    get_pkg_path().join("test_bins")
}

pub fn get_probana_lib() -> PathBuf {
    get_pkg_path()
        .parent()
        .unwrap()
        .join("target/lib_out/debug/libprobana_zz.so")
}

pub fn get_pkg_path() -> PathBuf {
    let repo_dir: String = match env::var("CARGO_MANIFEST_DIR") {
        Ok(v) => v,
        Err(_e) => {
            println!("CARGO_MANIFEST_DIR must be set.");
            std::process::exit(1)
        }
    };
    let path = PathBuf::from_str(repo_dir.as_str());
    match path {
        Ok(p) => p,
        Err(_p) => panic!("Could not build path to test bins"),
    }
}

pub fn init_rizin_instance(binary: &str) -> *mut RzCore {
    let core: *mut RzCore;
    unsafe {
        println!("Core init");
        core = rz_core_new();
        if core == std::ptr::null_mut() {
            panic!("Could not init RzCore.");
        }
        println!("Open file");
        let b_path = CString::new(binary).unwrap();
        if !rz_core_file_open_load(core, b_path.as_ptr(), 0, RZ_PERM_R as i32, false) {
            panic!("Could not open file {}", binary);
        }

        println!("Open plugin");
        let lib_path = CString::new(
            get_probana_lib()
                .as_os_str()
                .to_str()
                .expect("Path creation failure."),
        )
        .expect("CString failure");
        rz_lib_open((*core).lib, lib_path.as_ptr());
        println!("Run aaa");
        rz_core_perform_auto_analysis(core, RzCoreAnalysisType_RZ_CORE_ANALYSIS_DEEP);
    };
    core
}

pub fn rz_notify_begin(rz_core: GRzCore, mut msg: String) {
    msg.push('\0');
    let core = rz_core.lock().unwrap();
    unsafe { rz_core_notify_begin_str(core.ptr, msg.as_ptr().cast()) };
}

pub fn rz_notify_done(rz_core: GRzCore, mut msg: String) {
    msg.push('\0');
    let core = rz_core.lock().unwrap();
    unsafe { rz_core_notify_done_str(core.ptr, msg.as_ptr().cast()) };
}

pub fn rz_notify_error(rz_core: GRzCore, mut msg: String) {
    msg.push('\0');
    let core = rz_core.lock().unwrap();
    unsafe { rz_core_notify_error_str(core.ptr, msg.as_ptr().cast()) };
}

/// Converts a BitVector to an arbitrary sized BigInt.
/// It returns the big integer and the lenght in bits.
pub fn bv_to_int(bv: *mut RzBitVector) -> (BigUint, u64) {
    null_check!(bv);
    let bits: u32 = unsafe { rz_bv_len(bv) };
    let buf_size = ((bits + 7) >> 3) as usize;
    let mut buf = Vec::<u8>::with_capacity(buf_size);
    unsafe {
        rz_bv_set_to_bytes_le(bv, buf.as_mut_ptr());
        buf.set_len(buf_size);
    }
    let n = BigUint::from_bytes_le(buf.as_slice());
    (n, bits as u64)
}
