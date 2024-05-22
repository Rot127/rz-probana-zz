// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use core::panic;
use std::{
    env,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex},
};

#[macro_export]
macro_rules! log_rz {
    ($level:ident, $tag:expr, $msg:expr) => {
        log_rizin($level, $tag, $msg, line!(), file!().to_string())
    };
}

#[macro_export]
macro_rules! null_check {
    ( $($ptr:expr),* ) => {
        $(
            assert_ne!($ptr, std::ptr::null_mut(), "{:?} is NULL", $ptr);
        )*
    };
}

#[macro_export]
macro_rules! pderef {
    ($ptr:expr) => {{
        assert_ne!($ptr, std::ptr::null_mut(), "{:?} is NULL", $ptr);
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
pub fn log_rizin(
    level: rz_log_level,
    tag: Option<String>,
    mut msg: String,
    line: u32,
    mut filename: String,
) {
    msg.push('\n');
    msg.push('\0');
    filename.push('\0');
    unsafe {
        rz_log_str(
            "\0".as_ptr().cast(),
            filename.as_str().as_ptr().cast(),
            line,
            level,
            match tag {
                Some(mut t) => {
                    t.push('\0');
                    t.as_str().as_ptr().cast()
                }
                None => std::ptr::null_mut(),
            },
            msg.as_str().as_ptr().cast(),
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

    pub fn get_iword(&self, addr: u64) -> *mut RzAnalysisInsnWord {
        let iword_decoder = self.get_iword_decoder();
        unsafe {
            let leading_bytes = if addr < 8 { addr } else { 8 };
            let iword = rz_analysis_insn_word_new();
            let buf_len = 64;
            let mut buf = Vec::<u8>::with_capacity(buf_len);
            if !rz_io_read_at_mapped(
                self.get_io(),
                addr - leading_bytes,
                buf.as_mut_ptr(),
                buf_len,
            ) {
                log_rz!(
                    LOG_ERROR,
                    None,
                    format!("rz_io_read_at_mapped() failed at {}", addr)
                );
                return std::ptr::null_mut();
            }
            let success = iword_decoder.unwrap()(
                self.get_analysis(),
                iword,
                addr,
                buf.as_ptr(),
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
            while unsafe { reg_bindings.offset(count) } != std::ptr::null_mut() {
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

pub fn init_rizin_instance(binary: &str) -> *mut RzCore {
    let core: *mut RzCore;
    unsafe {
        println!("init");
        core = rz_core_new();
        if core == std::ptr::null_mut() {
            panic!("Could not init RzCore.");
        }
        println!("Core init");
        let cf: *const RzCoreFile =
            rz_core_file_open(core, binary.as_ptr().cast(), RZ_PERM_R as i32, 0);
        if cf == std::ptr::null_mut() {
            panic!("Could not open file {}", binary);
        }
        println!("Opened file");
        rz_core_bin_load(core, std::ptr::null(), 0);
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

/// Converts a BitVector to an arbitrary sized Integer. It panics in case of failure.
pub fn bv_to_int(bv: *mut RzBitVector) -> i128 {
    null_check!(bv);
    let len = unsafe { rz_bv_len(bv) };
    if len <= 64 {
        return unsafe { rz_bv_to_ut64(bv) } as i128;
    }
    todo!()
}
