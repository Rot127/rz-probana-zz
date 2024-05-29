// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#![allow(unused)]
#![allow(non_upper_case_globals)]

use binding::{
    bv_to_int, c_to_str, log_rizin, log_rz, null_check, pderef, RzILOpEffect, RzILOpEffectCode,
    RzILOpEffectCode_RZ_IL_OP_BLK, RzILOpEffectCode_RZ_IL_OP_BRANCH,
    RzILOpEffectCode_RZ_IL_OP_EFFECT_MAX, RzILOpEffectCode_RZ_IL_OP_EMPTY,
    RzILOpEffectCode_RZ_IL_OP_GOTO, RzILOpEffectCode_RZ_IL_OP_JMP, RzILOpEffectCode_RZ_IL_OP_NOP,
    RzILOpEffectCode_RZ_IL_OP_REPEAT, RzILOpEffectCode_RZ_IL_OP_SEQ, RzILOpEffectCode_RZ_IL_OP_SET,
    RzILOpEffectCode_RZ_IL_OP_STORE, RzILOpEffectCode_RZ_IL_OP_STOREW, RzILOpPure, RzILOpPureCode,
    RzILOpPureCode_RZ_IL_OP_ADD, RzILOpPureCode_RZ_IL_OP_AND, RzILOpPureCode_RZ_IL_OP_APPEND,
    RzILOpPureCode_RZ_IL_OP_B0, RzILOpPureCode_RZ_IL_OP_B1, RzILOpPureCode_RZ_IL_OP_BITV,
    RzILOpPureCode_RZ_IL_OP_CAST, RzILOpPureCode_RZ_IL_OP_DIV, RzILOpPureCode_RZ_IL_OP_EQ,
    RzILOpPureCode_RZ_IL_OP_FABS, RzILOpPureCode_RZ_IL_OP_FADD, RzILOpPureCode_RZ_IL_OP_FBITS,
    RzILOpPureCode_RZ_IL_OP_FCAST_FLOAT, RzILOpPureCode_RZ_IL_OP_FCAST_INT,
    RzILOpPureCode_RZ_IL_OP_FCAST_SFLOAT, RzILOpPureCode_RZ_IL_OP_FCAST_SINT,
    RzILOpPureCode_RZ_IL_OP_FCOMPOUND, RzILOpPureCode_RZ_IL_OP_FCONVERT,
    RzILOpPureCode_RZ_IL_OP_FDIV, RzILOpPureCode_RZ_IL_OP_FHYPOT, RzILOpPureCode_RZ_IL_OP_FLOAT,
    RzILOpPureCode_RZ_IL_OP_FMAD, RzILOpPureCode_RZ_IL_OP_FMOD, RzILOpPureCode_RZ_IL_OP_FMUL,
    RzILOpPureCode_RZ_IL_OP_FNEG, RzILOpPureCode_RZ_IL_OP_FORDER, RzILOpPureCode_RZ_IL_OP_FPOW,
    RzILOpPureCode_RZ_IL_OP_FPOWN, RzILOpPureCode_RZ_IL_OP_FPRED, RzILOpPureCode_RZ_IL_OP_FREQUAL,
    RzILOpPureCode_RZ_IL_OP_FROOTN, RzILOpPureCode_RZ_IL_OP_FROUND, RzILOpPureCode_RZ_IL_OP_FRSQRT,
    RzILOpPureCode_RZ_IL_OP_FSQRT, RzILOpPureCode_RZ_IL_OP_FSUB, RzILOpPureCode_RZ_IL_OP_FSUCC,
    RzILOpPureCode_RZ_IL_OP_INV, RzILOpPureCode_RZ_IL_OP_IS_FINITE,
    RzILOpPureCode_RZ_IL_OP_IS_FNEG, RzILOpPureCode_RZ_IL_OP_IS_FPOS,
    RzILOpPureCode_RZ_IL_OP_IS_FZERO, RzILOpPureCode_RZ_IL_OP_IS_INF,
    RzILOpPureCode_RZ_IL_OP_IS_NAN, RzILOpPureCode_RZ_IL_OP_IS_ZERO, RzILOpPureCode_RZ_IL_OP_ITE,
    RzILOpPureCode_RZ_IL_OP_LET, RzILOpPureCode_RZ_IL_OP_LOAD, RzILOpPureCode_RZ_IL_OP_LOADW,
    RzILOpPureCode_RZ_IL_OP_LOGAND, RzILOpPureCode_RZ_IL_OP_LOGNOT, RzILOpPureCode_RZ_IL_OP_LOGOR,
    RzILOpPureCode_RZ_IL_OP_LOGXOR, RzILOpPureCode_RZ_IL_OP_LSB, RzILOpPureCode_RZ_IL_OP_MOD,
    RzILOpPureCode_RZ_IL_OP_MSB, RzILOpPureCode_RZ_IL_OP_MUL, RzILOpPureCode_RZ_IL_OP_NEG,
    RzILOpPureCode_RZ_IL_OP_OR, RzILOpPureCode_RZ_IL_OP_PURE_MAX, RzILOpPureCode_RZ_IL_OP_SDIV,
    RzILOpPureCode_RZ_IL_OP_SHIFTL, RzILOpPureCode_RZ_IL_OP_SHIFTR, RzILOpPureCode_RZ_IL_OP_SLE,
    RzILOpPureCode_RZ_IL_OP_SMOD, RzILOpPureCode_RZ_IL_OP_SUB, RzILOpPureCode_RZ_IL_OP_ULE,
    RzILOpPureCode_RZ_IL_OP_VAR, RzILOpPureCode_RZ_IL_OP_XOR, RzILTypePure,
    RzILVarKind_RZ_IL_VAR_KIND_GLOBAL, RzILVarKind_RZ_IL_VAR_KIND_LOCAL,
    RzILVarKind_RZ_IL_VAR_KIND_LOCAL_PURE, LOG_ERROR, LOG_WARN,
};

use crate::interpreter::{AbstrVM, AbstrVal, Address, Const};

pub const IL_OP_VAR: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_VAR;
pub const IL_OP_ITE: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_ITE;
pub const IL_OP_LET: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_LET;
pub const IL_OP_B0: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_B0;
pub const IL_OP_B1: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_B1;
pub const IL_OP_INV: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_INV;
pub const IL_OP_AND: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_AND;
pub const IL_OP_OR: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_OR;
pub const IL_OP_XOR: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_XOR;
pub const IL_OP_BITV: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_BITV;
pub const IL_OP_MSB: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_MSB;
pub const IL_OP_LSB: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_LSB;
pub const IL_OP_IS_ZERO: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_IS_ZERO;
pub const IL_OP_NEG: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_NEG;
pub const IL_OP_LOGNOT: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_LOGNOT;
pub const IL_OP_ADD: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_ADD;
pub const IL_OP_SUB: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_SUB;
pub const IL_OP_MUL: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_MUL;
pub const IL_OP_DIV: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_DIV;
pub const IL_OP_SDIV: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_SDIV;
pub const IL_OP_MOD: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_MOD;
pub const IL_OP_SMOD: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_SMOD;
pub const IL_OP_LOGAND: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_LOGAND;
pub const IL_OP_LOGOR: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_LOGOR;
pub const IL_OP_LOGXOR: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_LOGXOR;
pub const IL_OP_SHIFTR: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_SHIFTR;
pub const IL_OP_SHIFTL: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_SHIFTL;
pub const IL_OP_EQ: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_EQ;
pub const IL_OP_SLE: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_SLE;
pub const IL_OP_ULE: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_ULE;
pub const IL_OP_CAST: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_CAST;
pub const IL_OP_APPEND: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_APPEND;
pub const IL_OP_FLOAT: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_FLOAT;
pub const IL_OP_FBITS: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_FBITS;
pub const IL_OP_IS_FINITE: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_IS_FINITE;
pub const IL_OP_IS_NAN: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_IS_NAN;
pub const IL_OP_IS_INF: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_IS_INF;
pub const IL_OP_IS_FZERO: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_IS_FZERO;
pub const IL_OP_IS_FNEG: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_IS_FNEG;
pub const IL_OP_IS_FPOS: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_IS_FPOS;
pub const IL_OP_FNEG: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_FNEG;
pub const IL_OP_FABS: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_FABS;
pub const IL_OP_FCAST_INT: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_FCAST_INT;
pub const IL_OP_FCAST_SINT: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_FCAST_SINT;
pub const IL_OP_FCAST_FLOAT: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_FCAST_FLOAT;
pub const IL_OP_FCAST_SFLOAT: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_FCAST_SFLOAT;
pub const IL_OP_FCONVERT: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_FCONVERT;
pub const IL_OP_FREQUAL: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_FREQUAL;
pub const IL_OP_FSUCC: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_FSUCC;
pub const IL_OP_FPRED: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_FPRED;
pub const IL_OP_FORDER: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_FORDER;
pub const IL_OP_FROUND: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_FROUND;
pub const IL_OP_FSQRT: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_FSQRT;
pub const IL_OP_FRSQRT: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_FRSQRT;
pub const IL_OP_FADD: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_FADD;
pub const IL_OP_FSUB: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_FSUB;
pub const IL_OP_FMUL: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_FMUL;
pub const IL_OP_FDIV: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_FDIV;
pub const IL_OP_FMOD: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_FMOD;
pub const IL_OP_FHYPOT: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_FHYPOT;
pub const IL_OP_FPOW: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_FPOW;
pub const IL_OP_FMAD: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_FMAD;
pub const IL_OP_FROOTN: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_FROOTN;
pub const IL_OP_FPOWN: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_FPOWN;
pub const IL_OP_FCOMPOUND: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_FCOMPOUND;
pub const IL_OP_LOAD: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_LOAD;
pub const IL_OP_LOADW: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_LOADW;
pub const IL_OP_PURE_MAX: RzILOpPureCode = RzILOpPureCode_RZ_IL_OP_PURE_MAX;

pub const IL_OP_STORE: RzILOpEffectCode = RzILOpEffectCode_RZ_IL_OP_STORE;
pub const IL_OP_STOREW: RzILOpEffectCode = RzILOpEffectCode_RZ_IL_OP_STOREW;
pub const IL_OP_EMPTY: RzILOpEffectCode = RzILOpEffectCode_RZ_IL_OP_EMPTY;
pub const IL_OP_NOP: RzILOpEffectCode = RzILOpEffectCode_RZ_IL_OP_NOP;
pub const IL_OP_SET: RzILOpEffectCode = RzILOpEffectCode_RZ_IL_OP_SET;
pub const IL_OP_JMP: RzILOpEffectCode = RzILOpEffectCode_RZ_IL_OP_JMP;
pub const IL_OP_GOTO: RzILOpEffectCode = RzILOpEffectCode_RZ_IL_OP_GOTO;
pub const IL_OP_SEQ: RzILOpEffectCode = RzILOpEffectCode_RZ_IL_OP_SEQ;
pub const IL_OP_BLK: RzILOpEffectCode = RzILOpEffectCode_RZ_IL_OP_BLK;
pub const IL_OP_REPEAT: RzILOpEffectCode = RzILOpEffectCode_RZ_IL_OP_REPEAT;
pub const IL_OP_BRANCH: RzILOpEffectCode = RzILOpEffectCode_RZ_IL_OP_BRANCH;

macro_rules! check_pure_validity {
    ($pure:expr, $return:expr) => {
        if $pure.is_none() {
            log_rz!(LOG_ERROR, None, "Pure evaluated failed".to_string());
            return $return;
        }
    };
}

macro_rules! check_effect_success {
    ($effect_res:expr) => {
        if !$effect_res {
            log_rz!(LOG_ERROR, None, "Effect evaluated to 'false'".to_string());
            return false;
        }
    };
}

fn rz_il_handler_bool_false(vm: &mut AbstrVM, _: *mut RzILOpPure) -> Option<AbstrVal> {
    let v = AbstrVal::new_global(0, None);
    vm.set_taint_flag(&v, false);
    Some(v)
}

fn rz_il_handler_bool_true(vm: &mut AbstrVM, _: *mut RzILOpPure) -> Option<AbstrVal> {
    let v = AbstrVal::new_global(1, None);
    vm.set_taint_flag(&v, false);
    Some(v)
}

fn rz_il_handler_bitv(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    let bv = unsafe { pderef!(op).op.bitv.value };
    let v = AbstrVal::new_global(bv_to_int(bv), None);
    vm.set_taint_flag(&v, false);
    Some(v)
}

fn rz_il_handler_var(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    match (unsafe { (*op).op.var }.kind) {
        RzILVarKind_RZ_IL_VAR_KIND_GLOBAL => {
            vm.get_varg(unsafe { &c_to_str(pderef!(op).op.var.v) })
        }
        RzILVarKind_RZ_IL_VAR_KIND_LOCAL => vm.get_varl(unsafe { &c_to_str(pderef!(op).op.var.v) }),
        RzILVarKind_RZ_IL_VAR_KIND_LOCAL_PURE => {
            vm.get_lpure(unsafe { &c_to_str(pderef!(op).op.var.v) })
        }
        _ => {
            log_rz!(LOG_ERROR, None, "Unknown var kind".to_owned());
            None
        }
    }
}

fn rz_il_handler_let(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    let let_name = unsafe { &c_to_str((*op).op.let_.name) };
    let let_v = eval_pure(vm, unsafe { (*op).op.let_.exp });
    if let_v.is_none() {
        log_rz!(
            LOG_ERROR,
            None,
            format!("LET '{}' has invalid expression.", let_name)
        );
        return None;
    }
    vm.set_lpure(let_name.to_owned(), let_v.unwrap());
    let result_body = eval_pure(vm, unsafe { (*op).op.let_.body });
    if result_body.is_none() {
        log_rz!(
            LOG_ERROR,
            None,
            format!("LET '{}' has invalid body.", let_name)
        );
    }
    vm.rm_lpure(let_name);
    result_body
}

// Handler for core theory opcodes
fn rz_il_handler_ite(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    let cond = eval_pure(vm, unsafe { (*op).op.ite.condition });
    let x = eval_pure(vm, unsafe { (*op).op.ite.x });
    let y = eval_pure(vm, unsafe { (*op).op.ite.y });
    if cond.is_none() {
        log_rz!(
            LOG_ERROR,
            None,
            "Condition is not a valid Pure.".to_string()
        );
        return None;
    }
    if cond.unwrap().is_global_zero() {
        return y;
    }
    x
}

fn rz_il_handler_msb(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    let v1 = eval_pure(vm, unsafe { (*op).op.msb.bv });
    check_pure_validity!(v1, None);
    // Biased, because we don't know the width of the bitvector, but it is very unlikely 128bit (as our Const here).
    // In cases when MSB is not used with negative values, we sample too often 0.
    let (v3, tainted) = vm.calc_value_1(
        |c1| (if c1.reverse_bits() & 1 == 1 { 1 } else { 0 }),
        v1.unwrap(),
        true,
    );
    vm.set_taint_flag(&v3, tainted);
    Some(v3)
}

fn rz_il_handler_lsb(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    let v1 = eval_pure(vm, unsafe { (*op).op.lsb.bv });
    check_pure_validity!(v1, None);
    let (v3, tainted) = vm.calc_value_1(|c1| (if c1 & 1 == 1 { 1 } else { 0 }), v1.unwrap(), true);
    vm.set_taint_flag(&v3, tainted);
    Some(v3)
}

fn rz_il_handler_is_zero(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    let v1 = eval_pure(vm, unsafe { (*op).op.is_zero.bv });
    check_pure_validity!(v1, None);
    let (v3, tainted) = vm.calc_value_1(|c1| (if *c1 == 0 { 1 } else { 0 }), v1.unwrap(), true);
    vm.set_taint_flag(&v3, tainted);
    Some(v3)
}

fn rz_il_handler_eq(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    let v1 = eval_pure(vm, unsafe { (*op).op.eq.x });
    check_pure_validity!(v1, None);
    let v2 = eval_pure(vm, unsafe { (*op).op.eq.y });
    check_pure_validity!(v2, None);
    let (v3, tainted) = vm.calc_value_2(
        |c1, c2| (if c1 < c2 { 1 } else { 0 }),
        v1.unwrap(),
        v2.unwrap(),
        true,
    );
    vm.set_taint_flag(&v3, tainted);
    Some(v3)
}

fn rz_il_handler_ule(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    let v1 = eval_pure(vm, unsafe { (*op).op.ule.x });
    check_pure_validity!(v1, None);
    let v2 = eval_pure(vm, unsafe { (*op).op.ule.y });
    check_pure_validity!(v2, None);
    let (v3, tainted) = vm.calc_value_2(
        |c1, c2| (if c1 <= c2 { 1 } else { 0 }),
        v1.unwrap(),
        v2.unwrap(),
        true,
    );
    vm.set_taint_flag(&v3, tainted);
    Some(v3)
}

fn rz_il_handler_sle(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    let v1 = eval_pure(vm, unsafe { (*op).op.sle.x });
    check_pure_validity!(v1, None);
    let v2 = eval_pure(vm, unsafe { (*op).op.sle.y });
    check_pure_validity!(v2, None);
    let (v3, tainted) = vm.calc_value_2(
        |c1, c2| (if c1 <= c2 { 1 } else { 0 }),
        v1.unwrap(),
        v2.unwrap(),
        true,
    );
    vm.set_taint_flag(&v3, tainted);
    Some(v3)
}

fn rz_il_handler_bool_and(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    let v1 = eval_pure(vm, unsafe { (*op).op.booland.x });
    check_pure_validity!(v1, None);
    let v2 = eval_pure(vm, unsafe { (*op).op.booland.y });
    check_pure_validity!(v2, None);
    let (v3, tainted) = vm.calc_value_2(
        |c1, c2| (if *c1 != 0 && *c2 != 0 { 1 } else { 0 }),
        v1.unwrap(),
        v2.unwrap(),
        true,
    );
    vm.set_taint_flag(&v3, tainted);
    Some(v3)
}

fn rz_il_handler_bool_or(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    let v1 = eval_pure(vm, unsafe { (*op).op.boolor.x });
    check_pure_validity!(v1, None);
    let v2 = eval_pure(vm, unsafe { (*op).op.boolor.y });
    check_pure_validity!(v2, None);
    let (v3, tainted) = vm.calc_value_2(
        |c1, c2| (if *c1 != 0 || *c2 != 0 { 1 } else { 0 }),
        v1.unwrap(),
        v2.unwrap(),
        true,
    );
    vm.set_taint_flag(&v3, tainted);
    Some(v3)
}

fn rz_il_handler_bool_xor(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    let v1 = eval_pure(vm, unsafe { (*op).op.boolxor.x });
    check_pure_validity!(v1, None);
    let v2 = eval_pure(vm, unsafe { (*op).op.boolxor.y });
    check_pure_validity!(v2, None);
    let (v3, tainted) = vm.calc_value_2(
        |c1, c2| {
            (if ((*c1 == 0) && (*c2 == 0)) || ((*c1 != 0) && (*c2 != 0)) {
                0
            } else {
                1
            })
        },
        v1.unwrap(),
        v2.unwrap(),
        true,
    );
    vm.set_taint_flag(&v3, tainted);
    Some(v3)
}

fn rz_il_handler_bool_inv(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    let v1 = eval_pure(vm, unsafe { (*op).op.boolinv.x });
    check_pure_validity!(v1, None);
    let (v3, tainted) = vm.calc_value_1(|c1| (!c1), v1.unwrap(), true);
    vm.set_taint_flag(&v3, tainted);
    Some(v3)
}

fn rz_il_handler_neg(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    let v1 = eval_pure(vm, unsafe { (*op).op.neg.bv });
    check_pure_validity!(v1, None);
    let (v3, tainted) = vm.calc_value_1(|c1| (-c1), v1.unwrap(), false);
    vm.set_taint_flag(&v3, tainted);
    Some(v3)
}

fn rz_il_handler_logical_not(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    let v1 = eval_pure(vm, unsafe { (*op).op.lognot.bv });
    check_pure_validity!(v1, None);
    let (v3, tainted) = vm.calc_value_1(|c1| (!c1), v1.unwrap(), false);
    vm.set_taint_flag(&v3, tainted);
    Some(v3)
}

fn rz_il_handler_add(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    let v1 = eval_pure(vm, unsafe { (*op).op.add.x });
    check_pure_validity!(v1, None);
    let v2 = eval_pure(vm, unsafe { (*op).op.add.y });
    check_pure_validity!(v2, None);
    let (v3, tainted) = vm.calc_value_2(
        |c1, c2| (c1.overflowing_add(*c2).0),
        v1.unwrap(),
        v2.unwrap(),
        false,
    );
    vm.set_taint_flag(&v3, tainted);
    Some(v3)
}

fn rz_il_handler_sub(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    let v1 = eval_pure(vm, unsafe { (*op).op.sub.x });
    check_pure_validity!(v1, None);
    let v2 = eval_pure(vm, unsafe { (*op).op.sub.y });
    check_pure_validity!(v2, None);
    let (v3, tainted) = vm.calc_value_2(
        |c1, c2| (c1.overflowing_sub(*c2).0),
        v1.unwrap(),
        v2.unwrap(),
        false,
    );
    vm.set_taint_flag(&v3, tainted);
    Some(v3)
}

fn rz_il_handler_mul(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    let v1 = eval_pure(vm, unsafe { (*op).op.mul.x });
    check_pure_validity!(v1, None);
    let v2 = eval_pure(vm, unsafe { (*op).op.mul.y });
    check_pure_validity!(v2, None);
    let (v3, tainted) = vm.calc_value_2(
        |c1, c2| (c1.overflowing_mul(*c2).0),
        v1.unwrap(),
        v2.unwrap(),
        false,
    );
    vm.set_taint_flag(&v3, tainted);
    Some(v3)
}

fn rz_il_handler_div(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    let v1 = eval_pure(vm, unsafe { (*op).op.div.x });
    check_pure_validity!(v1, None);
    let v2 = eval_pure(vm, unsafe { (*op).op.div.y });
    check_pure_validity!(v2, None);
    let (v3, tainted) = vm.calc_value_2(|c1, c2| (c1 / c2), v1.unwrap(), v2.unwrap(), false);
    vm.set_taint_flag(&v3, tainted);
    Some(v3)
}

fn rz_il_handler_sdiv(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    let v1 = eval_pure(vm, unsafe { (*op).op.sdiv.x });
    check_pure_validity!(v1, None);
    let v2 = eval_pure(vm, unsafe { (*op).op.sdiv.y });
    check_pure_validity!(v2, None);
    let (v3, tainted) = vm.calc_value_2(|c1, c2| (c1 / c2), v1.unwrap(), v2.unwrap(), false);
    vm.set_taint_flag(&v3, tainted);
    Some(v3)
}

fn rz_il_handler_mod(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    let v1 = eval_pure(vm, unsafe { (*op).op.mod_.x });
    check_pure_validity!(v1, None);
    let v2 = eval_pure(vm, unsafe { (*op).op.mod_.y });
    check_pure_validity!(v2, None);
    let (v3, tainted) = vm.calc_value_2(|c1, c2| (c1 % c2), v1.unwrap(), v2.unwrap(), false);
    vm.set_taint_flag(&v3, tainted);
    Some(v3)
}

fn rz_il_handler_smod(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    let v1 = eval_pure(vm, unsafe { (*op).op.smod.x });
    check_pure_validity!(v1, None);
    let v2 = eval_pure(vm, unsafe { (*op).op.smod.y });
    check_pure_validity!(v2, None);
    let (v3, tainted) = vm.calc_value_2(|c1, c2| (c1 % c2), v1.unwrap(), v2.unwrap(), false);
    vm.set_taint_flag(&v3, tainted);
    Some(v3)
}

fn rz_il_handler_shiftl(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    let v1 = eval_pure(vm, unsafe { (*op).op.shiftl.x });
    check_pure_validity!(v1, None);
    let v2 = eval_pure(vm, unsafe { (*op).op.shiftl.y });
    check_pure_validity!(v2, None);
    let (v3, tainted) = vm.calc_value_2(
        |c1, c2| (c1.overflowing_shl(*c2 as u32).0),
        v1.unwrap(),
        v2.unwrap(),
        false,
    );
    vm.set_taint_flag(&v3, tainted);
    Some(v3)
}

fn rz_il_handler_shiftr(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    let v1 = eval_pure(vm, unsafe { (*op).op.shiftr.x });
    check_pure_validity!(v1, None);
    let v2 = eval_pure(vm, unsafe { (*op).op.shiftr.y });
    check_pure_validity!(v2, None);
    let (v3, tainted) = vm.calc_value_2(
        |c1, c2| (c1.overflowing_shr(*c2 as u32).0),
        v1.unwrap(),
        v2.unwrap(),
        false,
    );
    vm.set_taint_flag(&v3, tainted);
    Some(v3)
}

fn rz_il_handler_logical_and(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    let v1 = eval_pure(vm, unsafe { (*op).op.logand.x });
    check_pure_validity!(v1, None);
    let v2 = eval_pure(vm, unsafe { (*op).op.logand.y });
    check_pure_validity!(v2, None);
    let (v3, tainted) = vm.calc_value_2(|c1, c2| (c1 & c2), v1.unwrap(), v2.unwrap(), false);
    vm.set_taint_flag(&v3, tainted);
    Some(v3)
}

fn rz_il_handler_logical_or(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    let v1 = eval_pure(vm, unsafe { (*op).op.logor.x });
    check_pure_validity!(v1, None);
    let v2 = eval_pure(vm, unsafe { (*op).op.logor.y });
    check_pure_validity!(v2, None);
    let (v3, tainted) = vm.calc_value_2(|c1, c2| (c1 | c2), v1.unwrap(), v2.unwrap(), false);
    vm.set_taint_flag(&v3, tainted);
    Some(v3)
}

fn rz_il_handler_logical_xor(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    let v1 = eval_pure(vm, unsafe { (*op).op.logxor.x });
    check_pure_validity!(v1, None);
    let v2 = eval_pure(vm, unsafe { (*op).op.logxor.y });
    check_pure_validity!(v2, None);
    let (v3, tainted) = vm.calc_value_2(|c1, c2| (c1 ^ c2), v1.unwrap(), v2.unwrap(), false);
    vm.set_taint_flag(&v3, tainted);
    Some(v3)
}

fn rz_il_handler_cast(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    let v1 = eval_pure(vm, unsafe { (*op).op.cast.val });
    check_pure_validity!(v1, None);
    Some(v1.unwrap().clone())
}

fn rz_il_handler_append(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_append not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_float(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_float not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_fbits(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_fbits not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_is_finite(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_is_finite not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_is_nan(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_is_nan not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_is_inf(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_is_inf not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_is_fzero(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_is_fzero not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_is_fneg(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_is_fneg not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_is_fpos(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_is_fpos not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_fneg(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_fneg not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_fabs(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_fabs not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_fcast_int(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_fcast_int not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_fcast_sint(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_fcast_sint not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_fcast_float(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_fcast_float not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_fcast_sfloat(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_fcast_sfloat not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_fconvert(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_fconvert not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_frequal(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_frequal not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_fsucc(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_fsucc not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_fpred(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_fpred not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_forder(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_forder not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_fround(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_fround not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_fsqrt(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_fsqrt not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_frsqrt(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_frsqrt not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_fadd(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_fadd not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_fsub(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_fsub not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_fdiv(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_fdiv not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_fmul(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_fmul not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_fmod(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_fmod not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_fhypot(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_fhypot not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_fpow(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_fpow not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_fmad(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_fmad not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_frootn(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_frootn not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_fpown(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_fpown not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_fcompound(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_fcompound not yet implemented.".to_string()
    );
    None
}

fn rz_il_handler_load(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    let k = eval_pure(vm, unsafe { (*op).op.load.key });
    check_pure_validity!(k, None);
    let key = k.unwrap();
    let key_t = vm.get_taint_flag(&key);
    let norm_k = vm.normalize_val(key);
    // We assume for now a size of 8 bytes. Just as rz_il_mem_value_len() does.
    let size = 8;
    let v = vm.get_mem_val(&norm_k, size);
    let norm_t = key_t || vm.get_taint_flag(&norm_k);
    vm.set_taint_flag(&norm_k, norm_t);
    vm.enqueue_mos(&v);
    if norm_k.is_global() && !vm.get_taint_flag(&norm_k) {
        vm.add_mem_xref(norm_k.get_offset() as Address, size as u64);
    }
    Some(v)
}

fn rz_il_handler_loadw(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    let k = eval_pure(vm, unsafe { (*op).op.loadw.key });
    let n_bytes = unsafe { (*op).op.loadw.n_bits } / 8;
    check_pure_validity!(k, None);
    let key = k.unwrap();
    let key_t = vm.get_taint_flag(&key);
    let norm_k = vm.normalize_val(key);
    let v = vm.get_mem_val(&norm_k, n_bytes as usize);
    let norm_t = key_t || vm.get_taint_flag(&norm_k);
    vm.set_taint_flag(&norm_k, norm_t);
    vm.enqueue_mos(&v);
    if norm_k.is_global() && !vm.get_taint_flag(&norm_k) {
        vm.add_mem_xref(norm_k.get_offset() as Address, n_bytes as u64);
    }
    Some(v)
}

fn rz_il_handler_pure_unimplemented(vm: &mut AbstrVM, op: *mut RzILOpPure) -> Option<AbstrVal> {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_pure_unimplemented reached.".to_string()
    );
    None
}

fn rz_il_handler_empty(vm: &mut AbstrVM, op: *mut RzILOpEffect) -> bool {
    null_check!(op);
    true
}

fn rz_il_handler_store(vm: &mut AbstrVM, op: *mut RzILOpEffect) -> bool {
    null_check!(op);
    let mut k = eval_pure(vm, unsafe { (*op).op.store.key });
    check_pure_validity!(k, false);
    let key = k.unwrap();
    let value = eval_pure(vm, unsafe { (*op).op.store.value });
    check_pure_validity!(value, false);
    let v = value.unwrap();
    let norm_t = vm.get_taint_flag(&key) || vm.get_taint_flag(&v);
    let norm_k = &vm.normalize_val(key);
    vm.set_mem_val(norm_k, v.clone());
    vm.set_taint_flag(&norm_k, norm_t);
    vm.enqueue_mos(&norm_k);
    if norm_k.is_global() && !vm.get_taint_flag(&norm_k) {
        vm.add_mem_xref(norm_k.get_offset() as Address, 8 as u64);
    }
    true
}

fn rz_il_handler_storew(vm: &mut AbstrVM, op: *mut RzILOpEffect) -> bool {
    null_check!(op);
    let mut k = eval_pure(vm, unsafe { (*op).op.storew.key });
    check_pure_validity!(k, false);
    let key = k.unwrap();
    let value = eval_pure(vm, unsafe { (*op).op.storew.value });
    check_pure_validity!(value, false);
    let v = value.unwrap();
    let norm_t = vm.get_taint_flag(&key) || vm.get_taint_flag(&v);
    let norm_k = &vm.normalize_val(key);
    vm.set_mem_val(norm_k, v.clone());
    vm.set_taint_flag(&norm_k, norm_t);
    vm.enqueue_mos(&norm_k);
    if norm_k.is_global() && !vm.get_taint_flag(&norm_k) {
        vm.add_mem_xref(norm_k.get_offset() as Address, 8 as u64);
    }
    true
}

fn rz_il_handler_nop(vm: &mut AbstrVM, op: *mut RzILOpEffect) -> bool {
    null_check!(op);
    true
}

fn rz_il_handler_set(vm: &mut AbstrVM, op: *mut RzILOpEffect) -> bool {
    null_check!(op);
    let pure = unsafe { (*op).op.set.x };
    let av = eval_pure(vm, pure);
    if av.is_none() {
        log_rz!(LOG_ERROR, None, "Error in pure evalutation.".to_string());
        return false;
    }
    if unsafe { (*op).op.set.is_local } {
        vm.set_varl(unsafe { &c_to_str(pderef!(op).op.set.v) }, av.unwrap());
    } else {
        vm.set_varg(unsafe { &c_to_str(pderef!(op).op.set.v) }, av.unwrap());
    }
    true
}

fn rz_il_handler_jmp(vm: &mut AbstrVM, op: *mut RzILOpEffect) -> bool {
    null_check!(op);
    // Jump is pretty much ignored (because the path was already sampled).
    // So we only check for calls to input and malloc
    // functions.
    if vm.cur_is_call() {
        vm.call_stack_push(
            *vm.peak_next()
                .expect("There whould always be a next instruction after a call"),
        );
    }

    let mut dst = eval_pure(vm, unsafe { (*op).op.jmp.dst });
    check_pure_validity!(dst, false);
    let jdst = &dst.unwrap();
    if !jdst.is_global() {
        return true;
    }
    // There is the possibility that a jump to this address wasn't disovered yet.
    // Log it for later.
    let addr = jdst.get_offset() as Address;
    if vm.get_taint_flag(jdst) {
        // Tainted addresses rely on sampled values and are useless to us.
        return true;
    }
    vm.add_call_xref(addr);
    if vm.is_call(addr) {
        // Push new stack frame.
        vm.call_stack_push(addr);
    }

    true
}

fn rz_il_handler_goto(vm: &mut AbstrVM, op: *mut RzILOpEffect) -> bool {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_goto not yet implemented".to_string()
    );
    false
}

fn rz_il_handler_seq(vm: &mut AbstrVM, op: *mut RzILOpEffect) -> bool {
    null_check!(op);
    let x_success = eval_effect(vm, unsafe { (*op).op.seq.x });
    check_effect_success!(x_success);
    let y_success = eval_effect(vm, unsafe { (*op).op.seq.y });
    check_effect_success!(y_success);
    return x_success && y_success;
}

fn rz_il_handler_blk(vm: &mut AbstrVM, op: *mut RzILOpEffect) -> bool {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_blk not yet implemented".to_string()
    );
    false
}

fn rz_il_handler_repeat(vm: &mut AbstrVM, op: *mut RzILOpEffect) -> bool {
    null_check!(op);
    // We are for now, don't check the condition for a static limit.
    for _ in (0..vm.get_limit_repeat()) {
        let body_success = eval_effect(vm, unsafe { (*op).op.repeat.data_eff });
        check_effect_success!(body_success);
    }
    true
}

fn rz_il_handler_branch(vm: &mut AbstrVM, op: *mut RzILOpEffect) -> bool {
    null_check!(op);
    let cond = eval_pure(vm, unsafe { (*op).op.branch.condition });
    check_pure_validity!(cond, false);
    if cond.unwrap().is_global_zero() {
        return eval_effect(vm, unsafe { (*op).op.branch.false_eff });
    }
    eval_effect(vm, unsafe { (*op).op.branch.true_eff })
}

fn rz_il_handler_effect_unimplemented(vm: &mut AbstrVM, op: *mut RzILOpEffect) -> bool {
    null_check!(op);
    log_rz!(
        LOG_WARN,
        None,
        "rz_il_handler_effect_unimplemented reached".to_string()
    );
    false
}

pub fn eval_pure(vm: &mut AbstrVM, pure: *mut RzILOpPure) -> Option<AbstrVal> {
    match pderef!(pure).code {
        IL_OP_B0 => rz_il_handler_bool_false(vm, pure),
        IL_OP_B1 => rz_il_handler_bool_true(vm, pure),
        IL_OP_BITV => rz_il_handler_bitv(vm, pure),
        IL_OP_VAR => rz_il_handler_var(vm, pure),
        IL_OP_ITE => rz_il_handler_ite(vm, pure),
        IL_OP_LET => rz_il_handler_let(vm, pure),
        IL_OP_INV => rz_il_handler_bool_inv(vm, pure),
        IL_OP_AND => rz_il_handler_bool_and(vm, pure),
        IL_OP_OR => rz_il_handler_bool_or(vm, pure),
        IL_OP_XOR => rz_il_handler_bool_xor(vm, pure),
        IL_OP_MSB => rz_il_handler_msb(vm, pure),
        IL_OP_LSB => rz_il_handler_lsb(vm, pure),
        IL_OP_IS_ZERO => rz_il_handler_is_zero(vm, pure),
        IL_OP_NEG => rz_il_handler_neg(vm, pure),
        IL_OP_LOGNOT => rz_il_handler_logical_not(vm, pure),
        IL_OP_ADD => rz_il_handler_add(vm, pure),
        IL_OP_SUB => rz_il_handler_sub(vm, pure),
        IL_OP_MUL => rz_il_handler_mul(vm, pure),
        IL_OP_DIV => rz_il_handler_div(vm, pure),
        IL_OP_SDIV => rz_il_handler_sdiv(vm, pure),
        IL_OP_MOD => rz_il_handler_mod(vm, pure),
        IL_OP_SMOD => rz_il_handler_smod(vm, pure),
        IL_OP_LOGAND => rz_il_handler_logical_and(vm, pure),
        IL_OP_LOGOR => rz_il_handler_logical_or(vm, pure),
        IL_OP_LOGXOR => rz_il_handler_logical_xor(vm, pure),
        IL_OP_SHIFTR => rz_il_handler_shiftr(vm, pure),
        IL_OP_SHIFTL => rz_il_handler_shiftl(vm, pure),
        IL_OP_EQ => rz_il_handler_eq(vm, pure),
        IL_OP_SLE => rz_il_handler_sle(vm, pure),
        IL_OP_ULE => rz_il_handler_ule(vm, pure),
        IL_OP_CAST => rz_il_handler_cast(vm, pure),
        IL_OP_APPEND => rz_il_handler_append(vm, pure),
        IL_OP_FLOAT => rz_il_handler_float(vm, pure),
        IL_OP_FBITS => rz_il_handler_fbits(vm, pure),
        IL_OP_IS_FINITE => rz_il_handler_is_finite(vm, pure),
        IL_OP_IS_NAN => rz_il_handler_is_nan(vm, pure),
        IL_OP_IS_INF => rz_il_handler_is_inf(vm, pure),
        IL_OP_IS_FZERO => rz_il_handler_is_fzero(vm, pure),
        IL_OP_IS_FNEG => rz_il_handler_is_fneg(vm, pure),
        IL_OP_IS_FPOS => rz_il_handler_is_fpos(vm, pure),
        IL_OP_FNEG => rz_il_handler_fneg(vm, pure),
        IL_OP_FABS => rz_il_handler_fabs(vm, pure),
        IL_OP_FCAST_INT => rz_il_handler_fcast_int(vm, pure),
        IL_OP_FCAST_SINT => rz_il_handler_fcast_sint(vm, pure),
        IL_OP_FCAST_FLOAT => rz_il_handler_fcast_float(vm, pure),
        IL_OP_FCAST_SFLOAT => rz_il_handler_fcast_sfloat(vm, pure),
        IL_OP_FCONVERT => rz_il_handler_fconvert(vm, pure),
        IL_OP_FREQUAL => rz_il_handler_frequal(vm, pure),
        IL_OP_FSUCC => rz_il_handler_fsucc(vm, pure),
        IL_OP_FPRED => rz_il_handler_fpred(vm, pure),
        IL_OP_FORDER => rz_il_handler_forder(vm, pure),
        IL_OP_FROUND => rz_il_handler_fround(vm, pure),
        IL_OP_FSQRT => rz_il_handler_fsqrt(vm, pure),
        IL_OP_FRSQRT => rz_il_handler_frsqrt(vm, pure),
        IL_OP_FADD => rz_il_handler_fadd(vm, pure),
        IL_OP_FSUB => rz_il_handler_fsub(vm, pure),
        IL_OP_FMUL => rz_il_handler_fmul(vm, pure),
        IL_OP_FDIV => rz_il_handler_fdiv(vm, pure),
        IL_OP_FMOD => rz_il_handler_fmod(vm, pure),
        IL_OP_FHYPOT => rz_il_handler_fhypot(vm, pure),
        IL_OP_FPOW => rz_il_handler_fpow(vm, pure),
        IL_OP_FMAD => rz_il_handler_fmad(vm, pure),
        IL_OP_FROOTN => rz_il_handler_frootn(vm, pure),
        IL_OP_FPOWN => rz_il_handler_fpown(vm, pure),
        IL_OP_FCOMPOUND => rz_il_handler_fcompound(vm, pure),
        IL_OP_LOAD => rz_il_handler_load(vm, pure),
        IL_OP_LOADW => rz_il_handler_loadw(vm, pure),
        pt => panic!("Pure type {} not handled.", pt),
    }
}

pub fn eval_effect(vm: &mut AbstrVM, eff: *mut RzILOpEffect) -> bool {
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
