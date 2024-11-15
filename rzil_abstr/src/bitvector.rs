// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

use std::{
    fmt::LowerHex,
    hash::Hash,
    ops::{Add, AddAssign, BitAnd, BitOr, BitXor, Div, Mul, Neg, Not, Shl, Shr, Sub},
};

use binding::{
    bitvector_t, c_to_str, pderef, rz_bv_add, rz_bv_and, rz_bv_as_hex_string, rz_bv_cast,
    rz_bv_complement_1, rz_bv_complement_2, rz_bv_div, rz_bv_dup, rz_bv_eq, rz_bv_free, rz_bv_hash,
    rz_bv_is_zero_vector, rz_bv_lsb, rz_bv_lshift, rz_bv_mod, rz_bv_msb, rz_bv_mul, rz_bv_new,
    rz_bv_new_from_bytes_be, rz_bv_new_from_st64, rz_bv_new_from_ut64, rz_bv_or, rz_bv_rshift,
    rz_bv_sdiv, rz_bv_set_all, rz_bv_set_range, rz_bv_sle, rz_bv_smod, rz_bv_sub, rz_bv_to_ut16,
    rz_bv_to_ut32, rz_bv_to_ut64, rz_bv_to_ut8, rz_bv_ule, rz_bv_xor,
};
use helper::num::subscript;

#[derive(Debug)]
pub struct BitVector {
    bv: Option<*mut bitvector_t>,
}

impl Drop for BitVector {
    fn drop(&mut self) {
        if let Some(ptr) = self.bv {
            Self::free_ptr(ptr);
        }
    }
}

impl Hash for BitVector {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(unsafe { &rz_bv_hash(self.bv.unwrap()).to_be_bytes() });
    }
}

/// The pointers are not save to send and sync. But the ownership logic is simple enough.
/// The alternative is to use a package like rug for the numbers.
/// But it misses some essential operations for the bitvectors (e.g. signed mod).
unsafe impl Send for BitVector {}
unsafe impl Sync for BitVector {}

impl LowerHex for BitVector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.as_str(), subscript(self.width()))
    }
}

impl Clone for BitVector {
    fn clone(&self) -> Self {
        BitVector {
            bv: Some(unsafe { rz_bv_dup(self.bv.unwrap()) }),
        }
    }
}

impl Ord for BitVector {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let a = self.as_u64();
        let b = other.as_u64();
        if a < b {
            return std::cmp::Ordering::Less;
        } else if a > b {
            return std::cmp::Ordering::Greater;
        }
        return std::cmp::Ordering::Equal;
    }
}

impl PartialOrd for BitVector {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for BitVector {}
impl PartialEq for BitVector {
    fn eq(&self, other: &Self) -> bool {
        unsafe { rz_bv_eq(self.bv.unwrap(), other.bv.unwrap()) }
    }
}

impl PartialEq<i8> for BitVector {
    fn eq(&self, other: &i8) -> bool {
        &self.as_i8() == other
    }
}

impl PartialEq<i16> for BitVector {
    fn eq(&self, other: &i16) -> bool {
        &self.as_i16() == other
    }
}

impl PartialEq<i32> for BitVector {
    fn eq(&self, other: &i32) -> bool {
        &self.as_i32() == other
    }
}

impl PartialEq<i64> for BitVector {
    fn eq(&self, other: &i64) -> bool {
        &self.as_i64() == other
    }
}

impl PartialEq<u8> for BitVector {
    fn eq(&self, other: &u8) -> bool {
        &self.as_u8() == other
    }
}

impl PartialEq<u16> for BitVector {
    fn eq(&self, other: &u16) -> bool {
        &self.as_u16() == other
    }
}

impl PartialEq<u32> for BitVector {
    fn eq(&self, other: &u32) -> bool {
        &self.as_u32() == other
    }
}

impl PartialEq<u64> for BitVector {
    fn eq(&self, other: &u64) -> bool {
        &self.as_u64() == other
    }
}

impl Add for &BitVector {
    type Output = BitVector;

    fn add(self, rhs: Self) -> Self::Output {
        BitVector::new_from_raw_bv(unsafe {
            rz_bv_add(self.bv.unwrap(), rhs.bv.unwrap(), std::ptr::null_mut())
        })
    }
}

impl AddAssign<&BitVector> for BitVector {
    fn add_assign(&mut self, rhs: &BitVector) {
        let bv = self.take();
        let sum = unsafe { rz_bv_add(bv, rhs.bv.unwrap(), std::ptr::null_mut()) };
        Self::free_ptr(bv);
        let _ = self.bv.insert(sum);
    }
}

impl Sub for &BitVector {
    type Output = BitVector;

    fn sub(self, rhs: Self) -> Self::Output {
        BitVector::new_from_raw_bv(unsafe {
            rz_bv_sub(self.bv.unwrap(), rhs.bv.unwrap(), std::ptr::null_mut())
        })
    }
}

impl Mul for &BitVector {
    type Output = BitVector;

    fn mul(self, rhs: Self) -> Self::Output {
        BitVector::new_from_raw_bv(unsafe { rz_bv_mul(self.bv.unwrap(), rhs.bv.unwrap()) })
    }
}

impl Div for &BitVector {
    type Output = BitVector;

    fn div(self, rhs: Self) -> Self::Output {
        BitVector::new_from_raw_bv(unsafe { rz_bv_div(self.bv.unwrap(), rhs.bv.unwrap()) })
    }
}

impl Shl for &BitVector {
    type Output = BitVector;

    fn shl(self, rhs: Self) -> Self::Output {
        let shifted = self.clone();
        unsafe { rz_bv_lshift(shifted.bv.unwrap(), rhs.as_u32()) };
        shifted
    }
}

impl Shl<u32> for &BitVector {
    type Output = BitVector;

    fn shl(self, rhs: u32) -> Self::Output {
        let shifted = self.clone();
        unsafe { rz_bv_lshift(shifted.bv.unwrap(), rhs) };
        shifted
    }
}

impl Shr for &BitVector {
    type Output = BitVector;

    fn shr(self, rhs: Self) -> Self::Output {
        let shifted = self.clone();
        unsafe { rz_bv_rshift(shifted.bv.unwrap(), rhs.as_u32()) };
        shifted
    }
}

impl BitXor for &BitVector {
    type Output = BitVector;

    fn bitxor(self, rhs: Self) -> Self::Output {
        BitVector::new_from_raw_bv(unsafe { rz_bv_xor(self.bv.unwrap(), rhs.bv.unwrap()) })
    }
}

impl BitOr for &BitVector {
    type Output = BitVector;

    fn bitor(self, rhs: Self) -> Self::Output {
        BitVector::new_from_raw_bv(unsafe { rz_bv_or(self.bv.unwrap(), rhs.bv.unwrap()) })
    }
}

impl BitAnd for &BitVector {
    type Output = BitVector;

    fn bitand(self, rhs: Self) -> Self::Output {
        BitVector::new_from_raw_bv(unsafe { rz_bv_and(self.bv.unwrap(), rhs.bv.unwrap()) })
    }
}

impl Not for &BitVector {
    type Output = BitVector;

    fn not(self) -> Self::Output {
        BitVector::new_from_raw_bv(unsafe { rz_bv_complement_1(self.bv.unwrap()) })
    }
}

impl Neg for &BitVector {
    type Output = BitVector;

    fn neg(self) -> Self::Output {
        BitVector::new_from_raw_bv(unsafe { rz_bv_complement_2(self.bv.unwrap()) })
    }
}

macro_rules! i_str {
    ($get_n:expr, $width:expr) => {{
        let n = $get_n;
        format!(
            "{}{:#x}{}",
            if n < 0 { "-" } else { "" },
            if n < 0 { ((!n) + 1) } else { n },
            subscript($width)
        )
    }};
}

impl BitVector {
    fn take(&mut self) -> *mut bitvector_t {
        self.bv.take().unwrap()
    }

    fn get(&mut self) -> Option<*mut bitvector_t> {
        self.bv
    }

    fn free_ptr(ptr: *mut bitvector_t) {
        unsafe { rz_bv_free(ptr) };
    }

    pub fn new(bits: u32) -> BitVector {
        BitVector {
            bv: unsafe {
                let bv = rz_bv_new(bits as u32);
                assert!(bv != std::ptr::null_mut());
                Some(bv)
            },
        }
    }

    /// Pointer is borrowed.
    pub fn new_from_raw_bv(borrowed_ptr: *mut bitvector_t) -> BitVector {
        assert!(borrowed_ptr != std::ptr::null_mut());
        BitVector {
            bv: Some(unsafe { rz_bv_dup(borrowed_ptr) }),
        }
    }

    pub fn new_from_i64(width: u32, num: i64) -> BitVector {
        BitVector {
            bv: unsafe {
                let bv = rz_bv_new_from_st64(width as u32, num);
                assert!(bv != std::ptr::null_mut());
                Some(bv)
            },
        }
    }

    pub fn new_from_i32(width: u32, num: i32) -> BitVector {
        BitVector {
            bv: unsafe {
                let bv = rz_bv_new_from_st64(width, num as i64);
                assert!(bv != std::ptr::null_mut());
                Some(bv)
            },
        }
    }

    pub fn new_from_u64(bits: u32, num: u64) -> BitVector {
        BitVector {
            bv: unsafe {
                let bv = rz_bv_new_from_ut64(bits as u32, num);
                assert!(bv != std::ptr::null_mut());
                Some(bv)
            },
        }
    }

    pub fn new_zero(width: u32) -> BitVector {
        BitVector::new_from_u64(width, 0)
    }

    pub fn new_false() -> BitVector {
        BitVector::new_from_u64(1, 0)
    }

    pub fn new_true() -> BitVector {
        BitVector::new_from_u64(1, 1)
    }

    pub fn width(&self) -> u32 {
        pderef!(self.bv.unwrap()).len
    }

    pub fn as_str(&self) -> String {
        unsafe { c_to_str(rz_bv_as_hex_string(self.bv.unwrap(), false)) }
    }

    pub fn as_signed_str(&self) -> String {
        match (self.width(), self.msb()) {
            (8, true) => i_str!(self.as_i8(), 8),
            (16, true) => i_str!(self.as_i16(), 16),
            (32, true) => i_str!(self.as_i32(), 32),
            (64, true) => i_str!(self.as_i64(), 64),
            (8, false) => format!("{:#x}", self.as_u8()),
            (16, false) => format!("{:#x}", self.as_u16()),
            (32, false) => format!("{:#x}", self.as_u32()),
            (64, false) => format!("{:#x}", self.as_u64()),
            _ => self.as_str(),
        }
    }

    pub fn cast(&self, to_size: u32, fill_bit: bool) -> BitVector {
        BitVector {
            bv: unsafe {
                let bv = rz_bv_cast(self.bv.unwrap(), to_size, fill_bit);
                assert!(bv != std::ptr::null_mut());
                Some(bv)
            },
        }
    }

    pub fn set_all(&mut self, bit: bool) {
        unsafe {
            rz_bv_set_all(self.get().unwrap(), bit);
        }
    }

    pub fn get_mask(width: u32) -> BitVector {
        let mut bv = BitVector::new(width);
        bv.set_all(true);
        bv
    }

    pub fn is_zero(&self) -> bool {
        unsafe { rz_bv_is_zero_vector(self.bv.unwrap()) }
    }

    pub fn msb(&self) -> bool {
        unsafe { rz_bv_msb(self.bv.unwrap()) }
    }

    pub fn lsb(&self) -> bool {
        unsafe { rz_bv_lsb(self.bv.unwrap()) }
    }

    pub fn ule(&self, other: &Self) -> bool {
        unsafe { rz_bv_ule(self.bv.unwrap(), other.bv.unwrap()) }
    }

    pub fn sle(&self, other: &Self) -> bool {
        unsafe { rz_bv_sle(self.bv.unwrap(), other.bv.unwrap()) }
    }

    pub fn sdiv(&self, other: &Self) -> BitVector {
        BitVector::new_from_raw_bv(unsafe { rz_bv_sdiv(self.bv.unwrap(), other.bv.unwrap()) })
    }

    pub fn div(&self, other: &Self) -> BitVector {
        BitVector::new_from_raw_bv(unsafe { rz_bv_div(self.bv.unwrap(), other.bv.unwrap()) })
    }

    pub fn umod(&self, rhs: &Self) -> BitVector {
        BitVector::new_from_raw_bv(unsafe { rz_bv_mod(self.bv.unwrap(), rhs.bv.unwrap()) })
    }

    pub fn smod(&self, rhs: &Self) -> BitVector {
        BitVector::new_from_raw_bv(unsafe { rz_bv_smod(self.bv.unwrap(), rhs.bv.unwrap()) })
    }

    pub fn as_u8(&self) -> u8 {
        unsafe { rz_bv_to_ut8(self.bv.unwrap()) }
    }

    pub fn as_u16(&self) -> u16 {
        unsafe { rz_bv_to_ut16(self.bv.unwrap()) }
    }

    pub fn as_u32(&self) -> u32 {
        unsafe { rz_bv_to_ut32(self.bv.unwrap()) }
    }

    pub fn as_u64(&self) -> u64 {
        unsafe { rz_bv_to_ut64(self.bv.unwrap()) }
    }

    pub fn as_i8(&self) -> i8 {
        self.as_u8() as i8
    }

    pub fn as_i16(&self) -> i16 {
        self.as_u16() as i16
    }

    pub fn as_i32(&self) -> i32 {
        self.as_u32() as i32
    }

    pub fn as_i64(&self) -> i64 {
        self.as_u64() as i64
    }

    pub fn from_bytes_be(width: u32, slices: Vec<u8>) -> BitVector {
        let mut boxed = Box::<Vec<u8>>::from(slices);
        BitVector {
            bv: Some(unsafe { rz_bv_new_from_bytes_be(boxed.as_mut_ptr(), 0, width) }),
        }
    }

    pub fn is_neg(&self) -> bool {
        self.msb()
    }

    pub fn set_range(&mut self, pos_start: u32, pos_end: u32, fill_bit: bool) {
        unsafe { rz_bv_set_range(self.bv.unwrap(), pos_start, pos_end, fill_bit) };
    }
}
