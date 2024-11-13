// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeSet, VecDeque},
        sync::{
            mpsc::{channel, Receiver, Sender},
            Arc, Mutex,
        },
    };

    use binding::{get_test_bin_path, init_rizin_instance, wait_for_exlusive_core, RzCoreWrapper};

    use crate::{
        bitvector::BitVector,
        interpreter::{
            interpret, AbstrVal, ConcreteCodeXref, IWordInfo, IntrpPath, IntrpProducts, MemOp,
            MemXref, StackXref, NO_ADDR_INFO,
        },
        op_handler::cast,
    };

    fn get_x86_icall_test() -> (Arc<Mutex<RzCoreWrapper>>, IntrpPath) {
        let icall_o = get_test_bin_path().join("x86_icall.o");
        let rz_core =
            RzCoreWrapper::new(init_rizin_instance(icall_o.to_str().expect("Path wrong")));
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.entries", "0x08000040");
        let v = VecDeque::from(vec![
            (0x08000040, NO_ADDR_INFO),
            (0x08000041, NO_ADDR_INFO),
            (0x08000044, NO_ADDR_INFO),
            (0x08000048, NO_ADDR_INFO),
            (0x0800004f, NO_ADDR_INFO),
            (0x08000056, NO_ADDR_INFO),
            (0x08000059, NO_ADDR_INFO),
            (0x0800005b, NO_ADDR_INFO),
            (0x0800005d, IWordInfo::IsCall),
            (0x080000b0, NO_ADDR_INFO),
            (0x080000b1, NO_ADDR_INFO),
            (0x080000b4, NO_ADDR_INFO),
            (0x080000b6, NO_ADDR_INFO),
            (0x080000b7, IWordInfo::IsReturnPoint),
            (0x08000064, NO_ADDR_INFO),
            (0x08000067, NO_ADDR_INFO),
            (0x0800006a, NO_ADDR_INFO),
            (0x0800006d, NO_ADDR_INFO),
            (0x08000070, NO_ADDR_INFO),
            (0x08000073, NO_ADDR_INFO),
            (0x08000076, NO_ADDR_INFO),
            (0x08000078, NO_ADDR_INFO),
            (0x0800007a, IWordInfo::IsCall),
            (0x080000c0, NO_ADDR_INFO),
            (0x080000c1, NO_ADDR_INFO),
            (0x080000c4, NO_ADDR_INFO),
            (0x080000c9, NO_ADDR_INFO),
            (0x080000ca, IWordInfo::IsReturnPoint),
            (0x08000081, NO_ADDR_INFO),
            (0x08000084, NO_ADDR_INFO),
            (0x08000087, NO_ADDR_INFO),
            (0x0800008a, NO_ADDR_INFO),
            (0x0800008d, NO_ADDR_INFO),
            (0x08000090, NO_ADDR_INFO),
            (0x08000093, NO_ADDR_INFO),
            (0x08000095, NO_ADDR_INFO),
            (0x08000097, IWordInfo::IsCall),
            (0x080000d0, NO_ADDR_INFO),
            (0x080000d1, NO_ADDR_INFO),
            (0x080000d4, NO_ADDR_INFO),
            (0x080000d9, NO_ADDR_INFO),
            (0x080000da, IWordInfo::IsReturnPoint),
            (0x0800009e, NO_ADDR_INFO),
            (0x080000a1, NO_ADDR_INFO),
            (0x080000a4, NO_ADDR_INFO),
            (0x080000a7, NO_ADDR_INFO),
            (0x080000ab, NO_ADDR_INFO),
            (0x080000ac, IWordInfo::IsReturnPoint),
        ]);
        let path = IntrpPath::from(v);

        (rz_core, path)
    }

    fn get_hexagon_icall_test() -> (Arc<Mutex<RzCoreWrapper>>, IntrpPath) {
        let icall_o = get_test_bin_path().join("hexagon_icall.o");
        let rz_core =
            RzCoreWrapper::new(init_rizin_instance(icall_o.to_str().expect("Path wrong")));
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.entries", "0x08000040");
        let v = VecDeque::from(vec![
            (0x08000040, NO_ADDR_INFO),
            (0x0800004c, NO_ADDR_INFO),
            (0x08000050, IWordInfo::IsCall),
            (0x08000070, IWordInfo::IsReturnPoint),
            (0x08000054, NO_ADDR_INFO),
            (0x08000058, IWordInfo::IsCall),
            (0x08000080, IWordInfo::IsReturnPoint),
            (0x0800005c, NO_ADDR_INFO),
            (0x08000060, IWordInfo::IsCall),
            (0x08000090, IWordInfo::IsReturnPoint),
            (0x08000064, IWordInfo::IsReturnPoint),
        ]);
        let path = IntrpPath::from(v);

        (rz_core, path)
    }

    fn get_x86_malloc_test() -> (Arc<Mutex<RzCoreWrapper>>, IntrpPath) {
        let icall_o = get_test_bin_path().join("x86_malloc.o");
        let rz_core =
            RzCoreWrapper::new(init_rizin_instance(icall_o.to_str().expect("Path wrong")));
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.entries", "0x08000060");
        // Path over main. Not entering dummy_malloc()
        let v = VecDeque::from(vec![
            (0x08000060, NO_ADDR_INFO),
            (0x08000061, NO_ADDR_INFO),
            (0x08000064, NO_ADDR_INFO),
            (0x08000068, NO_ADDR_INFO),
            (0x0800006f, NO_ADDR_INFO),
            (0x08000074, IWordInfo::CallsMalloc),
            (0x08000079, IWordInfo::IsReturnPoint),
            (0x0800007d, NO_ADDR_INFO),
            (0x08000082, IWordInfo::CallsMalloc),
            (0x08000087, IWordInfo::IsReturnPoint),
            (0x0800008b, NO_ADDR_INFO),
            (0x0800008f, NO_ADDR_INFO),
            (0x08000099, NO_ADDR_INFO),
            (0x0800009c, NO_ADDR_INFO),
            (0x080000a0, NO_ADDR_INFO),
            (0x080000a7, NO_ADDR_INFO),
            (0x080000ab, NO_ADDR_INFO),
            (0x080000b1, NO_ADDR_INFO),
            (0x080000b5, NO_ADDR_INFO),
            (0x080000bb, NO_ADDR_INFO),
            (0x080000bd, NO_ADDR_INFO),
            (0x080000c1, NO_ADDR_INFO),
            (0x080000c2, IWordInfo::IsReturnPoint),
        ]);
        let path = IntrpPath::from(v);

        (rz_core, path)
    }

    fn get_hexagon_malloc_test() -> (Arc<Mutex<RzCoreWrapper>>, IntrpPath) {
        let icall_o = get_test_bin_path().join("hexagon_malloc.o");
        let rz_core =
            RzCoreWrapper::new(init_rizin_instance(icall_o.to_str().expect("Path wrong")));
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.entries", "0x08000060");
        // Path over main. Not entering dummy_malloc()
        let v = VecDeque::from(vec![
            (0x08000060, NO_ADDR_INFO),
            (0x08000064, NO_ADDR_INFO),
            (0x08000068, NO_ADDR_INFO),
            (0x0800006c, NO_ADDR_INFO),
            (0x08000070, IWordInfo::CallsMalloc),
            (0x08000074, IWordInfo::IsReturnPoint),
            (0x08000078, NO_ADDR_INFO),
            (0x0800007c, IWordInfo::CallsMalloc),
            (0x08000080, IWordInfo::IsReturnPoint),
            (0x08000084, NO_ADDR_INFO),
            (0x08000088, NO_ADDR_INFO),
            (0x08000090, NO_ADDR_INFO),
            (0x08000098, NO_ADDR_INFO),
            (0x0800009c, NO_ADDR_INFO),
            (0x080000a0, NO_ADDR_INFO),
            (0x080000a8, NO_ADDR_INFO),
            (0x080000ac, NO_ADDR_INFO),
            (0x080000b4, NO_ADDR_INFO),
            (0x080000b8, NO_ADDR_INFO),
            (0x080000c0, NO_ADDR_INFO),
            (0x080000c4, IWordInfo::IsReturnPoint),
        ]);
        let path = IntrpPath::from(v);
        (rz_core, path)
    }

    #[test]
    fn test_x86_icall_discover() {
        wait_for_exlusive_core!();

        let (core, path) = get_x86_icall_test();
        let (tx, rx): (Sender<IntrpProducts>, Receiver<IntrpProducts>) = channel();
        interpret(0, core, path, tx);
        let products: IntrpProducts;
        if let Ok(prods) = rx.try_recv() {
            products = prods;
        } else {
            panic!("Received no products.");
        }
        let mut call_expected = BTreeSet::new();
        call_expected.insert(ConcreteCodeXref::new(
            crate::interpreter::CodeXrefType::IndirectCall,
            0x08000040,
            0x0800005d,
            0x080000b0,
        ));
        call_expected.insert(ConcreteCodeXref::new(
            crate::interpreter::CodeXrefType::IndirectCall,
            0x08000040,
            0x0800007a,
            0x080000c0,
        ));
        call_expected.insert(ConcreteCodeXref::new(
            crate::interpreter::CodeXrefType::IndirectCall,
            0x08000040,
            0x08000097,
            0x080000d0,
        ));
        assert!(products.concrete_calls.eq(&call_expected));
        println!("Stack xrefs");
        for sxref in products.stack_xrefs.iter() {
            println!("{}", sxref);
        }
        let mut stack_expected = BTreeSet::new();
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        stack_expected.insert(StackXref::new(0x8000040, BitVector::new_from_i64(64, -0x8), 0x8000040));
        stack_expected.insert(StackXref::new(0x8000048, BitVector::new_from_i64(64, -0xc), 0x8000040));
        stack_expected.insert(StackXref::new(0x800004f, BitVector::new_from_i64(64, -0x10), 0x8000040));
        stack_expected.insert(StackXref::new(0x8000056, BitVector::new_from_i64(64, -0x10), 0x8000040));
        stack_expected.insert(StackXref::new(0x800005d, BitVector::new_from_i64(64, -0x20), 0x8000040));
        stack_expected.insert(StackXref::new(0x8000064, BitVector::new_from_i64(64, -0xc), 0x8000040));
        stack_expected.insert(StackXref::new(0x8000067, BitVector::new_from_i64(64, -0xc), 0x8000040));
        stack_expected.insert(StackXref::new(0x800006a, BitVector::new_from_i64(64, -0x10), 0x8000040));
        stack_expected.insert(StackXref::new(0x8000070, BitVector::new_from_i64(64, -0x10), 0x8000040));
        stack_expected.insert(StackXref::new(0x8000073, BitVector::new_from_i64(64, -0x10), 0x8000040));
        stack_expected.insert(StackXref::new(0x800007a, BitVector::new_from_i64(64, -0x20), 0x8000040));
        stack_expected.insert(StackXref::new(0x8000081, BitVector::new_from_i64(64, -0xc), 0x8000040));
        stack_expected.insert(StackXref::new(0x8000084, BitVector::new_from_i64(64, -0xc), 0x8000040));
        stack_expected.insert(StackXref::new(0x8000087, BitVector::new_from_i64(64, -0x10), 0x8000040));
        stack_expected.insert(StackXref::new(0x800008d, BitVector::new_from_i64(64, -0x10), 0x8000040));
        stack_expected.insert(StackXref::new(0x8000090, BitVector::new_from_i64(64, -0x10), 0x8000040));
        stack_expected.insert(StackXref::new(0x8000097, BitVector::new_from_i64(64, -0x20), 0x8000040));
        stack_expected.insert(StackXref::new(0x800009e, BitVector::new_from_i64(64, -0xc), 0x8000040));
        stack_expected.insert(StackXref::new(0x80000a1, BitVector::new_from_i64(64, -0xc), 0x8000040));
        stack_expected.insert(StackXref::new(0x80000a4, BitVector::new_from_i64(64, -0xc), 0x8000040));
        stack_expected.insert(StackXref::new(0x80000ab, BitVector::new_from_i64(64, -0x8), 0x8000040));
        stack_expected.insert(StackXref::new(0x80000ac, BitVector::new_from_i64(64, 0x0), 0x8000040));
        stack_expected.insert(StackXref::new(0x80000b0, BitVector::new_from_i64(64, -0x8), 0x80000b0));
        stack_expected.insert(StackXref::new(0x80000b6, BitVector::new_from_i64(64, -0x8), 0x80000b0));
        stack_expected.insert(StackXref::new(0x80000b7, BitVector::new_from_i64(64, -0x20), 0x8000040));
        stack_expected.insert(StackXref::new(0x80000c0, BitVector::new_from_i64(64, -0x8), 0x80000c0));
        stack_expected.insert(StackXref::new(0x80000c9, BitVector::new_from_i64(64, -0x8), 0x80000c0));
        stack_expected.insert(StackXref::new(0x80000ca, BitVector::new_from_i64(64, -0x20), 0x8000040));
        stack_expected.insert(StackXref::new(0x80000d0, BitVector::new_from_i64(64, -0x8), 0x80000d0));
        stack_expected.insert(StackXref::new(0x80000d9, BitVector::new_from_i64(64, -0x8), 0x80000d0));
        stack_expected.insert(StackXref::new(0x80000da, BitVector::new_from_i64(64, -0x20), 0x8000040));
        }
        assert!(products.stack_xrefs.eq(&stack_expected));

        println!("Mem xrefs");
        for sxref in products.mem_xrefs.iter() {
            println!("{}", sxref);
        }
        let mut mem_expected = BTreeSet::new();
        mem_expected.insert(MemXref::new(0x0800005d, 0x080000e0, 8));
        mem_expected.insert(MemXref::new(0x0800007a, 0x080000e8, 8));
        mem_expected.insert(MemXref::new(0x08000097, 0x080000f0, 8));
        assert!(products.mem_xrefs.eq(&mem_expected));
    }

    #[test]
    fn test_hexagon_icall_discover() {
        wait_for_exlusive_core!();

        let (core, path) = get_hexagon_icall_test();
        let (tx, rx): (Sender<IntrpProducts>, Receiver<IntrpProducts>) = channel();
        interpret(0, core, path, tx);
        let products: IntrpProducts;
        if let Ok(prods) = rx.try_recv() {
            products = prods;
        } else {
            panic!("Received no products.");
        }
        let mut call_expected = BTreeSet::new();
        call_expected.insert(ConcreteCodeXref::new(
            crate::interpreter::CodeXrefType::IndirectCall,
            0x08000040,
            0x08000050,
            0x08000070,
        ));
        call_expected.insert(ConcreteCodeXref::new(
            crate::interpreter::CodeXrefType::IndirectCall,
            0x08000040,
            0x08000058,
            0x08000080,
        ));
        call_expected.insert(ConcreteCodeXref::new(
            crate::interpreter::CodeXrefType::IndirectCall,
            0x08000040,
            0x08000060,
            0x08000090,
        ));
        println!("call xrefs");
        for call in products.concrete_calls.iter() {
            println!("{}", call);
        }
        assert!(products.concrete_calls.eq(&call_expected));
        println!("Stack xrefs");
        for sxref in products.stack_xrefs.iter() {
            println!("{}", sxref);
        }
        let mut stack_expected = BTreeSet::new();
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        stack_expected.insert(StackXref::new(0x8000040, BitVector::new_from_i32(32, -0x8), 0x8000040));
        stack_expected.insert(StackXref::new(0x8000040, BitVector::new_from_i32(32, -0x10), 0x8000040));
        stack_expected.insert(StackXref::new(0x8000064, BitVector::new_from_i32(32, -0x8), 0x8000040));
        stack_expected.insert(StackXref::new(0x8000064, BitVector::new_from_i32(32, 0), 0x8000040));
        }
        assert!(products.stack_xrefs.eq(&stack_expected));

        println!("Mem xrefs");
        for sxref in products.mem_xrefs.iter() {
            println!("{}", sxref);
        }
        let mut mem_expected = BTreeSet::new();
        mem_expected.insert(MemXref::new(0x800004c, 0x8000098, 4));
        mem_expected.insert(MemXref::new(0x8000054, 0x800009c, 4));
        mem_expected.insert(MemXref::new(0x800005c, 0x80000a0, 4));
        assert!(products.mem_xrefs.eq(&mem_expected));
    }

    #[test]
    fn test_constant() {
        wait_for_exlusive_core!();

        let u_32_max = BitVector::new_from_u64(32, 0xffffffff);
        // Comparison tests. Due to our bit width limitation, we need to check
        // how the converted values are interpreted.
        // This should be independent of the underlying BigInt or BigUint struct.
        assert_eq!(u_32_max, 0xffffffffu32);
        assert_eq!(u_32_max, -1);
        assert_ne!(u_32_max, 0xffffffffu64);

        let (mut casted, mut tainted) = cast(&u_32_max, 64, AbstrVal::new_false());
        assert!(tainted.is_unset());
        assert_eq!(casted, 0xffffffffu32);
        assert_eq!(casted, 0xffffffffu64);

        (casted, tainted) = cast(&u_32_max, 64, AbstrVal::new_true());
        assert!(tainted.is_unset());
        assert_eq!(casted, 0xffffffffffffffffu64);
        assert_eq!(casted, -1);

        (casted, tainted) = cast(&u_32_max, 0, AbstrVal::new_false());
        assert!(tainted.is_unset());
        assert_eq!(casted, 0x0u64);
        assert_eq!(casted, 0);

        let u_16_half = BitVector::new_from_u64(16, 0xffff);
        assert_eq!(u_16_half, 0xffffu16);
        assert_eq!(u_16_half, -1);
        assert_ne!(u_16_half, 0xffffu64);

        (casted, tainted) = cast(&u_16_half, 64, AbstrVal::new_true());
        assert!(tainted.is_unset());
        assert_eq!(casted, 0xffffffffffffffffu64);
        assert_eq!(casted, -1);

        let u_16_pat = BitVector::new_from_u64(16, 0x1010);
        assert_eq!(u_16_pat, 0x1010u64);
        assert_eq!(u_16_pat, 0x1010u64);
        (casted, tainted) = cast(&u_16_pat, 64, AbstrVal::new_true());
        assert!(tainted.is_unset());
        assert_eq!(casted, 0xffffffffffff1010u64);
        assert_eq!(casted, (0xffffffffffff1010u64 as i64));

        // Not a true/false value for the bit set.
        // This is tainted.
        (_, tainted) = cast(
            &u_16_pat,
            64,
            AbstrVal::new_global(1, BitVector::new_from_u64(16, 0xffff), None, 0),
        );
        assert!(tainted.is_set());
    }

    #[test]
    fn test_x86_malloc() {
        wait_for_exlusive_core!();

        let (core, path) = get_x86_malloc_test();
        let (tx, rx): (Sender<IntrpProducts>, Receiver<IntrpProducts>) = channel();
        interpret(0, core, path, tx);
        let products: IntrpProducts;
        if let Ok(prods) = rx.try_recv() {
            products = prods;
        } else {
            panic!("Received no products.");
        }
        println!("call xrefs");
        for call in products.concrete_calls.iter() {
            println!("{}", call);
        }

        let call_expected = BTreeSet::new();
        assert!(products.concrete_calls.eq(&call_expected));

        println!("Stack xrefs");
        for sxref in products.stack_xrefs.iter() {
            println!("{}", sxref);
        }
        let mut stack_expected = BTreeSet::new();
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        stack_expected.insert(StackXref::new(0x8000060, BitVector::new_from_i32(64, -0x8), 0x8000060));
        stack_expected.insert(StackXref::new(0x8000068, BitVector::new_from_i32(64, -0xc), 0x8000060));
        stack_expected.insert(StackXref::new(0x8000079, BitVector::new_from_i32(64, -0x18), 0x8000060));
        stack_expected.insert(StackXref::new(0x8000087, BitVector::new_from_i32(64, -0x20), 0x8000060));
        stack_expected.insert(StackXref::new(0x800008b, BitVector::new_from_i32(64, -0x18), 0x8000060));
        stack_expected.insert(StackXref::new(0x800009c, BitVector::new_from_i32(64, -0x18), 0x8000060));
        stack_expected.insert(StackXref::new(0x80000a7, BitVector::new_from_i32(64, -0x20), 0x8000060));
        stack_expected.insert(StackXref::new(0x80000b1, BitVector::new_from_i32(64, -0x20), 0x8000060));
        stack_expected.insert(StackXref::new(0x80000c1, BitVector::new_from_i32(64, -0x8), 0x8000060));
        stack_expected.insert(StackXref::new(0x80000c2, BitVector::new_from_i32(64, 0x0), 0x8000060));
        }
        assert!(products.stack_xrefs.eq(&stack_expected));

        println!("Mem xrefs");
        for sxref in products.mem_xrefs.iter() {
            println!("{}", sxref);
        }
        assert!(products.mem_xrefs.is_empty());

        println!("MOS");
        for memop in products.mos.iter() {
            println!("{}", memop);
        }
        let mut expected_heap_mos = BTreeSet::new();
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        expected_heap_mos.insert(MemOp::new(0x8000099, AbstrVal::new_heap(1, BitVector::new_from_u64(64, 0x0), 0x8000074)));
        expected_heap_mos.insert(MemOp::new(0x80000ab, AbstrVal::new_heap(1, BitVector::new_from_u64(64, 0x0), 0x8000082)));
        expected_heap_mos.insert(MemOp::new(0x80000a0, AbstrVal::new_heap(1, BitVector::new_from_u64(64, 0x8), 0x8000074)));
        expected_heap_mos.insert(MemOp::new(0x80000b5, AbstrVal::new_heap(1, BitVector::new_from_u64(64, 0x4), 0x8000082)));
        }
        assert_eq!(products.mos.iter().filter(|x| x.is_heap()).count(), 4);
        for op in expected_heap_mos.iter() {
            assert!(products.mos.contains(op), "{} not in MOS", op);
        }
    }

    #[test]
    fn test_hexagon_malloc() {
        wait_for_exlusive_core!();

        let (core, path) = get_hexagon_malloc_test();
        let (tx, rx): (Sender<IntrpProducts>, Receiver<IntrpProducts>) = channel();
        interpret(0, core, path, tx);
        let products: IntrpProducts;
        if let Ok(prods) = rx.try_recv() {
            products = prods;
        } else {
            panic!("Received no products.");
        }
        let call_expected = BTreeSet::new();
        assert!(products.concrete_calls.eq(&call_expected));

        println!("Stack xrefs");
        for sxref in products.stack_xrefs.iter() {
            println!("{}", sxref);
        }
        let mut stack_expected = BTreeSet::new();
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        stack_expected.insert(StackXref::new(0x8000060, BitVector::new_from_i32(32, -0x8), 0x8000060));
        stack_expected.insert(StackXref::new(0x8000068, BitVector::new_from_i32(32, -0xc), 0x8000060));
        stack_expected.insert(StackXref::new(0x8000074, BitVector::new_from_i32(32, -0x10), 0x8000060));
        stack_expected.insert(StackXref::new(0x8000080, BitVector::new_from_i32(32, -0x14), 0x8000060));
        stack_expected.insert(StackXref::new(0x8000084, BitVector::new_from_i32(32, -0x10), 0x8000060));
        stack_expected.insert(StackXref::new(0x800009c, BitVector::new_from_i32(32, -0x10), 0x8000060));
        stack_expected.insert(StackXref::new(0x80000a8, BitVector::new_from_i32(32, -0x14), 0x8000060));
        stack_expected.insert(StackXref::new(0x80000b4, BitVector::new_from_i32(32, -0x14), 0x8000060));
        stack_expected.insert(StackXref::new(0x80000c4, BitVector::new_from_i32(32, -0x8), 0x8000060));
        }
        assert!(products.stack_xrefs.eq(&stack_expected));

        println!("Mem xrefs");
        for sxref in products.mem_xrefs.iter() {
            println!("{}", sxref);
        }
        let mem_expected = BTreeSet::new();
        assert!(products.mem_xrefs.eq(&mem_expected));

        println!("MOS");
        for memop in products.mos.iter() {
            println!("{}", memop);
        }
        let mut expected_heap_mos = BTreeSet::new();
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        expected_heap_mos.insert(MemOp::new(0x8000098, AbstrVal::new_heap(1, BitVector::new_from_u64(32, 0x0), 0x8000070)));
        expected_heap_mos.insert(MemOp::new(0x80000a0, AbstrVal::new_heap(1, BitVector::new_from_u64(32, 0x8), 0x8000070)));
        expected_heap_mos.insert(MemOp::new(0x80000ac, AbstrVal::new_heap(1, BitVector::new_from_u64(32, 0x0), 0x800007c)));
        expected_heap_mos.insert(MemOp::new(0x80000b8, AbstrVal::new_heap(1, BitVector::new_from_u64(32, 0x4), 0x800007c)));
        }
        assert_eq!(products.mos.iter().filter(|x| x.is_heap()).count(), 4);
        for op in expected_heap_mos.iter() {
            assert!(products.mos.contains(op), "{} not in MOS", op);
        }
    }
}
