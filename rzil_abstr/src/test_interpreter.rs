// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashSet, VecDeque},
        sync::{
            mpsc::{channel, Receiver, Sender},
            Arc, Mutex,
        },
    };

    use binding::{get_test_bin_path, init_rizin_instance, wait_for_exlusive_core, RzCoreWrapper};
    use num_bigint::{ToBigInt, ToBigUint};

    use crate::interpreter::{
        interpret, AbstrVal, AddrInfo, ConcreteCodeXref, Const, IntrpPath, IntrpProducts, MemOp,
        MemXref, StackXref, NO_ADDR_INFO,
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
            (0x0800005d, AddrInfo::new_call()),
            (0x080000b0, NO_ADDR_INFO),
            (0x080000b1, NO_ADDR_INFO),
            (0x080000b4, NO_ADDR_INFO),
            (0x080000b6, NO_ADDR_INFO),
            (0x080000b7, AddrInfo::new_return_point()),
            (0x08000064, NO_ADDR_INFO),
            (0x08000067, NO_ADDR_INFO),
            (0x0800006a, NO_ADDR_INFO),
            (0x0800006d, NO_ADDR_INFO),
            (0x08000070, NO_ADDR_INFO),
            (0x08000073, NO_ADDR_INFO),
            (0x08000076, NO_ADDR_INFO),
            (0x08000078, NO_ADDR_INFO),
            (0x0800007a, AddrInfo::new_call()),
            (0x080000c0, NO_ADDR_INFO),
            (0x080000c1, NO_ADDR_INFO),
            (0x080000c4, NO_ADDR_INFO),
            (0x080000c9, NO_ADDR_INFO),
            (0x080000ca, AddrInfo::new_return_point()),
            (0x08000081, NO_ADDR_INFO),
            (0x08000084, NO_ADDR_INFO),
            (0x08000087, NO_ADDR_INFO),
            (0x0800008a, NO_ADDR_INFO),
            (0x0800008d, NO_ADDR_INFO),
            (0x08000090, NO_ADDR_INFO),
            (0x08000093, NO_ADDR_INFO),
            (0x08000095, NO_ADDR_INFO),
            (0x08000097, AddrInfo::new_call()),
            (0x080000d0, NO_ADDR_INFO),
            (0x080000d1, NO_ADDR_INFO),
            (0x080000d4, NO_ADDR_INFO),
            (0x080000d9, NO_ADDR_INFO),
            (0x080000da, AddrInfo::new_return_point()),
            (0x0800009e, NO_ADDR_INFO),
            (0x080000a1, NO_ADDR_INFO),
            (0x080000a4, NO_ADDR_INFO),
            (0x080000a7, NO_ADDR_INFO),
            (0x080000ab, NO_ADDR_INFO),
            (0x080000ac, AddrInfo::new_return_point()),
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
            (0x08000050, AddrInfo::new_call()),
            (0x08000070, AddrInfo::new_return_point()),
            (0x08000054, NO_ADDR_INFO),
            (0x08000058, AddrInfo::new_call()),
            (0x08000080, AddrInfo::new_return_point()),
            (0x0800005c, NO_ADDR_INFO),
            (0x08000060, AddrInfo::new_call()),
            (0x08000090, AddrInfo::new_return_point()),
            (0x08000064, AddrInfo::new_return_point()),
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
            (0x08000074, AddrInfo::new_malloc_call()),
            (0x08000079, AddrInfo::new_return_point()),
            (0x0800007d, NO_ADDR_INFO),
            (0x08000082, AddrInfo::new_malloc_call()),
            (0x08000087, AddrInfo::new_return_point()),
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
            (0x080000c2, AddrInfo::new_return_point()),
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
            (0x08000070, AddrInfo::new_malloc_call()),
            (0x08000074, AddrInfo::new_return_point()),
            (0x08000078, NO_ADDR_INFO),
            (0x0800007c, AddrInfo::new_malloc_call()),
            (0x08000080, AddrInfo::new_return_point()),
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
            (0x080000c4, AddrInfo::new_return_point()),
        ]);
        let path = IntrpPath::from(v);
        (rz_core, path)
    }

    #[test]
    fn test_x86_icall_discover() {
        wait_for_exlusive_core!();

        let (core, path) = get_x86_icall_test();
        let (tx, rx): (Sender<IntrpProducts>, Receiver<IntrpProducts>) = channel();
        interpret(core, path, tx);
        let products: IntrpProducts;
        if let Ok(prods) = rx.try_recv() {
            products = prods;
        } else {
            panic!("Received no products.");
        }
        let mut call_expected = HashSet::new();
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
        let mut stack_expected = HashSet::new();
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        stack_expected.insert(StackXref::new(0x8000040, Const::new_i64(-0x8, 64), 0x8000040));
        stack_expected.insert(StackXref::new(0x8000048, Const::new_i64(-0xc, 64), 0x8000040));
        stack_expected.insert(StackXref::new(0x800004f, Const::new_i64(-0x10, 64), 0x8000040));
        stack_expected.insert(StackXref::new(0x8000056, Const::new_i64(-0x10, 64), 0x8000040));
        stack_expected.insert(StackXref::new(0x800005d, Const::new_i64(-0x20, 64), 0x8000040));
        stack_expected.insert(StackXref::new(0x8000064, Const::new_i64(-0xc, 64), 0x8000040));
        stack_expected.insert(StackXref::new(0x8000067, Const::new_i64(-0xc, 64), 0x8000040));
        stack_expected.insert(StackXref::new(0x800006a, Const::new_i64(-0x10, 64), 0x8000040));
        stack_expected.insert(StackXref::new(0x8000070, Const::new_i64(-0x10, 64), 0x8000040));
        stack_expected.insert(StackXref::new(0x8000073, Const::new_i64(-0x10, 64), 0x8000040));
        stack_expected.insert(StackXref::new(0x800007a, Const::new_i64(-0x20, 64), 0x8000040));
        stack_expected.insert(StackXref::new(0x8000081, Const::new_i64(-0xc, 64), 0x8000040));
        stack_expected.insert(StackXref::new(0x8000084, Const::new_i64(-0xc, 64), 0x8000040));
        stack_expected.insert(StackXref::new(0x8000087, Const::new_i64(-0x10, 64), 0x8000040));
        stack_expected.insert(StackXref::new(0x800008d, Const::new_i64(-0x10, 64), 0x8000040));
        stack_expected.insert(StackXref::new(0x8000090, Const::new_i64(-0x10, 64), 0x8000040));
        stack_expected.insert(StackXref::new(0x8000097, Const::new_i64(-0x20, 64), 0x8000040));
        stack_expected.insert(StackXref::new(0x800009e, Const::new_i64(-0xc, 64), 0x8000040));
        stack_expected.insert(StackXref::new(0x80000a1, Const::new_i64(-0xc, 64), 0x8000040));
        stack_expected.insert(StackXref::new(0x80000a4, Const::new_i64(-0xc, 64), 0x8000040));
        stack_expected.insert(StackXref::new(0x80000ab, Const::new_i64(-0x8, 64), 0x8000040));
        stack_expected.insert(StackXref::new(0x80000ac, Const::new_i64(0x0, 64), 0x8000040));
        stack_expected.insert(StackXref::new(0x80000b0, Const::new_i64(-0x8, 64), 0x80000b0));
        stack_expected.insert(StackXref::new(0x80000b6, Const::new_i64(-0x8, 64), 0x80000b0));
        stack_expected.insert(StackXref::new(0x80000b7, Const::new_i64(-0x20, 64), 0x8000040));
        stack_expected.insert(StackXref::new(0x80000c0, Const::new_i64(-0x8, 64), 0x80000c0));
        stack_expected.insert(StackXref::new(0x80000c9, Const::new_i64(-0x8, 64), 0x80000c0));
        stack_expected.insert(StackXref::new(0x80000ca, Const::new_i64(-0x20, 64), 0x8000040));
        stack_expected.insert(StackXref::new(0x80000d0, Const::new_i64(-0x8, 64), 0x80000d0));
        stack_expected.insert(StackXref::new(0x80000d9, Const::new_i64(-0x8, 64), 0x80000d0));
        stack_expected.insert(StackXref::new(0x80000da, Const::new_i64(-0x20, 64), 0x8000040));
        }
        assert!(products.stack_xrefs.eq(&stack_expected));

        println!("Mem xrefs");
        for sxref in products.mem_xrefs.iter() {
            println!("{}", sxref);
        }
        let mut mem_expected = HashSet::new();
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
        interpret(core, path, tx);
        let products: IntrpProducts;
        if let Ok(prods) = rx.try_recv() {
            products = prods;
        } else {
            panic!("Received no products.");
        }
        let mut call_expected = HashSet::new();
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
        let mut stack_expected = HashSet::new();
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        stack_expected.insert(StackXref::new(0x8000040, Const::new_i32(-0x8, 32), 0x8000040));
        stack_expected.insert(StackXref::new(0x8000040, Const::new_i32(-0x10, 32), 0x8000040));
        stack_expected.insert(StackXref::new(0x8000064, Const::new_i32(-0x8, 32), 0x8000040));
        stack_expected.insert(StackXref::new(0x8000064, Const::new_i32(0, 32), 0x8000040));
        }
        assert!(products.stack_xrefs.eq(&stack_expected));

        println!("Mem xrefs");
        for sxref in products.mem_xrefs.iter() {
            println!("{}", sxref);
        }
        let mut mem_expected = HashSet::new();
        mem_expected.insert(MemXref::new(0x800004c, 0x8000098, 4));
        mem_expected.insert(MemXref::new(0x8000054, 0x800009c, 4));
        mem_expected.insert(MemXref::new(0x800005c, 0x80000a0, 4));
        assert!(products.mem_xrefs.eq(&mem_expected));
    }

    #[test]
    fn test_constant() {
        wait_for_exlusive_core!();

        let u_32_max = Const::new_u64(0xffffffff, 32);
        // Comparison tests. Due to our bit width limitation, we need to check
        // how the converted values are interpreted.
        // This should be independent of the underlying BigInt or BigUint struct.
        assert_eq!(u_32_max.vu(), 0xffffffffu32.to_biguint().unwrap());
        assert_eq!(u_32_max.v(), -1.to_bigint().unwrap());
        assert_ne!(u_32_max.v(), 0xffffffffu64.to_bigint().unwrap());

        let (mut casted, mut tainted) = u_32_max.cast(64, AbstrVal::new_false());
        assert!(tainted.is_unset());
        assert_eq!(casted.vu(), 0xffffffffu32.to_biguint().unwrap());
        assert_eq!(casted.v(), 0xffffffffu64.to_bigint().unwrap());

        (casted, tainted) = u_32_max.cast(64, AbstrVal::new_true());
        assert!(tainted.is_unset());
        assert_eq!(casted.vu(), 0xffffffffffffffffu64.to_biguint().unwrap());
        assert_eq!(casted.v(), -1.to_bigint().unwrap());

        (casted, tainted) = u_32_max.cast(0, AbstrVal::new_false());
        assert!(tainted.is_unset());
        assert_eq!(casted.vu(), 0x0u64.to_biguint().unwrap());
        assert_eq!(casted.v(), 0.to_bigint().unwrap());

        let u_16_half = Const::new_u64(0xffff, 16);
        assert_eq!(u_16_half.vu(), 0xffffu16.to_biguint().unwrap());
        assert_eq!(u_16_half.v(), -1.to_bigint().unwrap());
        assert_ne!(u_16_half.v(), 0xffffu64.to_bigint().unwrap());

        (casted, tainted) = u_16_half.cast(64, AbstrVal::new_true());
        assert!(tainted.is_unset());
        assert_eq!(casted.vu(), 0xffffffffffffffffu64.to_biguint().unwrap());
        assert_eq!(casted.v(), -1.to_bigint().unwrap());

        let u_16_pat = Const::new_u64(0x1010, 16);
        assert_eq!(u_16_pat.vu(), 0x1010u64.to_biguint().unwrap());
        assert_eq!(u_16_pat.v(), 0x1010u64.to_bigint().unwrap());
        (casted, tainted) = u_16_pat.cast(64, AbstrVal::new_true());
        assert!(tainted.is_unset());
        assert_eq!(casted.vu(), 0xffffffffffff1010u64.to_biguint().unwrap());
        assert_eq!(
            casted.v(),
            (0xffffffffffff1010u64 as i64).to_bigint().unwrap()
        );

        // Not a true/false value for the bit set.
        // This is tainted.
        (_, tainted) = u_16_pat.cast(
            64,
            AbstrVal::new_global(1, Const::new_u64(0xffff, 16), None, 0),
        );
        assert!(tainted.is_set());
    }

    #[test]
    fn test_x86_malloc() {
        wait_for_exlusive_core!();

        let (core, path) = get_x86_malloc_test();
        let (tx, rx): (Sender<IntrpProducts>, Receiver<IntrpProducts>) = channel();
        interpret(core, path, tx);
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

        let call_expected = HashSet::new();
        assert!(products.concrete_calls.eq(&call_expected));

        println!("Stack xrefs");
        for sxref in products.stack_xrefs.iter() {
            println!("{}", sxref);
        }
        let mut stack_expected = HashSet::new();
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        stack_expected.insert(StackXref::new(0x8000060, Const::new_i32(-0x8, 64), 0x8000060));
        stack_expected.insert(StackXref::new(0x8000068, Const::new_i32(-0xc, 64), 0x8000060));
        stack_expected.insert(StackXref::new(0x8000079, Const::new_i32(-0x18, 64), 0x8000060));
        stack_expected.insert(StackXref::new(0x8000087, Const::new_i32(-0x20, 64), 0x8000060));
        stack_expected.insert(StackXref::new(0x800008b, Const::new_i32(-0x18, 64), 0x8000060));
        stack_expected.insert(StackXref::new(0x800009c, Const::new_i32(-0x18, 64), 0x8000060));
        stack_expected.insert(StackXref::new(0x80000a7, Const::new_i32(-0x20, 64), 0x8000060));
        stack_expected.insert(StackXref::new(0x80000b1, Const::new_i32(-0x20, 64), 0x8000060));
        stack_expected.insert(StackXref::new(0x80000c1, Const::new_i32(-0x8, 64), 0x8000060));
        stack_expected.insert(StackXref::new(0x80000c2, Const::new_i32(0x0, 64), 0x8000060));
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
        let mut expected_heap_mos = HashSet::new();
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        expected_heap_mos.insert(MemOp::new(0x8000099, AbstrVal::new_heap(1, Const::new_u64(0x0, 64), 0x8000074)));
        expected_heap_mos.insert(MemOp::new(0x80000ab, AbstrVal::new_heap(1, Const::new_u64(0x0, 64), 0x8000082)));
        expected_heap_mos.insert(MemOp::new(0x80000a0, AbstrVal::new_heap(1, Const::new_u64(0x8, 64), 0x8000074)));
        expected_heap_mos.insert(MemOp::new(0x80000b5, AbstrVal::new_heap(1, Const::new_u64(0x4, 64), 0x8000082)));
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
        interpret(core, path, tx);
        let products: IntrpProducts;
        if let Ok(prods) = rx.try_recv() {
            products = prods;
        } else {
            panic!("Received no products.");
        }
        let call_expected = HashSet::new();
        assert!(products.concrete_calls.eq(&call_expected));

        println!("Stack xrefs");
        for sxref in products.stack_xrefs.iter() {
            println!("{}", sxref);
        }
        let mut stack_expected = HashSet::new();
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        stack_expected.insert(StackXref::new(0x8000060, Const::new_i32(-0x8, 32), 0x8000060));
        stack_expected.insert(StackXref::new(0x8000068, Const::new_i32(-0xc, 32), 0x8000060));
        stack_expected.insert(StackXref::new(0x8000074, Const::new_i32(-0x10, 32), 0x8000060));
        stack_expected.insert(StackXref::new(0x8000080, Const::new_i32(-0x14, 32), 0x8000060));
        stack_expected.insert(StackXref::new(0x8000084, Const::new_i32(-0x10, 32), 0x8000060));
        stack_expected.insert(StackXref::new(0x800009c, Const::new_i32(-0x10, 32), 0x8000060));
        stack_expected.insert(StackXref::new(0x80000a8, Const::new_i32(-0x14, 32), 0x8000060));
        stack_expected.insert(StackXref::new(0x80000b4, Const::new_i32(-0x14, 32), 0x8000060));
        stack_expected.insert(StackXref::new(0x80000c4, Const::new_i32(-0x8, 32), 0x8000060));
        }
        assert!(products.stack_xrefs.eq(&stack_expected));

        println!("Mem xrefs");
        for sxref in products.mem_xrefs.iter() {
            println!("{}", sxref);
        }
        let mem_expected = HashSet::new();
        assert!(products.mem_xrefs.eq(&mem_expected));

        println!("MOS");
        for memop in products.mos.iter() {
            println!("{}", memop);
        }
        let mut expected_heap_mos = HashSet::new();
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        expected_heap_mos.insert(MemOp::new(0x8000098, AbstrVal::new_heap(1, Const::new_u64(0x0, 32), 0x8000070)));
        expected_heap_mos.insert(MemOp::new(0x80000a0, AbstrVal::new_heap(1, Const::new_u64(0x8, 32), 0x8000070)));
        expected_heap_mos.insert(MemOp::new(0x80000ac, AbstrVal::new_heap(1, Const::new_u64(0x0, 32), 0x800007c)));
        expected_heap_mos.insert(MemOp::new(0x80000b8, AbstrVal::new_heap(1, Const::new_u64(0x4, 32), 0x800007c)));
        }
        assert_eq!(products.mos.iter().filter(|x| x.is_heap()).count(), 4);
        for op in expected_heap_mos.iter() {
            assert!(products.mos.contains(op), "{} not in MOS", op);
        }
    }
}
