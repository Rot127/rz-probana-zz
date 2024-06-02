// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashSet, VecDeque},
        sync::{Arc, Mutex},
    };

    use binding::{get_test_bin_path, init_rizin_instance, RzCoreWrapper};

    use crate::interpreter::{interpret, AddrInfo, ConcreteCall, IntrpPath};

    fn get_icall_test() -> (Arc<Mutex<RzCoreWrapper>>, IntrpPath) {
        let icall_o = get_test_bin_path().join("icall.o");
        let rz_core =
            RzCoreWrapper::new(init_rizin_instance(icall_o.to_str().expect("Path wrong")));
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.entries", "0x08000040");
        let v = VecDeque::from(vec![
            0x08000040, 0x08000041, 0x08000044, 0x08000048, 0x0800004f, 0x08000056, 0x08000059,
            0x0800005b, 0x0800005d, 0x080000b0, 0x080000b1, 0x080000b4, 0x080000b6, 0x080000b7,
            0x08000064, 0x08000067, 0x0800006a, 0x0800006d, 0x08000070, 0x08000073, 0x08000076,
            0x08000078, 0x0800007a, 0x080000c0, 0x080000c1, 0x080000c4, 0x080000c9, 0x080000ca,
            0x08000081, 0x08000084, 0x08000087, 0x0800008a, 0x0800008d, 0x08000090, 0x08000093,
            0x08000095, 0x08000097, 0x080000d0, 0x080000d1, 0x080000d4, 0x080000d9, 0x080000da,
            0x0800009e, 0x080000a1, 0x080000a4, 0x080000a7, 0x080000ab, 0x080000ac,
        ]);
        let mut path = IntrpPath::from(v);
        path.push_info(0x0800005d, AddrInfo::new_call());
        path.push_info(0x0800007a, AddrInfo::new_call());
        path.push_info(0x08000097, AddrInfo::new_call());
        path.push_info(0x080000b7, AddrInfo::new_return());
        path.push_info(0x080000ca, AddrInfo::new_return());
        path.push_info(0x080000da, AddrInfo::new_return());
        path.push_info(0x080000ac, AddrInfo::new_return());

        (rz_core, path)
    }

    #[test]
    fn test_icall_discover() {
        let (core, path) = get_icall_test();
        let products = interpret(core, path);
        let mut expected = HashSet::new();
        expected.insert(ConcreteCall::new(0x0800005d, 0x080000b0));
        expected.insert(ConcreteCall::new(0x0800007a, 0x080000c0));
        expected.insert(ConcreteCall::new(0x08000097, 0x080000d0));
        assert!(products.concrete_calls.eq(&expected));
    }
}
