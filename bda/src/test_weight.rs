// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#[cfg(test)]
mod tests {
    use crate::weight::{u128_to_integer_wid, WeightMap};

    #[test]
    fn test_add() {
        let wmap = &WeightMap::new();
        assert_eq!(wmap.read().unwrap().num_weights(), 2);
        assert_eq!(wmap.read().unwrap().num_constants(), 2);
        let n0 = wmap.read().unwrap().get_zero();
        assert_eq!(wmap.read().unwrap().num_weights(), 2);
        assert_eq!(wmap.read().unwrap().num_constants(), 2);
        let n1 = wmap.read().unwrap().get_one();
        assert_eq!(wmap.read().unwrap().num_weights(), 2);
        assert_eq!(wmap.read().unwrap().num_constants(), 2);

        let mut res = n0.add(&n0, wmap);
        assert!(res.eq(&n0));
        assert!(res.eq_w(&n0, wmap));
        assert!(res.eq_usize(0, wmap));
        assert_eq!(wmap.read().unwrap().num_weights(), 2);
        assert_eq!(wmap.read().unwrap().num_constants(), 2);

        res = n0.add(&n1, wmap);
        assert!(res.eq(&n1));
        assert!(res.eq_w(&n1, wmap));
        assert!(res.eq_usize(1, wmap));
        assert_eq!(wmap.read().unwrap().num_weights(), 2);
        assert_eq!(wmap.read().unwrap().num_constants(), 2);

        res = n1.add(&n1, wmap);
        assert_eq!(wmap.read().unwrap().num_weights(), 3);
        assert_eq!(wmap.read().unwrap().num_constants(), 3);
        let n2 = wmap
            .read()
            .unwrap()
            .get_wid_of_u128(2)
            .expect("Weight was not saved during addition.");
        assert!(res.eq(&n2));
        assert!(res.eq_w(&n2, wmap));
        assert!(res.eq_usize(2, wmap));

        let n256max = wmap.write().unwrap().add_root_const_digits(
            &[
                0xffffffffffffffff_ffffffffffffffffu128,
                0xffffffffffffffff_ffffffffffffffffu128,
            ],
            rug::integer::Order::Msf,
        );
        assert_eq!(wmap.read().unwrap().num_weights(), 4);
        assert_eq!(wmap.read().unwrap().num_constants(), 4);
        res = n1.add(&n256max, wmap);
        assert_eq!(wmap.read().unwrap().num_weights(), 5);
        assert_eq!(wmap.read().unwrap().num_constants(), 5);

        let n257bit0 = wmap
            .read()
            .unwrap()
            .get_wid_of_digits(
                &[
                    0x1u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                rug::integer::Order::Msf,
            )
            .expect("Weight was not added during addition.");
        assert!(res.eq(&n257bit0));
        assert!(res.eq_w(&n257bit0, wmap));

        res = n1.add(&n257bit0, wmap);
        assert_eq!(wmap.read().unwrap().num_weights(), 6);
        assert_eq!(wmap.read().unwrap().num_constants(), 6);

        let n257bit1 = wmap
            .read()
            .unwrap()
            .get_wid_of_digits(
                &[
                    0x1u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                ],
                rug::integer::Order::Msf,
            )
            .expect("Weight was not added during addition.");
        assert!(res.eq(&n257bit1));
        assert!(res.eq_w(&n257bit1, wmap));

        wmap.read().unwrap().print();

        // Clean the whole constant map and check if the operations still work.
        wmap.write().unwrap().clear_derived_constants();

        assert_eq!(wmap.read().unwrap().num_weights(), 6);
        assert_eq!(wmap.read().unwrap().num_constants(), 3); // the 256bit number is now also a root const.
        let n0 = wmap.read().unwrap().get_zero();
        let n1 = wmap.read().unwrap().get_one();

        let mut res = n0.add(&n0, wmap);
        assert!(res.eq(&n0));
        assert!(res.eq_w(&n0, wmap));
        assert!(res.eq_usize(0, wmap));
        assert_eq!(wmap.read().unwrap().num_weights(), 6);
        assert_eq!(wmap.read().unwrap().num_constants(), 3);

        res = n0.add(&n1, wmap);
        assert!(res.eq(&n1));
        assert!(res.eq_w(&n1, wmap));
        assert!(res.eq_usize(1, wmap));
        assert_eq!(wmap.read().unwrap().num_weights(), 6);
        assert_eq!(wmap.read().unwrap().num_constants(), 3);

        res = n1.add(&n1, wmap);
        assert_eq!(wmap.read().unwrap().num_weights(), 6);
        assert_eq!(wmap.read().unwrap().num_constants(), 4);
        assert!(res.eq(&n2));
        assert!(res.eq_w(&n2, wmap));
        assert!(res.eq_usize(2, wmap));

        res = n1.add(&n256max, wmap);
        assert_eq!(wmap.read().unwrap().num_weights(), 6);
        assert_eq!(wmap.read().unwrap().num_constants(), 5);

        assert!(res.eq(&n257bit0));
        assert!(res.eq_w(&n257bit0, wmap));

        res = n1.add(&n257bit0, wmap);
        assert_eq!(wmap.read().unwrap().num_weights(), 6);
        assert_eq!(wmap.read().unwrap().num_constants(), 6);

        let n257bit1 = wmap
            .read()
            .unwrap()
            .get_wid_of_digits(
                &[
                    0x1u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                ],
                rug::integer::Order::Msf,
            )
            .expect("Weight was not added during addition.");
        assert!(res.eq(&n257bit1));
        assert!(res.eq_w(&n257bit1, wmap));
    }

    #[test]
    #[should_panic = "WeightMap is inconsistent! WeightID should have been in the map."]
    fn test_missing_root_const() {
        let wmap = &WeightMap::new();
        let n0 = wmap.read().unwrap().get_zero();
        let (_, n2) = u128_to_integer_wid(2);
        n0.add(&n2, wmap);
    }
}
