// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#[cfg(test)]
mod tests {
    use crate::{flow_graphs::Address, state::BDAState};

    #[test]
    pub fn test_state_ranges() {
        let mut state = BDAState::new(0, 0, 0, 0);
        // By default we should have 0x0 - Address::MAX
        assert!(state.addr_in_ranges(&0));
        assert!(state.addr_in_ranges(&Address::MAX));
        state.set_ranges(Vec::from([0x1..=0x2, 0x55..=0xfff]));
        assert!(!state.addr_in_ranges(&0));
        assert!(!state.addr_in_ranges(&Address::MAX));
        assert!(state.addr_in_ranges(&0x1));
        assert!(state.addr_in_ranges(&0x2));
        assert!(state.addr_in_ranges(&0x55));
        assert!(state.addr_in_ranges(&0xfff));
        assert!(state.addr_in_ranges(&0xee));
        state.set_ranges(Vec::from([0x5..=0x5]));
        assert!(state.addr_in_ranges(&0x5));
        assert!(!state.addr_in_ranges(&0x6));
        assert!(!state.addr_in_ranges(&0x1));
    }
}
