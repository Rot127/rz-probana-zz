// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#[cfg(test)]
mod tests {
    use binding::{
        get_rz_test_bin_path, get_test_bin_path, init_rizin_instance, rz_core_graph_icfg,
        wait_for_exlusive_core, GRzCore, RzCoreWrapper,
    };
    use rzil_abstr::interpreter::{AbstrVal, Const, MemOp};

    use crate::{
        bda::run_bda,
        bda_binding::{add_procedures_to_icfg, get_graph, setup_procedure_at_addr},
        flow_graphs::{FlowGraphOperations, NodeId},
        icfg::ICFG,
        state::BDAState,
    };

    #[test]
    pub fn test_setup_unmapped_procedure() {
        wait_for_exlusive_core!();

        let rz_core = RzCoreWrapper::new(init_rizin_instance("="));
        let mut unk_procedure = setup_procedure_at_addr(&rz_core.lock().unwrap(), 0x0);
        assert!(
            unk_procedure.is_some(),
            "Procedure was not intiazlized. But should be."
        );
        assert!(
            rz_core.lock().unwrap().run_cmd("f+ malloc @ 0x2"),
            "Running command failed."
        );
        unk_procedure = setup_procedure_at_addr(&rz_core.lock().unwrap(), 0x2);
        assert!(unk_procedure.is_some(), "Procedure was not intiazlized.");
        assert!(
            unk_procedure.unwrap().is_malloc(),
            "Procedure was not markes as malloc although the flag name suggests it."
        );
    }

    fn get_x86_discover_recurse() -> (GRzCore, ICFG) {
        let discover_o = get_test_bin_path().join("x86_discover_recurse.o");
        let rz_core = RzCoreWrapper::new(init_rizin_instance(
            discover_o.to_str().expect("Path wrong"),
        ));
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.entries", "0x08000040");
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.skip_questions", "true");
        let rz_icfg = unsafe { rz_core_graph_icfg(rz_core.lock().unwrap().get_ptr()) };
        let mut icfg = ICFG::new_graph(get_graph(rz_icfg));
        add_procedures_to_icfg(rz_core.clone(), &mut icfg);
        (rz_core, icfg)
    }

    #[test]
    fn test_x86_discover_recurse() {
        wait_for_exlusive_core!();

        let (core, mut icfg) = get_x86_discover_recurse();
        let mut state = BDAState::new(1, 2);
        assert!(icfg.get_procedures().len() == 2, "Incomplete iCFG");
        run_bda(core, &mut icfg, &mut state);
        icfg.dot_graph_to_stdout();

        assert_eq!(icfg.get_graph().edge_count(), 7, "Wrong number of edges");
        assert_eq!(icfg.get_graph().node_count(), 8, "Wrong number of nodes");
        let procs = icfg.get_procedures();
        let rec_nid_0 = NodeId::new(0, 0, 0x08000070);
        let rec_nid_1 = NodeId::new(1, 0, 0x08000070);
        let rec_nid_2 = NodeId::new(2, 0, 0x08000070);
        let rec_nid_3 = NodeId::new(3, 0, 0x08000070);
        let main_nid_0 = NodeId::new(0, 0, 0x08000040);
        let main_nid_1 = NodeId::new(1, 0, 0x08000040);
        let main_nid_2 = NodeId::new(2, 0, 0x08000040);
        let main_nid_3 = NodeId::new(3, 0, 0x08000040);
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        assert!(procs.contains_key(&rec_nid_0), "function {} not discovered.", rec_nid_0);
        assert!(procs.contains_key(&rec_nid_1), "function {} not discovered.", rec_nid_1);
        assert!(procs.contains_key(&rec_nid_2), "function {} not discovered.", rec_nid_2);
        assert!(procs.contains_key(&rec_nid_3), "function {} not discovered.", rec_nid_3);
        assert!(procs.contains_key(&main_nid_0), "function {} not discovered.", main_nid_0);
        assert!(procs.contains_key(&main_nid_1), "function {} not discovered.", main_nid_1);
        assert!(procs.contains_key(&main_nid_2), "function {} not discovered.", main_nid_2);
        assert!(procs.contains_key(&main_nid_3), "function {} not discovered.", main_nid_3);
        }

        icfg.dot_graph_to_stdout();
        // Main procedures
        let p = procs.get(&main_nid_0).unwrap();
        let cts = p.read().unwrap().get_cfg().get_all_call_targets();
        assert_eq!(cts.len(), 1, "Wrong number of call targets");
        assert_eq!(cts.get(0).unwrap().0, rec_nid_0, "Wrong call target");

        let p = procs.get(&main_nid_1).unwrap();
        let cts = p.read().unwrap().get_cfg().get_all_call_targets();
        assert_eq!(cts.len(), 1, "Wrong number of call targets");
        assert_eq!(cts.get(0).unwrap().0, rec_nid_1, "Wrong call target");

        let p = procs.get(&main_nid_2).unwrap();
        let cts = p.read().unwrap().get_cfg().get_all_call_targets();
        assert_eq!(cts.len(), 1, "Wrong number of call targets");
        assert_eq!(cts.get(0).unwrap().0, rec_nid_2, "Wrong call target");

        let p = procs.get(&main_nid_3).unwrap();
        let cts = p.read().unwrap().get_cfg().get_all_call_targets();
        assert_eq!(cts.len(), 1, "Wrong number of call targets");
        assert_eq!(cts.get(0).unwrap().0, rec_nid_3, "Wrong call target");

        // recurse procedures
        let p = procs.get(&rec_nid_0).unwrap();
        let cts = p.read().unwrap().get_cfg().get_all_call_targets();
        assert_eq!(cts.len(), 1, "Wrong number of call targets");
        assert_eq!(cts.get(0).unwrap().0, main_nid_1, "Wrong call target");

        let p = procs.get(&rec_nid_1).unwrap();
        let cts = p.read().unwrap().get_cfg().get_all_call_targets();
        assert_eq!(cts.len(), 1, "Wrong number of call targets");
        assert_eq!(cts.get(0).unwrap().0, main_nid_2, "Wrong call target");

        let p = procs.get(&rec_nid_2).unwrap();
        let cts = p.read().unwrap().get_cfg().get_all_call_targets();
        assert_eq!(cts.len(), 1, "Wrong number of call targets");
        assert_eq!(cts.get(0).unwrap().0, main_nid_3, "Wrong call target");

        assert!(procs.get(&rec_nid_3).is_some());
        assert!(procs
            .get(&rec_nid_3)
            .unwrap()
            .read()
            .unwrap()
            .get_cfg()
            .get_all_call_targets()
            .is_empty());
    }

    fn get_hexagon_discover_recurse() -> (GRzCore, ICFG) {
        let discover_o = get_test_bin_path().join("hexagon_discover_recurse.o");
        let rz_core = RzCoreWrapper::new(init_rizin_instance(
            discover_o.to_str().expect("Path wrong"),
        ));
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.entries", "0x08000040");
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.skip_questions", "true");
        let rz_icfg = unsafe { rz_core_graph_icfg(rz_core.lock().unwrap().get_ptr()) };
        let mut icfg = ICFG::new_graph(get_graph(rz_icfg));
        add_procedures_to_icfg(rz_core.clone(), &mut icfg);
        (rz_core, icfg)
    }

    #[test]
    fn test_hexagonl_discover_recurse() {
        wait_for_exlusive_core!();

        let (core, mut icfg) = get_hexagon_discover_recurse();
        let mut state = BDAState::new(1, 2);
        assert!(icfg.get_procedures().len() == 2, "Incomplete iCFG");
        run_bda(core, &mut icfg, &mut state);

        assert_eq!(icfg.get_graph().edge_count(), 7, "Wrong number of edges");
        assert_eq!(icfg.get_graph().node_count(), 8, "Wrong number of nodes");
        let procs = icfg.get_procedures();
        let rec_nid_0 = NodeId::new(0, 0, 0x08000080);
        let rec_nid_1 = NodeId::new(1, 0, 0x08000080);
        let rec_nid_2 = NodeId::new(2, 0, 0x08000080);
        let rec_nid_3 = NodeId::new(3, 0, 0x08000080);
        let main_nid_0 = NodeId::new(0, 0, 0x08000040);
        let main_nid_1 = NodeId::new(1, 0, 0x08000040);
        let main_nid_2 = NodeId::new(2, 0, 0x08000040);
        let main_nid_3 = NodeId::new(3, 0, 0x08000040);
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        assert!(procs.contains_key(&rec_nid_0), "function {} not discovered.", rec_nid_0);
        assert!(procs.contains_key(&rec_nid_1), "function {} not discovered.", rec_nid_1);
        assert!(procs.contains_key(&rec_nid_2), "function {} not discovered.", rec_nid_2);
        assert!(procs.contains_key(&rec_nid_3), "function {} not discovered.", rec_nid_3);
        assert!(procs.contains_key(&main_nid_0), "function {} not discovered.", main_nid_0);
        assert!(procs.contains_key(&main_nid_1), "function {} not discovered.", main_nid_1);
        assert!(procs.contains_key(&main_nid_2), "function {} not discovered.", main_nid_2);
        assert!(procs.contains_key(&main_nid_3), "function {} not discovered.", main_nid_3);
        }

        // Main procedures
        let p = procs.get(&main_nid_0).unwrap();
        let cts = p.read().unwrap().get_cfg().get_all_call_targets();
        assert_eq!(cts.len(), 1, "Wrong number of call targets");
        assert_eq!(cts.get(0).unwrap().0, rec_nid_0, "Wrong call target");

        let p = procs.get(&main_nid_1).unwrap();
        let cts = p.read().unwrap().get_cfg().get_all_call_targets();
        assert_eq!(cts.len(), 1, "Wrong number of call targets");
        assert_eq!(cts.get(0).unwrap().0, rec_nid_1, "Wrong call target");

        let p = procs.get(&main_nid_2).unwrap();
        let cts = p.read().unwrap().get_cfg().get_all_call_targets();
        assert_eq!(cts.len(), 1, "Wrong number of call targets");
        assert_eq!(cts.get(0).unwrap().0, rec_nid_2, "Wrong call target");

        let p = procs.get(&main_nid_3).unwrap();
        let cts = p.read().unwrap().get_cfg().get_all_call_targets();
        assert_eq!(cts.len(), 1, "Wrong number of call targets");
        assert_eq!(cts.get(0).unwrap().0, rec_nid_3, "Wrong call target");

        // recurse procedures
        let p = procs.get(&rec_nid_0).unwrap();
        let cts = p.read().unwrap().get_cfg().get_all_call_targets();
        assert_eq!(cts.len(), 1, "Wrong number of call targets");
        assert_eq!(cts.get(0).unwrap().0, main_nid_1, "Wrong call target");

        let p = procs.get(&rec_nid_1).unwrap();
        let cts = p.read().unwrap().get_cfg().get_all_call_targets();
        assert_eq!(cts.len(), 1, "Wrong number of call targets");
        assert_eq!(cts.get(0).unwrap().0, main_nid_2, "Wrong call target");

        let p = procs.get(&rec_nid_2).unwrap();
        let cts = p.read().unwrap().get_cfg().get_all_call_targets();
        assert_eq!(cts.len(), 1, "Wrong number of call targets");
        assert_eq!(cts.get(0).unwrap().0, main_nid_3, "Wrong call target");

        assert!(procs.get(&rec_nid_3).is_some());
        assert!(procs
            .get(&rec_nid_3)
            .unwrap()
            .read()
            .unwrap()
            .get_cfg()
            .get_all_call_targets()
            .is_empty());
    }

    fn get_x86_icall_malloc() -> (GRzCore, ICFG) {
        let discover_o = get_test_bin_path().join("x86_icall_malloc.o");
        let rz_core = RzCoreWrapper::new(init_rizin_instance(
            discover_o.to_str().expect("Path wrong"),
        ));
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.entries", "0x08000040");
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.skip_questions", "true");
        rz_core
            .lock()
            .unwrap()
            .run_cmd("f+ calloc @ 0x080004a0 ; f+ malloc @ 0x080004a8 ; f+ realloc @ 0x080004b0");
        let rz_icfg = unsafe { rz_core_graph_icfg(rz_core.lock().unwrap().get_ptr()) };
        let mut icfg = ICFG::new_graph(get_graph(rz_icfg));
        add_procedures_to_icfg(rz_core.clone(), &mut icfg);
        (rz_core, icfg)
    }

    #[test]
    fn test_x86_icall_malloc() {
        wait_for_exlusive_core!();

        let (core, mut icfg) = get_x86_icall_malloc();
        let mut state = BDAState::new(1, 3);
        assert_eq!(icfg.get_procedures().len(), 4, "Incomplete iCFG");
        run_bda(core, &mut icfg, &mut state);

        let mos = &state.mos;
        #[cfg_attr(rustfmt, rustfmt_skip)]
        {
        let heap_val_0 = MemOp::new(0x08000078, AbstrVal::new_heap(1, Const::get_zero(64), 0x080000ac));
        let heap_val_1 = MemOp::new(0x08000078, AbstrVal::new_heap(1, Const::get_zero(64), 0x080000c9));
        let heap_val_2 = MemOp::new(0x08000078, AbstrVal::new_heap(1, Const::get_zero(64), 0x080000dd));
        assert!(mos.contains(&heap_val_0), "HeapVal {} not in MOS", heap_val_0);
        assert!(mos.contains(&heap_val_1), "HeapVal {} not in MOS", heap_val_1);
        assert!(mos.contains(&heap_val_2), "HeapVal {} not in MOS", heap_val_2);
        }
    }

    fn get_hexagon_icall_malloc() -> (GRzCore, ICFG) {
        let discover_o = get_test_bin_path().join("hexagon_icall_malloc.o");
        let rz_core = RzCoreWrapper::new(init_rizin_instance(
            discover_o.to_str().expect("Path wrong"),
        ));
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.entries", "0x08000040");
        rz_core
            .lock()
            .unwrap()
            .set_conf_val("plugins.bda.skip_questions", "true");
        rz_core
            .lock()
            .unwrap()
            .run_cmd("f+ calloc @ 0x080002dc ; f+ malloc @ 0x80002e0 ; f+ realloc @ 0x80002e4");
        let rz_icfg = unsafe { rz_core_graph_icfg(rz_core.lock().unwrap().get_ptr()) };
        let mut icfg = ICFG::new_graph(get_graph(rz_icfg));
        add_procedures_to_icfg(rz_core.clone(), &mut icfg);
        (rz_core, icfg)
    }

    #[test]
    fn test_hexagon_icall_malloc() {
        wait_for_exlusive_core!();

        let (core, mut icfg) = get_hexagon_icall_malloc();
        let mut state = BDAState::new(1, 3);
        assert_eq!(icfg.get_procedures().len(), 4, "Incomplete iCFG");
        run_bda(core, &mut icfg, &mut state);

        let mos = &state.mos;
        let heap_val_0 = MemOp::new(
            0x08000084,
            AbstrVal::new_heap(1, Const::get_zero(32), 0x080000bc),
        );
        let heap_val_1 = MemOp::new(
            0x08000084,
            AbstrVal::new_heap(1, Const::get_zero(32), 0x080000d8),
        );
        let heap_val_2 = MemOp::new(
            0x08000084,
            AbstrVal::new_heap(1, Const::get_zero(32), 0x080000ec),
        );
        assert!(
            mos.contains(&heap_val_0),
            "HeapVal {} not in MOS",
            heap_val_0
        );
        assert!(
            mos.contains(&heap_val_1),
            "HeapVal {} not in MOS",
            heap_val_1
        );
        assert!(
            mos.contains(&heap_val_2),
            "HeapVal {} not in MOS",
            heap_val_2
        );
    }
}
