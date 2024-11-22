// SPDX-FileCopyrightText: 2023 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

mod bda;
pub mod bda_binding;
pub mod cfg;
pub mod flow_graphs;
pub mod icfg;
mod path_sampler;
mod post_analysis;
pub mod state;
mod test_flow_graphs;
pub mod test_graphs;
mod test_path_sampler;
mod test_post_analysis;
mod test_unit;
mod test_weight;
pub mod weight;
