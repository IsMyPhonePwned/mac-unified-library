// SPDX-License-Identifier: GPL-3.0-only
//! Entity store, map-reduce merge, analysers, system overview.

#![forbid(unsafe_code)]

pub mod analysers;
pub mod anomalies;
pub mod ioc;
pub mod normalize;
pub mod overview;
pub mod plan;
pub mod store;
pub mod tcc_labels;

pub use overview::{DeviceInfo, SystemOverview};
pub use store::{PartialStore, Store};
