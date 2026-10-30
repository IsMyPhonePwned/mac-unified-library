// SPDX-License-Identifier: GPL-3.0-only
//! Input discovery and adapters (-ng, logarchive, FFS, live).

#![forbid(unsafe_code)]

pub mod detect;
pub mod input;

#[cfg(feature = "ng")]
pub mod ng;

pub use detect::detect_input;
pub use input::{Input, InputKind};
