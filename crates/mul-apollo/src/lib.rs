// SPDX-License-Identifier: GPL-3.0-only
//! APOLLO-NG: module IR, legacy importer, SQLite runtime, Biome/SEGB.

#![forbid(unsafe_code)]

pub mod epoch;
pub mod error;
pub mod legacy;
pub mod module;
pub mod protolite;
pub mod registry;
pub mod runtime;
pub mod schema;
pub mod toml_v2;

#[cfg(feature = "biome")]
pub mod biome;
#[cfg(feature = "biome")]
pub mod segb;

pub use epoch::Epoch;
pub use error::ApolloError;
pub use legacy::parse_legacy_module;
pub use module::{
    Module, ModuleSet, Platform, SourceSpec, TimestampSpec, Variant, VariantBody,
};
pub use registry::ModuleRegistry;
pub use runtime::{path_matches_module, ModuleRunStatus, RunOptions, SqliteRuntime};
pub use toml_v2::{module_to_toml, parse_module_toml};
