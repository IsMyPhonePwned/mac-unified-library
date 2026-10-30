// SPDX-License-Identifier: GPL-3.0-only
//! Facade crate: `Session` API and re-exports.

#![forbid(unsafe_code)]

pub mod session;

pub use mul_apollo::{ModuleRegistry, ModuleSet, SqliteRuntime};
pub use mul_core::{Event, Filter, Interner, MulError, Result, Val};
pub use mul_correlate::analysers::AnalyserId;
pub use mul_correlate::{Store, SystemOverview};
pub use mul_ingest::{detect_input, Input, InputKind};
pub use mul_unifiedlog::{Options as LogOptions, OwnedLogEvent, UnifiedLog};
pub use session::{ParseReport, Session, SessionBuilder, SessionStats};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
