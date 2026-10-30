// SPDX-License-Identifier: GPL-3.0-only
//! Core types for mac-unified-library: events, values, interner, filters, and parallelism.

#![forbid(unsafe_code)]

pub mod cur;
pub mod error;
pub mod event;
pub mod filter;
pub mod interner;
pub mod par;
pub mod predicate;
pub mod sink;
pub mod val;

pub use cur::Cur;
pub use error::{FormatError, MulError, Result};
pub use event::{
    EntityKey, Event, EventKind, Evidence, LazyText, Level, SourceId, TsQuality,
};
pub use filter::Filter;
pub use interner::{Interner, Sym};
pub use sink::EventSink;
pub use val::Val;
