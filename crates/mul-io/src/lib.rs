// SPDX-License-Identifier: GPL-3.0-only
//! Source abstraction, path normalisation, gzip helpers.

#![forbid(unsafe_code)]

pub mod bytes;
pub mod gzip;
pub mod path;
pub mod source;

pub use bytes::Bytes;
pub use path::norm_path;
pub use source::{DirSource, FileRef, MapSource, SourceError};
