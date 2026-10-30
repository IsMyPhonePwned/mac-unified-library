// SPDX-License-Identifier: GPL-3.0-only

use thiserror::Error;

/// Bounds-checked binary parse failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("format error at offset {offset}: {what}")]
pub struct FormatError {
    pub offset: usize,
    pub what: String,
}

impl FormatError {
    pub fn new(offset: usize, what: impl Into<String>) -> Self {
        Self {
            offset,
            what: what.into(),
        }
    }
}

#[derive(Debug, Error)]
pub enum MulError {
    #[error(transparent)]
    Format(#[from] FormatError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Msg(String),
    #[error("filter: {0}")]
    Filter(String),
    #[error("sqlite unavailable on this target")]
    SqliteUnavailable,
    #[error("module not found: {0}")]
    ModuleNotFound(String),
    #[error("cancelled")]
    Cancelled,
}

pub type Result<T> = std::result::Result<T, MulError>;

impl MulError {
    pub fn msg(s: impl Into<String>) -> Self {
        Self::Msg(s.into())
    }
}
