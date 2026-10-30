// SPDX-License-Identifier: GPL-3.0-only

use mul_core::FormatError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum UlError {
    #[error(transparent)]
    Format(#[from] FormatError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Msg(String),
}

impl From<UlError> for mul_core::MulError {
    fn from(e: UlError) -> Self {
        match e {
            UlError::Format(f) => mul_core::MulError::Format(f),
            UlError::Io(i) => mul_core::MulError::Io(i),
            UlError::Msg(m) => mul_core::MulError::Msg(m),
        }
    }
}
