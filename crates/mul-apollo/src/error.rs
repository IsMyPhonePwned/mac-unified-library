// SPDX-License-Identifier: GPL-3.0-only

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApolloError {
    #[error("module parse: {0}")]
    Parse(String),
    #[error("sqlite: {0}")]
    Sqlite(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("sqlite unavailable")]
    SqliteUnavailable,
    #[error("{0}")]
    Msg(String),
}

impl From<ApolloError> for mul_core::MulError {
    fn from(e: ApolloError) -> Self {
        match e {
            ApolloError::SqliteUnavailable => mul_core::MulError::SqliteUnavailable,
            other => mul_core::MulError::Msg(other.to_string()),
        }
    }
}
