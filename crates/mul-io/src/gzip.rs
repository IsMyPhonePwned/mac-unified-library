// SPDX-License-Identifier: GPL-3.0-only

use crate::bytes::Bytes;
use flate2::read::GzDecoder;
use std::io::Read;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GzipError {
    #[error("gzip decode: {0}")]
    Io(#[from] std::io::Error),
}

pub fn inflate_gz(input: &[u8]) -> Result<Bytes, GzipError> {
    let mut dec = GzDecoder::new(input);
    let mut out = Vec::new();
    dec.read_to_end(&mut out)?;
    Ok(Bytes::from_owned(out))
}
