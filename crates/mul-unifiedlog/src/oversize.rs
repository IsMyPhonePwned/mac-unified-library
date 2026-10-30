// SPDX-License-Identifier: GPL-3.0-only
//! Oversize chunk collection for two-phase firehose resolution.

use mul_core::{Cur, FormatError};
use std::collections::HashMap;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct OversizeKey {
    pub first_proc_id: u64,
    pub second_proc_id: u32,
    pub data_ref: u32,
}

#[derive(Debug, Clone)]
pub struct OversizeRecord {
    pub continuous_time: u64,
    pub public_data: Vec<u8>,
    pub private_data: Vec<u8>,
}

pub type OversizeMap = HashMap<OversizeKey, OversizeRecord>;

/// Parse one oversize chunk body (tag 0x6002 data).
pub fn parse_oversize(data: &[u8]) -> Result<(OversizeKey, OversizeRecord), FormatError> {
    let mut c = Cur::new(data);
    let first_proc_id = c.u64_le()?;
    let second_proc_id = c.u32_le()?;
    let _ttl = c.u8()?;
    let _unk = c.u8()?;
    let _unk2 = c.u16_le()?;
    let continuous_time = c.u64_le()?;
    let data_ref = c.u32_le()?;
    let public_size = c.u16_le()? as usize;
    let private_size = c.u16_le()? as usize;
    let public_data = c.bytes(public_size)?.to_vec();
    let private_data = if private_size > 0 && c.remaining() >= private_size {
        c.bytes(private_size)?.to_vec()
    } else {
        Vec::new()
    };
    Ok((
        OversizeKey {
            first_proc_id,
            second_proc_id,
            data_ref,
        },
        OversizeRecord {
            continuous_time,
            public_data,
            private_data,
        },
    ))
}
