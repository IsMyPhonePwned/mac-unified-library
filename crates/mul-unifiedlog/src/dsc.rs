// SPDX-License-Identifier: GPL-3.0-only
//! Shared-cache strings (dsc) — layout from libyal dtformats. Ranges sorted + binary-searched.

use mul_core::{Cur, FormatError};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone)]
struct Range {
    range_offset: u64,
    range_size: u32,
    data_offset: u32,
    uuid_index: usize,
}

#[derive(Debug, Clone)]
struct UuidDesc {
    #[allow(dead_code)]
    text_offset: u64,
    #[allow(dead_code)]
    text_size: u32,
    uuid: Uuid,
    path_offset: u32,
}

#[derive(Debug, Clone)]
pub struct Dsc {
    ranges: Vec<Range>, // sorted by range_offset
    uuids: Vec<UuidDesc>,
    data: Arc<[u8]>,
}

impl Dsc {
    pub fn parse(data: &[u8]) -> Result<Self, FormatError> {
        let mut c = Cur::new(data);
        let mag = c.bytes(4)?;
        if mag != b"hcsd" {
            return Err(FormatError::new(0, "bad dsc magic"));
        }
        let major = c.u16_le()?;
        let _minor = c.u16_le()?;
        let range_count = c.u32_le()? as usize;
        let uuid_count = c.u32_le()? as usize;

        let mut ranges = Vec::with_capacity(range_count);
        if major >= 2 {
            for _ in 0..range_count {
                let range_offset = c.u64_le()?;
                let data_offset = c.u32_le()?;
                let range_size = c.u32_le()?;
                let uuid_index = c.u64_le()? as usize;
                ranges.push(Range {
                    range_offset,
                    range_size,
                    data_offset,
                    uuid_index,
                });
            }
        } else {
            for _ in 0..range_count {
                let uuid_index = c.u32_le()? as usize;
                let range_offset = c.u32_le()? as u64;
                let data_offset = c.u32_le()?;
                let range_size = c.u32_le()?;
                ranges.push(Range {
                    range_offset,
                    range_size,
                    data_offset,
                    uuid_index,
                });
            }
        }

        let mut uuids = Vec::with_capacity(uuid_count);
        if major >= 2 {
            for _ in 0..uuid_count {
                let text_offset = c.u64_le()?;
                let text_size = c.u32_le()?;
                let uuid = Uuid::from_bytes(c.uuid_bytes()?);
                let path_offset = c.u32_le()?;
                uuids.push(UuidDesc {
                    text_offset,
                    text_size,
                    uuid,
                    path_offset,
                });
            }
        } else {
            for _ in 0..uuid_count {
                let text_offset = c.u32_le()? as u64;
                let text_size = c.u32_le()?;
                let uuid = Uuid::from_bytes(c.uuid_bytes()?);
                let path_offset = c.u32_le()?;
                uuids.push(UuidDesc {
                    text_offset,
                    text_size,
                    uuid,
                    path_offset,
                });
            }
        }

        ranges.sort_by_key(|r| r.range_offset);
        Ok(Self {
            ranges,
            uuids,
            data: Arc::from(data.to_vec()),
        })
    }

    /// Look up format string for shared-cache offset.
    pub fn string_at(&self, offset: u64) -> Option<&str> {
        let idx = match self
            .ranges
            .binary_search_by_key(&offset, |r| r.range_offset)
        {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };
        let r = &self.ranges[idx];
        if offset < r.range_offset || offset >= r.range_offset + r.range_size as u64 {
            return None;
        }
        let rel = (offset - r.range_offset) as usize;
        let pos = r.data_offset as usize + rel;
        cstr_at(&self.data, pos)
    }

    pub fn path_for_offset(&self, offset: u64) -> Option<&str> {
        let idx = match self
            .ranges
            .binary_search_by_key(&offset, |r| r.range_offset)
        {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };
        let r = &self.ranges[idx];
        if offset < r.range_offset || offset >= r.range_offset + r.range_size as u64 {
            return None;
        }
        let u = self.uuids.get(r.uuid_index)?;
        cstr_at(&self.data, u.path_offset as usize)
    }

    pub fn uuid_path(&self, uuid: Uuid) -> Option<&str> {
        self.uuids
            .iter()
            .find(|u| u.uuid == uuid)
            .and_then(|u| cstr_at(&self.data, u.path_offset as usize))
    }
}

fn cstr_at(buf: &[u8], pos: usize) -> Option<&str> {
    if pos >= buf.len() {
        return None;
    }
    let end = buf[pos..].iter().position(|&b| b == 0).map(|i| pos + i)?;
    std::str::from_utf8(&buf[pos..end]).ok()
}
