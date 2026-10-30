// SPDX-License-Identifier: GPL-3.0-only
//! SEGB v1/v2 readers (Biome stream files).

use mul_core::{Cur, FormatError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegbVersion {
    V1,
    V2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryState {
    Written,
    Deleted,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct SegbEntry {
    pub state: EntryState,
    /// Cocoa epoch seconds when known (recorded write time).
    pub time_cocoa: Option<f64>,
    pub payload: Vec<u8>,
    pub offset: usize,
}

#[derive(Debug, Clone)]
pub struct SegbFile {
    pub version: SegbVersion,
    pub entries: Vec<SegbEntry>,
}

pub fn detect_version(data: &[u8]) -> SegbVersion {
    if data.len() >= 4 && &data[0..4] == b"SEGB" {
        SegbVersion::V2
    } else {
        SegbVersion::V1
    }
}

pub fn parse(data: &[u8]) -> Result<SegbFile, FormatError> {
    match detect_version(data) {
        SegbVersion::V2 => parse_v2(data),
        SegbVersion::V1 => parse_v1(data),
    }
}

fn parse_v2(data: &[u8]) -> Result<SegbFile, FormatError> {
    let mut c = Cur::new(data);
    let mag = c.bytes(4)?;
    if mag != b"SEGB" {
        return Err(FormatError::new(0, "not SEGB v2"));
    }
    // Community layout (approx): after magic — version/flags, entry count, creation time, …
    // Then entries; trailer at end locates them. Be tolerant.
    let _unk0 = c.u32_le().unwrap_or(0);
    let entry_count = c.u32_le().unwrap_or(0) as usize;
    let creation = c.f64_le().ok();
    let mut entries = Vec::new();

    // Prefer trailer walk if present: look for repeating offset table near EOF.
    // Fallback: scan remaining as length-prefixed blobs.
    if let Some(from_trailer) = try_v2_trailer(data, entry_count) {
        entries = from_trailer;
    } else {
        while c.remaining() >= 8 && entries.len() < entry_count.max(1).saturating_mul(4) {
            let start = c.pos();
            let state_raw = c.u32_le()?;
            let size = c.u32_le()? as usize;
            if size > c.remaining() || size > 16 * 1024 * 1024 {
                break;
            }
            let payload = c.bytes(size)?.to_vec();
            let state = match state_raw {
                1 => EntryState::Written,
                2 => EntryState::Deleted,
                _ => EntryState::Unknown,
            };
            entries.push(SegbEntry {
                state,
                time_cocoa: creation,
                payload,
                offset: start,
            });
            let _ = c.align(8);
        }
    }

    Ok(SegbFile {
        version: SegbVersion::V2,
        entries,
    })
}

fn try_v2_trailer(data: &[u8], hint_count: usize) -> Option<Vec<SegbEntry>> {
    if data.len() < 64 || hint_count == 0 || hint_count > 1_000_000 {
        return None;
    }
    // Trailer: last hint_count * 8 bytes as u32 offset + u32 size pairs (hypothesis).
    let table_bytes = hint_count.checked_mul(8)?;
    if table_bytes + 32 > data.len() {
        return None;
    }
    let start = data.len() - table_bytes;
    let mut entries = Vec::with_capacity(hint_count);
    let mut c = Cur::at(data, start).ok()?;
    for _ in 0..hint_count {
        let off = c.u32_le().ok()? as usize;
        let size = c.u32_le().ok()? as usize;
        if off + size > data.len() || size > 16 * 1024 * 1024 {
            return None;
        }
        let payload = data[off..off + size].to_vec();
        entries.push(SegbEntry {
            state: EntryState::Written,
            time_cocoa: None,
            payload,
            offset: off,
        });
    }
    Some(entries)
}

fn parse_v1(data: &[u8]) -> Result<SegbFile, FormatError> {
    // v1: no magic; stream of records with cocoa timestamps — best-effort scan.
    let mut c = Cur::new(data);
    let mut entries = Vec::new();
    while c.remaining() >= 16 {
        let start = c.pos();
        let ts = c.f64_le()?;
        let size = c.u32_le()? as usize;
        let state_raw = c.u32_le()?;
        if size > c.remaining() || size > 16 * 1024 * 1024 {
            break;
        }
        let payload = c.bytes(size)?.to_vec();
        entries.push(SegbEntry {
            state: match state_raw {
                0 => EntryState::Written,
                1 => EntryState::Deleted,
                _ => EntryState::Unknown,
            },
            time_cocoa: if ts.is_finite() { Some(ts) } else { None },
            payload,
            offset: start,
        });
        let _ = c.align(8);
    }
    Ok(SegbFile {
        version: SegbVersion::V1,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_v2_magic() {
        let mut d = b"SEGB".to_vec();
        d.extend_from_slice(&0u32.to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes());
        d.extend_from_slice(&0f64.to_le_bytes());
        assert_eq!(detect_version(&d), SegbVersion::V2);
        let f = parse(&d).unwrap();
        assert_eq!(f.version, SegbVersion::V2);
    }
}
