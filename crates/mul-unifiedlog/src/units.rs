// SPDX-License-Identifier: GPL-3.0-only
//! Work-unit discovery: walk preambles, pair catalogs with chunksets.

use crate::catalog::Catalog;
use crate::chunk::{TAG_CATALOG, TAG_CHUNKSET, TAG_HEADER};
use crate::header::TraceHeader;
use mul_core::{Cur, MulError, Result};
use mul_io::source::FileRef;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct WorkUnit {
    pub file: FileRef,
    pub file_id: u32,
    pub header_boot: Option<uuid::Uuid>,
    pub header_numer: u32,
    pub header_denom: u32,
    pub catalog_offset: usize,
    pub catalog_len: usize,
    pub chunkset_offset: usize,
    pub chunkset_len: usize,
    pub catalog_sub_idx: usize,
    pub ct_min: u64,
    pub ct_max: u64,
}

#[derive(Debug, Default, Clone)]
pub struct Tracev3Stats {
    pub files: usize,
    pub boots: usize,
    pub chunk_count: usize,
    pub header_count: usize,
    pub catalog_count: usize,
    pub chunkset_count: usize,
    pub unit_count: usize,
    pub total_data_bytes: u64,
    pub firehose_entries: u64,
    pub span_start_ns: Option<i64>,
    pub span_end_ns: Option<i64>,
    pub boot_uuids: Vec<String>,
    pub build: Option<String>,
    pub hardware_model: Option<String>,
}

impl Tracev3Stats {
    pub fn merge(&mut self, other: Tracev3Stats) {
        self.files += other.files;
        self.chunk_count += other.chunk_count;
        self.header_count += other.header_count;
        self.catalog_count += other.catalog_count;
        self.chunkset_count += other.chunkset_count;
        self.unit_count += other.unit_count;
        self.total_data_bytes += other.total_data_bytes;
        self.firehose_entries += other.firehose_entries;
        for u in other.boot_uuids {
            if !self.boot_uuids.contains(&u) {
                self.boot_uuids.push(u);
            }
        }
        if self.build.is_none() {
            self.build = other.build;
        }
        if self.hardware_model.is_none() {
            self.hardware_model = other.hardware_model;
        }
        self.span_start_ns = match (self.span_start_ns, other.span_start_ns) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        self.span_end_ns = match (self.span_end_ns, other.span_end_ns) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ChunkPreamble {
    pub tag: u32,
    pub subtag: u32,
    pub data_size: u64,
    pub offset: usize,
}

/// Scan one tracev3 file into work units (no decompression).
pub fn scan_file(
    file: &FileRef,
    file_id: u32,
    data: &[u8],
) -> Result<(Tracev3Stats, Vec<WorkUnit>, Option<TraceHeader>)> {
    let mut c = Cur::new(data);
    let mut stats = Tracev3Stats {
        files: 1,
        ..Default::default()
    };
    let mut header: Option<TraceHeader> = None;
    let mut pending_catalog: Option<(usize, usize, Catalog)> = None;
    let mut next_sub = 0usize;
    let mut units = Vec::new();

    while c.remaining() >= 16 {
        let offset = c.pos();
        let tag = match c.u32_le() {
            Ok(t) => t,
            Err(_) => break,
        };
        let subtag = match c.u32_le() {
            Ok(t) => t,
            Err(_) => break,
        };
        let data_size = match c.u64_le() {
            Ok(t) => t,
            Err(_) => break,
        };
        if data_size > c.remaining() as u64 {
            break;
        }
        let _ = (ChunkPreamble {
            tag,
            subtag,
            data_size,
            offset,
        },);
        stats.chunk_count += 1;
        stats.total_data_bytes += data_size;
        let body_off = c.pos();
        let body = c.bytes(data_size as usize).map_err(MulError::from)?;

        match tag {
            TAG_HEADER => {
                stats.header_count += 1;
                if let Ok(h) = TraceHeader::parse(body) {
                    if let Some(u) = h.boot_uuid {
                        let s = u.to_string();
                        if !stats.boot_uuids.contains(&s) {
                            stats.boot_uuids.push(s);
                        }
                    }
                    if stats.build.is_none() {
                        stats.build = h.build.clone();
                    }
                    if stats.hardware_model.is_none() {
                        stats.hardware_model = h.hardware_model.clone();
                    }
                    header = Some(h);
                }
            }
            TAG_CATALOG => {
                stats.catalog_count += 1;
                match Catalog::parse(body) {
                    Ok(cat) => {
                        next_sub = 0;
                        pending_catalog = Some((body_off, body.len(), cat));
                    }
                    Err(_) => pending_catalog = None,
                }
            }
            TAG_CHUNKSET => {
                stats.chunkset_count += 1;
                if let Some((cat_off, cat_len, ref cat)) = pending_catalog {
                    if next_sub < cat.subchunks.len() {
                        let sub = &cat.subchunks[next_sub];
                        let boot = header.as_ref().and_then(|h| h.boot_uuid);
                        let (numer, denom) = header
                            .as_ref()
                            .map(|h| (h.numer, h.denom.max(1)))
                            .unwrap_or((1, 1));
                        units.push(WorkUnit {
                            file: file.clone(),
                            file_id,
                            header_boot: boot,
                            header_numer: numer,
                            header_denom: denom,
                            catalog_offset: cat_off,
                            catalog_len: cat_len,
                            chunkset_offset: body_off,
                            chunkset_len: body.len(),
                            catalog_sub_idx: next_sub,
                            ct_min: sub.ct_start,
                            ct_max: sub.ct_end,
                        });
                        next_sub += 1;
                    }
                }
            }
            _ => {}
        }
        if let Err(e) = c.align(8) {
            let _ = e;
            break;
        }
    }
    stats.unit_count = units.len();
    Ok((stats, units, header))
}

pub fn walk_preambles(data: &[u8]) -> Result<Tracev3Stats> {
    let dummy = FileRef::new("_");
    let (stats, _, _) = scan_file(&dummy, 0, data)?;
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_ok() {
        let s = walk_preambles(&[]).unwrap();
        assert_eq!(s.chunk_count, 0);
    }

    #[test]
    fn one_header_chunk() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1000u32.to_le_bytes());
        data.extend_from_slice(&0x11u32.to_le_bytes());
        // minimal header body that parse can tolerate — use zeros of size 40
        let body = vec![0u8; 40];
        data.extend_from_slice(&(body.len() as u64).to_le_bytes());
        data.extend_from_slice(&body);
        let s = walk_preambles(&data).unwrap();
        assert_eq!(s.header_count, 1);
    }
}
