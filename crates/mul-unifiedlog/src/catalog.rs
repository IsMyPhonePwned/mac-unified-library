// SPDX-License-Identifier: GPL-3.0-only
//! Catalog chunk (tag 0x600B) — layout from libyal dtformats.

use mul_core::{Cur, FormatError};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct CatalogSubChunk {
    pub ct_start: u64,
    pub ct_end: u64,
    pub uncompressed_size: u32,
    pub compression: u32,
    pub proc_indexes: Vec<u16>,
}

#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub entry_index: u16,
    pub main_uuid_idx: u16,
    pub dsc_uuid_idx: u16,
    pub first_proc_id: u64,
    pub second_proc_id: u32,
    pub pid: u32,
    pub euid: u32,
    /// subsystem id → (subsystem_off, category_off) relative to strings blob
    pub subsystems: Vec<(u16, u16, u16)>,
}

#[derive(Debug, Clone)]
pub struct Catalog {
    pub earliest_firehose_ct: u64,
    pub uuids: Vec<Uuid>,
    pub strings: Vec<u8>,
    pub procs: Vec<ProcInfo>,
    pub subchunks: Vec<CatalogSubChunk>,
}

impl Catalog {
    pub fn parse(data: &[u8]) -> Result<Self, FormatError> {
        let mut c = Cur::new(data);
        let strings_off = c.u16_le()? as usize;
        let procs_off = c.u16_le()? as usize;
        let proc_count = c.u16_le()? as usize;
        let subchunks_off = c.u16_le()? as usize;
        let subchunk_count = c.u16_le()? as usize;
        let _pad = c.bytes(6)?;
        let earliest = c.u64_le()?;

        // UUID table starts here (offset 24 from chunk data start = pos after earliest).
        let uuid_table_start = c.pos();
        // Number of UUIDs = strings_off / 16
        if !strings_off.is_multiple_of(16) {
            return Err(FormatError::new(
                uuid_table_start,
                "catalog strings_off not multiple of 16",
            ));
        }
        let uuid_count = strings_off / 16;
        let mut uuids = Vec::with_capacity(uuid_count);
        for _ in 0..uuid_count {
            let b = c.uuid_bytes()?;
            uuids.push(Uuid::from_bytes(b));
        }

        // Absolute offsets relative to uuid table start
        let abs = |rel: usize| uuid_table_start + rel;
        let strings_abs = abs(strings_off);
        let procs_abs = abs(procs_off);
        let subchunks_abs = abs(subchunks_off);

        if strings_abs > data.len() || procs_abs > data.len() || subchunks_abs > data.len() {
            return Err(FormatError::new(0, "catalog offsets out of range"));
        }

        let strings_end = procs_abs.min(data.len());
        let strings = data[strings_abs..strings_end].to_vec();

        c.set_pos(procs_abs)?;
        let mut procs = Vec::with_capacity(proc_count);
        for _ in 0..proc_count {
            let start = c.pos();
            let entry_index = c.u16_le()?;
            let _unk = c.u16_le()?;
            let main_uuid_idx = c.u16_le()?;
            let dsc_uuid_idx = c.u16_le()?;
            let first_proc_id = c.u64_le()?;
            let second_proc_id = c.u32_le()?;
            let pid = c.u32_le()?;
            let euid = c.u32_le()?;
            let _unk2 = c.u32_le()?;
            let uuidinfo_count = c.u32_le()? as usize;
            let _unk3 = c.u32_le()?;
            c.skip(uuidinfo_count.saturating_mul(16))?;
            let sub_count = c.u32_le()? as usize;
            let _unk4 = c.u32_le()?;
            let mut subsystems = Vec::with_capacity(sub_count);
            for _ in 0..sub_count {
                let id = c.u16_le()?;
                let sub_off = c.u16_le()?;
                let cat_off = c.u16_le()?;
                subsystems.push((id, sub_off, cat_off));
            }
            // Align entry to 8
            let consumed = c.pos() - start;
            let pad = (8 - (consumed % 8)) % 8;
            if pad > 0 && c.remaining() >= pad {
                c.skip(pad)?;
            }
            procs.push(ProcInfo {
                entry_index,
                main_uuid_idx,
                dsc_uuid_idx,
                first_proc_id,
                second_proc_id,
                pid,
                euid,
                subsystems,
            });
        }

        c.set_pos(subchunks_abs)?;
        let mut subchunks = Vec::with_capacity(subchunk_count);
        for _ in 0..subchunk_count {
            let ct_start = c.u64_le()?;
            let ct_end = c.u64_le()?;
            let uncompressed_size = c.u32_le()?;
            let compression = c.u32_le()?;
            let n_idx = c.u32_le()? as usize;
            let mut proc_indexes = Vec::with_capacity(n_idx);
            for _ in 0..n_idx {
                proc_indexes.push(c.u16_le()?);
            }
            let n_off = c.u32_le()? as usize;
            c.skip(n_off.saturating_mul(2))?;
            // pad to 8
            let rem = c.pos() % 8;
            if rem != 0 {
                let pad = 8 - rem;
                if c.remaining() >= pad {
                    c.skip(pad)?;
                }
            }
            subchunks.push(CatalogSubChunk {
                ct_start,
                ct_end,
                uncompressed_size,
                compression,
                proc_indexes,
            });
        }

        Ok(Catalog {
            earliest_firehose_ct: earliest,
            uuids,
            strings,
            procs,
            subchunks,
        })
    }

    pub fn string_at(&self, off: u16) -> &str {
        let o = off as usize;
        if o >= self.strings.len() {
            return "";
        }
        let end = self.strings[o..]
            .iter()
            .position(|&b| b == 0)
            .map(|i| o + i)
            .unwrap_or(self.strings.len());
        std::str::from_utf8(&self.strings[o..end]).unwrap_or("")
    }

    pub fn find_proc(&self, first: u64, second: u32) -> Option<&ProcInfo> {
        self.procs
            .iter()
            .find(|p| p.first_proc_id == first && p.second_proc_id == second)
    }

    pub fn subsystem_strings(&self, proc: &ProcInfo, id: u16) -> (String, String) {
        for (sid, so, co) in &proc.subsystems {
            if *sid == id {
                return (
                    self.string_at(*so).to_string(),
                    self.string_at(*co).to_string(),
                );
            }
        }
        (String::new(), String::new())
    }
}
