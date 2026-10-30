// SPDX-License-Identifier: GPL-3.0-only
//! uuidtext string files — layout from libyal dtformats.

use mul_core::{Cur, FormatError};
use std::sync::Arc;

const MAGIC: u32 = 0x6677_8899;

#[derive(Debug, Clone)]
pub struct UuidText {
    entries: Vec<(u32, u32)>, // range_start, size
    strings: Arc<[u8]>,
    pub image_path: String,
}

impl UuidText {
    pub fn parse(data: &[u8]) -> Result<Self, FormatError> {
        let mut c = Cur::new(data);
        let magic = c.u32_le()?;
        if magic != MAGIC {
            return Err(FormatError::new(0, format!("bad uuidtext magic {magic:#x}")));
        }
        let _major = c.u32_le()?;
        let _minor = c.u32_le()?;
        let count = c.u32_le()? as usize;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let start = c.u32_le()?;
            let size = c.u32_le()?;
            entries.push((start, size));
        }
        let strings_start = c.pos();
        // Footer path is after the string blob. Total string blob size = sum of entry sizes
        // (entries describe ranges into the blob by range_start, not contiguous packing).
        // Library practice: remaining bytes minus trailing path = string area; path is last C string.
        let rest = &data[strings_start..];
        // Find last NUL-terminated path: typically the final C string after all string data.
        // Heuristic: entries' max(range_start+size) gives blob length.
        let blob_end = entries
            .iter()
            .map(|(s, sz)| *s as usize + *sz as usize)
            .max()
            .unwrap_or(0)
            .min(rest.len());
        let strings = Arc::<[u8]>::from(rest[..blob_end].to_vec());
        let path_area = &rest[blob_end..];
        let image_path = {
            let end = path_area.iter().position(|&b| b == 0).unwrap_or(path_area.len());
            String::from_utf8_lossy(&path_area[..end]).into_owned()
        };
        Ok(Self {
            entries,
            strings,
            image_path,
        })
    }

    /// Format / sender string at image offset `o`.
    pub fn string_at(&self, offset: u64) -> Option<&str> {
        let o = offset as u32;
        for &(start, size) in &self.entries {
            if o >= start && o < start.saturating_add(size) {
                let rel = (o - start) as usize;
                // The entry's range_start is the PC/offset key; strings are packed in file order.
                // Per dtformats: read a C string at the file position corresponding to the entry.
                // Common implementation: string data for entry i starts at cumulative sizes of
                // prior entries, and offset within entry is (o - start).
                let base = self
                    .entries
                    .iter()
                    .take_while(|(s, _)| *s != start)
                    .map(|(_, sz)| *sz as usize)
                    .sum::<usize>();
                let pos = base + rel;
                return cstr_at(&self.strings, pos);
            }
        }
        None
    }
}

fn cstr_at(buf: &[u8], pos: usize) -> Option<&str> {
    if pos >= buf.len() {
        return None;
    }
    let end = buf[pos..].iter().position(|&b| b == 0).map(|i| pos + i)?;
    std::str::from_utf8(&buf[pos..end]).ok()
}
