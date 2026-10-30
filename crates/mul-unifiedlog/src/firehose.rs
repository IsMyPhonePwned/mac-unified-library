// SPDX-License-Identifier: GPL-3.0-only
//! Firehose chunk + tracepoint parsing (libyal dtformats).

use mul_core::{Cur, FormatError};

pub const FLAG_HAS_AID: u16 = 0x0001;
pub const FLAG_STRINGS_MASK: u16 = 0x000e;
pub const FLAG_MAIN_EXE: u16 = 0x0002;
pub const FLAG_SHARED_CACHE: u16 = 0x0004;
pub const FLAG_ABSOLUTE: u16 = 0x0008;
pub const FLAG_UUID_RELATIVE: u16 = 0x000a;
pub const FLAG_LARGE_SHARED_CACHE: u16 = 0x000c;
pub const FLAG_HAS_UNIQUE_PID: u16 = 0x0010;
pub const FLAG_HAS_LARGE_OFFSET: u16 = 0x0020;
pub const FLAG_HAS_PRIVATE: u16 = 0x0100;
pub const FLAG_HAS_SUBSYSTEM: u16 = 0x0200;
pub const FLAG_HAS_RULES: u16 = 0x0400;
pub const FLAG_HAS_OVERSIZE: u16 = 0x0800;
pub const FLAG_HAS_BACKTRACE: u16 = 0x1000;
pub const FLAG_HAS_NAME: u16 = 0x8000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivityType {
    Unused,
    Activity,
    Trace,
    Log,
    Signpost,
    Loss,
    Other(u8),
}

impl ActivityType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x00 => Self::Unused,
            0x02 => Self::Activity,
            0x03 => Self::Trace,
            0x04 => Self::Log,
            0x06 => Self::Signpost,
            0x07 => Self::Loss,
            o => Self::Other(o),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unused => "unused",
            Self::Activity => "activityCreateEvent",
            Self::Trace => "traceEvent",
            Self::Log => "logEvent",
            Self::Signpost => "signpostEvent",
            Self::Loss => "lossEvent",
            Self::Other(_) => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogType {
    Default,
    Info,
    Debug,
    Error,
    Fault,
    Other(u8),
}

impl LogType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x00 => Self::Default,
            0x01 => Self::Info,
            0x02 => Self::Debug,
            0x10 => Self::Error,
            0x11 => Self::Fault,
            o => Self::Other(o),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "Default",
            Self::Info => "Info",
            Self::Debug => "Debug",
            Self::Error => "Error",
            Self::Fault => "Fault",
            Self::Other(_) => "Unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub enum ItemValue {
    Inline(Vec<u8>),
    PublicRange { offset: u16, size: u16 },
    PrivateRange { offset: u16, size: u16 },
    PrivatePlaceholder,
}

#[derive(Debug, Clone)]
pub struct DataItem {
    pub type_id: u8,
    pub value: ItemValue,
}

#[derive(Debug, Clone)]
pub struct FirehoseEntry {
    pub activity_type: ActivityType,
    pub log_type: LogType,
    pub flags: u16,
    pub format_ref_lower: u32,
    pub thread_id: u64,
    pub ct_delta: u64, // 48-bit
    pub continuous_time: u64,
    pub activity_id: Option<u64>,
    pub unique_pid: Option<u64>,
    pub subsystem_id: Option<u16>,
    pub oversize_ref: Option<u16>,
    pub large_offset: Option<u16>,
    pub large_shared_cache: Option<u16>,
    pub absolute_uuid: Option<[u8; 16]>,
    pub sender_pc_low: u32,
    pub items: Vec<DataItem>,
    /// Raw values area after item descriptors (for range-based items).
    pub values_data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct FirehoseChunk {
    pub first_proc_id: u64,
    pub second_proc_id: u32,
    pub public_data_size: u16,
    pub private_virt_off: u16,
    pub base_ct: u64,
    pub private_data: Vec<u8>,
    pub entries: Vec<FirehoseEntry>,
}

impl FirehoseChunk {
    pub fn parse(data: &[u8]) -> Result<Self, FormatError> {
        let mut c = Cur::new(data);
        let first_proc_id = c.u64_le()?;
        let second_proc_id = c.u32_le()?;
        let _ttl = c.u8()?;
        let _collapsed = c.u8()?;
        let _reserved = c.u16_le()?;
        let public_data_size = c.u16_le()?;
        let private_virt_off = c.u16_le()?;
        let _unk = c.u16_le()?;
        let _stream = c.u8()?;
        let _unk3 = c.u8()?;
        let base_ct = c.u64_le()?;

        // Public area follows; private at end when virt_off < 0x1000
        // After base_ct, pos is 32 from chunk-data start; public entries follow.
        let pub_start = c.pos();
        let pub_end = (pub_start + public_data_size as usize).min(data.len());

        let private_data = if private_virt_off < 0x1000 {
            let priv_size = 0x1000usize.saturating_sub(private_virt_off as usize);
            // In collapsed form, private sits at end of chunk data
            if data.len() >= priv_size {
                data[data.len() - priv_size..].to_vec()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        let mut entries = Vec::new();
        c.set_pos(pub_start)?;
        while c.pos() + 24 <= pub_end {
            // Align to 8 within public area
            let aligned = (c.pos() + 7) & !7;
            if aligned != c.pos() {
                if aligned >= pub_end {
                    break;
                }
                c.set_pos(aligned)?;
            }
            if c.pos() + 24 > pub_end {
                break;
            }
            match parse_entry(&mut c, base_ct, pub_end) {
                Ok(Some(e)) => entries.push(e),
                Ok(None) => break,
                Err(_) => break,
            }
        }

        Ok(Self {
            first_proc_id,
            second_proc_id,
            public_data_size,
            private_virt_off,
            base_ct,
            private_data,
            entries,
        })
    }
}

fn parse_entry(
    c: &mut Cur<'_>,
    base_ct: u64,
    pub_end: usize,
) -> Result<Option<FirehoseEntry>, FormatError> {
    let start = c.pos();
    let activity_raw = c.u8()?;
    if activity_raw == 0 {
        return Ok(None);
    }
    let log_raw = c.u8()?;
    let flags = c.u16_le()?;
    let format_ref_lower = c.u32_le()?;
    let thread_id = c.u64_le()?;
    let delta_lo = c.u32_le()? as u64;
    let delta_hi = c.u16_le()? as u64;
    let ct_delta = delta_lo | (delta_hi << 32);
    let data_size = c.u16_le()? as usize;
    if start + 24 + data_size > pub_end {
        return Err(FormatError::new(start, "firehose entry past public area"));
    }
    let data = c.bytes(data_size)?;
    let continuous_time = base_ct.wrapping_add(ct_delta);

    let mut dc = Cur::new(data);
    let mut activity_id = None;
    let mut unique_pid = None;
    let mut subsystem_id = None;
    let mut oversize_ref = None;
    let mut large_offset = None;
    let mut large_shared_cache = None;
    let mut absolute_uuid = None;
    let mut sender_pc_low = 0u32;

    let strings_type = flags & FLAG_STRINGS_MASK;
    let is_logish = matches!(
        ActivityType::from_u8(activity_raw),
        ActivityType::Log | ActivityType::Signpost | ActivityType::Activity
    );

    if flags & FLAG_HAS_AID != 0 {
        activity_id = Some(dc.u64_le()?);
    }
    if flags & FLAG_HAS_PRIVATE != 0 && is_logish {
        let _priv_off = dc.u16_le()?;
        let _priv_sz = dc.u16_le()?;
    }
    if (is_logish || ActivityType::from_u8(activity_raw) == ActivityType::Trace)
        && dc.remaining() >= 4
    {
        sender_pc_low = dc.u32_le()?;
    }
    if flags & FLAG_HAS_LARGE_OFFSET != 0 {
        large_offset = Some(dc.u16_le()?);
    }
    if strings_type == FLAG_ABSOLUTE {
        let _hi = dc.u16_le()?;
    }
    if strings_type == FLAG_UUID_RELATIVE {
        absolute_uuid = Some(dc.uuid_bytes()?);
    }
    if strings_type == FLAG_LARGE_SHARED_CACHE {
        large_shared_cache = Some(dc.u16_le()?);
    }
    if flags & FLAG_HAS_UNIQUE_PID != 0 {
        unique_pid = Some(dc.u64_le()?);
    }
    if flags & FLAG_HAS_SUBSYSTEM != 0
        && ActivityType::from_u8(activity_raw) != ActivityType::Activity
    {
        subsystem_id = Some(dc.u16_le()?);
    }
    if flags & FLAG_HAS_RULES != 0 {
        let _ttl = dc.u8()?;
    }
    if flags & FLAG_HAS_OVERSIZE != 0 {
        oversize_ref = Some(dc.u16_le()?);
    }

    let mut items = Vec::new();
    let mut values_data = Vec::new();
    if matches!(
        ActivityType::from_u8(activity_raw),
        ActivityType::Log | ActivityType::Signpost
    ) && dc.remaining() >= 2
    {
        let _unk = dc.u8()?;
        let item_count = dc.u8()? as usize;
        for _ in 0..item_count {
            if dc.remaining() < 2 {
                break;
            }
            let type_id = dc.u8()?;
            let size = dc.u8()? as usize;
            let value = match type_id {
                0x01 => ItemValue::PrivatePlaceholder,
                0x20 | 0x22 | 0x40 | 0x42 => {
                    // public range
                    if size >= 4 && dc.remaining() >= 4 {
                        let offset = dc.u16_le()?;
                        let sz = dc.u16_le()?;
                        ItemValue::PublicRange {
                            offset,
                            size: sz,
                        }
                    } else {
                        let b = dc.bytes(size.min(dc.remaining()))?.to_vec();
                        ItemValue::Inline(b)
                    }
                }
                0x21 | 0x25 | 0x41 | 0x45 => {
                    if size >= 4 && dc.remaining() >= 4 {
                        let offset = dc.u16_le()?;
                        let sz = dc.u16_le()?;
                        ItemValue::PrivateRange {
                            offset,
                            size: sz,
                        }
                    } else {
                        ItemValue::PrivatePlaceholder
                    }
                }
                _ => {
                    let take = size.min(dc.remaining());
                    ItemValue::Inline(dc.bytes(take)?.to_vec())
                }
            };
            items.push(DataItem { type_id, value });
        }
        values_data = dc.buf()[dc.pos()..].to_vec();
    }

    Ok(Some(FirehoseEntry {
        activity_type: ActivityType::from_u8(activity_raw),
        log_type: LogType::from_u8(log_raw),
        flags,
        format_ref_lower,
        thread_id,
        ct_delta,
        continuous_time,
        activity_id,
        unique_pid,
        subsystem_id,
        oversize_ref,
        large_offset,
        large_shared_cache,
        absolute_uuid,
        sender_pc_low,
        items,
        values_data,
    }))
}

impl FirehoseEntry {
    pub fn format_offset(&self) -> u64 {
        let lower = (self.format_ref_lower & 0x7fff_ffff) as u64;
        if let Some(hi) = self.large_shared_cache {
            return ((hi as u64) << 31) | lower;
        }
        if let Some(hi) = self.large_offset {
            return ((hi as u64) << 31) | lower;
        }
        lower
    }

    pub fn strings_kind(&self) -> u16 {
        self.flags & FLAG_STRINGS_MASK
    }
}
