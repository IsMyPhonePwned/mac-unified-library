// SPDX-License-Identifier: GPL-3.0-only
//! Tracev3 header chunk (tag 0x1000) — layout from libyal dtformats.

use crate::chunk::{SUB_BOOT_UUID, SUB_BUILD, SUB_CONT_TIME, SUB_TIMEZONE};
use mul_core::{Cur, FormatError};
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct TraceHeader {
    pub numer: u32,
    pub denom: u32,
    pub start_continuous: u64,
    pub wall_time_secs: i32,
    pub tz_bias_minutes: i32,
    pub dst: u32,
    pub flags: u32,
    pub boot_uuid: Option<Uuid>,
    pub logd_pid: Option<u32>,
    pub build: Option<String>,
    pub hardware_model: Option<String>,
    pub timezone_path: Option<String>,
}

impl TraceHeader {
    pub fn parse(data: &[u8]) -> Result<Self, FormatError> {
        let mut c = Cur::new(data);
        let mut h = TraceHeader {
            numer: c.u32_le()?,
            denom: c.u32_le()?.max(1),
            start_continuous: c.u64_le()?,
            wall_time_secs: c.i32_le()?,
            ..Default::default()
        };
        let _unk1 = c.u32_le()?;
        let _unk2 = c.u32_le()?;
        h.tz_bias_minutes = c.i32_le()?;
        h.dst = c.u32_le()?;
        h.flags = c.u32_le()?;

        while c.remaining() >= 8 {
            let tag = c.u32_le()?;
            let size = c.u32_le()? as usize;
            let body = c.bytes(size)?;
            match tag {
                SUB_CONT_TIME => {
                    if body.len() >= 8 {
                        h.start_continuous =
                            u64::from_le_bytes(body[0..8].try_into().unwrap());
                    }
                }
                SUB_BUILD => {
                    if body.len() >= 56 {
                        h.build = cstr_lossy(&body[8..24]);
                        h.hardware_model = cstr_lossy(&body[24..56]);
                    } else if body.len() >= 48 {
                        // size field may exclude unknowns differently
                        h.build = cstr_lossy(body.get(8..24).unwrap_or(&[]));
                        h.hardware_model = cstr_lossy(body.get(24..).unwrap_or(&[]));
                    }
                }
                SUB_BOOT_UUID => {
                    if body.len() >= 24 {
                        h.boot_uuid = Some(Uuid::from_bytes(body[0..16].try_into().unwrap()));
                        h.logd_pid = Some(u32::from_le_bytes(body[16..20].try_into().unwrap()));
                    }
                }
                SUB_TIMEZONE => {
                    h.timezone_path = cstr_lossy(body);
                }
                _ => {}
            }
        }
        Ok(h)
    }
}

fn cstr_lossy(bytes: &[u8]) -> Option<String> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let s = String::from_utf8_lossy(&bytes[..end]).into_owned();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}
