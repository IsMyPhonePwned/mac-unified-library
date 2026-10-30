// SPDX-License-Identifier: GPL-3.0-only
//! Timesync database — layout from libyal dtformats.

use mul_core::{Cur, FormatError};
use uuid::Uuid;

const BOOT_SIG: u16 = 0xBBB0;
const TS_SIG: u16 = 0x7354; // "Ts" LE

#[derive(Debug, Clone)]
pub struct BootRecord {
    pub boot_uuid: Uuid,
    pub numer: u32,
    pub denom: u32,
    pub boot_wall_ns: i64,
    pub tz_minutes: i32,
    pub dst: u32,
}

#[derive(Debug, Clone)]
pub struct TsRecord {
    pub kernel_time: u64,
    pub walltime_ns: i64,
}

#[derive(Debug, Default, Clone)]
pub struct TimesyncTable {
    boots: Vec<(BootRecord, Vec<TsRecord>)>,
}

impl TimesyncTable {
    pub fn parse(data: &[u8]) -> Result<Self, FormatError> {
        let mut c = Cur::new(data);
        let mut boots = Vec::new();
        while c.remaining() >= 4 {
            let sig = c.u16_le()?;
            let size = c.u16_le()? as usize;
            if size < 4 || size > c.remaining() + 4 {
                // size includes the 4-byte header we already read
                break;
            }
            let body_len = size - 4;
            let body_start = c.pos();
            if sig == BOOT_SIG {
                if body_len < 44 {
                    break;
                }
                let _unk = c.u32_le()?;
                let uuid = Uuid::from_bytes(c.uuid_bytes()?);
                let numer = c.u32_le()?;
                let denom = c.u32_le()?.max(1);
                let boot_wall_ns = c.i64_le()?;
                let tz_minutes = c.i32_le()?;
                let dst = c.u32_le()?;
                // skip any extra
                let consumed = c.pos() - body_start;
                if body_len > consumed {
                    c.skip(body_len - consumed)?;
                }
                boots.push((
                    BootRecord {
                        boot_uuid: uuid,
                        numer,
                        denom,
                        boot_wall_ns,
                        tz_minutes,
                        dst,
                    },
                    Vec::new(),
                ));
            } else if sig == TS_SIG {
                if body_len < 28 {
                    break;
                }
                let _unk = c.u32_le()?;
                let kernel_time = c.u64_le()?;
                let walltime_ns = c.i64_le()?;
                let _tz = c.i32_le()?;
                let _dst = c.u32_le()?;
                let consumed = c.pos() - body_start;
                if body_len > consumed {
                    c.skip(body_len - consumed)?;
                }
                if let Some((_, recs)) = boots.last_mut() {
                    recs.push(TsRecord {
                        kernel_time,
                        walltime_ns,
                    });
                }
            } else {
                break;
            }
        }
        // Ensure sync records sorted by kernel_time for binary search
        for (_, recs) in &mut boots {
            recs.sort_by_key(|r| r.kernel_time);
        }
        Ok(Self { boots })
    }

    pub fn boot_count(&self) -> usize {
        self.boots.len()
    }

    pub fn boots(&self) -> impl Iterator<Item = &BootRecord> {
        self.boots.iter().map(|(b, _)| b)
    }

    pub fn merge(&mut self, other: TimesyncTable) {
        self.boots.extend(other.boots);
    }

    /// Wall time (UTC ns) for continuous time `ct` under `boot_uuid`.
    pub fn wall_ns(&self, boot_uuid: Uuid, ct: u64) -> Option<i64> {
        let (boot, recs) = self.boots.iter().find(|(b, _)| b.boot_uuid == boot_uuid)?;
        Self::wall_ns_boot(boot, recs, ct)
    }

    pub fn wall_ns_boot(boot: &BootRecord, recs: &[TsRecord], ct: u64) -> Option<i64> {
        // last record with kernel_time <= ct
        let idx = match recs.binary_search_by_key(&ct, |r| r.kernel_time) {
            Ok(i) => i,
            Err(0) => {
                // before first sync — use boot wall + ct from 0 via timebase
                if boot.boot_wall_ns == 0 && recs.is_empty() {
                    return None;
                }
                if recs.is_empty() {
                    let ticks = ct as i128 * boot.numer as i128 / boot.denom as i128;
                    return Some(boot.boot_wall_ns.saturating_add(ticks as i64));
                }
                0
            }
            Err(i) => i - 1,
        };
        let rec = &recs[idx];
        if rec.kernel_time > ct && idx == 0 {
            // still before first — extrapolate from boot
            let ticks = ct as i128 * boot.numer as i128 / boot.denom as i128;
            return Some(boot.boot_wall_ns.saturating_add(ticks as i64));
        }
        let delta = ct.saturating_sub(rec.kernel_time) as i128;
        let ticks = delta * boot.numer as i128 / boot.denom as i128;
        Some(rec.walltime_ns.saturating_add(ticks as i64))
    }

    /// Best-effort wall conversion when boot UUID is known from header.
    pub fn wall_ns_any(&self, boot_uuid: Option<Uuid>, ct: u64) -> Option<i64> {
        if let Some(u) = boot_uuid {
            if let Some(ns) = self.wall_ns(u, ct) {
                return Some(ns);
            }
        }
        // fall back to first boot
        let (boot, recs) = self.boots.first()?;
        Self::wall_ns_boot(boot, recs, ct)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_boot_and_ts() {
        let mut data = Vec::new();
        // boot: sig, size=48, unk, uuid, numer, denom, wall, tz, dst
        data.extend_from_slice(&BOOT_SIG.to_le_bytes());
        data.extend_from_slice(&48u16.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&[1u8; 16]);
        data.extend_from_slice(&125u32.to_le_bytes());
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(&1_000_000_000i64.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        // ts
        data.extend_from_slice(&TS_SIG.to_le_bytes());
        data.extend_from_slice(&32u16.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&300u64.to_le_bytes());
        data.extend_from_slice(&2_000_000_000i64.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());

        let t = TimesyncTable::parse(&data).unwrap();
        assert_eq!(t.boot_count(), 1);
        let uuid = Uuid::from_bytes([1u8; 16]);
        // ct=300 → exactly at sync
        assert_eq!(t.wall_ns(uuid, 300), Some(2_000_000_000));
        // ct=303 → +1s at 125/3 → (3*125/3)=125 ns? wait 3 ticks * 125/3 = 125 ns
        let ns = t.wall_ns(uuid, 303).unwrap();
        assert_eq!(ns, 2_000_000_000 + 125);
    }
}
