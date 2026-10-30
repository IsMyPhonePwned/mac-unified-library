// SPDX-License-Identifier: GPL-3.0-only
//! Decode work units → owned log events.

use crate::catalog::Catalog;
use crate::chunk::{TAG_FIREHOSE, TAG_OVERSIZE, TAG_SIMPLEDUMP, TAG_STATEDUMP};
use crate::chunkset;
use crate::firehose::{
    ActivityType, FirehoseChunk, FLAG_ABSOLUTE, FLAG_LARGE_SHARED_CACHE, FLAG_MAIN_EXE,
    FLAG_SHARED_CACHE, FLAG_UUID_RELATIVE,
};
use crate::formatter::{parse_format, render};
use crate::oversize::{self, OversizeKey, OversizeMap};
use crate::source::LogSource;
use crate::strings_cache::StringsCache;
use crate::timesync::TimesyncTable;
use crate::units::WorkUnit;
use crate::OwnedLogEvent;
use mul_core::{Cur, Result};
use std::sync::Arc;
use uuid::Uuid;

pub struct DecodeCtx<'a> {
    pub source: &'a dyn LogSource,
    pub timesync: &'a TimesyncTable,
    pub strings: &'a StringsCache,
    pub include_signposts: bool,
}

pub fn decode_unit(ctx: &DecodeCtx<'_>, unit: &WorkUnit, file_bytes: &[u8]) -> Result<Vec<OwnedLogEvent>> {
    let cat_end = unit
        .catalog_offset
        .saturating_add(unit.catalog_len)
        .min(file_bytes.len());
    let cat_body = &file_bytes[unit.catalog_offset..cat_end];
    let catalog = match Catalog::parse(cat_body) {
        Ok(c) => c,
        Err(_) => return Ok(Vec::new()),
    };

    let cs_end = unit
        .chunkset_offset
        .saturating_add(unit.chunkset_len)
        .min(file_bytes.len());
    let cs_body = &file_bytes[unit.chunkset_offset..cs_end];
    let mut decompressed = Vec::new();
    if chunkset::decompress_into(cs_body, &mut decompressed).is_err() {
        return Ok(Vec::new());
    }

    // Pass 1: collect oversize records for two-phase firehose resolution.
    let mut oversize: OversizeMap = OversizeMap::new();
    {
        let mut c = Cur::new(&decompressed);
        while c.remaining() >= 16 {
            let tag = match c.u32_le() {
                Ok(t) => t,
                Err(_) => break,
            };
            let _sub = match c.u32_le() {
                Ok(t) => t,
                Err(_) => break,
            };
            let size = match c.u64_le() {
                Ok(t) => t,
                Err(_) => break,
            };
            if size > c.remaining() as u64 {
                break;
            }
            let body = match c.bytes(size as usize) {
                Ok(b) => b,
                Err(_) => break,
            };
            if tag == TAG_OVERSIZE {
                if let Ok((k, rec)) = oversize::parse_oversize(body) {
                    oversize.insert(k, rec);
                }
            }
            let _ = c.align(8);
        }
    }

    // Pass 2: emit events; firehose entries with oversize_ref splice public data.
    let mut events = Vec::new();
    let mut c = Cur::new(&decompressed);
    while c.remaining() >= 16 {
        let tag = match c.u32_le() {
            Ok(t) => t,
            Err(_) => break,
        };
        let _sub = match c.u32_le() {
            Ok(t) => t,
            Err(_) => break,
        };
        let size = match c.u64_le() {
            Ok(t) => t,
            Err(_) => break,
        };
        if size > c.remaining() as u64 {
            break;
        }
        let body = match c.bytes(size as usize) {
            Ok(b) => b,
            Err(_) => break,
        };
        match tag {
            TAG_FIREHOSE => {
                if let Ok(mut fh) = FirehoseChunk::parse(body) {
                    apply_oversize(&mut fh, &oversize);
                    for e in &fh.entries {
                        if e.activity_type == ActivityType::Signpost && !ctx.include_signposts {
                            continue;
                        }
                        if e.activity_type == ActivityType::Unused {
                            continue;
                        }
                        if let Some(ev) = materialize(ctx, unit, &catalog, &fh, e) {
                            events.push(ev);
                        }
                    }
                }
            }
            TAG_SIMPLEDUMP => {
                if let Some(ev) = parse_simpledump(ctx, unit, body) {
                    events.push(ev);
                }
            }
            TAG_STATEDUMP => {
                if let Some(ev) = parse_statedump(ctx, unit, body) {
                    events.push(ev);
                }
            }
            TAG_OVERSIZE => {}
            _ => {}
        }
        let _ = c.align(8);
    }
    Ok(events)
}

fn apply_oversize(fh: &mut FirehoseChunk, map: &OversizeMap) {
    for e in &mut fh.entries {
        let Some(data_ref) = e.oversize_ref else {
            continue;
        };
        let key = OversizeKey {
            first_proc_id: fh.first_proc_id,
            second_proc_id: fh.second_proc_id,
            data_ref: data_ref as u32,
        };
        if let Some(rec) = map.get(&key) {
            if e.values_data.is_empty() && !rec.public_data.is_empty() {
                e.values_data = rec.public_data.clone();
            }
            if fh.private_data.is_empty() && !rec.private_data.is_empty() {
                fh.private_data = rec.private_data.clone();
            }
        }
    }
}

fn materialize(
    ctx: &DecodeCtx<'_>,
    unit: &WorkUnit,
    catalog: &Catalog,
    fh: &FirehoseChunk,
    e: &crate::firehose::FirehoseEntry,
) -> Option<OwnedLogEvent> {
    let proc = catalog.find_proc(fh.first_proc_id, fh.second_proc_id);
    let (process_path, sender_path, fmt_string) = resolve_strings(ctx, catalog, proc, e);
    let (subsystem, category) = if let (Some(p), Some(id)) = (proc, e.subsystem_id) {
        catalog.subsystem_strings(p, id)
    } else {
        (String::new(), String::new())
    };

    let message = if let Some(ref fmt) = fmt_string {
        let pieces = parse_format(fmt);
        render(&pieces, &e.items, &e.values_data, &fh.private_data)
    } else {
        let raw: Vec<_> = e
            .items
            .iter()
            .map(|i| format!("argty={:#x}", i.type_id))
            .collect();
        format!("<unknown format string> {}", raw.join(" "))
    };

    let wall_ns = ctx
        .timesync
        .wall_ns_any(unit.header_boot, e.continuous_time);

    let timestamp = wall_ns.map(|ns| {
        let secs = ns.div_euclid(1_000_000_000);
        let nsec = ns.rem_euclid(1_000_000_000) as u32;
        format_rfc3339(secs, nsec)
    });

    Some(OwnedLogEvent {
        timestamp,
        mach_timestamp: Some(e.continuous_time),
        process_id: proc.map(|p| p.pid),
        process_image_path: process_path,
        sender_image_path: sender_path,
        subsystem: if subsystem.is_empty() {
            None
        } else {
            Some(subsystem)
        },
        category: if category.is_empty() {
            None
        } else {
            Some(category)
        },
        message_type: Some(e.log_type.as_str().to_string()),
        event_type: Some(e.activity_type.as_str().to_string()),
        event_message: Some(message),
        thread_id: Some(e.thread_id),
        activity_identifier: e.activity_id,
        boot_uuid: unit.header_boot.map(|u| u.to_string()),
        format_string: fmt_string,
        trace_id: None,
    })
}

fn resolve_strings(
    ctx: &DecodeCtx<'_>,
    catalog: &Catalog,
    proc: Option<&crate::catalog::ProcInfo>,
    e: &crate::firehose::FirehoseEntry,
) -> (Option<String>, Option<String>, Option<String>) {
    let offset = e.format_offset();
    let kind = e.strings_kind();
    let mut process_path = None;
    let mut sender_path = None;
    let mut fmt = None;

    let main_uuid = proc.and_then(|p| catalog.uuids.get(p.main_uuid_idx as usize).copied());
    let dsc_uuid = proc.and_then(|p| {
        if p.dsc_uuid_idx == 0xffff {
            None
        } else {
            catalog.uuids.get(p.dsc_uuid_idx as usize).copied()
        }
    });

    if let Some(u) = main_uuid {
        if let Some(ut) = ctx.strings.uuidtext(ctx.source, u) {
            process_path = Some(ut.image_path.clone());
        }
    }

    match kind {
        FLAG_MAIN_EXE => {
            if let Some(u) = main_uuid {
                if let Some(ut) = ctx.strings.uuidtext(ctx.source, u) {
                    fmt = ut.string_at(offset).map(|s| s.to_string());
                    sender_path = Some(ut.image_path.clone());
                }
            }
        }
        FLAG_SHARED_CACHE | FLAG_LARGE_SHARED_CACHE => {
            if let Some(u) = dsc_uuid {
                if let Some(dsc) = ctx.strings.dsc(ctx.source, u) {
                    fmt = dsc.string_at(offset).map(|s| s.to_string());
                    sender_path = dsc.path_for_offset(offset).map(|s| s.to_string());
                }
            }
        }
        FLAG_UUID_RELATIVE => {
            if let Some(bytes) = e.absolute_uuid {
                let u = Uuid::from_bytes(bytes);
                if let Some(ut) = ctx.strings.uuidtext(ctx.source, u) {
                    fmt = ut.string_at(offset).map(|s| s.to_string());
                    sender_path = Some(ut.image_path.clone());
                }
            }
        }
        FLAG_ABSOLUTE => {
            // absolute PC into uuidtext by load address — treat as main for now
            if let Some(u) = main_uuid {
                if let Some(ut) = ctx.strings.uuidtext(ctx.source, u) {
                    fmt = ut.string_at(offset).map(|s| s.to_string());
                    sender_path = Some(ut.image_path.clone());
                }
            }
        }
        _ => {}
    }

    (process_path, sender_path, fmt)
}

fn parse_statedump(ctx: &DecodeCtx<'_>, unit: &WorkUnit, body: &[u8]) -> Option<OwnedLogEvent> {
    let mut c = Cur::new(body);
    let _first = c.u64_le().ok()?;
    let _second = c.u32_le().ok()?;
    let _ttl = c.u8().ok()?;
    let _unk = c.u8().ok()?;
    let _unk2 = c.u16_le().ok()?;
    let ct = c.u64_le().ok()?;
    let rest = c.remaining();
    let preview = if rest > 0 {
        let n = rest.min(64);
        let slice = c.bytes(n).ok()?;
        format!("statedump {}B hex={}", rest, hex_preview(slice))
    } else {
        "statedump".into()
    };
    let wall = ctx.timesync.wall_ns_any(unit.header_boot, ct);
    Some(OwnedLogEvent {
        timestamp: wall.map(|ns| {
            format_rfc3339(ns.div_euclid(1_000_000_000), ns.rem_euclid(1_000_000_000) as u32)
        }),
        mach_timestamp: Some(ct),
        process_id: None,
        process_image_path: None,
        sender_image_path: None,
        subsystem: None,
        category: None,
        message_type: Some("Default".into()),
        event_type: Some("stateDump".into()),
        event_message: Some(preview),
        thread_id: None,
        activity_identifier: None,
        boot_uuid: unit.header_boot.map(|u| u.to_string()),
        format_string: None,
        trace_id: None,
    })
}

fn hex_preview(b: &[u8]) -> String {
    b.iter()
        .take(24)
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn parse_simpledump(ctx: &DecodeCtx<'_>, unit: &WorkUnit, body: &[u8]) -> Option<OwnedLogEvent> {
    let mut c = Cur::new(body);
    let _first = c.u64_le().ok()?;
    let _second = c.u32_le().ok()?;
    let _unk = c.u8().ok()?;
    let _unk2 = c.u8().ok()?;
    let _unk3 = c.u16_le().ok()?;
    let ct = c.u64_le().ok()?;
    let thread = c.u64_le().ok()?;
    let _sender = c.uuid_bytes().ok()?;
    let _dsc = c.uuid_bytes().ok()?;
    // subsystem + message as C strings
    let sub = read_cstr(&mut c).unwrap_or_default();
    let msg = read_cstr(&mut c).unwrap_or_default();
    let wall = ctx.timesync.wall_ns_any(unit.header_boot, ct);
    Some(OwnedLogEvent {
        timestamp: wall.map(|ns| {
            format_rfc3339(ns.div_euclid(1_000_000_000), ns.rem_euclid(1_000_000_000) as u32)
        }),
        mach_timestamp: Some(ct),
        process_id: None,
        process_image_path: None,
        sender_image_path: None,
        subsystem: if sub.is_empty() { None } else { Some(sub) },
        category: None,
        message_type: Some("Default".into()),
        event_type: Some("simpleDump".into()),
        event_message: Some(msg),
        thread_id: Some(thread),
        activity_identifier: None,
        boot_uuid: unit.header_boot.map(|u| u.to_string()),
        format_string: None,
        trace_id: None,
    })
}

fn read_cstr(c: &mut Cur<'_>) -> Option<String> {
    let b = c.cstr().ok()?;
    Some(String::from_utf8_lossy(b).into_owned())
}

fn format_rfc3339(secs: i64, nsec: u32) -> String {
    // Minimal UTC formatter without chrono clock feature.
    let (y, m, d, hh, mm, ss) = civil_from_unix(secs);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{nsec:09}Z")
}

fn civil_from_unix(secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86400);
    let tod = secs.rem_euclid(86400) as u32;
    let hh = tod / 3600;
    let mm = (tod % 3600) / 60;
    let ss = tod % 60;
    // Howard Hinnant civil_from_days
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d, hh, mm, ss)
}

/// Parallel/sequential decode of many units for one file's bytes.
pub fn decode_units_for_file(
    ctx: &DecodeCtx<'_>,
    units: &[WorkUnit],
    file_bytes: Arc<[u8]>,
) -> Result<Vec<OwnedLogEvent>> {
    let mut all = Vec::new();
    for u in units {
        let mut batch = decode_unit(ctx, u, &file_bytes)?;
        all.append(&mut batch);
    }
    Ok(all)
}
