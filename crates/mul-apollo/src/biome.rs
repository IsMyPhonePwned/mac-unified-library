// SPDX-License-Identifier: GPL-3.0-only
//! Biome stream inventory + SEGB → Event adapter.

use crate::epoch::{to_utc_ns, Epoch};
use crate::protolite::{self, ProtoValue};
use crate::segb::{self, EntryState};
use mul_core::event::{Event, EventKind, Evidence, LazyText, SourceId, TsQuality};
use mul_core::interner::Interner;
use mul_core::val::Val;
use smallvec::SmallVec;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct BiomeStreamInfo {
    pub path: PathBuf,
    pub stream_name: String,
    pub entry_count: usize,
    pub mapped: bool,
}

/// List Biome stream files under a filesystem root.
pub fn list_streams(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let candidates = [
        root.join("private/var/mobile/Library/Biome/streams"),
        root.join("private/var/db/biome/streams"),
        root.join("Library/Biome/streams"),
        root.join("Biome/streams"),
    ];
    for base in candidates {
        if !base.exists() {
            continue;
        }
        walk_files(&base, &mut out);
    }
    out.sort();
    out
}

fn walk_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk_files(&p, out);
        } else {
            out.push(p);
        }
    }
}

pub fn stream_name_from_path(path: &Path) -> String {
    // .../streams/{public,restricted}/<Stream>/local/<file>
    let parts: Vec<_> = path
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();
    if let Some(i) = parts.iter().position(|p| p.eq_ignore_ascii_case("streams")) {
        parts
            .get(i + 2)
            .or_else(|| parts.get(i + 1))
            .unwrap_or(&"unknown")
            .to_string()
    } else {
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string()
    }
}

pub fn parse_file_to_events(
    path: &Path,
    bytes: &[u8],
    interner: &Interner,
) -> Result<(BiomeStreamInfo, Vec<Event>), crate::ApolloError> {
    let stream = stream_name_from_path(path);
    let mapped = is_mapped(&stream);
    let file = segb::parse(bytes).map_err(|e| crate::ApolloError::Parse(e.to_string()))?;
    let mut events = Vec::new();
    for (idx, ent) in file.entries.iter().enumerate() {
        let mut ts = i64::MIN;
        let mut tq = TsQuality::Unknown;
        if let Some(cocoa) = ent.time_cocoa {
            if let Some(ns) = to_utc_ns(Epoch::Cocoa, cocoa) {
                ts = ns;
                tq = TsQuality::Recorded;
            }
        }
        let mut attrs: SmallVec<[(mul_core::Sym, Val); 6]> = SmallVec::new();
        attrs.push((
            interner.intern("state"),
            Val::Text(
                match ent.state {
                    EntryState::Written => "written",
                    EntryState::Deleted => "deleted",
                    EntryState::Unknown => "unknown",
                }
                .into(),
            ),
        ));
        attrs.push((
            interner.intern("stream"),
            Val::Text(stream.clone().into()),
        ));
        if let Ok(msg) = protolite::decode(&ent.payload) {
            if let Some(ProtoValue::String(s)) = msg.get_path("1") {
                attrs.push((interner.intern("field_1"), Val::Text(s.clone().into())));
            }
            // App.InFocus-ish bundle guess
            if let Some(ProtoValue::String(s)) = msg.get_path("1.6") {
                attrs.push((interner.intern("bundle_id"), Val::Text(s.clone().into())));
            }
        } else if !ent.payload.is_empty() {
            attrs.push((
                interner.intern("payload_len"),
                Val::I64(ent.payload.len() as i64),
            ));
        }
        let kind = if stream.to_ascii_lowercase().contains("infocus") {
            EventKind::AppFocus
        } else {
            EventKind::Generic
        };
        events.push(Event {
            ts,
            ts_quality: tq,
            source: SourceId::biome(&stream),
            kind,
            level: None,
            pid: None,
            process: None,
            bundle_id: None,
            subsystem: None,
            category: None,
            message: LazyText::owned(format!("biome:{stream}")),
            attrs,
            evidence: Evidence::new(path.display().to_string(), Some(idx as u64)),
        });
    }
    Ok((
        BiomeStreamInfo {
            path: path.to_path_buf(),
            stream_name: stream,
            entry_count: file.entries.len(),
            mapped,
        },
        events,
    ))
}

fn is_mapped(stream: &str) -> bool {
    let s = stream.to_ascii_lowercase();
    s.contains("infocus") || s.contains("app.") || s.contains("intent")
}
