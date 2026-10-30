// SPDX-License-Identifier: GPL-3.0-only
//! Clean-room Apple Unified Log decoder.

#![forbid(unsafe_code)]

pub mod catalog;
pub mod chunk;
pub mod chunkset;
pub mod decode;
pub mod dsc;
pub mod error;
pub mod firehose;
pub mod formatter;
pub mod header;
pub mod oversize;
pub mod source;
pub mod strings_cache;
pub mod timesync;
pub mod units;
pub mod uuidtext;

pub use error::UlError;
pub use source::{DirLogSource, LogSource, MapLogSource};
pub use timesync::TimesyncTable;
pub use units::{scan_file, walk_preambles, ChunkPreamble, Tracev3Stats, WorkUnit};

use decode::{decode_unit, DecodeCtx};
use mul_core::filter::Filter;
use mul_core::par;
use mul_core::Result;
use source::LogSource as LS;
use strings_cache::StringsCache;
use std::sync::Arc;
use units::WorkUnit as WU;

#[derive(Debug, Clone)]
pub struct Options {
    pub threads: usize,
    pub ordered: bool,
    pub include_signposts: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            threads: 0,
            ordered: true,
            include_signposts: false,
        }
    }
}

struct FilePlan {
    file_id: u32,
    bytes: Arc<[u8]>,
    units: Vec<WU>,
}

pub struct UnifiedLog {
    source: Arc<dyn LS>,
    options: Options,
    stats: Tracev3Stats,
    timesync: TimesyncTable,
    strings: StringsCache,
    plans: Vec<FilePlan>,
}

impl UnifiedLog {
    pub fn open(source: impl LS + 'static, options: Options) -> Result<Self> {
        let source: Arc<dyn LS> = Arc::new(source);
        let mut timesync = TimesyncTable::default();
        for f in source.timesync_files() {
            if let Ok(bytes) = source.open(&f) {
                if let Ok(t) = TimesyncTable::parse(bytes.as_slice()) {
                    timesync.merge(t);
                }
            }
        }

        let mut stats = Tracev3Stats {
            boots: timesync.boot_count(),
            ..Default::default()
        };
        for b in timesync.boots() {
            let s = b.boot_uuid.to_string();
            if !stats.boot_uuids.contains(&s) {
                stats.boot_uuids.push(s);
            }
        }

        let mut plans = Vec::new();
        let files = source.tracev3_files();
        for (file_id, f) in files.into_iter().enumerate() {
            let Ok(bytes) = source.open(&f) else {
                continue;
            };
            let owned: Arc<[u8]> = Arc::from(bytes.as_slice().to_vec());
            let (file_stats, units, _header) = scan_file(&f, file_id as u32, &owned)?;
            // Annotate span from unit CTs via timesync
            for u in &units {
                if let Some(ns) = timesync.wall_ns_any(u.header_boot, u.ct_min) {
                    stats.span_start_ns = Some(match stats.span_start_ns {
                        Some(a) => a.min(ns),
                        None => ns,
                    });
                }
                if let Some(ns) = timesync.wall_ns_any(u.header_boot, u.ct_max) {
                    stats.span_end_ns = Some(match stats.span_end_ns {
                        Some(a) => a.max(ns),
                        None => ns,
                    });
                }
            }
            stats.merge(file_stats);
            let _ = f;
            plans.push(FilePlan {
                file_id: file_id as u32,
                bytes: owned,
                units,
            });
        }
        stats.boots = stats.boot_uuids.len().max(timesync.boot_count());

        Ok(Self {
            source,
            options,
            stats,
            timesync,
            strings: StringsCache::new(),
            plans,
        })
    }

    pub fn stats(&self) -> &Tracev3Stats {
        &self.stats
    }

    pub fn options(&self) -> &Options {
        &self.options
    }

    pub fn source(&self) -> &Arc<dyn LS> {
        &self.source
    }

    pub fn timesync(&self) -> &TimesyncTable {
        &self.timesync
    }

    pub fn query(&self, filter: &Filter) -> Query<'_> {
        Query {
            log: self,
            filter: filter.clone(),
        }
    }
}

pub struct Query<'a> {
    log: &'a UnifiedLog,
    filter: Filter,
}

impl<'a> Query<'a> {
    fn units_filtered(&self) -> Vec<(&FilePlan, &WU)> {
        let mut out = Vec::new();
        for plan in &self.log.plans {
            for u in &plan.units {
                if let Filter::TimeRange {
                    start_ns: Some(s),
                    end_ns: Some(e),
                } = &self.filter
                {
                    let umin = self
                        .log
                        .timesync
                        .wall_ns_any(u.header_boot, u.ct_min);
                    let umax = self
                        .log
                        .timesync
                        .wall_ns_any(u.header_boot, u.ct_max);
                    if let (Some(a), Some(b)) = (umin, umax) {
                        if b < *s || a > *e {
                            continue;
                        }
                    }
                }
                out.push((plan, u));
            }
        }
        out
    }

    pub fn count(&self) -> Result<u64> {
        // Fast path: decode without caring about message filter first; message filters need format.
        let mut n = 0u64;
        self.for_each_batch(|batch| {
            n += batch.len() as u64;
            Ok(())
        })?;
        Ok(n)
    }

    pub fn for_each_batch<F>(&self, mut f: F) -> Result<()>
    where
        F: FnMut(&[OwnedLogEvent]) -> Result<()>,
    {
        let ctx = DecodeCtx {
            source: self.log.source.as_ref(),
            timesync: &self.log.timesync,
            strings: &self.log.strings,
            include_signposts: self.log.options.include_signposts,
        };

        let pairs = self.units_filtered();
        // Group by file for buffer reuse
        let mut by_file: hashbrown::HashMap<u32, (Arc<[u8]>, Vec<WU>)> = hashbrown::HashMap::new();
        for (plan, u) in pairs {
            by_file
                .entry(plan.file_id)
                .or_insert_with(|| (plan.bytes.clone(), Vec::new()))
                .1
                .push(u.clone());
        }

        let mut batches: Vec<Vec<OwnedLogEvent>> = par::map(
            by_file.into_iter().map(|(_, v)| v).collect::<Vec<_>>(),
            |(bytes, units)| {
                let mut out = Vec::new();
                for u in units {
                    if let Ok(mut batch) = decode_unit(&ctx, &u, &bytes) {
                        out.append(&mut batch);
                    }
                }
                out
            },
        );

        if self.log.options.ordered {
            // Stable key: wall timestamp string + mach + thread (wall is RFC3339 UTC).
            let key = |e: &OwnedLogEvent| {
                (
                    e.timestamp.clone().unwrap_or_default(),
                    e.mach_timestamp.unwrap_or(0),
                    e.thread_id.unwrap_or(0),
                )
            };
            for b in &mut batches {
                b.sort_by_key(key);
            }
            let mut all: Vec<OwnedLogEvent> = batches.into_iter().flatten().collect();
            all.sort_by_key(key);
            // apply message filter
            all.retain(|e| self.filter_event(e));
            const BATCH: usize = 4096;
            for chunk in all.chunks(BATCH) {
                f(chunk)?;
            }
        } else {
            for mut batch in batches {
                batch.retain(|e| self.filter_event(e));
                if !batch.is_empty() {
                    f(&batch)?;
                }
            }
        }
        Ok(())
    }

    pub fn iter_owned(self) -> Result<Vec<OwnedLogEvent>> {
        let mut all = Vec::new();
        self.for_each_batch(|b| {
            all.extend_from_slice(b);
            Ok(())
        })?;
        Ok(all)
    }

    fn filter_event(&self, e: &OwnedLogEvent) -> bool {
        self.filter.matches_event(
            e.subsystem.as_deref(),
            e.category.as_deref(),
            e.process_image_path.as_deref(),
            e.sender_image_path.as_deref(),
            e.process_id,
            e.event_message.as_deref().unwrap_or(""),
        )
    }
}

/// Owned log event with `log show --style ndjson` field names.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct OwnedLogEvent {
    pub timestamp: Option<String>,
    pub mach_timestamp: Option<u64>,
    pub process_id: Option<u32>,
    pub process_image_path: Option<String>,
    pub sender_image_path: Option<String>,
    pub subsystem: Option<String>,
    pub category: Option<String>,
    pub message_type: Option<String>,
    pub event_type: Option<String>,
    pub event_message: Option<String>,
    pub thread_id: Option<u64>,
    pub activity_identifier: Option<u64>,
    pub boot_uuid: Option<String>,
    pub format_string: Option<String>,
    pub trace_id: Option<u64>,
}
