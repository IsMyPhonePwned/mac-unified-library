// SPDX-License-Identifier: GPL-3.0-only
//! Adapters over `sysdiagnose_extractor_library` (consume public API only).

use mul_core::event::{Event, EventKind, Evidence, LazyText, SourceId, TsQuality};
use mul_core::interner::Interner;
use mul_io::bytes::Bytes;
use mul_io::source::FileRef;
use mul_unifiedlog::LogSource;
use serde_json::Value;
use std::sync::Arc;
use sysdiagnose_extractor_library::{
    all_parser_types, parse_into_sink, parser_for, parser_for_with_options, retention_plan,
    run_parsers_concurrently, ArchiveOptions, ParseOptions, ParserType, SysdiagnoseArchive,
    ValueSink,
};
use uuid::Uuid;

/// `-ng` parsers that APOLLO-NG replaces for overview ingest (SPEC §6.2.3).
/// Compat analysers that list these deps still run the `-ng` parsers for parity.
pub fn apollo_backed_parsers() -> &'static [ParserType] {
    &[
        ParserType::apollo_all,
        ParserType::powerlogs,
        ParserType::knowledgec,
        ParserType::interactionc,
        ParserType::netusage,
        ParserType::screentime,
        ParserType::safari_history,
        ParserType::quarantine_events,
    ]
}

pub fn open_archive(
    path: &std::path::Path,
    parsers: &[ParserType],
) -> Result<Arc<SysdiagnoseArchive>, mul_core::MulError> {
    open_archive_ex(path, parsers, false, false)
}

/// Extra retention beyond [`retention_plan`] for overview / APOLLO-NG module walks
/// (unified-log sources + common pattern-of-life DBs). Skip these for tight
/// `mul parse` so we do not pull ~hundreds of MB of tracev3/dsc when only
/// e.g. `powerlogs` is requested.
pub const POL_EXTRA_GLOBS: &[&str] = &[
    "**/*.tracev3",
    "**/timesync/*",
    "**/uuidtext/**",
    "**/dsc/*",
    "**/*.PLSQL",
    "**/*.PLSQL.gz",
    "**/TCC.db",
    "**/knowledgeC.db",
    "**/interactionC.db",
    "**/netusage.sqlite",
];

/// Open archive; when `full_inventory` is set, retain every member path (for `file_stats` /
/// `coverage`) while still keeping payloads needed by `parsers`.
///
/// When `retain_pol_extras` is set, also keep unified-log + common APOLLO DB
/// members even if they are not in the parser retention plan.
pub fn open_archive_ex(
    path: &std::path::Path,
    parsers: &[ParserType],
    full_inventory: bool,
    retain_pol_extras: bool,
) -> Result<Arc<SysdiagnoseArchive>, mul_core::MulError> {
    let mut plan = retention_plan(parsers);
    if retain_pol_extras {
        for g in POL_EXTRA_GLOBS {
            if !plan.globs.iter().any(|x| x == *g) {
                plan.globs.push((*g).to_string());
            }
        }
    }
    if full_inventory {
        plan.everything = true;
        // Keep payloads for parsers that still need to run; paths-only would break them.
        plan.paths_only = parsers.is_empty();
    }
    let opts = ArchiveOptions::default();
    SysdiagnoseArchive::open_path_with_plan(path, opts, &plan)
        .map(Arc::new)
        .map_err(|e| mul_core::MulError::msg(e.to_string()))
}

pub fn run_ng_parsers(
    archive: Arc<SysdiagnoseArchive>,
    parsers: Vec<ParserType>,
    exclude_apollo: bool,
) -> Vec<(ParserType, Result<Value, String>, std::time::Duration)> {
    run_ng_parsers_ex(archive, parsers, exclude_apollo, true)
}

/// Like [`run_ng_parsers`], with control over logarchive decode.
///
/// When `logarchive_inventory_only` is false, the logarchive parser emits timeline
/// events (needed for timesketch / install_enrichment parity with upstream).
pub fn run_ng_parsers_ex(
    archive: Arc<SysdiagnoseArchive>,
    parsers: Vec<ParserType>,
    exclude_apollo: bool,
    logarchive_inventory_only: bool,
) -> Vec<(ParserType, Result<Value, String>, std::time::Duration)> {
    let selected: Vec<_> = parsers
        .into_iter()
        .filter(|p| {
            if exclude_apollo {
                !apollo_backed_parsers().contains(p)
            } else {
                true
            }
        })
        .collect();
    let opts = ParseOptions {
        logarchive_inventory_only,
        ..Default::default()
    };
    // Concurrent Value path (rayon on native). Use [`run_ng_parsers_via_sink`]
    // when you need the typed EventSink surface (streaming-ready).
    let _ = (parse_into_sink, ValueSink::new, parser_for);
    let jobs: Vec<_> = selected
        .into_iter()
        .map(|t| (t, parser_for_with_options(t, opts.clone())))
        .collect();
    run_parsers_concurrently(archive, jobs)
        .into_iter()
        .map(|(t, res, d)| match res {
            Ok(v) => (t, Ok(v), d),
            Err(e) => (t, Err(e.to_string()), d),
        })
        .collect()
}

/// Sequential parse via [`parse_into_sink`] (typed EventSink / streaming surface).
pub fn run_ng_parsers_via_sink(
    archive: Arc<SysdiagnoseArchive>,
    parsers: Vec<ParserType>,
    exclude_apollo: bool,
    logarchive_inventory_only: bool,
) -> Vec<(ParserType, Result<Value, String>, std::time::Duration)> {
    let selected: Vec<_> = parsers
        .into_iter()
        .filter(|p| {
            if exclude_apollo {
                !apollo_backed_parsers().contains(p)
            } else {
                true
            }
        })
        .collect();
    let opts = ParseOptions {
        logarchive_inventory_only,
        ..Default::default()
    };
    let mut out = Vec::with_capacity(selected.len());
    for t in selected {
        let start = std::time::Instant::now();
        let parser = parser_for_with_options(t, opts.clone());
        let mut sink = ValueSink::new(t.as_str());
        let res = parse_into_sink(parser.as_ref(), archive.as_ref(), &mut sink)
            .map(|_| sink.into_jsonl())
            .map_err(|e| e.to_string());
        out.push((t, res, start.elapsed()));
    }
    out
}

/// Generic -ng JSONL → Event adapter (SPEC §6.2.5).
pub fn adapt_parser_generic(parser: &str, value: &Value, interner: &Interner) -> Vec<Event> {
    let mut out = Vec::new();
    let Some(events) = value.get("events").and_then(|e| e.as_array()) else {
        return out;
    };
    for (i, ev) in events.iter().enumerate() {
        let datetime = ev.get("datetime").and_then(|v| v.as_str()).unwrap_or("");
        let message = ev
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let module = ev
            .get("module")
            .and_then(|v| v.as_str())
            .unwrap_or(parser);
        let ts = mul_apollo::epoch::parse_iso_text(datetime).unwrap_or(i64::MIN);
        let ts_quality = if ts == i64::MIN {
            TsQuality::Unknown
        } else {
            TsQuality::Exact
        };
        let mut event = Event {
            ts,
            ts_quality,
            source: SourceId::ng(parser),
            kind: EventKind::Generic,
            level: None,
            pid: None,
            process: None,
            bundle_id: None,
            subsystem: None,
            category: None,
            message: LazyText::owned(message),
            attrs: smallvec::SmallVec::new(),
            evidence: Evidence::new(format!("ng:{module}"), Some(i as u64)),
        };
        if let Some(data) = ev.get("data").and_then(|d| d.as_object()) {
            for (k, v) in data {
                let sym = interner.intern(k);
                event.attrs.push((sym, mul_core::Val::from_json(v)));
            }
        }
        out.push(event);
    }
    out
}

/// LogSource backed by an -ng archive (members via get / spilled paths).
pub struct NgArchiveSource {
    archive: Arc<SysdiagnoseArchive>,
}

impl NgArchiveSource {
    pub fn new(archive: Arc<SysdiagnoseArchive>) -> Self {
        Self { archive }
    }

    fn open_member(&self, rel: &str) -> Option<Bytes> {
        if let Some(abs) = self.archive.spilled_logarchive_abs(rel) {
            if let Ok(data) = std::fs::read(abs) {
                return Some(Bytes::from_owned(data));
            }
        }
        self.archive.get(rel).map(Bytes::from_slice)
    }
}

impl LogSource for NgArchiveSource {
    fn tracev3_files(&self) -> Vec<FileRef> {
        self.archive
            .all_paths()
            .into_iter()
            .filter(|p| p.to_ascii_lowercase().ends_with(".tracev3"))
            .map(FileRef::new)
            .collect()
    }

    fn timesync_files(&self) -> Vec<FileRef> {
        self.archive
            .all_paths()
            .into_iter()
            .filter(|p| {
                let l = p.to_ascii_lowercase();
                l.contains("timesync/") && l.ends_with(".timesync")
            })
            .map(FileRef::new)
            .collect()
    }

    fn uuidtext(&self, uuid: Uuid) -> Option<Bytes> {
        let hex: String = uuid.as_bytes().iter().map(|b| format!("{b:02X}")).collect();
        self.open_member(&format!("uuidtext/{}/{}", &hex[0..2], &hex[2..]))
            .or_else(|| self.open_member(&format!("{}/{}", &hex[0..2], &hex[2..])))
    }

    fn dsc(&self, uuid: Uuid) -> Option<Bytes> {
        let hex: String = uuid.as_bytes().iter().map(|b| format!("{b:02X}")).collect();
        self.open_member(&format!("uuidtext/dsc/{hex}"))
            .or_else(|| self.open_member(&format!("dsc/{hex}")))
    }

    fn open(&self, f: &FileRef) -> Result<Bytes, mul_io::SourceError> {
        self.open_member(&f.path)
            .ok_or_else(|| mul_io::SourceError::Msg(format!("missing {}", f.path)))
    }
}

pub fn all_parsers() -> Vec<ParserType> {
    all_parser_types()
}

/// Resolve analyser plan names to `-ng` parser types (`*` = all).
pub fn parsers_for_names<'a, I>(names: I) -> Vec<ParserType>
where
    I: IntoIterator<Item = &'a str>,
{
    let set: std::collections::BTreeSet<&str> = names.into_iter().collect();
    if set.contains("*") {
        return all_parser_types();
    }
    all_parser_types()
        .into_iter()
        .filter(|p| set.contains(p.as_str()))
        .collect()
}

/// Identity plists + mobileactivation logs used by the `accounts` analyser.
pub fn load_identity_extras(
    archive: &SysdiagnoseArchive,
) -> (std::collections::HashMap<String, Value>, Vec<String>) {
    let mut identity_plists = std::collections::HashMap::new();
    let mut activation_lock_log_texts = Vec::new();
    for path in archive.all_paths() {
        let base = path.rsplit('/').next().unwrap_or(path.as_str());
        if base.starts_with("._") {
            continue;
        }
        let lower = path.to_ascii_lowercase();
        if lower.contains("mobileactivation/mobileactivationd.log") {
            if let Some(bytes) = archive.get(&path) {
                activation_lock_log_texts
                    .push(String::from_utf8_lossy(bytes.as_ref()).into_owned());
            }
            continue;
        }
        let want = path.contains("CloudConfigurationDetails.plist")
            || (lower.contains("mobilecal") && path.ends_with(".plist"))
            || path.contains("EffectiveUserSettings.plist");
        if !want {
            continue;
        }
        if let Some(bytes) = archive.get(&path) {
            if let Ok(pv) = plist::from_bytes::<plist::Value>(bytes.as_ref()) {
                if let Ok(jv) = serde_json::to_value(&pv) {
                    identity_plists.insert(path.clone(), jv);
                }
            }
        }
    }
    (identity_plists, activation_lock_log_texts)
}

/// MCState Shared `profile-*.stub` texts for `mcstateshared`.
pub fn load_mcstate_stubs(archive: &SysdiagnoseArchive) -> std::collections::HashMap<String, String> {
    const MAX: usize = 2 * 1024 * 1024;
    let mut stubs = std::collections::HashMap::new();
    for path in archive.all_paths() {
        let lower = path.to_ascii_lowercase();
        if !(lower.contains("mcstate/shared/")
            && lower.contains("profile-")
            && lower.ends_with(".stub"))
        {
            continue;
        }
        if let Some(bytes) = archive.get(&path) {
            if bytes.len() > MAX {
                continue;
            }
            stubs.insert(
                path.clone(),
                String::from_utf8_lossy(bytes.as_ref()).into_owned(),
            );
        }
    }
    stubs
}
