// SPDX-License-Identifier: GPL-3.0-only

use crate::store::Store;
use mul_core::event::EventKind;
use mul_core::Val;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Collection {
    pub inputs: Vec<String>,
    pub tool_version: String,
    pub timings_ms: Vec<(String, u64)>,
    pub coverage_pct: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub model: Option<String>,
    pub hardware_id: Option<String>,
    pub os_build: Option<String>,
    pub serial: Option<String>,
    pub udid: Option<String>,
    pub name: Option<String>,
    pub timezone: Option<String>,
    pub locale: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Boot {
    pub uuid: String,
    pub start_ns: Option<i64>,
    pub end_ns: Option<i64>,
    pub clean: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub kind: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppSummary {
    pub bundle_id: String,
    pub name: Option<String>,
    pub version: Option<String>,
    pub source: Option<String>,
    pub event_count: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessSummary {
    pub unique_executables: usize,
    pub unknown_paths: Vec<String>,
    pub top_by_events: Vec<(String, u64)>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkSummary {
    pub known_wifi: usize,
    pub top_endpoints: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecuritySummary {
    pub profiles: usize,
    pub tcc_grants: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActivitySummary {
    pub per_day_counts: Vec<(String, u64)>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogSummary {
    pub span_start_ns: Option<i64>,
    pub span_end_ns: Option<i64>,
    pub event_estimate: u64,
    pub loss_records: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Finding {
    pub severity: String,
    pub rule_id: String,
    pub explanation: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Coverage {
    pub sources: Vec<(String, String)>,
    pub apollo_variants: Vec<(String, String)>,
    pub biome_streams_present: usize,
    pub biome_streams_mapped: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SystemOverview {
    pub schema_version: u32,
    pub collection: Collection,
    pub device: DeviceInfo,
    pub boots: Vec<Boot>,
    pub accounts: Vec<Account>,
    pub apps: Vec<AppSummary>,
    pub processes: ProcessSummary,
    pub network: NetworkSummary,
    pub security: SecuritySummary,
    pub activity: ActivitySummary,
    pub logs: LogSummary,
    pub anomalies: Vec<Finding>,
    pub coverage: Coverage,
}

impl SystemOverview {
    pub fn empty() -> Self {
        Self {
            schema_version: 1,
            ..Default::default()
        }
    }
}

pub fn build_overview(
    store: &Store,
    inputs: &[String],
    version: &str,
    timings: Vec<(String, u64)>,
    module_count: usize,
    device: DeviceInfo,
    boots: Vec<Boot>,
) -> SystemOverview {
    let mut apps: hashbrown::HashMap<String, u64> = hashbrown::HashMap::new();
    let mut procs: hashbrown::HashMap<String, u64> = hashbrown::HashMap::new();
    let mut unknown_paths = Vec::new();
    let mut span_start = None;
    let mut span_end = None;
    let mut tcc = 0usize;
    let mut day_counts: hashbrown::HashMap<String, u64> = hashbrown::HashMap::new();
    let mut accounts = Vec::new();
    let mut wifi = 0usize;
    let mut endpoints = Vec::new();

    for e in &store.events {
        if e.ts != i64::MIN {
            span_start = Some(span_start.map_or(e.ts, |a: i64| a.min(e.ts)));
            span_end = Some(span_end.map_or(e.ts, |a: i64| a.max(e.ts)));
            let day = (e.ts.div_euclid(86_400_000_000_000)).to_string();
            *day_counts.entry(day).or_default() += 1;
        }
        if matches!(e.kind, EventKind::PermissionChange) || e.message.as_str().contains("TCC") {
            tcc += 1;
        }
        if e.source.0.contains("wifi") || e.message.as_str().contains("SSID") {
            wifi += 1;
        }
        for (_, v) in &e.attrs {
            if let Some(s) = val_as_text(v) {
                if looks_like_bundle(&s) {
                    *apps.entry(s.clone()).or_default() += 1;
                }
                if s.starts_with('/') {
                    *procs.entry(s.clone()).or_default() += 1;
                    if !path_looks_known(&s) {
                        unknown_paths.push(s.clone());
                    }
                }
                if s.contains('@') && s.contains('.') {
                    accounts.push(Account {
                        id: s.clone(),
                        kind: Some("email".into()),
                    });
                }
                if looks_like_host(&s) {
                    endpoints.push(s);
                }
            }
        }
        if let Some(path) = attr_path(e) {
            *procs.entry(path.clone()).or_default() += 1;
        }
    }

    let mut app_summaries: Vec<AppSummary> = apps
        .into_iter()
        .map(|(bundle_id, event_count)| AppSummary {
            bundle_id,
            name: None,
            version: None,
            source: None,
            event_count,
        })
        .collect();
    app_summaries.sort_by_key(|b| std::cmp::Reverse(b.event_count));
    app_summaries.truncate(200);

    let mut top: Vec<_> = procs.into_iter().collect();
    top.sort_by_key(|b| std::cmp::Reverse(b.1));
    top.truncate(50);

    unknown_paths.sort();
    unknown_paths.dedup();
    unknown_paths.truncate(32);

    accounts.sort_by(|a, b| a.id.cmp(&b.id));
    accounts.dedup_by(|a, b| a.id == b.id);
    accounts.truncate(64);

    endpoints.sort();
    endpoints.dedup();
    endpoints.truncate(50);

    let mut per_day: Vec<_> = day_counts.into_iter().collect();
    per_day.sort();

    let mut ov = SystemOverview::empty();
    ov.collection = Collection {
        inputs: inputs.to_vec(),
        tool_version: version.to_string(),
        timings_ms: timings,
        coverage_pct: if store.events.is_empty() { 0.0 } else { 100.0 },
    };
    ov.device = device;
    ov.boots = boots;
    ov.accounts = accounts;
    ov.apps = app_summaries;
    ov.processes = ProcessSummary {
        unique_executables: top.len(),
        unknown_paths,
        top_by_events: top,
    };
    ov.network = NetworkSummary {
        known_wifi: wifi,
        top_endpoints: endpoints,
    };
    ov.security.tcc_grants = tcc;
    ov.activity.per_day_counts = per_day;
    ov.logs = LogSummary {
        span_start_ns: span_start,
        span_end_ns: span_end,
        event_estimate: store.events.len() as u64,
        loss_records: 0,
    };
    ov.coverage.apollo_variants.push((
        "modules_loaded".into(),
        module_count.to_string(),
    ));
    ov.coverage.sources.push((
        "events".into(),
        format!("{} events", store.events.len()),
    ));
    ov.anomalies = crate::anomalies::find(store);
    ov
}

fn val_as_text(v: &Val) -> Option<String> {
    match v {
        Val::Text(s) => Some(s.to_string()),
        Val::I64(i) => Some(i.to_string()),
        _ => None,
    }
}

fn attr_path(e: &mul_core::Event) -> Option<String> {
    e.attrs.iter().find_map(|(_, v)| match v {
        Val::Text(s) if s.starts_with('/') => Some(s.to_string()),
        _ => None,
    })
}

fn looks_like_bundle(s: &str) -> bool {
    s.contains('.') && !s.contains(' ') && !s.starts_with('/') && s.len() > 4 && s.len() < 128
}

fn looks_like_host(s: &str) -> bool {
    s.contains('.')
        && !s.contains(' ')
        && !s.starts_with('/')
        && !s.contains('@')
        && s.len() < 253
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

fn path_looks_known(s: &str) -> bool {
    s.starts_with("/System/")
        || s.starts_with("/usr/")
        || s.starts_with("/bin/")
        || s.starts_with("/sbin/")
        || s.starts_with("/Applications/")
        || s.starts_with("/Library/")
        || s.starts_with("/private/var/containers/")
}
