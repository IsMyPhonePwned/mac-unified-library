// SPDX-License-Identifier: GPL-3.0-only

pub mod accounts;
pub mod common;

mod accessories;
mod account_trust;
mod apps;
mod coverage;
mod crashes;
mod device_integrity;
mod file_stats;
mod install_enrichment;
mod lockdown_pairing;
mod mcstateshared;
mod mdm;
mod network_extension;
mod network_iocs;
mod permissions;
mod processes;
mod quarantine;
mod runningboard;
mod summary;
mod timesketch;
mod trust_store;
mod wifi_geolocation;

use crate::overview::{self, Boot, DeviceInfo};
use crate::store::Store;
use mul_core::Val;
use serde_json::{json, Value};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum AnalyserId {
    accounts,
    apps,
    coverage,
    file_stats,
    install_enrichment,
    mcstateshared,
    network_iocs,
    permissions,
    /// Unified MDM: payloads + settings events + Shared_MDM status.
    mdm,
    /// Unified process inventory + per-PID source matrix.
    processes,
    summary,
    timesketch,
    /// Known Wi‑Fi geolocation as GPX + KML.
    wifi_geolocation,
    network_extension,
    trust_store,
    accessories,
    quarantine,
    lockdown_pairing,
    crashes,
    runningboard,
    account_trust,
    device_integrity,
    overview,
    app_activity,
    boots,
}

impl AnalyserId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::accounts => "accounts",
            Self::apps => "apps",
            Self::coverage => "coverage",
            Self::file_stats => "file_stats",
            Self::install_enrichment => "install_enrichment",
            Self::mcstateshared => "mcstateshared",
            Self::network_iocs => "network_iocs",
            Self::permissions => "permissions",
            Self::mdm => "mdm",
            Self::processes => "processes",
            Self::summary => "summary",
            Self::timesketch => "timesketch",
            Self::wifi_geolocation => "wifi_geolocation",
            Self::network_extension => "network_extension",
            Self::trust_store => "trust_store",
            Self::accessories => "accessories",
            Self::quarantine => "quarantine",
            Self::lockdown_pairing => "lockdown_pairing",
            Self::crashes => "crashes",
            Self::runningboard => "runningboard",
            Self::account_trust => "account_trust",
            Self::device_integrity => "device_integrity",
            Self::overview => "overview",
            Self::app_activity => "app_activity",
            Self::boots => "boots",
        }
    }

    /// Parse a mul analyser id. Aliases fold legacy split analysers into one id.
    pub fn parse(s: &str) -> Option<AnalyserId> {
        match s {
            "ps_everywhere" | "ps_matrix" | "process_matrix" => Some(Self::processes),
            "wifi_geolocation_kml" => Some(Self::wifi_geolocation),
            "plist" | "mdm_payloads" => Some(Self::mdm),
            other => Self::all().iter().copied().find(|a| a.as_str() == other),
        }
    }

    /// Drop-in analyser set with mul-native names (used by CLI `--analyser all` / Python defaults).
    pub fn compat_ids() -> &'static [AnalyserId] {
        &[
            Self::accounts,
            Self::apps,
            Self::coverage,
            Self::file_stats,
            Self::install_enrichment,
            Self::mcstateshared,
            Self::network_iocs,
            Self::permissions,
            Self::mdm,
            Self::processes,
            Self::summary,
            Self::timesketch,
            Self::wifi_geolocation,
        ]
    }

    pub fn all() -> &'static [AnalyserId] {
        &[
            Self::accounts,
            Self::apps,
            Self::coverage,
            Self::file_stats,
            Self::install_enrichment,
            Self::mcstateshared,
            Self::network_iocs,
            Self::permissions,
            Self::mdm,
            Self::processes,
            Self::summary,
            Self::timesketch,
            Self::wifi_geolocation,
            Self::network_extension,
            Self::trust_store,
            Self::accessories,
            Self::quarantine,
            Self::lockdown_pairing,
            Self::crashes,
            Self::runningboard,
            Self::account_trust,
            Self::device_integrity,
            Self::overview,
            Self::app_activity,
            Self::boots,
        ]
    }
}

#[derive(Default)]
pub struct AnalyseCtx {
    pub ioc_files: Vec<String>,
    pub device: DeviceInfo,
    pub boots: Vec<Boot>,
    pub inputs: Vec<String>,
    pub version: String,
    pub timings: Vec<(String, u64)>,
    pub module_count: usize,
    /// Raw -ng / parser JSON keyed by parser id (e.g. `transparency_json`).
    pub parsed: HashMap<String, Value>,
    /// Targeted identity plists (path → decoded JSON).
    pub identity_plists: HashMap<String, Value>,
    /// Raw `mobileactivationd.log*` text for ActivationLockUsername fallback.
    pub activation_lock_log_texts: Vec<String>,
    pub archive_paths: Vec<String>,
    pub archive_stub_texts: HashMap<String, String>,
    pub parser_types_total: usize,
    /// Powerlog SQLite payloads `(archive_path, bytes)` for direct App Info mining.
    pub powerlog_db_blobs: Vec<(String, Vec<u8>)>,
    /// Optional install-enrichment rules (TOML path or in-memory). Empty = built-in defaults.
    pub install_enrichment_rules_toml: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AnalyserOutput {
    pub id: String,
    pub value: Value,
}

pub fn run(id: AnalyserId, store: &Store, ctx: &AnalyseCtx) -> AnalyserOutput {
    let value = match id {
        AnalyserId::accounts => accounts::run(
            &ctx.parsed,
            &ctx.identity_plists,
            &ctx.activation_lock_log_texts,
        ),
        AnalyserId::apps => apps::run(&ctx.parsed, &ctx.powerlog_db_blobs),
        AnalyserId::coverage => coverage::run(&ctx.parsed, ctx),
        AnalyserId::file_stats => file_stats::run(&ctx.parsed, ctx),
        AnalyserId::install_enrichment => {
            install_enrichment::run(&ctx.parsed, ctx.install_enrichment_rules_toml.as_deref())
        }
        AnalyserId::mcstateshared => mcstateshared::run(&ctx.parsed, ctx),
        AnalyserId::network_iocs => network_iocs::run(&ctx.parsed),
        AnalyserId::permissions => permissions::run(&ctx.parsed),
        AnalyserId::mdm => mdm::run(&ctx.parsed),
        AnalyserId::processes => processes::run(&ctx.parsed),
        AnalyserId::summary => summary::run(&ctx.parsed),
        AnalyserId::timesketch => timesketch::run(&ctx.parsed, ctx),
        AnalyserId::wifi_geolocation => wifi_geolocation::run(&ctx.parsed),
        AnalyserId::network_extension => network_extension::run(&ctx.parsed),
        AnalyserId::trust_store => trust_store::run(&ctx.parsed),
        AnalyserId::accessories => accessories::run(&ctx.parsed),
        AnalyserId::quarantine => quarantine::run(&ctx.parsed),
        AnalyserId::lockdown_pairing => lockdown_pairing::run(&ctx.parsed),
        AnalyserId::crashes => crashes::run(&ctx.parsed),
        AnalyserId::runningboard => runningboard::run(&ctx.parsed),
        AnalyserId::account_trust => account_trust::run(&ctx.parsed),
        AnalyserId::device_integrity => device_integrity::run(&ctx.parsed),
        AnalyserId::overview => {
            let ov = overview::build_overview(
                store,
                &ctx.inputs,
                &ctx.version,
                ctx.timings.clone(),
                ctx.module_count,
                ctx.device.clone(),
                ctx.boots.clone(),
            );
            serde_json::to_value(ov).unwrap_or(json!({}))
        }
        AnalyserId::app_activity => {
            let mut by_day: hashbrown::HashMap<String, hashbrown::HashMap<String, u64>> =
                hashbrown::HashMap::new();
            for e in &store.events {
                if e.ts == i64::MIN {
                    continue;
                }
                let day = e.ts.div_euclid(86_400_000_000_000).to_string();
                let app = bundle_hint(e).unwrap_or_else(|| e.source.0.clone());
                *by_day.entry(day).or_default().entry(app).or_default() += 1;
            }
            let mut days = serde_json::Map::new();
            for (day, apps) in by_day {
                days.insert(day, map_to_obj(apps));
            }
            json!({ "by_day": days })
        }
        AnalyserId::boots => {
            let boots: Vec<_> = ctx
                .boots
                .iter()
                .map(|b| {
                    json!({
                        "uuid": b.uuid,
                        "start_ns": b.start_ns,
                        "end_ns": b.end_ns,
                        "clean": b.clean,
                    })
                })
                .collect();
            json!({ "boots": boots })
        }
    };
    AnalyserOutput {
        id: id.as_str().to_string(),
        value,
    }
}

fn map_to_obj(m: hashbrown::HashMap<String, u64>) -> Value {
    let mut obj = serde_json::Map::new();
    let mut keys: Vec<_> = m.keys().cloned().collect();
    keys.sort();
    for k in keys {
        if let Some(v) = m.get(&k) {
            obj.insert(k, json!(*v));
        }
    }
    Value::Object(obj)
}

fn bundle_hint(e: &mul_core::event::Event) -> Option<String> {
    for (_, v) in &e.attrs {
        if let Val::Text(s) = v {
            let s = s.as_ref();
            if s.contains('.') && !s.contains(' ') && !s.starts_with('/') && s.len() > 4 {
                return Some(s.to_string());
            }
        }
    }
    None
}
