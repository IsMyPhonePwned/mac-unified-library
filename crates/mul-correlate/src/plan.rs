// SPDX-License-Identifier: GPL-3.0-only
//! Analyser → parser dependency plan (SPEC §8.1 / upstream analyser needs).

use crate::analysers::AnalyserId;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Default)]
pub struct IngestPlan {
    pub parsers: BTreeSet<String>,
    /// Decode unified logs into the store (expensive).
    pub include_unified_logs: bool,
    /// Run APOLLO modules over archive DB members.
    pub include_apollo_modules: bool,
    /// Walk Biome/SEGB streams.
    pub include_biome: bool,
    /// Pull identity plists + mobileactivation raw logs (accounts).
    pub include_identity_extras: bool,
    /// Load MCState Shared profile-*.stub texts for `mcstateshared`.
    pub include_mcstate_stubs: bool,
    /// Retain every archive path (file_stats / coverage inventory).
    pub full_archive_inventory: bool,
    /// Decode logarchive into timeline events (timesketch / install_enrichment).
    pub decode_logarchive: bool,
}

impl IngestPlan {
    pub fn for_analysers(ids: &[AnalyserId]) -> Self {
        let mut plan = IngestPlan::default();
        for id in ids {
            plan.merge(&Self::for_analyser(*id));
        }
        plan
    }

    pub fn for_analyser(id: AnalyserId) -> Self {
        let mut plan = IngestPlan::default();
        match id {
            AnalyserId::accounts => {
                plan.parsers.extend(
                    ["mobileactivation", "plists", "transparency_json"]
                        .into_iter()
                        .map(str::to_string),
                );
                plan.include_identity_extras = true;
            }
            AnalyserId::apps => {
                plan.parsers.extend(
                    [
                        "accessibility_tcc",
                        "brctl",
                        "itunesstore",
                        "appinstallation",
                        "mobileinstallation",
                        "powerlogs",
                        "mobilebackup",
                        "plists",
                        "logdata_statistics",
                    ]
                    .into_iter()
                    .map(str::to_string),
                );
            }
            AnalyserId::coverage => {
                // Needs the full parser inventory for accurate totals; still skip logs/apollo.
                plan.parsers.insert("*".into());
                plan.full_archive_inventory = true;
            }
            AnalyserId::file_stats => {
                plan.parsers.insert("remotectl_dumpstate".into());
                plan.full_archive_inventory = true;
            }
            AnalyserId::install_enrichment => {
                plan.parsers.extend(
                    [
                        "mobileinstallation",
                        "logarchive",
                        "crashlogs",
                        "plists",
                        "ps",
                        "psthread",
                        "shutdownlogs",
                        "powerlogs",
                        "transparency_json",
                        "appinstallation",
                    ]
                    .into_iter()
                    .map(str::to_string),
                );
                plan.decode_logarchive = true;
            }
            AnalyserId::mcstateshared => {
                plan.parsers.insert("mcstate_shared_profile".into());
                plan.include_mcstate_stubs = true;
            }
            AnalyserId::network_iocs => {
                plan.parsers.extend(
                    [
                        "powerlogs",
                        "swcutil",
                        "safari_history",
                        "knowledgec",
                        "netusage",
                        "interactionc",
                        "quarantine_events",
                        "screentime",
                        "networkextension",
                        "networkextensioncache",
                        "plists",
                        "logarchive",
                        "transparency_json",
                        "crashlogs",
                        "logdata_statistics",
                        "logdata_statistics_txt",
                        "taskinfo",
                        "shutdownlogs",
                        "wifi_known_networks",
                        "wifinetworks",
                        "wifiscan",
                    ]
                    .into_iter()
                    .map(str::to_string),
                );
                // Decode unified log via mul-unifiedlog so IOC scan sees message hosts.
                plan.decode_logarchive = true;
            }
            AnalyserId::permissions => {
                plan.parsers.insert("accessibility_tcc".into());
            }
            AnalyserId::mdm => {
                plan.parsers.extend(
                    ["mcstate_shared_profile", "mcsettingsevents", "plists"]
                        .into_iter()
                        .map(str::to_string),
                );
                plan.include_mcstate_stubs = true;
            }
            AnalyserId::processes => {
                plan.parsers.extend(
                    [
                        "ps",
                        "psthread",
                        "taskinfo",
                        "shutdownlogs",
                        "logdata_statistics",
                        "uuid2path",
                        "remotectl_dumpstate",
                        "spindumpnosymbols",
                    ]
                    .into_iter()
                    .map(str::to_string),
                );
            }
            AnalyserId::summary => {
                plan.parsers.extend(
                    [
                        "remotectl_dumpstate",
                        "transparency_json",
                        "plists",
                        "mcstate_shared_profile",
                        "security_sysdiagnose",
                        "shutdownlogs",
                    ]
                    .into_iter()
                    .map(str::to_string),
                );
                plan.include_identity_extras = true;
                plan.include_mcstate_stubs = true;
            }
            AnalyserId::timesketch => {
                plan.parsers.insert("*".into());
                plan.decode_logarchive = true;
            }
            AnalyserId::wifi_geolocation => {
                plan.parsers.insert("wifi_known_networks".into());
            }
            AnalyserId::network_extension => {
                plan.parsers.extend(
                    ["networkextension", "networkextensioncache"]
                        .into_iter()
                        .map(str::to_string),
                );
            }
            AnalyserId::trust_store => {
                plan.parsers
                    .extend(["security_sysdiagnose", "plists"].into_iter().map(str::to_string));
            }
            AnalyserId::accessories => {
                plan.parsers
                    .extend(["bluetooth", "iousb"].into_iter().map(str::to_string));
            }
            AnalyserId::quarantine => {
                plan.parsers.insert("quarantine_events".into());
            }
            AnalyserId::lockdown_pairing => {
                plan.parsers.insert("lockdownd".into());
            }
            AnalyserId::crashes => {
                plan.parsers.insert("crashlogs".into());
            }
            AnalyserId::runningboard => {
                plan.parsers.insert("runningboard".into());
            }
            AnalyserId::account_trust => {
                plan.parsers.extend(
                    [
                        "ckks_pcs",
                        "usermanagement",
                        "transparency_json",
                        "security_sysdiagnose",
                    ]
                    .into_iter()
                    .map(str::to_string),
                );
            }
            AnalyserId::device_integrity => {
                plan.parsers
                    .extend(["mount", "ota_update"].into_iter().map(str::to_string));
            }
            AnalyserId::overview | AnalyserId::app_activity | AnalyserId::boots => {
                plan.parsers.insert("*".into());
                plan.include_unified_logs = true;
                plan.include_apollo_modules = true;
                plan.include_biome = true;
                plan.include_identity_extras = true;
                plan.include_mcstate_stubs = true;
            }
        }
        plan
    }

    pub fn merge(&mut self, other: &IngestPlan) {
        self.parsers.extend(other.parsers.iter().cloned());
        self.include_unified_logs |= other.include_unified_logs;
        self.include_apollo_modules |= other.include_apollo_modules;
        self.include_biome |= other.include_biome;
        self.include_identity_extras |= other.include_identity_extras;
        self.include_mcstate_stubs |= other.include_mcstate_stubs;
        self.full_archive_inventory |= other.full_archive_inventory;
        self.decode_logarchive |= other.decode_logarchive;
    }

    pub fn wants_all_parsers(&self) -> bool {
        self.parsers.contains("*")
    }
}
