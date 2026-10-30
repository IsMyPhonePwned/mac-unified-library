// SPDX-License-Identifier: GPL-3.0-only

use mul_apollo::{ModuleSet, RunOptions, SqliteRuntime};
use mul_core::event::{Event, EventKind, Evidence, LazyText, SourceId, TsQuality};
use mul_core::filter::Filter;
use mul_core::interner::Interner;
use mul_core::{MulError, Result};
use mul_correlate::analysers::{self, AnalyserId, AnalyseCtx};
use mul_correlate::overview::{self, Boot, DeviceInfo, SystemOverview};
use mul_correlate::plan::IngestPlan;
use mul_correlate::store::{PartialStore, Store};
use mul_ingest::{Input, InputKind};
use mul_unifiedlog::{DirLogSource, Options as LogOptions, OwnedLogEvent, UnifiedLog};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Debug, Default, Clone)]
pub struct SessionStats {
    pub stages: Vec<(String, u64)>,
}

/// Result of [`Session::parse_parsers`].
#[derive(Debug, Clone, Default)]
pub struct ParseReport {
    pub values: HashMap<String, Value>,
    /// Per-parser internal duration in milliseconds.
    pub timings_ms: HashMap<String, f64>,
    pub errors: HashMap<String, String>,
    /// End-to-end wall time for the parse call (includes archive open).
    pub wall_ms: f64,
}

pub struct SessionBuilder {
    inputs: Vec<Input>,
    threads: usize,
    mem_budget: usize,
    modules: Option<ModuleSet>,
    exclude_ng_apollo: bool,
    ioc_files: Vec<String>,
    log_event_cap: usize,
    install_enrichment_rules_toml: Option<String>,
}

impl SessionBuilder {
    pub fn new() -> Self {
        Self {
            inputs: Vec::new(),
            threads: 0,
            mem_budget: 512 << 20,
            modules: None,
            exclude_ng_apollo: true,
            ioc_files: Vec::new(),
            log_event_cap: 50_000,
            install_enrichment_rules_toml: None,
        }
    }

    pub fn input(mut self, input: Input) -> Self {
        self.inputs.push(input);
        self
    }

    pub fn threads(mut self, n: usize) -> Self {
        self.threads = n;
        self
    }

    pub fn mem_budget(mut self, n: usize) -> Self {
        self.mem_budget = n;
        self
    }

    pub fn modules(mut self, modules: ModuleSet) -> Self {
        self.modules = Some(modules);
        self
    }

    pub fn ng_apollo(mut self, enable: bool) -> Self {
        self.exclude_ng_apollo = !enable;
        self
    }

    pub fn ioc_file(mut self, path: impl Into<String>) -> Self {
        self.ioc_files.push(path.into());
        self
    }

    pub fn log_event_cap(mut self, n: usize) -> Self {
        self.log_event_cap = n;
        self
    }

    pub fn build(self) -> Result<Session> {
        if self.inputs.is_empty() {
            return Err(MulError::msg("no inputs"));
        }
        let modules = self.modules.unwrap_or_else(ModuleSet::default_set);
        Ok(Session {
            inputs: self.inputs,
            threads: self.threads,
            mem_budget: self.mem_budget,
            modules,
            exclude_ng_apollo: self.exclude_ng_apollo,
            ioc_files: self.ioc_files,
            log_event_cap: self.log_event_cap,
            interner: Interner::new(),
            apollo: SqliteRuntime::new(),
            store: None,
            parsed: HashMap::new(),
            parsers_done: BTreeSet::new(),
            identity_plists: HashMap::new(),
            activation_lock_log_texts: Vec::new(),
            archive_paths: Vec::new(),
            archive_stub_texts: HashMap::new(),
            powerlog_db_blobs: Vec::new(),
            install_enrichment_rules_toml: self.install_enrichment_rules_toml,
            identity_loaded: false,
            stubs_loaded: bool::default(),
            logs_ingested: false,
            apollo_ingested: false,
            biome_ingested: false,
            device: DeviceInfo::default(),
            boots: Vec::new(),
            stats: SessionStats::default(),
        })
    }

    pub fn install_enrichment_rules_toml(mut self, toml: impl Into<String>) -> Self {
        self.install_enrichment_rules_toml = Some(toml.into());
        self
    }
}

impl Default for SessionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Session {
    inputs: Vec<Input>,
    threads: usize,
    mem_budget: usize,
    modules: ModuleSet,
    exclude_ng_apollo: bool,
    ioc_files: Vec<String>,
    log_event_cap: usize,
    interner: Interner,
    apollo: SqliteRuntime,
    store: Option<Store>,
    parsed: HashMap<String, Value>,
    parsers_done: BTreeSet<String>,
    identity_plists: HashMap<String, Value>,
    activation_lock_log_texts: Vec<String>,
    archive_paths: Vec<String>,
    archive_stub_texts: HashMap<String, String>,
    powerlog_db_blobs: Vec<(String, Vec<u8>)>,
    install_enrichment_rules_toml: Option<String>,
    identity_loaded: bool,
    stubs_loaded: bool,
    logs_ingested: bool,
    apollo_ingested: bool,
    biome_ingested: bool,
    device: DeviceInfo,
    boots: Vec<Boot>,
    stats: SessionStats,
}

impl Session {
    pub fn builder() -> SessionBuilder {
        SessionBuilder::new()
    }

    /// Override install-enrichment rules (TOML text). `None` clears to builtins.
    pub fn set_install_enrichment_rules_toml(&mut self, toml: Option<String>) {
        self.install_enrichment_rules_toml = toml;
    }

    pub fn stats(&self) -> &SessionStats {
        &self.stats
    }

    pub fn modules(&self) -> &ModuleSet {
        &self.modules
    }

    pub fn apollo(&self) -> &SqliteRuntime {
        &self.apollo
    }

    pub fn info(&mut self) -> Result<Value> {
        let start = Instant::now();
        let mut inputs = Vec::new();
        for inp in &self.inputs {
            inputs.push(serde_json::json!({
                "path": inp.path.display().to_string(),
                "kind": format!("{:?}", inp.kind),
            }));
        }
        let mut boots = Vec::new();
        let mut units = 0usize;
        let mut files = 0usize;
        let mut span_start: Option<i64> = None;
        let mut span_end: Option<i64> = None;
        let mut build = None;
        let mut hw = None;
        for inp in &self.inputs {
            if matches!(
                inp.kind,
                InputKind::Logarchive
                    | InputKind::Unknown
                    | InputKind::Sysdiagnose
                    | InputKind::FullFilesystem
            ) || inp.path.extension().and_then(|e| e.to_str()) == Some("logarchive")
                || inp.path.is_dir()
            {
                let candidates = [
                    inp.path.join("system_logs.logarchive"),
                    inp.path.clone(),
                ];
                for cand in &candidates {
                    if !cand.exists() {
                        continue;
                    }
                    if let Ok(src) = DirLogSource::open(cand) {
                        let opts = LogOptions {
                            threads: self.threads,
                            ordered: false,
                            include_signposts: false,
                        };
                        if let Ok(log) = UnifiedLog::open(src, opts) {
                            let s = log.stats();
                            files += s.files;
                            units += s.unit_count;
                            for b in &s.boot_uuids {
                                if !boots.contains(b) {
                                    boots.push(b.clone());
                                }
                            }
                            span_start = match (span_start, s.span_start_ns) {
                                (Some(a), Some(b)) => Some(a.min(b)),
                                (a, b) => a.or(b),
                            };
                            span_end = match (span_end, s.span_end_ns) {
                                (Some(a), Some(b)) => Some(a.max(b)),
                                (a, b) => a.or(b),
                            };
                            if build.is_none() {
                                build = s.build.clone();
                            }
                            if hw.is_none() {
                                hw = s.hardware_model.clone();
                            }
                            break;
                        }
                    }
                }
            }
        }
        self.device.os_build = build.clone();
        self.device.hardware_id = hw.clone();
        self.device.model = hw.clone();
        self.boots = boots
            .iter()
            .map(|u| Boot {
                uuid: u.clone(),
                start_ns: span_start,
                end_ns: span_end,
                clean: None,
            })
            .collect();
        self.stats
            .stages
            .push(("info".into(), start.elapsed().as_millis() as u64));
        Ok(serde_json::json!({
            "version": crate::VERSION,
            "inputs": inputs,
            "modules": self.modules.len(),
            "boots": boots,
            "boot_count": boots.len(),
            "tracev3_files": files,
            "units": units,
            "span_start_ns": span_start,
            "span_end_ns": span_end,
            "build": build,
            "hardware_model": hw,
            "mem_budget": self.mem_budget,
        }))
    }

    /// Open unified logs for the first logarchive-like input.
    pub fn logs(&mut self) -> Result<UnifiedLog> {
        for inp in &self.inputs {
            let candidates = [
                inp.path.join("system_logs.logarchive"),
                inp.path.clone(),
            ];
            for cand in &candidates {
                if !cand.exists() {
                    continue;
                }
                if let Ok(src) = DirLogSource::open(cand) {
                    let opts = LogOptions {
                        threads: self.threads,
                        ordered: true,
                        include_signposts: false,
                    };
                    return UnifiedLog::open(src, opts);
                }
            }
        }
        Err(MulError::msg("no logarchive input found"))
    }

    /// Full ingest (all parsers + capped unified logs + APOLLO + biome).
    pub fn ensure_store(&mut self) -> Result<&Store> {
        let plan = IngestPlan {
            parsers: {
                let mut s = BTreeSet::new();
                s.insert("*".into());
                s
            },
            include_unified_logs: true,
            include_apollo_modules: true,
            include_biome: true,
            include_identity_extras: true,
            include_mcstate_stubs: true,
            full_archive_inventory: true,
            decode_logarchive: false,
        };
        self.apply_plan(&plan)?;
        self.rebuild_store_from_parsed()?;
        self.store
            .as_ref()
            .ok_or_else(|| MulError::msg("store missing after build"))
    }

    /// Run planned ingest for the given analysers (parser deps only; skip logs/apollo unless required).
    pub fn ensure_for_analysers(&mut self, ids: &[AnalyserId]) -> Result<()> {
        let plan = IngestPlan::for_analysers(ids);
        self.apply_plan(&plan)
    }

    /// Parse one or more `-ng` parsers with tight retention (no unified-log / biome ingest).
    ///
    /// Returns parser JSON plus per-parser wall times (ms). Empty `names` or `"*"` = all parsers.
    pub fn parse_parsers(
        &mut self,
        names: &[String],
        decode_logarchive: bool,
    ) -> Result<ParseReport> {
        #[cfg(not(feature = "ng"))]
        {
            let _ = (names, decode_logarchive);
            return Err(MulError::msg("ng feature disabled"));
        }
        #[cfg(feature = "ng")]
        {
            let start = Instant::now();
            let want_all = names.is_empty() || names.iter().any(|n| n == "*");
            let parsers = if want_all {
                mul_ingest::ng::all_parsers()
            } else {
                mul_ingest::ng::parsers_for_names(names.iter().map(|s| s.as_str()))
            };
            if parsers.is_empty() {
                return Err(MulError::msg("no matching parsers"));
            }

            let mut values = HashMap::new();
            let mut timings_ms = HashMap::new();
            let mut errors = HashMap::new();

            for inp in self.inputs.clone() {
                if !is_sysdiagnose_input(&inp) {
                    continue;
                }
                // Tight retention: only what the named parsers need (no logarchive/dsc extras).
                let archive =
                    mul_ingest::ng::open_archive_ex(&inp.path, &parsers, false, false)?;
                // Always run the named parsers (including apollo-backed ones) for fair
                // comparison with sdx-cli; skip mul-apollo module walk here.
                let results = mul_ingest::ng::run_ng_parsers_ex(
                    archive,
                    parsers.clone(),
                    false, // do not exclude apollo-backed -ng parsers
                    !decode_logarchive,
                );
                for (ty, res, d) in results {
                    let key = ty.as_str().to_string();
                    timings_ms.insert(key.clone(), d.as_secs_f64() * 1000.0);
                    self.parsers_done.insert(key.clone());
                    match res {
                        Ok(v) => {
                            // Single owner: report only. Full ingest (`apply_plan`) fills
                            // `self.parsed`; cloning the ~70MB powerlogs tree here just for
                            // the session cache doubles peak RSS on `mul parse`.
                            values.insert(key, v);
                        }
                        Err(e) => {
                            errors.insert(key, e);
                        }
                    }
                }
                break;
            }

            if values.is_empty() && errors.is_empty() {
                return Err(MulError::msg("no sysdiagnose input found"));
            }

            self.stats.stages.push((
                format!("parse:{}", values.len()),
                start.elapsed().as_millis() as u64,
            ));
            Ok(ParseReport {
                values,
                timings_ms,
                errors,
                wall_ms: start.elapsed().as_secs_f64() * 1000.0,
            })
        }
    }

    /// All `-ng` parser ids (sorted).
    pub fn list_parsers() -> Vec<String> {
        #[cfg(feature = "ng")]
        {
            let mut v: Vec<String> = mul_ingest::ng::all_parsers()
                .into_iter()
                .map(|p| p.as_str().to_string())
                .collect();
            v.sort();
            v
        }
        #[cfg(not(feature = "ng"))]
        {
            Vec::new()
        }
    }

    fn apply_plan(&mut self, plan: &IngestPlan) -> Result<()> {
        let start = Instant::now();

        #[cfg(feature = "ng")]
        {
            let want_names: Vec<&str> = if plan.wants_all_parsers() {
                vec!["*"]
            } else {
                plan.parsers.iter().map(|s| s.as_str()).collect()
            };
            let mut parsers = mul_ingest::ng::parsers_for_names(want_names);
            if !plan.wants_all_parsers() {
                parsers.retain(|p| !self.parsers_done.contains(p.as_str()));
            } else {
                // Still skip already-done parsers when expanding to all.
                parsers.retain(|p| !self.parsers_done.contains(p.as_str()));
            }

            let need_powerlog_blobs = plan.parsers.iter().any(|p| p == "powerlogs")
                && self.powerlog_db_blobs.is_empty();
            let need_open = !parsers.is_empty()
                || (plan.include_identity_extras && !self.identity_loaded)
                || (plan.include_mcstate_stubs && !self.stubs_loaded)
                || self.archive_paths.is_empty()
                || (plan.include_apollo_modules && !self.apollo_ingested)
                || need_powerlog_blobs;

            if need_open {
                for inp in self.inputs.clone() {
                    if !is_sysdiagnose_input(&inp) {
                        continue;
                    }
                    let mut names: BTreeSet<String> = plan.parsers.clone();
                    names.extend(self.parsers_done.iter().cloned());
                    if names.is_empty() {
                        names.insert("*".into());
                    }
                    let open_parsers =
                        mul_ingest::ng::parsers_for_names(names.iter().map(|s| s.as_str()));

                    match mul_ingest::ng::open_archive_ex(
                        &inp.path,
                        &open_parsers,
                        plan.full_archive_inventory,
                        plan.include_apollo_modules || plan.decode_logarchive,
                    ) {
                        Ok(archive) => {
                            if self.archive_paths.is_empty() {
                                // Match original sdx `archive.len()` / `iter_files()`:
                                // exclude spilled logarchive members (tracev3, …).
                                let spilled: BTreeSet<String> = archive
                                    .logarchive_spilled_entries()
                                    .into_iter()
                                    .map(|(p, _)| p)
                                    .collect();
                                self.archive_paths = archive
                                    .all_paths()
                                    .into_iter()
                                    .filter(|p| !spilled.contains(p))
                                    .collect();
                            }

                            if self.powerlog_db_blobs.is_empty() {
                                for path in archive.all_paths() {
                                    let low = path.to_ascii_lowercase();
                                    let is_plsql = (low.contains("powerlog") || low.ends_with(".plsql")
                                        || low.ends_with(".plsql.gz"))
                                        && (low.ends_with(".plsql")
                                            || low.ends_with(".plsql.gz")
                                            || low.contains("/powerlogs/"));
                                    if !is_plsql {
                                        continue;
                                    }
                                    if let Some(bytes) = archive.get(&path) {
                                        self.powerlog_db_blobs.push((path, bytes.to_vec()));
                                    }
                                }
                            }

                            if plan.include_identity_extras && !self.identity_loaded {
                                let (plists, logs) =
                                    mul_ingest::ng::load_identity_extras(archive.as_ref());
                                self.identity_plists.extend(plists);
                                self.activation_lock_log_texts.extend(logs);
                                self.identity_loaded = true;
                            }

                            if plan.include_mcstate_stubs && !self.stubs_loaded {
                                self.archive_stub_texts
                                    .extend(mul_ingest::ng::load_mcstate_stubs(archive.as_ref()));
                                self.stubs_loaded = true;
                            }

                            if !parsers.is_empty() {
                                // Compat analysers (timesketch, apps, network_iocs, …) need the
                                // upstream `-ng` powerlogs/knowledgec/… JSON. Only skip those
                                // parsers for mul-native full ingest when the plan does not name them.
                                let needs_apollo_parsers = plan.wants_all_parsers()
                                    || parsers.iter().any(|p| {
                                        mul_ingest::ng::apollo_backed_parsers().contains(p)
                                    });
                                let exclude_apollo =
                                    self.exclude_ng_apollo && !needs_apollo_parsers;
                                let results = mul_ingest::ng::run_ng_parsers_ex(
                                    archive.clone(),
                                    parsers.clone(),
                                    exclude_apollo,
                                    !plan.decode_logarchive,
                                );
                                for (ty, res, _d) in results {
                                    let key = ty.as_str().to_string();
                                    self.parsers_done.insert(key.clone());
                                    if let Ok(v) = res {
                                        self.parsed.insert(key, v);
                                    }
                                }
                            }

                            if plan.include_apollo_modules && !self.apollo_ingested {
                                let runtime = &self.apollo;
                                let mut partial = PartialStore::default();
                                for module in self.modules.modules() {
                                    for path in archive.all_paths() {
                                        if !mul_apollo::runtime::path_matches_module(module, &path)
                                        {
                                            continue;
                                        }
                                        if let Some(bytes) = archive.get(&path) {
                                            if let Ok((_st, rows)) = runtime.run_module_on_bytes(
                                                module,
                                                &path,
                                                bytes,
                                                &RunOptions::default(),
                                            ) {
                                                for ev in rows {
                                                    partial.ingest_event(ev);
                                                }
                                            }
                                        }
                                    }
                                }
                                if let Some(existing) = self.store.take() {
                                    for e in existing.events {
                                        partial.ingest_event(e);
                                    }
                                }
                                self.store = Some(Store::from_partials(vec![partial]));
                                self.apollo_ingested = true;
                            }
                            break;
                        }
                        Err(e) => {
                            tracing::warn!("sysdiagnose open failed: {e}");
                        }
                    }
                }
            }
        }

        #[cfg(not(feature = "ng"))]
        {
            let _ = plan;
            let _ = &self.interner;
            let _ = self.exclude_ng_apollo;
        }

        if plan.include_unified_logs && !self.logs_ingested {
            self.ingest_unified_logs()?;
            self.logs_ingested = true;
        }

        #[cfg(feature = "biome")]
        if plan.include_biome && !self.biome_ingested {
            self.ingest_biome()?;
            self.biome_ingested = true;
        }

        // Compat analysers need a store handle; keep a cheap empty/partial store.
        if self.store.is_none() {
            self.store = Some(Store::from_partials(vec![PartialStore::default()]));
        }

        self.stats.stages.push((
            format!("ingest_plan:{}", plan.parsers.len()),
            start.elapsed().as_millis() as u64,
        ));
        Ok(())
    }

    fn rebuild_store_from_parsed(&mut self) -> Result<()> {
        let start = Instant::now();
        let mut partial = PartialStore::default();
        #[cfg(feature = "ng")]
        {
            for (ty, v) in &self.parsed {
                for ev in mul_ingest::ng::adapt_parser_generic(ty, v, &self.interner) {
                    partial.ingest_event(ev);
                }
            }
        }
        // Preserve any previously ingested log/apollo/biome events.
        if let Some(old) = self.store.take() {
            for e in old.events {
                if e.source.0.starts_with("ng:") || e.evidence.path.starts_with("ng:") {
                    continue;
                }
                partial.ingest_event(e);
            }
        }
        self.store = Some(Store::from_partials(vec![partial]));
        self.stats
            .stages
            .push(("rebuild_store".into(), start.elapsed().as_millis() as u64));
        Ok(())
    }

    fn ingest_unified_logs(&mut self) -> Result<()> {
        let cap = self.log_event_cap;
        let threads = self.threads;
        let mut partial = PartialStore::default();
        for inp in &self.inputs {
            let candidates = [
                inp.path.join("system_logs.logarchive"),
                inp.path.clone(),
            ];
            for cand in &candidates {
                if !cand.exists() {
                    continue;
                }
                let Ok(src) = DirLogSource::open(cand) else {
                    continue;
                };
                let Ok(log) = UnifiedLog::open(
                    src,
                    LogOptions {
                        threads,
                        ordered: false,
                        include_signposts: false,
                    },
                ) else {
                    continue;
                };
                let mut n = 0usize;
                let _ = log.query(&Filter::True).for_each_batch(|batch| {
                    for e in batch {
                        if n >= cap {
                            return Ok(());
                        }
                        partial.ingest_event(owned_log_to_event(e));
                        n += 1;
                    }
                    Ok(())
                });
                break;
            }
        }
        if let Some(old) = self.store.take() {
            for e in old.events {
                partial.ingest_event(e);
            }
        }
        self.store = Some(Store::from_partials(vec![partial]));
        Ok(())
    }

    #[cfg(feature = "biome")]
    fn ingest_biome(&mut self) -> Result<()> {
        let mut partial = PartialStore::default();
        if let Some(old) = self.store.take() {
            for e in old.events {
                partial.ingest_event(e);
            }
        }
        for inp in &self.inputs {
            let streams = mul_apollo::biome::list_streams(&inp.path);
            for p in streams.into_iter().take(64) {
                if let Ok(bytes) = std::fs::read(&p) {
                    if let Ok((_info, evs)) =
                        mul_apollo::biome::parse_file_to_events(&p, &bytes, &self.interner)
                    {
                        for e in evs.into_iter().take(5_000) {
                            partial.ingest_event(e);
                        }
                    }
                }
            }
        }
        self.store = Some(Store::from_partials(vec![partial]));
        Ok(())
    }

    pub fn overview(&mut self) -> Result<SystemOverview> {
        let input_paths: Vec<String> = self
            .inputs
            .iter()
            .map(|i| i.path.display().to_string())
            .collect();
        let module_count = self.modules.len();
        let timings = self.stats.stages.clone();
        let device = self.device.clone();
        let boots = self.boots.clone();
        let version = crate::VERSION.to_string();
        let store = self.ensure_store()?;
        Ok(overview::build_overview(
            store,
            &input_paths,
            &version,
            timings,
            module_count,
            device,
            boots,
        ))
    }

    pub fn analyse(&mut self, ids: &[AnalyserId]) -> Result<HashMap<String, Value>> {
        self.ensure_for_analysers(ids)?;
        // Rebuild event store only when a mul-native analyser needs it.
        let needs_events = ids.iter().any(|id| {
            matches!(
                id,
                AnalyserId::overview | AnalyserId::app_activity
            )
        });
        if needs_events {
            self.rebuild_store_from_parsed()?;
        } else if self.store.is_none() {
            self.store = Some(Store::from_partials(vec![PartialStore::default()]));
        }

        let parser_types_total = {
            #[cfg(feature = "ng")]
            {
                mul_ingest::ng::all_parsers().len()
            }
            #[cfg(not(feature = "ng"))]
            {
                0usize
            }
        };

        let input_paths: Vec<String> = self
            .inputs
            .iter()
            .map(|i| i.path.display().to_string())
            .collect();
        // Normalize parser fields (battery/lock/MI versions/bundle_id) before analysers.
        let mut parsed = self.parsed.clone();
        mul_correlate::normalize::normalize_parsed_map(&mut parsed);
        let ctx = AnalyseCtx {
            ioc_files: self.ioc_files.clone(),
            device: self.device.clone(),
            boots: self.boots.clone(),
            inputs: input_paths,
            version: crate::VERSION.to_string(),
            timings: self.stats.stages.clone(),
            module_count: self.modules.len(),
            parsed,
            identity_plists: self.identity_plists.clone(),
            activation_lock_log_texts: self.activation_lock_log_texts.clone(),
            archive_paths: self.archive_paths.clone(),
            archive_stub_texts: self.archive_stub_texts.clone(),
            parser_types_total,
            powerlog_db_blobs: self.powerlog_db_blobs.clone(),
            install_enrichment_rules_toml: self.install_enrichment_rules_toml.clone(),
        };
        let store = self.store.as_ref().ok_or_else(|| MulError::msg("no store"))?;
        let mut out = HashMap::new();
        for id in ids {
            let r = analysers::run(*id, store, &ctx);
            out.insert(r.id, r.value);
        }
        Ok(out)
    }

    pub fn timeline_events(&mut self) -> Result<&[Event]> {
        let store = self.ensure_store()?;
        Ok(&store.events)
    }

    pub fn apollo_run_module(&self, id: &str) -> Result<Vec<Event>> {
        let module = self
            .modules
            .get(id)
            .ok_or_else(|| MulError::ModuleNotFound(id.to_string()))?;
        let _ = module;
        Ok(Vec::new())
    }

    pub fn apollo_run_module_on_path(
        &self,
        id: &str,
        path: impl Into<PathBuf>,
    ) -> Result<(mul_apollo::ModuleRunStatus, Vec<Event>)> {
        let module = self
            .modules
            .get(id)
            .ok_or_else(|| MulError::ModuleNotFound(id.to_string()))?;
        self.apollo
            .run_module_on_path(module, &path.into(), &RunOptions::default())
            .map_err(Into::into)
    }

    pub fn logs_filter(&self, predicate: &str) -> Result<Filter> {
        Filter::parse_predicate(predicate)
    }

    pub fn list_biome(&self) -> Vec<PathBuf> {
        #[cfg(feature = "biome")]
        {
            let mut all = Vec::new();
            for inp in &self.inputs {
                all.extend(mul_apollo::biome::list_streams(&inp.path));
            }
            all.sort();
            all.dedup();
            all
        }
        #[cfg(not(feature = "biome"))]
        {
            Vec::new()
        }
    }
}

fn is_sysdiagnose_input(inp: &Input) -> bool {
    inp.kind == InputKind::Sysdiagnose
        || inp
            .path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .contains("sysdiagnose")
}

fn owned_log_to_event(e: &OwnedLogEvent) -> Event {
    let ts = e
        .timestamp
        .as_deref()
        .and_then(parse_rfc3339_ns)
        .unwrap_or(i64::MIN);
    Event {
        ts,
        ts_quality: if ts == i64::MIN {
            TsQuality::Unknown
        } else {
            TsQuality::Exact
        },
        source: SourceId::unifiedlog(),
        kind: EventKind::Generic,
        level: None,
        pid: e.process_id,
        process: None,
        bundle_id: None,
        subsystem: None,
        category: None,
        message: LazyText::owned(e.event_message.clone().unwrap_or_default()),
        attrs: Default::default(),
        evidence: Evidence::new("unifiedlog", None),
    }
}

fn parse_rfc3339_ns(s: &str) -> Option<i64> {
    let s = s.trim().trim_end_matches('Z');
    let (date, time) = s.split_once('T')?;
    let mut dp = date.split('-');
    let y: i64 = dp.next()?.parse().ok()?;
    let m: u32 = dp.next()?.parse().ok()?;
    let d: u32 = dp.next()?.parse().ok()?;
    let (hms, frac) = match time.split_once('.') {
        Some((a, b)) => (a, b),
        None => (time, "0"),
    };
    let mut tp = hms.split(':');
    let hh: u32 = tp.next()?.parse().ok()?;
    let mm: u32 = tp.next()?.parse().ok()?;
    let ss: u32 = tp.next()?.parse().ok()?;
    let mut frac = frac.chars().take(9).collect::<String>();
    while frac.len() < 9 {
        frac.push('0');
    }
    let nsec: i64 = frac.parse().ok()?;
    let days = days_from_civil(y as i32, m, d)?;
    let secs = days as i64 * 86400 + (hh as i64) * 3600 + (mm as i64) * 60 + ss as i64;
    Some(secs * 1_000_000_000 + nsec)
}

fn days_from_civil(y: i32, m: u32, d: u32) -> Option<i32> {
    if m == 0 || m > 12 || d == 0 || d > 31 {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146097 + doe as i32 - 719468)
}
