// SPDX-License-Identifier: GPL-3.0-only

#![cfg_attr(
    not(all(feature = "sqlite", not(target_arch = "wasm32"))),
    allow(dead_code, unused_imports)
)]

use crate::epoch::{parse_iso_text, to_utc_ns, Epoch};
use crate::error::ApolloError;
use crate::module::{Module, SourceSpec, Variant, VariantBody};
use crate::schema::Schema;
use mul_core::event::{Event, EventKind, Evidence, LazyText, SourceId, TsQuality};
use mul_core::interner::Interner;
use mul_core::val::Val;
use smallvec::SmallVec;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Debug, Clone)]
pub enum ModuleRunStatus {
    Ran { variant: String, rows: usize, truncated: bool },
    NoMatchingVariant,
    NoDatabase,
    Error(String),
    SqliteUnavailable,
}

#[derive(Debug, Clone)]
pub struct RunOptions {
    pub max_rows: usize,
    /// `best` | `all` | `exact-os`
    pub mode: String,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            max_rows: 100_000,
            mode: "best".into(),
        }
    }
}

pub struct SqliteRuntime {
    interner: Interner,
    #[allow(dead_code)] // used on native sqlite builds
    cache: Mutex<HashMap<String, Vec<Event>>>,
}

impl Default for SqliteRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl SqliteRuntime {
    pub fn new() -> Self {
        Self {
            interner: Interner::new(),
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn interner(&self) -> &Interner {
        &self.interner
    }

    pub fn run_module_on_bytes(
        &self,
        module: &Module,
        db_path: &str,
        bytes: &[u8],
        opts: &RunOptions,
    ) -> Result<(ModuleRunStatus, Vec<Event>), ApolloError> {
        #[cfg(not(all(feature = "sqlite", not(target_arch = "wasm32"))))]
        {
            let _ = (module, db_path, bytes, opts);
            return Ok((ModuleRunStatus::SqliteUnavailable, Vec::new()));
        }
        #[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
        {
            self.run_native(module, db_path, bytes, opts)
        }
    }

    /// Run many modules against one DB payload: **one** temp write, **one** open,
    /// **one** schema probe (SPEC §5.4). Avoids the per-module reopen tax that
    /// made `apollo-mul` powerlogs slower than classic sdx.
    pub fn run_modules_on_bytes(
        &self,
        modules: &[&Module],
        db_path: &str,
        bytes: &[u8],
        opts: &RunOptions,
    ) -> Result<Vec<(String, ModuleRunStatus, Vec<Event>)>, ApolloError> {
        #[cfg(not(all(feature = "sqlite", not(target_arch = "wasm32"))))]
        {
            let _ = (modules, db_path, bytes, opts);
            return Ok(modules
                .iter()
                .map(|m| (m.id.clone(), ModuleRunStatus::SqliteUnavailable, Vec::new()))
                .collect());
        }
        #[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
        {
            self.run_native_many(modules, db_path, bytes, opts)
        }
    }

    pub fn run_module_on_path(
        &self,
        module: &Module,
        path: &Path,
        opts: &RunOptions,
    ) -> Result<(ModuleRunStatus, Vec<Event>), ApolloError> {
        #[cfg(not(all(feature = "sqlite", not(target_arch = "wasm32"))))]
        {
            let _ = (module, path, opts);
            return Ok((ModuleRunStatus::SqliteUnavailable, Vec::new()));
        }
        #[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
        {
            self.run_native_path(module, path, opts)
        }
    }

    #[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
    fn run_native_path(
        &self,
        module: &Module,
        path: &Path,
        opts: &RunOptions,
    ) -> Result<(ModuleRunStatus, Vec<Event>), ApolloError> {
        use rusqlite::Connection;

        let path_str = path.display().to_string();
        let is_gz = path_str.ends_with(".gz") || path_str.ends_with(".GZ");
        let wal = PathBuf::from(format!("{path_str}-wal"));
        let shm = PathBuf::from(format!("{path_str}-shm"));
        let has_wal = wal.exists();

        let dir = tempfile::tempdir().map_err(ApolloError::Io)?;
        let tmp = dir.path().join("db.sqlite");

        if is_gz {
            let compressed = std::fs::read(path)?;
            let inflated = mul_io::gzip::inflate_gz(&compressed)
                .map_err(|e| ApolloError::Msg(e.to_string()))?;
            std::fs::write(&tmp, inflated.as_slice())?;
        } else if has_wal {
            // Copy db + wal into private dir; open read-write so SQLite applies WAL.
            std::fs::copy(path, &tmp)?;
            let _ = std::fs::copy(&wal, dir.path().join("db.sqlite-wal"));
            if shm.exists() {
                let _ = std::fs::copy(&shm, dir.path().join("db.sqlite-shm"));
            }
            let conn = Connection::open(&tmp).map_err(|e| ApolloError::Sqlite(e.to_string()))?;
            let _ = conn.execute_batch(
                "PRAGMA journal_mode=DELETE; PRAGMA query_only=1; PRAGMA temp_store=memory; PRAGMA cache_size=-16384;",
            );
            return self.run_on_conn(module, &path_str, &conn, opts, format!("{path_str}:wal"));
        } else if std::fs::copy(path, &tmp).is_err() {
            let bytes = std::fs::read(path)?;
            std::fs::write(&tmp, bytes)?;
        }

        let bytes = std::fs::read(&tmp)?;
        self.run_native(module, &path_str, &bytes, opts)
    }

    #[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
    fn run_on_conn(
        &self,
        module: &Module,
        db_path: &str,
        conn: &rusqlite::Connection,
        opts: &RunOptions,
        cache_key: String,
    ) -> Result<(ModuleRunStatus, Vec<Event>), ApolloError> {
        if let Ok(cache) = self.cache.lock() {
            if let Some(hit) = cache.get(&cache_key) {
                return Ok((
                    ModuleRunStatus::Ran {
                        variant: "cache".into(),
                        rows: hit.len(),
                        truncated: false,
                    },
                    hit.clone(),
                ));
            }
        }
        let schema = read_schema(conn)?;
        let selected = select_variants(module, &schema, &opts.mode, conn)?;
        if selected.is_empty() {
            return Ok((ModuleRunStatus::NoMatchingVariant, Vec::new()));
        }
        let (status, events) = self.execute_variants(module, db_path, conn, &selected, opts)?;
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(cache_key, events.clone());
        }
        Ok((status, events))
    }

    #[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
    fn open_bytes_conn(
        bytes: &[u8],
    ) -> Result<(tempfile::TempDir, rusqlite::Connection), ApolloError> {
        use rusqlite::Connection;

        let dir = tempfile::tempdir().map_err(ApolloError::Io)?;
        let tmp = dir.path().join("db.sqlite");
        std::fs::write(&tmp, bytes)?;
        let uri = format!("file:{}?mode=ro&immutable=1", tmp.display());
        let conn = Connection::open_with_flags(
            &uri,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )
        .or_else(|_| Connection::open(&tmp))
        .map_err(|e| ApolloError::Sqlite(e.to_string()))?;
        let _ = conn.execute_batch(
            "PRAGMA query_only=1; PRAGMA temp_store=memory; PRAGMA cache_size=-16384;",
        );
        Ok((dir, conn))
    }

    #[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
    fn run_native(
        &self,
        module: &Module,
        db_path: &str,
        bytes: &[u8],
        opts: &RunOptions,
    ) -> Result<(ModuleRunStatus, Vec<Event>), ApolloError> {
        let cache_key = format!("{}:{}:{}", db_path, bytes.len(), module.id);
        if let Ok(cache) = self.cache.lock() {
            if let Some(hit) = cache.get(&cache_key) {
                return Ok((
                    ModuleRunStatus::Ran {
                        variant: "cache".into(),
                        rows: hit.len(),
                        truncated: false,
                    },
                    hit.clone(),
                ));
            }
        }

        let (_dir, conn) = Self::open_bytes_conn(bytes)?;
        let schema = read_schema(&conn)?;
        let selected = select_variants(module, &schema, &opts.mode, &conn)?;
        if selected.is_empty() {
            return Ok((ModuleRunStatus::NoMatchingVariant, Vec::new()));
        }
        let (status, events) = self.execute_variants(module, db_path, &conn, &selected, opts)?;
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(cache_key, events.clone());
        }
        Ok((status, events))
    }

    #[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
    fn run_native_many(
        &self,
        modules: &[&Module],
        db_path: &str,
        bytes: &[u8],
        opts: &RunOptions,
    ) -> Result<Vec<(String, ModuleRunStatus, Vec<Event>)>, ApolloError> {
        if modules.is_empty() {
            return Ok(Vec::new());
        }
        let (_dir, conn) = Self::open_bytes_conn(bytes)?;
        let schema = read_schema(&conn)?;
        let mut out = Vec::with_capacity(modules.len());
        for module in modules {
            let selected = select_variants(module, &schema, &opts.mode, &conn)?;
            if selected.is_empty() {
                out.push((
                    module.id.clone(),
                    ModuleRunStatus::NoMatchingVariant,
                    Vec::new(),
                ));
                continue;
            }
            let (status, events) =
                self.execute_variants(module, db_path, &conn, &selected, opts)?;
            out.push((module.id.clone(), status, events));
        }
        Ok(out)
    }

    #[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
    fn execute_variants(
        &self,
        module: &Module,
        db_path: &str,
        conn: &rusqlite::Connection,
        selected: &[&Variant],
        opts: &RunOptions,
    ) -> Result<(ModuleRunStatus, Vec<Event>), ApolloError> {
        let mut all_events = Vec::new();
        let mut truncated = false;
        let mut used_label = String::new();
        for variant in selected {
            used_label = variant.label.clone();
            let VariantBody::Sql(sql) = &variant.body else {
                continue;
            };
            let mut stmt = match conn.prepare(sql) {
                Ok(s) => s,
                Err(_) => {
                    // Schema mismatch is normal (classic APOLLO "yolo"); try next variant.
                    continue;
                }
            };
            let col_names: Vec<String> = stmt
                .column_names()
                .iter()
                .map(|s| (*s).to_string())
                .collect();
            let mut rows = stmt
                .query([])
                .map_err(|e| ApolloError::Sqlite(e.to_string()))?;
            let mut count = 0usize;
            while let Some(row) = rows
                .next()
                .map_err(|e| ApolloError::Sqlite(e.to_string()))?
            {
                if count >= opts.max_rows {
                    truncated = true;
                    break;
                }
                let mut attrs: SmallVec<[(mul_core::Sym, Val); 6]> = SmallVec::new();
                let mut ts = i64::MIN;
                let mut ts_quality = TsQuality::Unknown;
                for (i, name) in col_names.iter().enumerate() {
                    let val = rusqlite_to_val(row, i)?;
                    let snake = crate::legacy::snake_case_alias(name);
                    if snake == module.timestamp.column
                        || name.eq_ignore_ascii_case(&module.timestamp.column)
                    {
                        if let Some(parsed) = timestamp_from_val(&val, module.timestamp.epoch) {
                            ts = parsed;
                            ts_quality = TsQuality::Exact;
                        }
                    }
                    let sym = self.interner.intern(&snake);
                    attrs.push((sym, val));
                }
                all_events.push(Event {
                    ts,
                    ts_quality,
                    source: SourceId::apollo(&module.id),
                    kind: EventKind::Generic,
                    level: None,
                    pid: None,
                    process: None,
                    bundle_id: None,
                    subsystem: None,
                    category: None,
                    message: LazyText::owned(module.activity.clone()),
                    attrs,
                    evidence: Evidence::new(db_path, Some(count as u64)),
                });
                count += 1;
            }
            if opts.mode == "best" {
                break;
            }
        }
        if used_label.is_empty() {
            return Ok((ModuleRunStatus::NoMatchingVariant, Vec::new()));
        }
        Ok((
            ModuleRunStatus::Ran {
                variant: used_label,
                rows: all_events.len(),
                truncated,
            },
            all_events,
        ))
    }
}

fn timestamp_from_val(val: &Val, epoch: Epoch) -> Option<i64> {
    match epoch {
        Epoch::IsoText => match val {
            Val::Text(s) => parse_iso_text(s),
            Val::I64(i) => to_utc_ns(Epoch::Unix, *i as f64),
            Val::F64(f) => to_utc_ns(Epoch::Unix, *f),
            _ => None,
        },
        other => match val {
            Val::I64(i) => to_utc_ns(other, *i as f64),
            Val::F64(f) => to_utc_ns(other, *f),
            Val::Text(s) => {
                if let Ok(f) = s.parse::<f64>() {
                    to_utc_ns(other, f)
                } else {
                    parse_iso_text(s)
                }
            }
            _ => None,
        },
    }
}

#[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
fn rusqlite_to_val(row: &rusqlite::Row<'_>, i: usize) -> Result<Val, ApolloError> {
    use rusqlite::types::ValueRef;
    match row
        .get_ref(i)
        .map_err(|e| ApolloError::Sqlite(e.to_string()))?
    {
        ValueRef::Null => Ok(Val::Null),
        ValueRef::Integer(n) => Ok(Val::I64(n)),
        ValueRef::Real(f) => Ok(Val::F64(f)),
        ValueRef::Text(t) => Ok(Val::Text(
            String::from_utf8_lossy(t).into_owned().into_boxed_str(),
        )),
        ValueRef::Blob(b) => Ok(Val::Bytes(b.to_vec().into_boxed_slice())),
    }
}

#[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
fn read_schema(conn: &rusqlite::Connection) -> Result<Schema, ApolloError> {
    let mut schema = Schema::default();
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        .map_err(|e| ApolloError::Sqlite(e.to_string()))?;
    let tables: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| ApolloError::Sqlite(e.to_string()))?
        .filter_map(|r| r.ok())
        .collect();
    for table in tables {
        let mut cols = hashbrown::HashSet::new();
        let pragma = format!("PRAGMA table_xinfo({})", quote_ident(&table));
        let mut cstmt = conn
            .prepare(&pragma)
            .map_err(|e| ApolloError::Sqlite(e.to_string()))?;
        let mut rows = cstmt
            .query([])
            .map_err(|e| ApolloError::Sqlite(e.to_string()))?;
        while let Some(row) = rows
            .next()
            .map_err(|e| ApolloError::Sqlite(e.to_string()))?
        {
            let name: String = row.get(1).map_err(|e| ApolloError::Sqlite(e.to_string()))?;
            cols.insert(name);
        }
        schema.tables.insert(table, cols);
    }
    Ok(schema)
}

fn quote_ident(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

#[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
fn select_variants<'a>(
    module: &'a Module,
    schema: &Schema,
    mode: &str,
    conn: &rusqlite::Connection,
) -> Result<Vec<&'a Variant>, ApolloError> {
    let _ = mode;
    let mut out = Vec::new();
    for v in &module.variants {
        if !v.requires.tables.is_empty() || !v.requires.columns.is_empty() {
            if schema.satisfies(&v.requires) {
                out.push(v);
                if mode == "best" {
                    break;
                }
            }
            continue;
        }
        // Legacy empty requires: first that prepares wins.
        if let VariantBody::Sql(sql) = &v.body {
            match conn.prepare(sql) {
                Ok(_) => {
                    out.push(v);
                    if mode == "best" {
                        break;
                    }
                }
                Err(_) => continue,
            }
        }
    }
    Ok(out)
}

/// Check whether a path looks like a DB this module cares about.
pub fn path_matches_module(module: &Module, path: &str) -> bool {
    match &module.source {
        SourceSpec::Sqlite { db_names, .. } => {
            let file = path.rsplit('/').next().unwrap_or(path);
            db_names
                .iter()
                .any(|n| file.eq_ignore_ascii_case(n) || file.eq_ignore_ascii_case(&format!("{n}-wal")))
        }
        _ => false,
    }
}
