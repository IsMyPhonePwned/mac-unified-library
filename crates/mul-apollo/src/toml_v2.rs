// SPDX-License-Identifier: GPL-3.0-only

use crate::epoch::Epoch;
use crate::error::ApolloError;
use crate::module::{
    EntityMapping, Module, Platform, Requirements, SourceSpec, TimestampSpec, Variant, VariantBody,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct TomlModule {
    id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    activity: Option<String>,
    #[serde(default)]
    author: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    platforms: Vec<String>,
    source: TomlSource,
    timestamp: TomlTimestamp,
    #[serde(default)]
    mapping: Option<TomlMapping>,
    #[serde(default)]
    variant: Vec<TomlVariant>,
}

#[derive(Debug, Deserialize)]
struct TomlSource {
    kind: String,
    #[serde(default)]
    db_names: Vec<String>,
    #[serde(default)]
    path_globs: Vec<String>,
    #[serde(default)]
    stream_globs: Vec<String>,
    #[serde(default)]
    predicate: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TomlTimestamp {
    #[serde(default)]
    column: Option<String>,
    #[serde(default)]
    field: Option<String>,
    epoch: String,
    #[serde(default)]
    quality: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TomlMapping {
    kind: String,
    #[serde(default)]
    bundle_id: Option<String>,
    #[serde(default)]
    ts_quality: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TomlVariant {
    label: String,
    #[serde(default)]
    requires: TomlRequires,
    #[serde(default)]
    sql: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct TomlRequires {
    #[serde(default)]
    tables: Vec<String>,
    #[serde(default)]
    columns: Vec<Vec<String>>,
    #[serde(default)]
    min_os: Option<String>,
    #[serde(default)]
    max_os: Option<String>,
}

pub fn parse_module_toml(text: &str) -> Result<Module, ApolloError> {
    let t: TomlModule = toml::from_str(text).map_err(|e| ApolloError::Parse(e.to_string()))?;
    let source = match t.source.kind.as_str() {
        "sqlite" => SourceSpec::Sqlite {
            db_names: t.source.db_names,
            path_globs: t.source.path_globs,
        },
        "segb" => SourceSpec::Segb {
            stream_globs: t.source.stream_globs,
        },
        "plist" => SourceSpec::Plist {
            path_globs: t.source.path_globs,
        },
        "unifiedlog" => SourceSpec::UnifiedLog {
            predicate: t.source.predicate.unwrap_or_default(),
        },
        other => {
            return Err(ApolloError::Parse(format!("unknown source kind: {other}")));
        }
    };
    let epoch = parse_epoch(&t.timestamp.epoch)?;
    let column = t
        .timestamp
        .column
        .or(t.timestamp.field)
        .unwrap_or_else(|| "timestamp".into());
    let mut variants = Vec::new();
    for v in t.variant {
        let body = if let Some(sql) = v.sql {
            VariantBody::Sql(sql)
        } else {
            VariantBody::Fields {}
        };
        let columns = v
            .requires
            .columns
            .into_iter()
            .filter_map(|pair| {
                if pair.len() >= 2 {
                    Some((pair[0].clone(), pair[1].clone()))
                } else {
                    None
                }
            })
            .collect();
        variants.push(Variant {
            label: v.label,
            requires: Requirements {
                tables: v.requires.tables,
                columns,
                min_os: v.requires.min_os,
                max_os: v.requires.max_os,
            },
            body,
            legacy_versions: Vec::new(),
        });
    }
    let platforms = t
        .platforms
        .iter()
        .filter_map(|p| match p.to_ascii_lowercase().as_str() {
            "ios" => Some(Platform::Ios),
            "ipados" => Some(Platform::Ipados),
            "macos" => Some(Platform::Macos),
            "watchos" => Some(Platform::Watchos),
            _ => None,
        })
        .collect();
    Ok(Module {
        id: t.id.clone(),
        name: t.name.unwrap_or_else(|| t.id.clone()),
        activity: t.activity.unwrap_or_else(|| t.id.clone()),
        author: t.author,
        notes: t.notes,
        platforms,
        source,
        variants,
        timestamp: TimestampSpec {
            column,
            epoch,
            quality: t.timestamp.quality,
        },
        mapping: t.mapping.map(|m| EntityMapping {
            kind: m.kind,
            bundle_id: m.bundle_id,
            ts_quality: m.ts_quality,
        }),
        legacy: None,
        original_columns: Vec::new(),
    })
}

fn parse_epoch(s: &str) -> Result<Epoch, ApolloError> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "unix" => Epoch::Unix,
        "unix_ms" | "unixms" => Epoch::UnixMs,
        "unix_us" | "unixus" => Epoch::UnixUs,
        "cocoa" => Epoch::Cocoa,
        "cocoa_ns" | "cocoans" => Epoch::CocoaNs,
        "mach" => Epoch::Mach,
        "webkit" => Epoch::Webkit,
        "iso" | "isotext" | "iso_text" => Epoch::IsoText,
        other => {
            return Err(ApolloError::Parse(format!("unknown epoch: {other}")));
        }
    })
}

fn epoch_str(e: Epoch) -> &'static str {
    match e {
        Epoch::Unix => "unix",
        Epoch::UnixMs => "unix_ms",
        Epoch::UnixUs => "unix_us",
        Epoch::Cocoa => "cocoa",
        Epoch::CocoaNs => "cocoa_ns",
        Epoch::Mach => "mach",
        Epoch::Webkit => "webkit",
        Epoch::IsoText => "iso_text",
    }
}

fn platform_str(p: Platform) -> &'static str {
    match p {
        Platform::Ios => "ios",
        Platform::Ipados => "ipados",
        Platform::Macos => "macos",
        Platform::Watchos => "watchos",
    }
}

fn toml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn toml_string_array(items: &[String]) -> String {
    let parts: Vec<_> = items.iter().map(|s| toml_escape(s)).collect();
    format!("[{}]", parts.join(", "))
}

/// Infer SQLite table names from a SQL string (best-effort FROM / JOIN).
pub fn infer_tables_from_sql(sql: &str) -> Vec<String> {
    let mut tables = Vec::new();
    let upper = sql.to_ascii_uppercase();
    let bytes = sql.as_bytes();
    for (kw, kw_len) in [("FROM ", 5usize), ("JOIN ", 5)] {
        let mut start = 0usize;
        while let Some(rel) = upper[start..].find(kw) {
            let at = start + rel + kw_len;
            let rest = sql[at..].trim_start();
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '.')
                .collect();
            let base = name
                .rsplit('.')
                .next()
                .unwrap_or(&name)
                .trim_matches('"')
                .trim_matches('`')
                .trim_matches('[')
                .trim_matches(']');
            if !base.is_empty()
                && !matches!(
                    base.to_ascii_uppercase().as_str(),
                    "SELECT" | "WHERE" | "LEFT" | "RIGHT" | "INNER" | "OUTER" | "CROSS" | "("
                )
                && !tables.iter().any(|t| t == base)
            {
                tables.push(base.to_string());
            }
            start = at + 1;
            if start >= bytes.len() {
                break;
            }
        }
    }
    tables
}

/// Serialize a [`Module`] to APOLLO-NG v2 TOML (round-trips through [`parse_module_toml`]).
pub fn module_to_toml(m: &Module) -> String {
    let mut out = String::new();
    out.push_str("# SPDX-License-Identifier: GPL-3.0-only\n");
    if let Some(leg) = &m.legacy {
        out.push_str(&format!(
            "# Converted from legacy APOLLO module {:?}\n",
            leg.file_name
        ));
    }
    out.push('\n');
    out.push_str(&format!("id = {}\n", toml_escape(&m.id)));
    out.push_str(&format!("name = {}\n", toml_escape(&m.name)));
    out.push_str(&format!("activity = {}\n", toml_escape(&m.activity)));
    if let Some(a) = &m.author {
        out.push_str(&format!("author = {}\n", toml_escape(a)));
    }
    if let Some(n) = &m.notes {
        out.push_str(&format!("notes = {}\n", toml_escape(n)));
    }
    let platforms: Vec<String> = if m.platforms.is_empty() {
        vec!["ios".into()]
    } else {
        m.platforms.iter().map(|p| platform_str(*p).to_string()).collect()
    };
    out.push_str(&format!(
        "platforms = {}\n",
        toml_string_array(&platforms)
    ));
    out.push('\n');
    out.push_str("[source]\n");
    match &m.source {
        SourceSpec::Sqlite {
            db_names,
            path_globs,
        } => {
            out.push_str("kind = \"sqlite\"\n");
            out.push_str(&format!("db_names = {}\n", toml_string_array(db_names)));
            out.push_str(&format!(
                "path_globs = {}\n",
                toml_string_array(path_globs)
            ));
        }
        SourceSpec::Segb { stream_globs } => {
            out.push_str("kind = \"segb\"\n");
            out.push_str(&format!(
                "stream_globs = {}\n",
                toml_string_array(stream_globs)
            ));
        }
        SourceSpec::Plist { path_globs } => {
            out.push_str("kind = \"plist\"\n");
            out.push_str(&format!(
                "path_globs = {}\n",
                toml_string_array(path_globs)
            ));
        }
        SourceSpec::UnifiedLog { predicate } => {
            out.push_str("kind = \"unifiedlog\"\n");
            out.push_str(&format!("predicate = {}\n", toml_escape(predicate)));
        }
    }
    out.push('\n');
    out.push_str("[timestamp]\n");
    out.push_str(&format!("column = {}\n", toml_escape(&m.timestamp.column)));
    out.push_str(&format!("epoch = {:?}\n", epoch_str(m.timestamp.epoch)));
    if let Some(q) = &m.timestamp.quality {
        out.push_str(&format!("quality = {}\n", toml_escape(q)));
    }

    for v in &m.variants {
        out.push_str("\n[[variant]]\n");
        out.push_str(&format!("label = {}\n", toml_escape(&v.label)));
        if let VariantBody::Sql(sql) = &v.body {
            // Prefer literal multiline; fall back to basic if ''' appears.
            if sql.contains("'''") {
                out.push_str(&format!("sql = {}\n", toml_escape(sql)));
            } else {
                out.push_str("sql = '''\n");
                out.push_str(sql.trim_end());
                out.push_str("\n'''\n");
            }
        }
        let tables = if v.requires.tables.is_empty() {
            if let VariantBody::Sql(sql) = &v.body {
                infer_tables_from_sql(sql)
            } else {
                Vec::new()
            }
        } else {
            v.requires.tables.clone()
        };
        out.push_str("[variant.requires]\n");
        out.push_str(&format!("tables = {}\n", toml_string_array(&tables)));
        if !v.requires.columns.is_empty() {
            let cols: Vec<String> = v
                .requires
                .columns
                .iter()
                .map(|(a, b)| format!("[{}, {}]", toml_escape(a), toml_escape(b)))
                .collect();
            out.push_str(&format!("columns = [{}]\n", cols.join(", ")));
        }
        if let Some(min) = &v.requires.min_os {
            out.push_str(&format!("min_os = {}\n", toml_escape(min)));
        }
        if let Some(max) = &v.requires.max_os {
            out.push_str(&format!("max_os = {}\n", toml_escape(max)));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legacy::parse_legacy_module;

    #[test]
    fn round_trip_powerlog_snippet() {
        let text = r#"
[Query Metadata]
QUERY_NAME = powerlog_demo
ACTIVITY = Demo
KEY_TIMESTAMP = Timestamp
[Database Metadata]
DATABASE = CurrentPowerlog.PLSQL
PLATFORM = iOS
[SQL Query 14]
QUERY=
SELECT DATETIME(TIMESTAMP, 'UNIXEPOCH') AS TIMESTAMP, APPBUNDLEID FROM PLAPPLICATIONAGENT_EVENTNONE_ALLAPPS
"#;
        let m = parse_legacy_module("powerlog_demo.txt", text).unwrap();
        let toml = module_to_toml(&m);
        let m2 = parse_module_toml(&toml).unwrap();
        assert_eq!(m2.id, "powerlog_demo");
        assert_eq!(m2.variants.len(), 1);
        assert!(m2.variants[0]
            .requires
            .tables
            .iter()
            .any(|t| t == "PLAPPLICATIONAGENT_EVENTNONE_ALLAPPS"));
    }
}
