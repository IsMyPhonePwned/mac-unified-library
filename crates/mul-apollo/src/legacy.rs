// SPDX-License-Identifier: GPL-3.0-only
//! Compile-time / runtime importer for vendored APOLLO `*.txt` module files.
//!
//! Format (from APOLLO module docs / SPEC §5.2):
//! - `[Module Metadata]` — AUTHOR, MODULE_NOTES
//! - `[Database Metadata]` — DATABASE, PLATFORM, VERSIONS
//! - `[Query Metadata]` — QUERY_NAME, ACTIVITY, KEY_TIMESTAMP
//! - one or more `[SQL Query <versions>]` with `QUERY=` and multi-line SQL

use crate::epoch::Epoch;
use crate::error::ApolloError;
use crate::module::{
    LegacyInfo, Module, Platform, Requirements, SourceSpec, TimestampSpec, Variant, VariantBody,
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone)]
struct SqlSection {
    versions: Vec<String>,
    sql: String,
}

/// Parse one legacy APOLLO module text into the IR. Does not execute SQL.
pub fn parse_legacy_module(file_name: &str, text: &str) -> Result<Module, ApolloError> {
    let mut author = None;
    let mut notes = None;
    let mut database = String::new();
    let mut platforms = Vec::new();
    let mut versions_meta = Vec::new();
    let mut query_name = file_name.trim_end_matches(".txt").to_string();
    let mut activity = String::new();
    let mut key_timestamp = String::new();
    let mut sections: Vec<SqlSection> = Vec::new();

    let mut current_section = String::new();
    let mut in_sql = false;
    let mut sql_versions: Vec<String> = Vec::new();
    let mut sql = String::new();

    let flush_sql = |sql: &mut String,
                     sql_versions: &mut Vec<String>,
                     sections: &mut Vec<SqlSection>| {
        let trimmed = sql.trim().to_string();
        if !trimmed.is_empty() {
            sections.push(SqlSection {
                versions: std::mem::take(sql_versions),
                sql: trimmed,
            });
        }
        sql.clear();
    };

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            if in_sql {
                flush_sql(&mut sql, &mut sql_versions, &mut sections);
                in_sql = false;
            }
            current_section = trimmed[1..trimmed.len() - 1].to_string();
            let lower = current_section.to_ascii_lowercase();
            if lower.starts_with("sql query") {
                in_sql = true;
                sql_versions = parse_version_list(&current_section);
            }
            continue;
        }

        if in_sql {
            if let Some(rest) = trimmed.strip_prefix("QUERY=") {
                if !rest.is_empty() {
                    sql.push_str(rest);
                    sql.push('\n');
                }
                continue;
            }
            if trimmed.starts_with('#') {
                continue;
            }
            // Preserve SQL indentation from the original line (minus trailing CR).
            sql.push_str(line.trim_end_matches('\r'));
            sql.push('\n');
            continue;
        }

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((k, v)) = trimmed.split_once('=') else {
            continue;
        };
        let k = k.trim();
        let v = v.trim();
        let sec = current_section.to_ascii_lowercase();
        match (sec.as_str(), k) {
            (_, "AUTHOR") => author = Some(v.to_string()),
            (_, "MODULE_NOTES") => notes = Some(v.to_string()),
            (_, "DATABASE") => database = v.to_string(),
            (_, "PLATFORM") => platforms = parse_platforms(v),
            (_, "VERSIONS") => {
                versions_meta = v
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            (_, "QUERY_NAME") => query_name = v.to_string(),
            (_, "ACTIVITY") => activity = v.to_string(),
            (_, "KEY_TIMESTAMP") => key_timestamp = v.to_string(),
            _ => {}
        }
    }
    if in_sql {
        flush_sql(&mut sql, &mut sql_versions, &mut sections);
    }

    if database.is_empty() {
        return Err(ApolloError::Parse(format!(
            "{file_name}: missing DATABASE"
        )));
    }
    if sections.is_empty() {
        return Err(ApolloError::Parse(format!(
            "{file_name}: no SQL Query sections"
        )));
    }

    // Variants ordered by max version descending (SPEC §5.2).
    let mut indexed: Vec<(usize, SqlSection)> = sections.into_iter().enumerate().collect();
    indexed.sort_by(|(ia, a), (ib, b)| {
        max_version_key(&b.versions)
            .cmp(&max_version_key(&a.versions))
            .then_with(|| ia.cmp(ib))
    });

    let mut variants = Vec::new();
    for (_, sec) in indexed {
        let label = if sec.versions.is_empty() {
            "legacy".to_string()
        } else {
            format!("legacy-{}", sec.versions.join("_"))
        };
        variants.push(Variant {
            label,
            requires: Requirements::default(),
            body: VariantBody::Sql(sec.sql),
            legacy_versions: sec.versions,
        });
    }

    let column = snake_case_alias(&key_timestamp);
    let mut hasher = DefaultHasher::new();
    text.hash(&mut hasher);
    let header_hash = hasher.finish();

    Ok(Module {
        id: query_name.clone(),
        name: query_name.clone(),
        activity: if activity.is_empty() {
            query_name.clone()
        } else {
            activity
        },
        author,
        notes,
        platforms,
        source: SourceSpec::Sqlite {
            db_names: vec![database.clone()],
            path_globs: default_globs_for_db(&database),
        },
        variants,
        timestamp: TimestampSpec {
            column: column.clone(),
            // Legacy modules typically emit DATETIME(...) AS "KEY" → ISO text.
            epoch: Epoch::IsoText,
            quality: None,
        },
        mapping: None,
        legacy: Some(LegacyInfo {
            file_name: file_name.to_string(),
            versions: versions_meta,
            header_hash,
        }),
        original_columns: if key_timestamp.is_empty() {
            Vec::new()
        } else {
            vec![(column, key_timestamp)]
        },
    })
}

fn parse_version_list(section_title: &str) -> Vec<String> {
    // "SQL Query 10,11,12,13,14" or "SQL Query 9"
    let lower = section_title.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("sql query")
        .unwrap_or("")
        .trim();
    if rest.is_empty() {
        return Vec::new();
    }
    rest.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse_platforms(v: &str) -> Vec<Platform> {
    v.split(',')
        .filter_map(|p| match p.trim().to_ascii_uppercase().as_str() {
            "IOS" => Some(Platform::Ios),
            "IPADOS" => Some(Platform::Ipados),
            "MACOS" | "OS X" | "OSX" => Some(Platform::Macos),
            "WATCHOS" => Some(Platform::Watchos),
            _ => None,
        })
        .collect()
}

fn max_version_key(versions: &[String]) -> (i32, i32) {
    let mut best = (i32::MIN, i32::MIN);
    for v in versions {
        let key = version_sort_key(v);
        if key > best {
            best = key;
        }
    }
    best
}

fn version_sort_key(v: &str) -> (i32, i32) {
    let mut parts = v.split('.');
    let major = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (major, minor)
}

/// Normalise APOLLO display names ("HOUR OF DAY") to snake_case aliases.
pub fn snake_case_alias(s: &str) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.is_empty() && !out.ends_with('_') {
            out.push('_');
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    out
}

fn default_globs_for_db(database: &str) -> Vec<String> {
    let name = database.trim();
    vec![
        format!("**/{name}"),
        format!("**/{name}-wal"),
        format!("**/Archives/{name}.gz"),
        format!("**/Archives/{name}"),
    ]
}

/// Import all embedded legacy sources. Returns modules and any per-file errors.
pub fn import_all_legacy(sources: &[(&str, &str)]) -> (Vec<Module>, Vec<(String, String)>) {
    let mut modules = Vec::with_capacity(sources.len());
    let mut errors = Vec::new();
    for (name, text) in sources {
        match parse_legacy_module(name, text) {
            Ok(m) => modules.push(m),
            Err(e) => errors.push((name.to_string(), e.to_string())),
        }
    }
    (modules, errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[Module Metadata]
AUTHOR=Test
MODULE_NOTES=Example

[Database Metadata]
DATABASE=TCC.db
PLATFORM=MACOS,IOS
VERSIONS=13,14

[Query Metadata]
QUERY_NAME=tcc_db
ACTIVITY=App Permissions
KEY_TIMESTAMP=LAST MODIFIED

[SQL Query 14]
QUERY=
	SELECT DATETIME(LAST_MODIFIED,'UNIXEPOCH') AS "LAST MODIFIED", SERVICE FROM access

[SQL Query 13]
QUERY=
	SELECT DATETIME(LAST_MODIFIED,'UNIXEPOCH') AS "LAST MODIFIED", SERVICE FROM access_old
"#;

    #[test]
    fn parses_two_variants_newest_first() {
        let m = parse_legacy_module("tcc_db.txt", SAMPLE).unwrap();
        assert_eq!(m.id, "tcc_db");
        assert_eq!(m.variants.len(), 2);
        assert_eq!(m.variants[0].legacy_versions, vec!["14"]);
        assert_eq!(m.variants[1].legacy_versions, vec!["13"]);
        assert_eq!(m.timestamp.column, "last_modified");
        assert!(matches!(m.timestamp.epoch, Epoch::IsoText));
        match &m.source {
            SourceSpec::Sqlite { db_names, .. } => assert_eq!(db_names[0], "TCC.db"),
            _ => panic!("expected sqlite"),
        }
    }

    #[test]
    fn snake_case() {
        assert_eq!(snake_case_alias("HOUR OF DAY"), "hour_of_day");
        assert_eq!(snake_case_alias("LAST MODIFIED"), "last_modified");
    }
}
