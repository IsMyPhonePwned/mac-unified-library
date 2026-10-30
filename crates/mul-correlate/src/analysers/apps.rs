// SPDX-License-Identifier: GPL-3.0-only

//! Installed-app / bundle-ID aggregation across parsers.
//!
//! Preferred source set mirrors mobipwn Packages (`packagesQuery`):
//! `mobileinstallation`, `appinstallation`, `accessibility_tcc`, `itunesstore`,
//! `mobilebackup`, powerlogs **App Info** rows, and `itunesmetadata` plists.
//!
//! When Apollo powerlogs events are empty (browser WASM historically stubbed
//! SQLite), App Info is read directly from `PLAPPLICATIONAGENT_EVENTNONE_ALLAPPS`
//! via the powerlog DB blobs on [`AnalyseCtx`]. brctl / logdata mines run only if
//! the inventory is still empty after preferred sources.

use std::collections::HashMap;
use serde_json::{json, Map, Value};

use super::common::{
    brctl_match_context, bundle_id_re, extract_app_bundle_id_from_text, for_each_sqlite_row,
    parser_value, merge_app, merge_mvt_plist_bundle_signals, sqlite_row_apps_excerpt,
    tcc_client_and_service, truncate_json_string, value_looks_like_hard_error,
    APPS_MAX_HITS_PER_APP,
};

const POWERLOG_APP_INFO_SQL: &str = r#"
SELECT
    TIMESTAMP,
    APPNAME AS "app name",
    APPEXECUTABLE AS "app executable name",
    APPBUNDLEID AS "bundle id",
    APPBUILDVERSION AS "app build version",
    APPBUNDLEVERSION AS "app bundle version",
    APPTYPE AS "app type",
    APPDELETEDDATE AS "app deleted date raw",
    ID AS "allapps_id"
FROM PLAPPLICATIONAGENT_EVENTNONE_ALLAPPS
"#;

const POWERLOG_APP_INFO_SQL_MINIMAL: &str = r#"
SELECT
    TIMESTAMP,
    APPNAME AS "app name",
    APPBUNDLEID AS "bundle id",
    APPDELETEDDATE AS "app deleted date raw",
    ID AS "allapps_id"
FROM PLAPPLICATIONAGENT_EVENTNONE_ALLAPPS
"#;

pub fn run(parsed: &HashMap<String, Value>, powerlog_dbs: &[(String, Vec<u8>)]) -> Value {
    let mut apps: Map<String, Value> = Map::new();
    let mut app_info_hits = 0usize;
    let mut tcc_hits = 0usize;

    let tcc = parser_value(parsed, "accessibility_tcc");
    if !value_looks_like_hard_error(&tcc) {
        for_each_sqlite_row(&tcc, |rm, sqlite_db, sqlite_table| {
            if let Some((c, service)) = tcc_client_and_service(rm) {
                let mut extra = Map::new();
                if let Some(s) = service {
                    extra.insert("service".into(), json!(s));
                }
                if let Some(a) = rm
                    .get("allowed")
                    .or_else(|| rm.get("auth_value"))
                    .cloned()
                {
                    extra.insert("allowed".into(), a);
                }
                extra.insert("sqlite_db".into(), json!(sqlite_db));
                extra.insert("sqlite_table".into(), json!(sqlite_table));
                extra.insert("row".into(), sqlite_row_apps_excerpt(rm));
                merge_app(&mut apps, c, "accessibility_tcc", Value::Object(extra));
                tcc_hits += 1;
            }
        });
    }

    let itunes = parser_value(parsed, "itunesstore");
    if !value_looks_like_hard_error(&itunes) {
        for_each_sqlite_row(&itunes, |rm, sqlite_db, sqlite_table| {
            for key in ["bundle_id", "application_id"] {
                if let Some(b) = rm.get(key).and_then(|v| v.as_str()).map(str::trim) {
                    if !b.is_empty() {
                        merge_app(
                            &mut apps,
                            b.to_string(),
                            "itunesstore",
                            json!({
                                "sqlite_db": sqlite_db,
                                "sqlite_table": sqlite_table,
                                "matched_column": key,
                                "row": sqlite_row_apps_excerpt(rm),
                            }),
                        );
                    }
                }
            }
        });
    }

    let appinst = parser_value(parsed, "appinstallation");
    if !value_looks_like_hard_error(&appinst) {
        for_each_sqlite_row(&appinst, |rm, sqlite_db, sqlite_table| {
            let excerpt = sqlite_row_apps_excerpt(rm);
            let mut seen = false;
            for key in ["bundle_id", "bundle id", "application_id", "zbundlename"] {
                if let Some(b) = rm.get(key).and_then(|v| v.as_str()).map(str::trim) {
                    if b.is_empty() {
                        continue;
                    }
                    seen = true;
                    merge_app(
                        &mut apps,
                        b.to_string(),
                        "appinstallation",
                        json!({
                            "sqlite_db": sqlite_db,
                            "sqlite_table": sqlite_table,
                            "matched_column": key,
                            "row": excerpt.clone(),
                        }),
                    );
                }
            }
            if seen {
                return;
            }
            for (col, val) in rm {
                let Some(s) = val.as_str() else { continue };
                if let Some(bid) = extract_app_bundle_id_from_text(s) {
                    merge_app(
                        &mut apps,
                        bid,
                        "appinstallation",
                        json!({
                            "sqlite_db": sqlite_db,
                            "sqlite_table": sqlite_table,
                            "matched_column": col,
                            "matched_in": "cell_text",
                            "message": truncate_json_string(s, 400),
                            "row": excerpt.clone(),
                        }),
                    );
                }
            }
        });
    }

    let mobile = parser_value(parsed, "mobileinstallation");
    if !value_looks_like_hard_error(&mobile) {
        let mut mined_from_events = false;
        if let Some(events) = mobile.get("events").and_then(|e| e.as_array()) {
            for ev in events {
                let data = ev.get("data").and_then(|d| d.as_object());
                let msg = ev
                    .get("message")
                    .and_then(|v| v.as_str())
                    .or_else(|| data.and_then(|d| d.get("message")).and_then(|v| v.as_str()))
                    .unwrap_or("");
                let bid = data
                    .and_then(|d| {
                        d.get("bundle_id")
                            .or_else(|| d.get("bundle id"))
                            .or_else(|| d.get("BundleID"))
                            .and_then(|v| v.as_str())
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(String::from)
                    })
                    .or_else(|| extract_app_bundle_id_from_text(msg));
                let Some(bid) = bid else {
                    continue;
                };
                mined_from_events = true;
                let mut extra = Map::new();
                if !msg.is_empty() {
                    extra.insert("message".into(), json!(truncate_json_string(msg, 400)));
                    extra.insert(
                        "match_context".into(),
                        json!(truncate_json_string(msg, 240)),
                    );
                }
                if let Some(dt) = ev.get("datetime").cloned() {
                    extra.insert("datetime".into(), dt);
                } else if let Some(ts) = ev.get("timestamp").cloned() {
                    extra.insert("datetime".into(), ts);
                }
                if let Some(d) = data {
                    for k in [
                        "short_version",
                        "CFBundleShortVersionString",
                        "version",
                        "CFBundleVersion",
                        "source_file",
                        "path",
                    ] {
                        if let Some(v) = d.get(k) {
                            extra.insert(k.to_string(), v.clone());
                        }
                    }
                    extra.insert("row".into(), sqlite_row_apps_excerpt(d));
                }
                merge_app(&mut apps, bid, "mobileinstallation", Value::Object(extra));
            }
        }
        // Legacy / test shape: `{ "logs/...": "raw log text" }` when events are absent.
        if !mined_from_events {
            if let Value::Object(paths) = &mobile {
                for (path, val) in paths {
                    let Value::String(text) = val else {
                        continue;
                    };
                    for line in text.lines() {
                        let line = line.trim();
                        if line.is_empty() {
                            continue;
                        }
                        let Some(bid) = extract_app_bundle_id_from_text(line) else {
                            continue;
                        };
                        let mut extra = Map::new();
                        extra.insert("source_file".into(), json!(path));
                        extra.insert("message".into(), json!(truncate_json_string(line, 400)));
                        extra.insert(
                            "match_context".into(),
                            json!(truncate_json_string(line, 240)),
                        );
                        if let Some(dt) = mi_line_leading_datetime(line) {
                            extra.insert("datetime".into(), json!(dt));
                        }
                        merge_app(&mut apps, bid, "mobileinstallation", Value::Object(extra));
                    }
                }
            }
        }
    }

    let powerlogs = parser_value(parsed, "powerlogs");
    if !value_looks_like_hard_error(&powerlogs) {
        // Mobipwn Packages: powerlogs App Info inventory (apollo powerlog_app_info).
        // Prefer structured `bundle id` on the row — Apollo messages often omit it.
        for_each_sqlite_row(&powerlogs, |rm, sqlite_db, sqlite_table| {
            let msg = rm
                .get("message")
                .or_else(|| rm.get("Message"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let module = rm
                .get("apollo_module")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let is_app_info = module == "powerlog_app_info"
                || msg.contains("App Info:")
                || (rm.get("app name").is_some() && rm.get("bundle id").is_some());
            if !is_app_info {
                return;
            }
            let bid = rm
                .get("bundle id")
                .or_else(|| rm.get("BUNDLE ID"))
                .or_else(|| rm.get("bundle_id"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .or_else(|| extract_app_bundle_id_from_text(msg))
                .or_else(|| {
                    msg.split_once("bundle id=")
                        .or_else(|| msg.split_once("bundle ID="))
                        .or_else(|| msg.split_once("Bundle ID="))
                        .map(|(_, rest)| {
                            rest.split([',', ' ', '\t', '\n'])
                                .next()
                                .unwrap_or("")
                                .trim()
                                .to_string()
                        })
                        .filter(|s| !s.is_empty())
                });
            let Some(bid) = bid else { return };
            let mut extra = Map::new();
            extra.insert("sqlite_db".into(), json!(sqlite_db));
            extra.insert("sqlite_table".into(), json!(sqlite_table));
            extra.insert("matched_in".into(), json!("app_info_message"));
            extra.insert("row".into(), sqlite_row_apps_excerpt(rm));
            if !msg.is_empty() {
                extra.insert("message".into(), json!(truncate_json_string(msg, 800)));
            }
            if let Some(v) = rm.get("datetime").or_else(|| rm.get("timestamp")) {
                extra.insert("datetime".into(), v.clone());
            }
            for k in [
                "app name",
                "app executable name",
                "app bundle version",
                "app build version",
                "app deleted date",
                "app type",
                "bundle id",
            ] {
                if let Some(v) = rm.get(k) {
                    extra.insert(k.to_string(), v.clone());
                }
            }
            merge_app(&mut apps, bid, "powerlogs", Value::Object(extra));
            app_info_hits += 1;
        });
    }

    let mobilebackup = parser_value(parsed, "mobilebackup");
    if !value_looks_like_hard_error(&mobilebackup) {
        if let Value::Object(paths) = &mobilebackup {
            for (path, val) in paths {
                merge_mvt_plist_bundle_signals(val, &mut apps, "mobilebackup", Some(path.as_str()));
            }
        }
    }

    let plists = parser_value(parsed, "plists");
    if !value_looks_like_hard_error(&plists) {
        if let Some(files) = plists.get("files").and_then(|f| f.as_object()) {
            for (path, val) in files {
                if !path.to_ascii_lowercase().contains("itunesmetadata.plist") {
                    continue;
                }
                merge_mvt_plist_bundle_signals(
                    val,
                    &mut apps,
                    "plists_itunes_metadata",
                    Some(path.as_str()),
                );
            }
        }
    }

    // Apollo powerlogs may be empty (WASM / no matching modules). Read App Info
    // directly from the powerlog SQLite table — same source mobipwn Packages uses.
    let mut app_info_direct = 0usize;
    if app_info_hits == 0 {
        app_info_direct = mine_powerlog_app_info_from_blobs(powerlog_dbs, &mut apps);
        app_info_hits += app_info_direct;
    }

    // Last resort only: do not pollute a real inventory with brctl/logdata noise.
    let used_wasm_fallback = if apps.is_empty() {
        mine_brctl_bundle_ids(parsed, &mut apps);
        mine_logdata_bundle_ids(parsed, &mut apps);
        !apps.is_empty()
    } else {
        false
    };

    promote_app_summaries(&mut apps);

    let count = apps.len();
    let note = if used_wasm_fallback {
        "Preferred Packages sources were empty. Fell back to brctl + logdata bundle-id mines (weak evidence)."
    } else if app_info_direct > 0 {
        "Inventory includes powerlogs App Info read directly from PLAPPLICATIONAGENT_EVENTNONE_ALLAPPS (mobipwn Packages primary source)."
    } else {
        "Inventory mirrors mobipwn Packages: mobileinstallation, appinstallation, accessibility_tcc, itunesstore, mobilebackup, powerlogs App Info, itunesmetadata plists."
    };
    json!({
        "analyser": "apps",
        "apps": Value::Object(apps),
        "count": count,
        "hits_cap_per_app": APPS_MAX_HITS_PER_APP,
        "app_info_hits": app_info_hits,
        "app_info_direct_hits": app_info_direct,
        "tcc_hits": tcc_hits,
        "wasm_text_fallback": used_wasm_fallback,
        "note": note
    })
}

fn row_field_ci<'a>(rm: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a Value> {
    for want in keys {
        let want_l = want.to_ascii_lowercase();
        for (k, v) in rm {
            if k.to_ascii_lowercase() == want_l {
                return Some(v);
            }
        }
    }
    None
}

fn row_str_ci(rm: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    let v = row_field_ci(rm, keys)?;
    if let Some(s) = v.as_str() {
        let t = s.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
        return None;
    }
    if let Some(n) = v.as_i64() {
        return Some(n.to_string());
    }
    if let Some(n) = v.as_u64() {
        return Some(n.to_string());
    }
    if let Some(n) = v.as_f64() {
        return Some(n.to_string());
    }
    None
}

fn format_app_deleted_date(raw: Option<&Value>) -> String {
    let Some(v) = raw else {
        return "NOT DELETED".into();
    };
    let secs = if let Some(n) = v.as_i64() {
        n
    } else if let Some(n) = v.as_u64() {
        n as i64
    } else if let Some(s) = v.as_str() {
        let t = s.trim();
        if t.is_empty() || t.eq_ignore_ascii_case("not deleted") || t == "0" {
            return "NOT DELETED".into();
        }
        if let Ok(n) = t.parse::<i64>() {
            n
        } else {
            return t.to_string();
        }
    } else {
        return "NOT DELETED".into();
    };
    if secs <= 0 {
        return "NOT DELETED".into();
    }
    chrono::DateTime::from_timestamp(secs, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| secs.to_string())
}

fn merge_app_info_row(
    apps: &mut Map<String, Value>,
    rm: &Map<String, Value>,
    sqlite_db: &str,
) -> bool {
    let bid = row_str_ci(rm, &["bundle id", "APPBUNDLEID", "bundle_id"]).or_else(|| {
        row_str_ci(rm, &["message"]).and_then(|m| extract_app_bundle_id_from_text(&m))
    });
    let Some(bid) = bid else {
        return false;
    };

    let mut extra = Map::new();
    extra.insert("sqlite_db".into(), json!(sqlite_db));
    extra.insert("sqlite_table".into(), json!("powerlog_app_info"));
    extra.insert("matched_in".into(), json!("app_info_direct"));
    extra.insert("apollo_module".into(), json!("powerlog_app_info"));
    extra.insert("row".into(), Value::Object(rm.clone()));

    for (out_key, keys) in [
        ("app name", &["app name", "APPNAME"][..]),
        (
            "app executable name",
            &["app executable name", "APPEXECUTABLE"][..],
        ),
        (
            "app bundle version",
            &["app bundle version", "APPBUNDLEVERSION"][..],
        ),
        (
            "app build version",
            &["app build version", "APPBUILDVERSION"][..],
        ),
        ("app type", &["app type", "APPTYPE"][..]),
        ("bundle id", &["bundle id", "APPBUNDLEID"][..]),
    ] {
        if let Some(v) = row_field_ci(rm, keys) {
            extra.insert(out_key.into(), v.clone());
        }
    }

    let deleted = format_app_deleted_date(row_field_ci(
        rm,
        &["app deleted date raw", "APPDELETEDDATE", "app deleted date"],
    ));
    extra.insert("app deleted date".into(), json!(deleted));

    if let Some(ts) = row_field_ci(rm, &["TIMESTAMP", "timestamp", "datetime"]) {
        if let Some(n) = ts.as_i64().or_else(|| ts.as_u64().map(|u| u as i64)) {
            if n > 1_000_000_000 {
                if let Some(dt) = chrono::DateTime::from_timestamp(n, 0) {
                    extra.insert(
                        "datetime".into(),
                        json!(dt.format("%Y-%m-%d %H:%M:%S").to_string()),
                    );
                }
            }
        } else if let Some(s) = ts.as_str() {
            if !s.trim().is_empty() {
                extra.insert("datetime".into(), json!(s));
            }
        }
    }

    let name = row_str_ci(rm, &["app name", "APPNAME"]).unwrap_or_default();
    let exe = row_str_ci(rm, &["app executable name", "APPEXECUTABLE"]).unwrap_or_default();
    let ver = row_str_ci(rm, &["app bundle version", "APPBUNDLEVERSION"]).unwrap_or_default();
    let message = format!(
        "App Info: app name={name}, app executable name={exe}, bundle id={bid}, app bundle version={ver}, app deleted date={deleted}"
    );
    extra.insert("message".into(), json!(truncate_json_string(&message, 800)));

    merge_app(apps, bid, "powerlogs", Value::Object(extra));
    true
}

#[cfg(not(target_arch = "wasm32"))]
fn query_app_info_rows(bytes: &[u8]) -> Vec<Map<String, Value>> {
    use rusqlite::{types::ValueRef, Connection, OpenFlags};
    if bytes.len() < 16 || &bytes[..15] != b"SQLite format 3" {
        return Vec::new();
    }
    let Ok(mut tmp) = tempfile::NamedTempFile::new() else {
        return Vec::new();
    };
    if std::io::Write::write_all(&mut tmp, bytes).is_err() {
        return Vec::new();
    }
    let Ok(conn) = Connection::open_with_flags(tmp.path(), OpenFlags::SQLITE_OPEN_READ_ONLY) else {
        return Vec::new();
    };
    let _ = conn.pragma_update(None, "query_only", true);
    for sql in [POWERLOG_APP_INFO_SQL, POWERLOG_APP_INFO_SQL_MINIMAL] {
        let Ok(mut stmt) = conn.prepare(sql) else {
            continue;
        };
        let names: Vec<String> = stmt
            .column_names()
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let Ok(mut rows) = stmt.query([]) else {
            continue;
        };
        let mut out = Vec::new();
        while let Ok(Some(row)) = rows.next() {
            let mut obj = Map::new();
            for (i, name) in names.iter().enumerate() {
                let val = match row.get_ref(i) {
                    Ok(ValueRef::Null) => Value::Null,
                    Ok(ValueRef::Integer(n)) => json!(n),
                    Ok(ValueRef::Real(f)) => json!(f),
                    Ok(ValueRef::Text(t)) => {
                        Value::String(String::from_utf8_lossy(t).into_owned())
                    }
                    Ok(ValueRef::Blob(_)) => Value::Null,
                    Err(_) => Value::Null,
                };
                obj.insert(name.clone(), val);
            }
            out.push(obj);
        }
        if !out.is_empty() {
            return out;
        }
    }
    Vec::new()
}

#[cfg(target_arch = "wasm32")]
fn query_app_info_rows(_bytes: &[u8]) -> Vec<Map<String, Value>> {
    Vec::new()
}

/// Read Packages' primary inventory table without going through Apollo events.
fn mine_powerlog_app_info_from_blobs(
    blobs: &[(String, Vec<u8>)],
    apps: &mut Map<String, Value>,
) -> usize {
    let mut hits = 0usize;
    for (path, bytes) in blobs {
        let payload = if path.ends_with(".gz") || path.ends_with(".GZ") {
            match mul_io::gzip::inflate_gz(bytes) {
                Ok(b) => b.as_slice().to_vec(),
                Err(_) => continue,
            }
        } else {
            bytes.clone()
        };
        for rm in query_app_info_rows(&payload) {
            if merge_app_info_row(apps, &rm, path) {
                hits += 1;
            }
        }
        if hits > 0 {
            break;
        }
    }
    hits
}

/// Promote name / version / executable / deleted / type / sources onto each app object.
fn promote_app_summaries(apps: &mut Map<String, Value>) {
    for (_bid, app_val) in apps.iter_mut() {
        let Some(app) = app_val.as_object_mut() else {
            continue;
        };
        let sources: Vec<String> = app
            .get("found")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        app.insert("sources".into(), json!(sources));

        let hits = app
            .get("hits")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let pick = |keys: &[&str]| -> Option<Value> {
            for hit in &hits {
                let Some(h) = hit.as_object() else { continue };
                for k in keys {
                    if let Some(v) = h.get(*k) {
                        if let Some(s) = v.as_str() {
                            if !s.trim().is_empty() {
                                return Some(json!(s.trim()));
                            }
                        } else if !v.is_null() {
                            return Some(v.clone());
                        }
                    }
                    if let Some(row) = h.get("row").and_then(|r| r.as_object()) {
                        if let Some(v) = row.get(*k) {
                            if let Some(s) = v.as_str() {
                                if !s.trim().is_empty() {
                                    return Some(json!(s.trim()));
                                }
                            } else if !v.is_null() {
                                return Some(v.clone());
                            }
                        }
                    }
                }
            }
            None
        };

        if let Some(v) = pick(&["app name", "app_name", "name"]) {
            app.insert("name".into(), v);
        }
        if let Some(v) = pick(&[
            "app bundle version",
            "short_version",
            "CFBundleShortVersionString",
            "version",
        ]) {
            app.insert("version".into(), v);
        }
        if let Some(v) = pick(&["app build version", "CFBundleVersion", "build_version"]) {
            app.insert("build_version".into(), v);
        }
        if let Some(v) = pick(&["app executable name", "executable", "app_executable_name"]) {
            app.insert("executable".into(), v);
        }
        if let Some(v) = pick(&["app type", "app_type"]) {
            app.insert("app_type".into(), v);
        }
        let deleted = pick(&["app deleted date", "deleted_date"]);
        let deleted_str = deleted
            .as_ref()
            .and_then(|v| v.as_str())
            .unwrap_or("NOT DELETED");
        let is_deleted = !deleted_str.eq_ignore_ascii_case("NOT DELETED")
            && !deleted_str.is_empty()
            && deleted_str != "0";
        app.insert(
            "deleted_date".into(),
            deleted.unwrap_or_else(|| json!("NOT DELETED")),
        );
        app.insert("is_deleted".into(), json!(is_deleted));
    }
}

/// Best-effort leading Apple syslog stamp: `Thu Jan  1 12:00:00 2026 …`.
fn mi_line_leading_datetime(line: &str) -> Option<String> {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(
            r"(?i)^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\d{4})",
        )
        .expect("mi syslog ts")
    });
    let caps = re.captures(line)?;
    let mon = caps.get(2)?.as_str();
    let day: u32 = caps.get(3)?.as_str().parse().ok()?;
    let hms = caps.get(4)?.as_str();
    let year: i32 = caps.get(5)?.as_str().parse().ok()?;
    let mon_num = match &mon.to_ascii_lowercase()[..] {
        "jan" => 1,
        "feb" => 2,
        "mar" => 3,
        "apr" => 4,
        "may" => 5,
        "jun" => 6,
        "jul" => 7,
        "aug" => 8,
        "sep" => 9,
        "oct" => 10,
        "nov" => 11,
        "dec" => 12,
        _ => return None,
    };
    let naive = chrono::NaiveDate::from_ymd_opt(year, mon_num, day)?
        .and_time(chrono::NaiveTime::parse_from_str(hms, "%H:%M:%S").ok()?);
    Some(
        chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(naive, chrono::Utc)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string(),
    )
}

fn mine_brctl_bundle_ids(parsed: &HashMap<String, Value>, apps: &mut Map<String, Value>) {
    let brctl = parser_value(parsed, "brctl");
    let brctl_text = brctl
        .get("data")
        .map(|d| d.to_string())
        .or_else(|| brctl.get("files").map(|f| f.to_string()))
        .unwrap_or_default();
    if brctl_text.is_empty() || brctl_text == "{}" || brctl_text == "null" {
        return;
    }
    for cap in bundle_id_re().find_iter(&brctl_text) {
        merge_app(
            apps,
            cap.as_str().to_string(),
            "brctl",
            json!({
                "context": brctl_match_context(&brctl_text, &cap),
            }),
        );
    }
}

fn mine_logdata_bundle_ids(parsed: &HashMap<String, Value>, apps: &mut Map<String, Value>) {
    let logdata = parser_value(parsed, "logdata_statistics");
    let Value::Object(paths) = &logdata else {
        return;
    };
    for (_p, lines) in paths {
        let Some(arr) = lines.as_array() else {
            continue;
        };
        for line in arr {
            let sub = line
                .get("subsystem")
                .or_else(|| line.get("process"))
                .or_else(|| line.get("data").and_then(|d| d.get("subsystem")))
                .or_else(|| line.get("data").and_then(|d| d.get("process")))
                .and_then(|v| v.as_str());
            let Some(s) = sub.filter(|s| !s.is_empty()) else {
                continue;
            };
            let Some(c) = bundle_id_re().find(s) else {
                continue;
            };
            let mut ex = Map::new();
            if let Some(d) = line.get("data").and_then(|d| d.as_object()) {
                for k in [
                    "subsystem",
                    "category",
                    "process",
                    "pid",
                    "message",
                    "sender",
                    "recipient",
                ] {
                    if let Some(v) = d.get(k) {
                        ex.insert(k.to_string(), v.clone());
                    }
                }
            }
            if let Some(v) = line.get("datetime") {
                ex.insert("datetime".into(), v.clone());
            }
            if let Some(v) = line.get("message") {
                ex.insert("log_message".into(), v.clone());
            }
            if let Some(v) = line.get("subsystem").or_else(|| line.get("process")) {
                ex.insert("top_level_hint".into(), v.clone());
            }
            merge_app(
                apps,
                c.as_str().to_string(),
                "logdata_statistics",
                Value::Object(ex),
            );
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use std::collections::HashMap;

    #[test]
    fn mines_app_info_from_powerlog_blob() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = Connection::open(tmp.path()).unwrap();
        conn.execute_batch(
            "CREATE TABLE PLAPPLICATIONAGENT_EVENTNONE_ALLAPPS (
                ID INTEGER PRIMARY KEY,
                TIMESTAMP INTEGER,
                APPNAME TEXT,
                APPEXECUTABLE TEXT,
                APPBUNDLEID TEXT,
                APPBUILDVERSION TEXT,
                APPBUNDLEVERSION TEXT,
                APPTYPE INTEGER,
                APPDELETEDDATE INTEGER
            );
            INSERT INTO PLAPPLICATIONAGENT_EVENTNONE_ALLAPPS
                (TIMESTAMP, APPNAME, APPEXECUTABLE, APPBUNDLEID, APPBUILDVERSION, APPBUNDLEVERSION, APPTYPE, APPDELETEDDATE)
            VALUES
                (1700000000, 'Saracroche', 'Saracroche', 'com.cbouvat.saracroche', '100', '4.12.0', 4, 0);",
        )
        .unwrap();
        let bytes = std::fs::read(tmp.path()).unwrap();

        let mut parsed = HashMap::new();
        parsed.insert(
            "powerlogs".into(),
            json!({ "parser": "powerlogs", "format": "jsonl", "events": [] }),
        );
        parsed.insert("accessibility_tcc".into(), json!({ "events": [] }));
        parsed.insert("mobileinstallation".into(), json!({}));
        parsed.insert("appinstallation".into(), json!({}));
        parsed.insert("itunesstore".into(), json!({}));
        parsed.insert("mobilebackup".into(), json!({}));
        parsed.insert("plists".into(), json!({ "files": {} }));

        let blobs = vec![("logs/powerlogs/powerlog_test.PLSQL".into(), bytes)];
        let out = run(&parsed, &blobs);
        assert!(out["app_info_direct_hits"].as_u64().unwrap() >= 1);
        let apps = out["apps"].as_object().unwrap();
        let app = apps.get("com.cbouvat.saracroche").unwrap();
        assert_eq!(app["name"], "Saracroche");
        assert_eq!(app["version"], "4.12.0");
        assert_eq!(app["executable"], "Saracroche");
        assert_eq!(app["is_deleted"], false);
        assert!(app["sources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.as_str() == Some("powerlogs")));
    }
}
