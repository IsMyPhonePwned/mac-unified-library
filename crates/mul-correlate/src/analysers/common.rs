// SPDX-License-Identifier: GPL-3.0-only
//! Shared helpers for compat analysers (parser JSON lookup, plist/SQLite walks, Wi‑Fi plist helpers).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::OnceLock;

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use regex::Regex;
use serde_json::{json, Map, Value};

pub fn unwrap_parser<'a>(parsed: &'a HashMap<String, Value>, name: &str) -> Option<&'a Value> {
    let v = parsed.get(name)?;
    if let Some(data) = v.get("data") {
        if data.is_object() || data.is_array() {
            Some(data)
        } else {
            Some(v)
        }
    } else {
        Some(v)
    }
}

pub fn parser_value(parsed: &HashMap<String, Value>, id: &str) -> Value {
    match unwrap_parser(parsed, id) {
        Some(v) => v.clone(),
        None => json!({ "error": format!("missing parser: {id}") }),
    }
}

pub fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}


pub fn value_looks_like_hard_error(v: &Value) -> bool {
    v.get("error")
        .and_then(|e| e.as_str())
        .filter(|s| !s.is_empty())
        .is_some()
        && v.get("rows").is_none()
        && v.get("entries").is_none()
        && v.get("events").is_none()
}

pub fn find_map_with_keys(v: &Value, keys: &[&str]) -> Option<Map<String, Value>> {
    match v {
        Value::Object(m) => {
            if keys.iter().all(|k| m.contains_key(*k)) {
                return Some(m.clone());
            }
            for (_, c) in m {
                if let Some(inner) = find_map_with_keys(c, keys) {
                    return Some(inner);
                }
            }
        }
        Value::Array(a) => {
            for c in a {
                if let Some(inner) = find_map_with_keys(c, keys) {
                    return Some(inner);
                }
            }
        }
        _ => {}
    }
    None
}

pub fn device_props_from_remotectl(parsed: &HashMap<String, Value>) -> Value {
    let Some(v) = unwrap_parser(parsed, "remotectl_dumpstate") else {
        return json!(null);
    };
    let Some(props) = find_map_with_keys(v, &["OSVersion", "SerialNumber"])
        .or_else(|| find_map_with_keys(v, &["OSVersion", "BuildVersion"]))
    else {
        return json!(null);
    };
    json!({
        "os_version": props.get("OSVersion"),
        "build": props.get("BuildVersion"),
        "product_name": props.get("ProductName"),
        "product_type": props.get("ProductType"),
        "serial_number": props.get("SerialNumber"),
        "unique_device_id": props.get("UniqueDeviceID"),
    })
}


pub fn mime_hint_by_extension(path: &str) -> &'static str {
    let ext = std::path::Path::new(path)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "json" | "jsonl" => "application/json",
        "plist" => "application/x-plist",
        "txt" | "log" => "text/plain",
        "csv" => "text/csv",
        "xml" => "application/xml",
        "html" | "htm" => "text/html",
        "db" | "sqlitedb" => "application/x-sqlite3",
        "gz" => "application/gzip",
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "ips" => "text/plain",
        "" => "application/octet-stream",
        _ => "application/octet-stream",
    }
}

fn strip_process_name_quotes(s: &str) -> String {
    let t = s.trim();
    if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
        return t[1..t.len() - 1].to_string();
    }
    t.trim_matches('"').trim().to_string()
}

fn spindump_process_line_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^Process:\s*(.+?)\s+\[(\d+)\]\s*$").expect("regex"))
}

pub fn spindump_pid_to_process(text: &str) -> BTreeMap<i64, String> {
    let mut m = BTreeMap::new();
    for cap in spindump_process_line_re().captures_iter(text) {
        let Some(pid_s) = cap.get(2).map(|g| g.as_str()) else {
            continue;
        };
        let Ok(pid) = pid_s.parse::<i64>() else {
            continue;
        };
        let name = cap
            .get(1)
            .map(|g| strip_process_name_quotes(g.as_str()))
            .unwrap_or_default();
        if !name.is_empty() {
            m.entry(pid).or_insert(name);
        }
    }
    m
}

/// PIDs from **`spindumpnosymbols`** parser JSON: prefers jsonl **`events`** (upstream-shaped), else
/// legacy **`utf8_map`** path → raw text (regex on `Process:` lines).
pub fn spindump_pid_name_map(spin: &Value) -> BTreeMap<i64, String> {
    if let Some(events) = spin.get("events").and_then(|e| e.as_array()) {
        let mut m = BTreeMap::new();
        for ev in events {
            if ev.get("timestamp_desc").and_then(|t| t.as_str())
                != Some("process running during spindump")
            {
                continue;
            }
            let Some(data) = ev.get("data").and_then(|d| d.as_object()) else {
                continue;
            };
            let Some(pid) = data.get("pid").and_then(|p| p.as_i64()) else {
                continue;
            };
            let name = data
                .get("process")
                .and_then(|p| p.as_str())
                .unwrap_or("")
                .to_string();
            if !name.is_empty() {
                m.entry(pid).or_insert(name);
            }
        }
        return m;
    }

    let mut combined = String::new();
    if let Value::Object(map) = spin {
        for (_p, v) in map {
            if let Some(s) = v.as_str() {
                combined.push_str(s);
                combined.push('\n');
            }
        }
    }
    spindump_pid_to_process(&combined)
}

pub fn collect_remotectl_service_paths(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(map) => {
            if let Some(Value::Array(arr)) = map.get("Services") {
                for x in arr {
                    if let Some(s) = x.as_str() {
                        let t = s.trim();
                        if !t.is_empty() {
                            out.push(t.to_string());
                        }
                    }
                }
            }
            for child in map.values() {
                collect_remotectl_service_paths(child, out);
            }
        }
        Value::Array(a) => {
            for x in a {
                collect_remotectl_service_paths(x, out);
            }
        }
        _ => {}
    }
}

pub fn logdata_line_process(line: &Value) -> Option<String> {
    line.get("data")
        .and_then(|d| d.get("process"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            line.get("process")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
}

/// Optional fields from a logdata.statistics JSONL line (beyond the process name).
pub fn logdata_line_context(line: &Value) -> Map<String, Value> {
    let mut m = Map::new();
    if let Some(v) = line.get("datetime") {
        if !v.is_null() && v.as_str().map(|s| !s.is_empty()).unwrap_or(true) {
            m.insert("datetime".into(), v.clone());
        }
    }
    if let Some(obj) = line.get("data").and_then(|d| d.as_object()) {
        for k in ["pid", "subsystem", "category"] {
            if let Some(v) = obj.get(k) {
                if !v.is_null() && v.as_str().map(|s| !s.is_empty()).unwrap_or(true) {
                    m.insert(k.to_string(), v.clone());
                }
            }
        }
    }
    m
}

pub fn uuid2path_strings(plist_root: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Value::Object(m) = plist_root {
        for v in m.values() {
            if let Some(s) = v.as_str() {
                let t = s.trim();
                if !t.is_empty() {
                    out.push(t.to_string());
                }
            }
        }
    }
    out
}

pub fn walk_transparency_contact_uris(v: &Value, out: &mut BTreeSet<String>) {
    match v {
        Value::String(s) => {
            if s.starts_with("im://mailto:")
                || s.starts_with("im://tel:")
                || s.starts_with("mailto:")
                || s.starts_with("tel:")
            {
                out.insert(s.clone());
            }
        }
        Value::Object(m) => {
            for c in m.values() {
                walk_transparency_contact_uris(c, out);
            }
        }
        Value::Array(a) => {
            for c in a {
                walk_transparency_contact_uris(c, out);
            }
        }
        _ => {}
    }
}

pub fn lockdown_mode_from_effective_settings(v: &Value) -> Option<bool> {
    v.get("restrictedBool")
        .and_then(|r| r.get("allowLockdownMode"))
        .and_then(|a| a.get("value"))
        .and_then(|x| x.as_bool())
}

pub fn owner_emails_from_mobilecal(v: &Value) -> Vec<String> {
    let mut vout = Vec::new();
    match v.get("OwnerEmailAddress") {
        Some(Value::Array(a)) => {
            for x in a {
                if let Some(s) = x.as_str() {
                    if !s.is_empty() {
                        vout.push(s.to_string());
                    }
                }
            }
        }
        Some(Value::String(s)) if !s.is_empty() => vout.push(s.clone()),
        _ => {}
    }
    vout
}

pub fn mcstate_stub_summary_lines(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    for raw in text.lines() {
        let t = raw.trim();
        if let Some(rest) = t.strip_prefix("PayloadIdentifier:") {
            lines.push(format!("Payload identifier: {}", rest.trim()));
        } else if let Some(rest) = t.strip_prefix("PayloadUUID:") {
            lines.push(format!("Payload UUID: {}", rest.trim()));
        } else if let Some(rest) = t.strip_prefix("PayloadOrganization:") {
            lines.push(format!("Payload organisation: {}", rest.trim()));
        } else if let Some(rest) = t.strip_prefix("InstallDate:") {
            lines.push(format!("Install date {}", rest.trim()));
        }
    }
    lines
}

/// Max evidence rows per bundle id (additional hits are dropped to keep output bounded).
pub const APPS_MAX_HITS_PER_APP: usize = 64;

fn append_app_hit(m: &mut Map<String, Value>, source: &str, extra: Value) {
    let arr = m.entry("hits".to_string()).or_insert_with(|| json!([]));
    let Some(hits) = arr.as_array_mut() else {
        return;
    };
    if hits.len() >= APPS_MAX_HITS_PER_APP {
        return;
    }
    let mut hit = Map::new();
    hit.insert("source".to_string(), json!(source));
    match &extra {
        Value::Object(e) => {
            for (k, v) in e {
                if k != "source" {
                    hit.insert(k.clone(), v.clone());
                }
            }
        }
        v if !v.is_null() => {
            hit.insert("detail".to_string(), (*v).clone());
        }
        _ => {}
    }
    hits.push(Value::Object(hit));

    // Backward compatibility: last non-empty object (or scalar) wins for `_{source}`.
    let key = format!("_{source}");
    match extra {
        Value::Object(e) if !e.is_empty() => {
            m.insert(key, Value::Object(e));
        }
        v if !v.is_null() => {
            m.insert(key, v);
        }
        _ => {}
    }
}

pub fn merge_app(apps: &mut Map<String, Value>, id: String, source: &str, extra: Value) {
    let Some(id) = canonicalize_app_bundle_id(&id) else {
        return;
    };
    use serde_json::map::Entry;
    match apps.entry(id) {
        Entry::Vacant(v) => {
            let mut m = Map::new();
            m.insert("found".to_string(), json!([source]));
            append_app_hit(&mut m, source, extra);
            v.insert(Value::Object(m));
        }
        Entry::Occupied(mut o) => {
            let Value::Object(m) = o.get_mut() else {
                return;
            };
            let found = m.entry("found".to_string()).or_insert_with(|| json!([]));
            if let Some(arr) = found.as_array_mut() {
                let s = json!(source);
                if !arr.contains(&s) {
                    arr.push(s);
                }
            }
            append_app_hit(m, source, extra);
        }
    }
}

pub(crate) fn bundle_id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b([a-zA-Z][a-zA-Z0-9_-]*(?:\.[a-zA-Z0-9][a-zA-Z0-9_-]*)+)\b").expect("regex")
    })
}

fn staging_uuid_prefix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^[0-9A-Fa-f][0-9A-Fa-f-]{6,}_([A-Za-z][A-Za-z0-9_-]*(?:\.[A-Za-z0-9][A-Za-z0-9_-]*)+)$")
            .expect("regex")
    })
}

fn appstored_composite_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\[([^\]]+)\]").expect("regex"))
}

/// Last segments that indicate a URL/file/asset, not an app bundle id.
fn non_bundle_last_segments() -> &'static BTreeSet<&'static str> {
    static SET: OnceLock<BTreeSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| {
        [
            // Public TLDs commonly scraped from URLs
            "com", "net", "org", "edu", "gov", "io", "co", "uk", "de", "fr", "us", "app", "dev",
            "info", "biz", "me", "tv", "cc", "cn", "jp", "ru", "au", "ca", "nl", "it", "es",
            // File / asset extensions from plist URL dumps
            "png", "jpg", "jpeg", "gif", "webp", "svg", "bmp", "ico", "plist", "xml", "json",
            "html", "htm", "css", "js", "ts", "map", "pdf", "zip", "gz", "txt", "log", "db", "sql",
            "sqlite", "svc", "woa", "aspx", "php", "asp", "dylib", "framework", "bundle", "mp3",
            "mp4", "mov", "wav", "aac", "m4a", "caf", "strings", "nib", "storyboard", "xib", "car",
            "metallib",
        ]
        .into_iter()
        .collect()
    })
}

/// PluginKit / Network Extension suffixes rolled up into the host app.
fn appex_suffixes() -> &'static BTreeSet<&'static str> {
    static SET: OnceLock<BTreeSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| {
        [
            "unwanted",
            "filter",
            "blocker",
            "appex",
            "extension",
            "notification",
            "notifications",
            "notificationservice",
            "notificationcontent",
            "intent",
            "intents",
            "intentsui",
            "intentui",
            "widget",
            "widgets",
            "widgetextension",
            "shareextension",
            "share",
            "today",
            "todayextension",
            "watchkitapp",
            "watchkitextension",
            "broadcastupload",
            "broadcastsetupui",
            "packettunnel",
            "appproxy",
            "dnsproxy",
            "filterdata",
            "filtercontrol",
            "networkextension",
        ]
        .into_iter()
        .collect()
    })
}

/// Compound PluginKit tails (`MessagesExtension`, `OrderStatusNotification`, `iUpNotification`).
fn appex_compound_tails() -> &'static [&'static str] {
    &[
        "notificationservice",
        "notificationcontent",
        "notification",
        "notifications",
        "widgetextension",
        "watchkitextension",
        "watchkitapp",
        "shareextension",
        "todayextension",
        "broadcastupload",
        "broadcastsetupui",
        "networkextension",
        "packettunnel",
        "intentsui",
        "intentui",
        "extension",
    ]
}

fn is_appex_segment(seg: &str) -> bool {
    let s = seg.to_ascii_lowercase();
    if appex_suffixes().contains(s.as_str()) {
        return true;
    }
    for t in appex_compound_tails() {
        // Require a real compound (`MessagesExtension`), not the bare token alone
        // (bare tokens are handled by `appex_suffixes`).
        if s.len() > t.len() && s.ends_with(t) {
            return true;
        }
    }
    false
}

/// Canonical host-app bundle id for inventory (apps analyser).
///
/// - Unwraps App Store composite ids (`com.apple.appstored:[…:com.foo]`)
/// - Strips mobileinstallation staging UUID prefixes
/// - Collapses known appex / NE suffixes (`.blocker`, `.filter`, …)
/// - Rejects URL hostnames / file assets (`portal…microsoft.com`, `clock_1x.png`)
pub fn canonicalize_app_bundle_id(raw: &str) -> Option<String> {
    let mut trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(caps) = appstored_composite_re().captures(&trimmed) {
        if let Some(inner) = caps.get(1).map(|m| m.as_str()) {
            for part in inner.split(':').rev() {
                let part = part.trim();
                if let Some(c) = canonicalize_app_bundle_id(part) {
                    return Some(c);
                }
            }
        }
    }

    if let Some(caps) = staging_uuid_prefix_re().captures(&trimmed) {
        if let Some(rest) = caps.get(1).map(|m| m.as_str()) {
            trimmed = rest.to_string();
        }
    }

    if !bundle_id_re().is_match(&trimmed) {
        return None;
    }
    if trimmed.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return None;
    }

    let mut segments: Vec<&str> = trimmed.split('.').collect();
    while segments.len() > 3 {
        let last = segments[segments.len() - 1].to_ascii_lowercase();
        if !is_appex_segment(&last) {
            break;
        }
        segments.pop();
    }
    let collapsed = segments.join(".");
    if is_likely_app_bundle_id(&collapsed) {
        Some(collapsed)
    } else {
        None
    }
}

pub fn is_likely_app_bundle_id(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() < 4 {
        return false;
    }
    if trimmed.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return false;
    }
    if staging_uuid_prefix_re().is_match(trimmed) {
        return false;
    }
    if !bundle_id_re().is_match(trimmed) {
        return false;
    }
    let parts: Vec<&str> = trimmed.split('.').collect();
    // Require reverse-DNS style `com.vendor.app`, not `file.ext`.
    if parts.len() < 3 {
        return false;
    }
    let last = parts[parts.len() - 1].to_ascii_lowercase();
    if non_bundle_last_segments().contains(last.as_str()) {
        return false;
    }
    if parts
        .iter()
        .any(|p| p.ends_with("_1x") || p.ends_with("_2x") || p.ends_with("_3x") || *p == "1x" || *p == "2x" || *p == "3x")
    {
        return false;
    }
    true
}

fn preferred_bundle_id_res() -> &'static [Regex] {
    static RES: OnceLock<Vec<Regex>> = OnceLock::new();
    RES.get_or_init(|| {
        vec![
            Regex::new(r"\bID=([a-zA-Z][a-zA-Z0-9_-]*(?:\.[a-zA-Z0-9][a-zA-Z0-9_-]*)+)").unwrap(),
            Regex::new(r"\bCustomer:([a-zA-Z][a-zA-Z0-9_-]*(?:\.[a-zA-Z0-9][a-zA-Z0-9_-]*)+)").unwrap(),
            Regex::new(r"(?i)\bfor app\s+([a-zA-Z][a-zA-Z0-9_-]*(?:\.[a-zA-Z0-9][a-zA-Z0-9_-]*)+)").unwrap(),
            Regex::new(
                r"(?i)\bData container for\s+([a-zA-Z][a-zA-Z0-9_-]*(?:\.[a-zA-Z0-9][a-zA-Z0-9_-]*)+)\s+is now at",
            )
            .unwrap(),
            Regex::new(
                r#"(?i)\bstaged update(?: identifier)?\s+"?([0-9A-Fa-f][0-9A-Fa-f-]*_[a-zA-Z][a-zA-Z0-9_.-]*)"#,
            )
            .unwrap(),
            Regex::new(
                r"(?i)\bbundle\s*id\s*=\s*([a-zA-Z][a-zA-Z0-9_-]*(?:\.[a-zA-Z0-9][a-zA-Z0-9_-]*)+)",
            )
            .unwrap(),
        ]
    })
    .as_slice()
}

/// Pull a host-app bundle id out of free text (mobileinstallation logs, etc.).
pub fn extract_app_bundle_id_from_text(text: &str) -> Option<String> {
    if text.trim().is_empty() {
        return None;
    }

    for re in preferred_bundle_id_res() {
        if let Some(caps) = re.captures(text) {
            if let Some(m) = caps.get(1) {
                if let Some(id) = canonicalize_app_bundle_id(m.as_str()) {
                    return Some(id);
                }
            }
        }
    }

    let mut best: Option<String> = None;
    let mut candidate_count = 0usize;
    for caps in bundle_id_re().captures_iter(text) {
        let Some(m) = caps.get(1).or_else(|| caps.get(0)) else {
            continue;
        };
        candidate_count += 1;
        let Some(id) = canonicalize_app_bundle_id(m.as_str()) else {
            continue;
        };
        best = Some(match best {
            Some(cur) if cur.len() < id.len() || (cur.len() == id.len() && cur <= id) => cur,
            Some(_) => id,
            None => id,
        });
    }
    if let Some(ref id) = best {
        if id.starts_with("com.apple.") && candidate_count > 1 {
            // Prefer non-Apple when multiple reverse-DNS tokens exist.
            for caps in bundle_id_re().captures_iter(text) {
                let Some(m) = caps.get(1).or_else(|| caps.get(0)) else {
                    continue;
                };
                if let Some(other) = canonicalize_app_bundle_id(m.as_str()) {
                    if !other.starts_with("com.apple.") {
                        return Some(other);
                    }
                }
            }
        }
    }
    best
}

pub fn for_each_sqlite_row(
    root: &Value,
    mut visit: impl FnMut(&Map<String, Value>, &str, &str),
) {
    if matches!(
        root.get("parser").and_then(|p| p.as_str()),
        Some("accessibility_tcc") | Some("powerlogs")
    ) {
        if let Some(events) = root.get("events").and_then(|e| e.as_array()) {
            for ev in events {
                let Some(data) = ev.get("data").and_then(|d| d.as_object()) else {
                    continue;
                };
                let sqlite_table = data
                    .get("apollo_module")
                    .and_then(|v| v.as_str())
                    .unwrap_or("apollo");
                let sqlite_db = data.get("source_db").and_then(|v| v.as_str()).unwrap_or("");
                visit(data, sqlite_db, sqlite_table);
            }
            return;
        }
    }

    if root.get("parser").and_then(|p| p.as_str()) == Some("itunesstore") {
        if let Some(tables) = root.get("data").and_then(|d| d.as_object()) {
            let db_path = root
                .get("source_path")
                .and_then(|v| v.as_str())
                .unwrap_or("itunesstore");
            for (table_name, rows_val) in tables {
                let Some(rows) = rows_val.as_array() else {
                    continue;
                };
                for row in rows {
                    if let Some(rm) = row.as_object() {
                        visit(rm, db_path, table_name.as_str());
                    }
                }
            }
            return;
        }
    }

    let Some(files) = root.as_object() else {
        return;
    };
    for (db_path, file_val) in files {
        let Some(tables) = file_val.as_object() else {
            continue;
        };
        for (table_name, rows_val) in tables {
            let Some(rows) = rows_val.as_array() else {
                continue;
            };
            for row in rows {
                if let Some(rm) = row.as_object() {
                    visit(rm, db_path.as_str(), table_name.as_str());
                }
            }
        }
    }
}

pub fn truncate_json_string(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut t: String = s.chars().take(max).collect();
    t.push('…');
    t
}

fn value_excerpt_for_apps(v: &Value, max_str: usize) -> Value {
    match v {
        Value::String(s) => json!(truncate_json_string(s, max_str)),
        Value::Array(a) if a.len() <= 32 => v.clone(),
        Value::Array(a) => json!(format!("[{} items]", a.len())),
        Value::Object(o) if o.len() <= 24 => v.clone(),
        Value::Object(o) => json!(format!("{{{} keys}}", o.len())),
        _ => v.clone(),
    }
}

/// Subset of a SQLite row for the apps analyser (bundle-adjacent columns, truncated).
pub fn sqlite_row_apps_excerpt(rm: &Map<String, Value>) -> Value {
    const MAX_KEYS: usize = 48;
    const MAX_STR: usize = 512;
    let mut out = Map::new();
    for (i, (k, v)) in rm.iter().enumerate() {
        if i >= MAX_KEYS {
            break;
        }
        let kl = k.to_ascii_lowercase();
        let keep = sqlite_column_likely_bundle_id(k)
            || kl.contains("name")
            || kl.contains("proc")
            || kl.contains("version")
            || kl.contains("app")
            || kl.contains("product")
            || kl.contains("vendor")
            || kl.contains("id")
            || kl.starts_with("z");
        if !keep {
            continue;
        }
        out.insert(k.clone(), value_excerpt_for_apps(v, MAX_STR));
    }
    json!(out)
}

pub fn brctl_match_context(text: &str, m: &regex::Match) -> String {
    const PAD: usize = 80;
    let start = m.start().saturating_sub(PAD);
    let end = (m.end() + PAD).min(text.len());
    let slice = &text[start..end];
    truncate_json_string(slice, 240)
}

pub fn tcc_client_and_service(rm: &Map<String, Value>) -> Option<(String, Option<String>)> {
    let nested = rm.get("data").and_then(|v| v.as_object());
    let client = rm
        .get("client")
        .or_else(|| nested.and_then(|n| n.get("client")))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)?;
    let service = rm
        .get("service")
        .or_else(|| nested.and_then(|n| n.get("service")))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);
    Some((client, service))
}

pub fn sqlite_column_likely_bundle_id(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "zbundlename"
            | "zbundleid"
            | "ztargetbundleid"
            | "bundle_id"
            | "bundle id"
            | "bundleid"
            | "application_id"
            | "target_bundle_id"
            | "softwareversionbundleid"
            | "cfbundleidentifier"
    )
}

pub fn merge_sqlite_row_bundle_columns(
    rm: &Map<String, Value>,
    apps: &mut Map<String, Value>,
    source: &'static str,
    sqlite_db: &str,
    sqlite_table: &str,
) {
    let row = sqlite_row_apps_excerpt(rm);
    for (k, v) in rm {
        if !sqlite_column_likely_bundle_id(k) {
            continue;
        }
        let Some(s) = v.as_str() else { continue };
        let t = s.trim();
        if t.is_empty() {
            continue;
        }
        if bundle_id_re().is_match(t) {
            merge_app(
                apps,
                t.to_string(),
                source,
                json!({
                    "sqlite_db": sqlite_db,
                    "sqlite_table": sqlite_table,
                    "matched_column": k,
                    "row": row,
                }),
            );
        }
    }
}

pub fn merge_mvt_plist_bundle_signals(
    v: &Value,
    apps: &mut Map<String, Value>,
    source: &'static str,
    plist_path: Option<&str>,
) {
    match v {
        Value::Object(m) => {
            for (k, val) in m {
                let kl = k.to_ascii_lowercase();
                if kl == "installed applications" {
                    if let Value::Array(a) = val {
                        for x in a {
                            if let Some(s) = x.as_str() {
                                let t = s.trim();
                                if !t.is_empty() && bundle_id_re().is_match(t) {
                                    let mut extra = Map::new();
                                    extra.insert("signal".into(), json!("Installed Applications"));
                                    if let Some(p) = plist_path {
                                        extra.insert("plist_path".into(), json!(p));
                                    }
                                    merge_app(apps, t.to_string(), source, Value::Object(extra));
                                }
                            }
                        }
                    }
                }
                if matches!(
                    kl.as_str(),
                    "softwareversionbundleid" | "cfbundleidentifier" | "bundleid"
                ) {
                    if let Some(s) = val.as_str() {
                        let t = s.trim();
                        if !t.is_empty() && bundle_id_re().is_match(t) {
                            let mut extra = Map::new();
                            extra.insert("plist_key".into(), json!(k));
                            if let Some(p) = plist_path {
                                extra.insert("plist_path".into(), json!(p));
                            }
                            merge_app(apps, t.to_string(), source, Value::Object(extra));
                        }
                    }
                }
                merge_mvt_plist_bundle_signals(val, apps, source, plist_path);
            }
        }
        Value::Array(a) => {
            for x in a {
                merge_mvt_plist_bundle_signals(x, apps, source, plist_path);
            }
        }
        _ => {}
    }
}

pub fn plist_top_keys(v: &Value) -> Vec<String> {
    match v {
        Value::Object(m) => m.keys().take(40).cloned().collect(),
        _ => vec![],
    }
}

pub fn first_word_command(cmd: &str) -> String {
    cmd.split_whitespace().next().unwrap_or("").to_string()
}

pub fn pid_from_row(row: &Value) -> Option<i64> {
    row.get("pid")
        .and_then(|v| v.as_i64().or_else(|| v.as_str()?.parse().ok()))
}

pub fn parse_wifi_timestamp(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .ok()
        .or_else(|| {
            NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
                .ok()
                .map(|n| Utc.from_utc_datetime(&n))
        })
}

/// Top-level keys under a known-networks plist root (drops keys ending in `.plist`).
pub fn wifi_network_dicts(plist_root: &Value) -> Vec<(String, &Value)> {
    let mut out = Vec::new();
    if let Value::Object(m) = plist_root {
        for (k, v) in m {
            if k.ends_with(".plist") {
                continue;
            }
            out.push((k.clone(), v));
        }
    }
    out
}

pub fn f64_from_plist(v: &Value) -> Option<f64> {
    v.as_f64()
        .or_else(|| v.as_i64().map(|i| i as f64))
        .or_else(|| v.as_str()?.parse().ok())
}
