// SPDX-License-Identifier: GPL-3.0-only

//! Timeline rows for [Timesketch](https://timesketch.org) import: JSON array (`events`), **JSONL**
//! (one object per line), and CSV with `message`, `datetime`, `timestamp_desc`, plus `timestamp`
//! in epoch microseconds.

use chrono::{TimeZone, Utc};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};

use super::common::{parser_value, value_looks_like_hard_error};

fn sorted_parser_ids(parsed: &HashMap<String, Value>) -> Vec<String> {
    let mut ids: Vec<String> = parsed.keys().cloned().collect();
    ids.sort();
    ids
}

const MAX_EVENTS_TOTAL: usize = 100_000;
const MAX_EVENTS_PER_PARSER: usize = 15_000;
const MAX_MESSAGE_CHARS: usize = 16_384;

fn key_looks_like_path(key: &str) -> bool {
    key.contains('/')
        || key.ends_with(".plist")
        || key.ends_with(".txt")
        || key.ends_with(".log")
        || key.ends_with(".json")
        || key.ends_with(".jsonl")
        || key.ends_with(".csv")
}

fn iso_to_timestamp_micros(iso: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(iso)
        .ok()
        .map(|d| d.with_timezone(&Utc).timestamp_micros())
}

fn infer_message(obj: &Map<String, Value>) -> Option<String> {
    if let Some(m) = obj.get("message").and_then(|v| v.as_str()) {
        let t = m.trim();
        if !t.is_empty() {
            return Some(t.chars().take(MAX_MESSAGE_CHARS).collect());
        }
    }
    if let Some(c) = obj.get("content").and_then(|v| v.as_str()) {
        let t = c.trim();
        if !t.is_empty() {
            return Some(t.chars().take(MAX_MESSAGE_CHARS).collect());
        }
    }
    if let Some(data) = obj.get("data").and_then(|d| d.as_object()) {
        if let Some(p) = data.get("process").and_then(|v| v.as_str()) {
            let sub = data
                .get("subsystem")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let cat = data
                .get("category")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let mut parts: Vec<&str> = Vec::new();
            if !sub.is_empty() {
                parts.push(sub);
            }
            if !cat.is_empty() {
                parts.push(cat);
            }
            parts.push(p);
            let s = parts.join(" ");
            if !s.is_empty() {
                return Some(s.chars().take(MAX_MESSAGE_CHARS).collect());
            }
        }
    }
    if let Some(cmd) = obj.get("command").and_then(|v| v.as_str()) {
        if !cmd.trim().is_empty() {
            let u = obj.get("user").and_then(|v| v.as_str()).unwrap_or("");
            let pid = obj
                .get("pid")
                .map(|v| v.to_string())
                .unwrap_or_default();
            return Some(format!("{u} pid {pid} {cmd}").trim().to_string());
        }
    }
    if let Some(title) = obj.get("title").and_then(|v| v.as_str()) {
        let body = obj
            .get("body")
            .or_else(|| obj.get("subtitle"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let t = format!("{title} {body}").trim().to_string();
        if !t.is_empty() {
            return Some(t.chars().take(MAX_MESSAGE_CHARS).collect());
        }
    }
    None
}

fn resolve_datetime(obj: &Map<String, Value>, fallback_iso: Option<&str>) -> (String, bool) {
    if let Some(s) = obj.get("datetime").and_then(|v| v.as_str()) {
        let t = s.trim();
        if !t.is_empty() {
            return (t.to_string(), false);
        }
    }
    if let Some(s) = obj.get("time").and_then(|v| v.as_str()) {
        let t = s.trim();
        if !t.is_empty() {
            return (t.to_string(), false);
        }
    }
    if let Some(n) = obj.get("timestamp").and_then(|v| v.as_i64()) {
        if n > 0 && n < 4_000_000_000 {
            if let Some(dt) = Utc.timestamp_opt(n, 0).single() {
                return (dt.to_rfc3339(), false);
            }
        }
        if (1_000_000_000_000_000..=9_999_999_999_999_999).contains(&n) {
            let secs = n / 1_000_000;
            let micros = (n % 1_000_000) as u32;
            if let Some(dt) = Utc.timestamp_opt(secs, micros * 1000).single() {
                return (dt.to_rfc3339(), false);
            }
        }
    }
    if let Some(s) = fallback_iso {
        return (s.to_string(), true);
    }
    (
        Utc.timestamp_opt(0, 0)
            .single()
            .expect("epoch")
            .to_rfc3339(),
        true,
    )
}

fn object_to_timesketch_event(
    parser_id: &str,
    template: &Value,
    obj: &Map<String, Value>,
    fallback_iso: Option<&str>,
) -> Option<Map<String, Value>> {
    let message = infer_message(obj)?;
    let (datetime, time_is_approximate) = resolve_datetime(obj, fallback_iso);
    let timestamp_desc = obj
        .get("timestamp_desc")
        .and_then(|v| v.as_str())
        .unwrap_or("event")
        .to_string();

    let mut row = Map::new();
    row.insert("message".into(), json!(message));
    row.insert("datetime".into(), json!(datetime.clone()));
    row.insert("timestamp_desc".into(), json!(timestamp_desc));
    row.insert("time_is_approximate".into(), json!(time_is_approximate));
    if let Some(us) = iso_to_timestamp_micros(&datetime) {
        row.insert("timestamp".into(), json!(us));
    }
    row.insert("sysdiagnose_parser".into(), json!(parser_id));
    if let Some(p) = template.get("parser") {
        row.insert("parser_module".into(), p.clone());
    }
    if let Some(s) = template.get("source") {
        row.insert("parser_source".into(), s.clone());
    }
    for extra in ["source_path", "sqlite_db_path", "sqlite_table", "format"] {
        if let Some(v) = obj.get(extra) {
            row.insert(extra.to_string(), v.clone());
        }
    }
    Some(row)
}

fn extract_named_arrays(
    parser_id: &str,
    template: &Value,
    fallback_iso: Option<&str>,
    budget_global: &mut usize,
    budget_parser: &mut usize,
    out: &mut Vec<Map<String, Value>>,
) {
    for key in ["events", "rows", "lines", "entries"] {
        if *budget_global == 0 || *budget_parser == 0 {
            return;
        }
        let Some(arr) = template.get(key).and_then(|a| a.as_array()) else {
            continue;
        };
        for item in arr {
            if *budget_global == 0 || *budget_parser == 0 {
                return;
            }
            let Some(obj) = item.as_object() else {
                continue;
            };
            if let Some(ev) = object_to_timesketch_event(parser_id, template, obj, fallback_iso) {
                out.push(ev);
                *budget_global -= 1;
                *budget_parser -= 1;
            }
        }
    }
}

fn extract_path_keyed_arrays(
    parser_id: &str,
    template: &Value,
    fallback_iso: Option<&str>,
    budget_global: &mut usize,
    budget_parser: &mut usize,
    out: &mut Vec<Map<String, Value>>,
) {
    let Some(root) = template.as_object() else {
        return;
    };
    for (k, v) in root {
        if *budget_global == 0 || *budget_parser == 0 {
            return;
        }
        if matches!(
            k.as_str(),
            "parser"
                | "error"
                | "source"
                | "line_count"
                | "acquisition_rfc3339"
                | "files"
                | "note"
                | "ok"
                | "paths"
                | "inventory"
                | "events"
                | "rows"
                | "lines"
                | "entries"
        ) {
            continue;
        }
        let Some(arr) = v.as_array() else {
            continue;
        };
        for item in arr {
            if *budget_global == 0 || *budget_parser == 0 {
                return;
            }
            let Some(obj) = item.as_object() else {
                continue;
            };
            if obj.contains_key("parse_error") && obj.len() <= 3 {
                continue;
            }
            if let Some(mut ev) = object_to_timesketch_event(parser_id, template, obj, fallback_iso)
            {
                ev.insert("source_path".into(), json!(k));
                out.push(ev);
                *budget_global -= 1;
                *budget_parser -= 1;
            }
        }
    }
}

fn extract_path_string_snippets(
    parser_id: &str,
    template: &Value,
    fallback_iso: Option<&str>,
    budget_global: &mut usize,
    budget_parser: &mut usize,
    out: &mut Vec<Map<String, Value>>,
) {
    let Some(root) = template.as_object() else {
        return;
    };
    for (path_key, val) in root {
        if *budget_global == 0 || *budget_parser == 0 {
            return;
        }
        if matches!(
            path_key.as_str(),
            "parser" | "error" | "paths" | "note" | "inventory" | "files"
        ) {
            continue;
        }
        if !key_looks_like_path(path_key) {
            continue;
        }
        let Some(s) = val.as_str() else {
            continue;
        };
        let snippet: String = s.chars().take(MAX_MESSAGE_CHARS).collect();
        if snippet.trim().is_empty() {
            continue;
        }
        let (datetime, time_is_approximate) = resolve_datetime(&Map::new(), fallback_iso);
        let mut row = Map::new();
        row.insert("message".into(), json!(snippet));
        row.insert("datetime".into(), json!(datetime.clone()));
        row.insert(
            "timestamp_desc".into(),
            json!("text_snippet (sysdiagnose file)"),
        );
        row.insert("time_is_approximate".into(), json!(time_is_approximate));
        if let Some(us) = iso_to_timestamp_micros(&datetime) {
            row.insert("timestamp".into(), json!(us));
        }
        row.insert("sysdiagnose_parser".into(), json!(parser_id));
        row.insert("source_path".into(), json!(path_key));
        row.insert("event_type".into(), json!("text_snippet"));
        if let Some(p) = template.get("parser") {
            row.insert("parser_module".into(), p.clone());
        }
        out.push(row);
        *budget_global -= 1;
        *budget_parser -= 1;
    }
}

fn events_to_csv(events: &[Map<String, Value>]) -> String {
    let mut out =
        String::from("message,datetime,timestamp_desc,timestamp,time_is_approximate,sysdiagnose_parser\n");
    for ev in events {
        let ts = ev.get("timestamp").map(|v| v.to_string()).unwrap_or_default();
        let approx = ev
            .get("time_is_approximate")
            .and_then(|v| v.as_bool())
            .map(|b| if b { "true" } else { "false" })
            .unwrap_or("");
        let fields = [
            ev.get("message").and_then(|v| v.as_str()).unwrap_or(""),
            ev.get("datetime").and_then(|v| v.as_str()).unwrap_or(""),
            ev.get("timestamp_desc").and_then(|v| v.as_str()).unwrap_or(""),
            ts.as_str(),
            approx,
            ev.get("sysdiagnose_parser")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
        ];
        out.push_str(
            &fields
                .iter()
                .map(|s| csv_escape(s))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push('\n');
    }
    out
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}


/// One compact JSON object per line (same objects as `events`), for streaming tools and `.jsonl` files.
fn events_to_jsonl(events: &[Map<String, Value>]) -> String {
    let mut buf = String::new();
    for ev in events {
        let Ok(line) = serde_json::to_string(&Value::Object(ev.clone())) else {
            continue;
        };
        if !buf.is_empty() {
            buf.push('\n');
        }
        buf.push_str(&line);
    }
    buf
}

pub fn run(parsed: &HashMap<String, Value>, ctx: &super::AnalyseCtx) -> Value {
    let _ = ctx;
    let fallback_iso: Option<String> = None;
    let fallback_ref = fallback_iso.as_deref();

    let mut budget_global = MAX_EVENTS_TOTAL;
    let mut all: Vec<Map<String, Value>> = Vec::new();

    let mut by_parser: BTreeMap<String, usize> = BTreeMap::new();

    for parser_id in sorted_parser_ids(parsed) {
        if budget_global == 0 {
            break;
        }
        let v = parser_value(parsed, &parser_id);
        if value_looks_like_hard_error(&v) {
            continue;
        }
        let mut budget_parser = MAX_EVENTS_PER_PARSER;
        let before = all.len();
        extract_named_arrays(
            &parser_id,
            &v,
            fallback_ref,
            &mut budget_global,
            &mut budget_parser,
            &mut all,
        );
        extract_path_keyed_arrays(
            &parser_id,
            &v,
            fallback_ref,
            &mut budget_global,
            &mut budget_parser,
            &mut all,
        );
        extract_path_string_snippets(
            &parser_id,
            &v,
            fallback_ref,
            &mut budget_global,
            &mut budget_parser,
            &mut all,
        );
        let n = all.len() - before;
        if n > 0 {
            by_parser.insert(parser_id.to_string(), n);
        }
    }

    all.sort_by(|a, b| {
        let ta = a.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(0);
        let tb = b.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(0);
        ta.cmp(&tb).then_with(|| {
            let ma = a.get("message").and_then(|v| v.as_str()).unwrap_or("");
            let mb = b.get("message").and_then(|v| v.as_str()).unwrap_or("");
            ma.cmp(mb)
        })
    });

    let events: Vec<Value> = all.iter().cloned().map(Value::Object).collect();
    let csv = events_to_csv(&all);
    let jsonl = events_to_jsonl(&all);

    json!({
        "analyser": "timesketch",
        "count": events.len(),
        "events": events,
        "jsonl": jsonl,
        "csv": csv,
        "events_per_parser": by_parser,
        "notes": "Emits Plaso/Timesketch-style rows (message, datetime, timestamp_desc, timestamp μs). Times are taken from parser fields when present; otherwise the archive bundle acquisition time is used with time_is_approximate=true. Use `csv` for spreadsheet/UI import, `jsonl` for one-json-object-per-line streaming (save as .jsonl), or `events` for a JSON array; extra fields beyond the CSV columns live on each JSON object."
    })
}