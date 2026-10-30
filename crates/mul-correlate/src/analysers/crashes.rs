// SPDX-License-Identifier: GPL-3.0-only

//! Per-app IPS crash corpus rollup.

use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};

use super::common::parser_value;

pub fn run(parsed: &HashMap<String, Value>) -> Value {
    let crash = parser_value(parsed, "crashlogs");
    let mut by_app: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
    let mut recent = Vec::new();
    let mut summary_lines = 0usize;
    let mut total = 0usize;

    if let Some(arr) = crash.get("events").and_then(|e| e.as_array()) {
        for ev in arr {
            let data = ev.get("data").cloned().unwrap_or(Value::Null);
            if data.get("format").and_then(|f| f.as_str()) == Some("summary_text") {
                summary_lines += 1;
                continue;
            }
            total += 1;
            let app = data
                .get("app_name")
                .or_else(|| data.get("procName"))
                .or_else(|| data.get("bundleID"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let entry = by_app.entry(app.clone()).or_insert_with(|| {
                let mut m = Map::new();
                m.insert("app".into(), json!(app.clone()));
                m.insert("count".into(), json!(0));
                m.insert("paths".into(), json!([]));
                m.insert("exceptions".into(), json!([]));
                m
            });
            if let Some(c) = entry.get("count").and_then(|v| v.as_u64()) {
                entry.insert("count".into(), json!(c + 1));
            }
            if let Some(path) = data.get("path").or_else(|| data.get("filename")) {
                if let Some(Value::Array(a)) = entry.get_mut("paths") {
                    if a.len() < 8 && !a.contains(path) {
                        a.push(path.clone());
                    }
                }
            }
            if let Some(ex) = data
                .get("exception")
                .or_else(|| data.get("exceptionType"))
                .or_else(|| data.get("signal"))
            {
                if let Some(Value::Array(a)) = entry.get_mut("exceptions") {
                    if a.len() < 8 && !a.contains(ex) {
                        a.push(ex.clone());
                    }
                }
            }
            if recent.len() < 50 {
                recent.push(json!({
                    "datetime": ev.get("datetime").or_else(|| data.get("timestamp")),
                    "app": app,
                    "message": ev.get("message"),
                    "path": data.get("path"),
                    "exception": data.get("exception").or_else(|| data.get("exceptionType")),
                }));
            }
        }
    }

    let by_app_json: BTreeMap<String, Value> = by_app
        .into_iter()
        .map(|(k, v)| (k, Value::Object(v)))
        .collect();

    json!({
        "analyser": "crashes",
        "by_app": by_app_json,
        "recent": recent,
        "total": total,
        "summary_lines": summary_lines,
        "notes": "IPS crash reports grouped by app/process; summary_text lines counted separately."
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_by_app() {
        let mut parsed = HashMap::new();
        parsed.insert(
            "crashlogs".into(),
            json!({
                "events": [
                    {"message": "crash Foo", "data": {"app_name": "Foo", "path": "a.ips", "exception": "EXC_BAD_ACCESS"}},
                    {"message": "crash Foo", "data": {"app_name": "Foo", "path": "b.ips"}},
                ]
            }),
        );
        let v = run(&parsed);
        assert_eq!(v["total"], 2);
        assert_eq!(v["by_app"]["Foo"]["count"], 2);
    }
}
