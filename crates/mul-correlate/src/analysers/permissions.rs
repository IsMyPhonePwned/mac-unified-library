// SPDX-License-Identifier: GPL-3.0-only

//! TCC (privacy) permissions rollup per app bundle id from `accessibility_tcc`.
//!
//! Handles modern `auth_value` integers, Apollo event rows, and human-readable
//! service labels / sensitive flags ([`crate::tcc_labels`]).

use serde_json::{json, Map, Value};
use std::collections::HashMap;

use super::common::{for_each_sqlite_row, parser_value, value_looks_like_hard_error};
use crate::tcc_labels::{allowed_from_auth_value, enrich_permission_value};

fn field_str(data: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(s) = data.get(*k).and_then(|v| v.as_str()) {
            let t = s.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    None
}

fn resolve_allowed(data: &Map<String, Value>) -> Option<String> {
    if let Some(s) = field_str(data, &["allowed", "ALLOWED"]) {
        if let Some(mapped) = allowed_from_auth_value(&json!(s)) {
            return Some(mapped);
        }
        return Some(s);
    }
    for k in ["auth_value", "auth value", "AUTH_VALUE", "authValue"] {
        if let Some(v) = data.get(k) {
            if let Some(mapped) = allowed_from_auth_value(v) {
                return Some(mapped);
            }
        }
    }
    None
}

fn push_perm(apps: &mut Map<String, Value>, client: String, mut perm: Value) {
    enrich_permission_value(&mut perm);
    match apps.get_mut(&client) {
        Some(Value::Object(app)) => {
            if let Some(arr) = app.get_mut("permissions").and_then(|p| p.as_array_mut()) {
                arr.push(perm);
            }
        }
        _ => {
            let mut app = Map::new();
            app.insert("permissions".into(), json!([perm]));
            apps.insert(client, Value::Object(app));
        }
    }
}

fn perm_from_row(data: &Map<String, Value>, datetime: Option<&Value>) -> Option<(String, Value)> {
    let client = field_str(data, &["client", "CLIENT"])?;
    let service = field_str(data, &["service", "SERVICE"]);
    let perm = json!({
        "service": service,
        "allowed": resolve_allowed(data),
        "last_modified": datetime.cloned().unwrap_or(Value::Null),
        "auth_reason": field_str(data, &["auth_reason", "auth reason", "AUTH REASON"]),
        "auth_value": data.get("auth_value").or_else(|| data.get("auth value")).cloned(),
        "client_type": field_str(data, &["client_type", "client type", "CLIENT TYPE"]),
        "indirect_object_identifier": field_str(data, &[
            "indirect_object_identifier",
            "indirect object identifier",
            "INDIRECT OBJECT IDENTIFIER",
        ]),
        "source_db": data.get("source_db").cloned().unwrap_or(Value::Null),
        "apollo_module": data.get("apollo_module").cloned().unwrap_or(Value::Null),
    });
    Some((client, perm))
}

pub fn run(parsed: &HashMap<String, Value>) -> Value {
    let tcc = parser_value(parsed, "accessibility_tcc");
    let mut apps: Map<String, Value> = Map::new();
    let mut from_events = 0usize;
    let mut from_sqlite = 0usize;

    if !value_looks_like_hard_error(&tcc) {
        if let Some(events) = tcc.get("events").and_then(|e| e.as_array()) {
            for ev in events {
                let Some(data) = ev.get("data").and_then(|d| d.as_object()) else {
                    continue;
                };
                if let Some((client, perm)) = perm_from_row(data, ev.get("datetime")) {
                    push_perm(&mut apps, client, perm);
                    from_events += 1;
                }
            }
        }

        // Also roll up sqlite-shaped dumps / nested tables when events are sparse.
        if from_events == 0 {
            for_each_sqlite_row(&tcc, |rm, sqlite_db, sqlite_table| {
                let mut data = rm.clone();
                if !data.contains_key("source_db") {
                    data.insert("source_db".into(), json!(sqlite_db));
                }
                if !data.contains_key("apollo_module") {
                    data.insert("apollo_module".into(), json!(sqlite_table));
                }
                if let Some((client, perm)) = perm_from_row(&data, data.get("datetime")) {
                    push_perm(&mut apps, client, perm);
                    from_sqlite += 1;
                }
            });
        }
    }

    let mut sensitive_grants = 0usize;
    for app in apps.values_mut() {
        if let Some(arr) = app.get_mut("permissions").and_then(|p| p.as_array_mut()) {
            arr.sort_by(|a, b| {
                let sa = a.get("service").and_then(|v| v.as_str()).unwrap_or("");
                let sb = b.get("service").and_then(|v| v.as_str()).unwrap_or("");
                sa.cmp(sb)
            });
            for p in arr.iter() {
                if p.get("sensitive").and_then(|v| v.as_bool()).unwrap_or(false)
                    && p
                        .get("allowed")
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| s.eq_ignore_ascii_case("ALLOWED"))
                {
                    sensitive_grants += 1;
                }
            }
        }
    }

    json!({
        "analyser": "permissions",
        "app_count": apps.len(),
        "apps": apps,
        "source_parser": "accessibility_tcc",
        "from_events": from_events,
        "from_sqlite_rows": from_sqlite,
        "sensitive_allowed_grants": sensitive_grants,
        "notes": "Rolls up APOLLO TCC.db rows (privacy services only — not full iOS Settings permissions). Maps modern auth_value→allowed, adds service_label/sensitive. Requires TCC.db in the archive.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn rolls_up_tcc_events_by_bundle_id() {
        let mut parsed = HashMap::new();
        parsed.insert(
            "accessibility_tcc".into(),
            json!({
                "parser": "accessibility_tcc",
                "format": "jsonl",
                "events": [
                    {
                        "datetime": "2023-11-14T22:13:20Z",
                        "data": {
                            "client": "com.example.cam",
                            "service": "kTCCServiceCamera",
                            "allowed": "ALLOWED",
                            "source_db": "logs/Accessibility/TCC.db",
                            "apollo_module": "tcc_db"
                        }
                    },
                    {
                        "datetime": "2023-11-14T22:14:00Z",
                        "data": {
                            "client": "com.example.cam",
                            "service": "kTCCServiceMicrophone",
                            "auth_value": 0,
                            "source_db": "logs/Accessibility/TCC.db",
                            "apollo_module": "tcc_db"
                        }
                    }
                ]
            }),
        );
        let v = run(&parsed);
        assert_eq!(v["app_count"], 1);
        let perms = v["apps"]["com.example.cam"]["permissions"]
            .as_array()
            .unwrap();
        assert_eq!(perms.len(), 2);
        assert_eq!(perms[0]["service"], "kTCCServiceCamera");
        assert_eq!(perms[0]["service_label"], "Camera");
        assert_eq!(perms[0]["sensitive"], true);
        assert_eq!(perms[1]["allowed"], "NOT ALLOWED");
    }
}
