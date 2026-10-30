// SPDX-License-Identifier: GPL-3.0-only

//! MobileLockdown host pairing / trust / session history.

use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};

use super::common::parser_value;

fn pairing_related(event_type: &str, message: &str) -> bool {
    let blob = format!("{event_type} {message}").to_ascii_lowercase();
    ["pair", "trust", "session", "host", "wifi", "mux", "bonjour", "receive"]
        .iter()
        .any(|k| blob.contains(k))
}

pub fn run(parsed: &HashMap<String, Value>) -> Value {
    let ld = parser_value(parsed, "lockdownd");
    let mut events = Vec::new();
    let mut by_event_type: BTreeMap<String, usize> = BTreeMap::new();
    let mut pairing_hints = Vec::new();

    if let Some(arr) = ld.get("events").and_then(|e| e.as_array()) {
        for ev in arr.iter().take(5000) {
            let data = ev.get("data").cloned().unwrap_or(Value::Null);
            let event_type = data
                .get("event_type")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let message = ev
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("")
                .to_string();
            if !event_type.is_empty() {
                *by_event_type.entry(event_type.clone()).or_insert(0) += 1;
            }
            let related = pairing_related(&event_type, &message);
            let row = json!({
                "datetime": ev.get("datetime"),
                "message": message.chars().take(300).collect::<String>(),
                "event_type": event_type,
                "pid": data.get("pid"),
                "pairing_related": related,
            });
            if related && pairing_hints.len() < 200 {
                pairing_hints.push(row.clone());
            }
            if events.len() < 1000 {
                events.push(row);
            }
        }
    }

    let counts = json!({
        "events": events.len(),
        "pairing_hints": pairing_hints.len(),
        "event_types": by_event_type.len(),
    });
    json!({
        "analyser": "lockdown_pairing",
        "events": events,
        "pairing_hints": pairing_hints,
        "by_event_type": by_event_type,
        "counts": counts,
        "notes": "lockdownd log events with pairing/trust/session heuristics (not Lockdown Mode)."
    })
}
