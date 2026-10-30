// SPDX-License-Identifier: GPL-3.0-only

//! LaunchServices QuarantineEvents timeline.

use serde_json::{json, Value};
use std::collections::HashMap;

use super::common::parser_value;

fn data_get<'a>(data: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    for k in keys {
        if let Some(v) = data.get(*k) {
            if !v.is_null() {
                return Some(v);
            }
        }
    }
    None
}

pub fn run(parsed: &HashMap<String, Value>) -> Value {
    let q = parser_value(parsed, "quarantine_events");
    let mut events = Vec::new();
    if let Some(arr) = q.get("events").and_then(|e| e.as_array()) {
        for ev in arr.iter().take(2000) {
            let data = ev.get("data").cloned().unwrap_or(Value::Null);
            events.push(json!({
                "datetime": ev.get("datetime"),
                "message": ev.get("message"),
                "agent": data_get(&data, &["LSQuarantineAgentName", "AgentName", "agent"]),
                "data_url": data_get(&data, &["LSQuarantineDataURLString", "DataURL", "data_url"]),
                "origin_url": data_get(&data, &["LSQuarantineOriginURLString", "OriginURL", "origin_url"]),
                "sender": data_get(&data, &["LSQuarantineSenderName", "SenderName"]),
                "path": data_get(&data, &["path", "Path", "LSQuarantinePath"]),
                "bundle_id": data_get(&data, &["bundle_id", "BundleID", "LSQuarantineAgentBundleIdentifier"]),
            }));
        }
    }
    let count = events.len();
    json!({
        "analyser": "quarantine",
        "events": events,
        "count": count,
        "notes": "LaunchServices QuarantineEventsV2 rows (download / Gatekeeper provenance)."
    })
}
