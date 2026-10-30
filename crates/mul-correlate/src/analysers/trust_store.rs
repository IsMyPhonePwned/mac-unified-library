// SPDX-License-Identifier: GPL-3.0-only

//! Trust / MITM / pinning / certificate signals from security-sysdiagnose + plists.

use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};

use super::common::{parser_value, plist_top_keys, unwrap_parser};

fn interesting(msg: &str) -> bool {
    let l = msg.to_ascii_lowercase();
    l.contains("trust")
        || l.contains("mitm")
        || l.contains("pinning")
        || l.contains("certificate")
        || l.contains("tls")
        || l.contains("anchor")
        || l.contains("issuer")
}

pub fn run(parsed: &HashMap<String, Value>) -> Value {
    let sec = parser_value(parsed, "security_sysdiagnose");
    let mut trust_events = Vec::new();
    let mut issuers = BTreeSet::new();
    let mut hostnames = BTreeSet::new();
    let mut mitm_scores = Vec::new();

    if let Some(events) = sec.get("events").and_then(|e| e.as_array()) {
        for ev in events {
            let msg = ev.get("message").and_then(|m| m.as_str()).unwrap_or("");
            let data = ev.get("data").cloned().unwrap_or(Value::Null);
            let data_s = data.to_string();
            if !(interesting(msg) || interesting(&data_s)) {
                continue;
            }
            if let Some(iss) = data.get("IssuerName").and_then(|v| v.as_str()) {
                issuers.insert(iss.to_string());
            }
            // IssuerName sometimes embedded in message Attributes blob
            if let Some(idx) = msg.find("IssuerName") {
                if let Some(rest) = msg[idx..].split(':').nth(1) {
                    let name = rest
                        .trim()
                        .trim_matches(|c| c == '{' || c == '}' || c == ',')
                        .trim();
                    if !name.is_empty() && name.len() < 200 {
                        issuers.insert(name.to_string());
                    }
                }
            }
            if let Some(h) = data.get("Hostname").and_then(|v| v.as_str()) {
                hostnames.insert(h.to_string());
            }
            if msg.contains("Hostname") {
                if let Some(rest) = msg.split("Hostname").nth(1) {
                    let h = rest
                        .trim_start_matches(|c: char| !c.is_alphanumeric())
                        .split([',', ' ', '}'])
                        .next()
                        .unwrap_or("")
                        .trim();
                    if h.contains('.') {
                        hostnames.insert(h.to_string());
                    }
                }
            }
            if msg.contains("overallScore") || data_s.contains("overallScore") {
                mitm_scores.push(json!({
                    "datetime": ev.get("datetime"),
                    "message": msg.chars().take(300).collect::<String>(),
                }));
            }
            if trust_events.len() < 200 {
                trust_events.push(json!({
                    "datetime": ev.get("datetime"),
                    "message": msg.chars().take(400).collect::<String>(),
                    "section": data.get("section"),
                }));
            }
        }
    }

    let mut trust_plists = Vec::new();
    if let Some(files) = unwrap_parser(parsed, "plists")
        .and_then(|p| p.get("files"))
        .and_then(|f| f.as_object())
    {
        for (path, val) in files {
            let pl = path.to_ascii_lowercase();
            if !(pl.contains("trust") || pl.contains("certificate") || pl.contains("cert")) {
                continue;
            }
            trust_plists.push(json!({
                "path": path,
                "keys": plist_top_keys(val),
            }));
        }
    }

    let issuer_list: Vec<_> = issuers.into_iter().collect();
    let hostname_list: Vec<_> = hostnames.into_iter().collect();
    let counts = json!({
        "trust_events": trust_events.len(),
        "issuers": issuer_list.len(),
        "hostnames": hostname_list.len(),
        "mitm_scores": mitm_scores.len(),
    });
    json!({
        "analyser": "trust_store",
        "trust_events": trust_events,
        "issuers": issuer_list,
        "hostnames": hostname_list,
        "mitm_scores": mitm_scores,
        "trust_plists": trust_plists,
        "counts": counts,
        "notes": "Heuristic trust/MITM/pinning extract from security-sysdiagnose (+ trust-related plists)."
    })
}
