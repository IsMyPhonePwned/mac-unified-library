// SPDX-License-Identifier: GPL-3.0-only

//! iCloud Circles / CKKS–PCS / personas / transparency trust view.

use serde_json::{json, Value};
use std::collections::HashMap;

use super::common::{parser_value, unwrap_parser};

fn snippet_lines(text: &str, needles: &[&str], cap: usize) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if needles.iter().any(|n| lower.contains(n)) {
            out.push(line.chars().take(240).collect());
            if out.len() >= cap {
                break;
            }
        }
    }
    out
}

pub fn run(parsed: &HashMap<String, Value>) -> Value {
    let mut ckks_snippets = Vec::new();
    let ckks = parser_value(parsed, "ckks_pcs");
    if let Some(files) = ckks.get("files").and_then(|f| f.as_object()) {
        for (path, val) in files {
            if let Some(text) = val.as_str() {
                for line in snippet_lines(text, &["circle", "trust", "octagon", "error", "locked", "pcs"], 40)
                {
                    ckks_snippets.push(json!({ "path": path, "line": line }));
                }
            }
        }
    }

    let mut um_snippets = Vec::new();
    let um = parser_value(parsed, "usermanagement");
    if let Some(files) = um.get("files").and_then(|f| f.as_object()) {
        for (path, val) in files {
            if let Some(text) = val.as_str() {
                for line in snippet_lines(text, &["persona", "user", "account", "uid", "gid"], 40) {
                    um_snippets.push(json!({ "path": path, "line": line }));
                }
            }
        }
    }

    let mut circles_hints = Vec::new();
    let sec = parser_value(parsed, "security_sysdiagnose");
    if let Some(events) = sec.get("events").and_then(|e| e.as_array()) {
        for ev in events.iter().take(5000) {
            let msg = ev.get("message").and_then(|m| m.as_str()).unwrap_or("");
            let lower = msg.to_ascii_lowercase();
            if lower.contains("circle")
                || lower.contains("sos")
                || lower.contains("ckks")
                || lower.contains("pcs")
                || lower.contains("octagon")
            {
                circles_hints.push(json!({
                    "datetime": ev.get("datetime"),
                    "message": msg.chars().take(300).collect::<String>(),
                }));
                if circles_hints.len() >= 100 {
                    break;
                }
            }
        }
    }

    let mut linked_devices = Vec::new();
    let mut contacts = Vec::new();
    if let Some(trans) = unwrap_parser(parsed, "transparency_json") {
        if let Some(devs) = trans
            .pointer("/data/linked_devices")
            .or_else(|| trans.get("linked_devices"))
            .and_then(|v| v.as_array())
        {
            linked_devices = devs.iter().take(100).cloned().collect();
        } else if let Some(obj) = trans.as_object() {
            // walk for device-like maps
            for (k, v) in obj {
                if k.to_ascii_lowercase().contains("device") {
                    linked_devices.push(json!({ "key": k, "value": v }));
                }
                if k.to_ascii_lowercase().contains("contact") {
                    contacts.push(json!({ "key": k, "value": v }));
                }
            }
        }
    }

    let counts = json!({
        "ckks_snippets": ckks_snippets.len(),
        "um_snippets": um_snippets.len(),
        "circles_hints": circles_hints.len(),
        "linked_devices": linked_devices.len(),
    });
    json!({
        "analyser": "account_trust",
        "ckks_snippets": ckks_snippets,
        "um_snippets": um_snippets,
        "circles_hints": circles_hints,
        "linked_devices": linked_devices,
        "contacts": contacts,
        "counts": counts,
        "notes": "CKKS/PCS + usermanagement + Circles/SOS hints + transparency devices (beyond accounts emails)."
    })
}
