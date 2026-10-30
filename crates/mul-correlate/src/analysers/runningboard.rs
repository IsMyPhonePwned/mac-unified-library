// SPDX-License-Identifier: GPL-3.0-only

//! RunningBoard domains / assertions / keep-alive grants.

use regex::Regex;
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};
use std::sync::OnceLock;

use super::common::parser_value;

fn scrape_text(text: &str, domains: &mut BTreeSet<String>, assertions: &mut BTreeSet<String>, grants: &mut BTreeSet<String>) -> usize {
    static DOMAIN_RE: OnceLock<Regex> = OnceLock::new();
    static NAME_RE: OnceLock<Regex> = OnceLock::new();
    static GRANT_RE: OnceLock<Regex> = OnceLock::new();
    let domain_re = DOMAIN_RE.get_or_init(|| Regex::new(r"domain:([A-Za-z0-9._-]+)").unwrap());
    let name_re = NAME_RE.get_or_init(|| Regex::new(r"\bname:([A-Za-z0-9._-]+)").unwrap());
    let grant_re = GRANT_RE.get_or_init(|| Regex::new(r"\b(RBS[A-Za-z0-9]+Grant)\b").unwrap());
    let mut prevent_idle = 0usize;
    for cap in domain_re.captures_iter(text) {
        domains.insert(cap[1].to_string());
    }
    for cap in name_re.captures_iter(text) {
        assertions.insert(cap[1].to_string());
    }
    for cap in grant_re.captures_iter(text) {
        let g = cap[1].to_string();
        if g.contains("PreventIdleSleep") {
            prevent_idle += 1;
        }
        grants.insert(g);
    }
    prevent_idle
}

pub fn run(parsed: &HashMap<String, Value>) -> Value {
    let rb = parser_value(parsed, "runningboard");
    let mut domains: BTreeSet<String> = BTreeSet::new();
    let mut assertions: BTreeSet<String> = BTreeSet::new();
    let mut grants: BTreeSet<String> = BTreeSet::new();
    let mut prevent_idle = 0usize;

    if let Some(arr) = rb.get("domains").and_then(|d| d.as_array()) {
        for d in arr {
            if let Some(s) = d.as_str() {
                domains.insert(s.to_string());
            }
        }
    }
    if let Some(arr) = rb.get("assertions").and_then(|d| d.as_array()) {
        for d in arr {
            if let Some(s) = d.as_str() {
                assertions.insert(s.to_string());
            }
        }
    }
    if let Some(arr) = rb.get("grants").and_then(|d| d.as_array()) {
        for d in arr {
            if let Some(s) = d.as_str() {
                grants.insert(s.to_string());
            }
        }
    }
    if let Some(n) = rb.get("prevent_idle_sleep_mentions").and_then(|v| v.as_u64()) {
        prevent_idle = n as usize;
    }

    if domains.is_empty() {
        if let Some(files) = rb.get("files").and_then(|f| f.as_object()) {
            for (_path, val) in files {
                if let Some(text) = val.as_str() {
                    prevent_idle += scrape_text(text, &mut domains, &mut assertions, &mut grants);
                }
            }
        }
    }

    let keep_alive: Vec<_> = grants
        .iter()
        .filter(|g| {
            g.contains("PreventIdleSleep")
                || g.contains("CPUAccess")
                || g.contains("RunningReason")
        })
        .cloned()
        .collect();

    let counts = json!({
        "domains": domains.len(),
        "assertions": assertions.len(),
        "grants": grants.len(),
    });
    json!({
        "analyser": "runningboard",
        "domains": domains.into_iter().collect::<Vec<_>>(),
        "assertions": assertions.into_iter().collect::<Vec<_>>(),
        "grants": grants.into_iter().collect::<Vec<_>>(),
        "keep_alive_grants": keep_alive,
        "prevent_idle_sleep_mentions": prevent_idle,
        "counts": counts,
        "notes": "RunningBoard domain/assertion/grant inventory (background keep-alive signal)."
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrapes_domain_from_files() {
        let mut parsed = HashMap::new();
        parsed.insert(
            "runningboard".into(),
            json!({
                "files": {
                    "RunningBoard/RunningBoard_state.log":
                        "domain:com.example.app name:Foreground RBSPreventIdleSleepGrant"
                }
            }),
        );
        let v = run(&parsed);
        assert!(v["domains"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d == "com.example.app"));
        assert!(v["prevent_idle_sleep_mentions"].as_u64().unwrap() >= 1);
    }
}
