// SPDX-License-Identifier: GPL-3.0-only

use crate::overview::Finding;
use crate::store::Store;
use mul_core::Val;
use serde_json::Value;
use std::fs;
use std::path::Path;

#[derive(Debug, Default)]
pub struct IocSet {
    pub domains: Vec<String>,
    pub processes: Vec<String>,
    pub paths: Vec<String>,
    pub bundle_ids: Vec<String>,
    pub emails: Vec<String>,
}

impl IocSet {
    pub fn load_file(path: &Path) -> std::io::Result<Self> {
        let text = fs::read_to_string(path)?;
        Ok(Self::from_json_str(&text))
    }

    pub fn from_json_str(text: &str) -> Self {
        let mut set = IocSet::default();
        let Ok(v) = serde_json::from_str::<Value>(text) else {
            // plain lines
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if line.contains('@') {
                    set.emails.push(line.to_string());
                } else if line.contains('.') && !line.starts_with('/') {
                    set.domains.push(line.to_string());
                } else if line.starts_with('/') {
                    set.paths.push(line.to_string());
                } else {
                    set.processes.push(line.to_string());
                }
            }
            return set;
        };
        // STIX-ish / MVT-ish: walk for type/value
        walk_json(&v, &mut set);
        set
    }

    pub fn match_store(&self, store: &Store) -> Vec<Finding> {
        let mut findings = Vec::new();
        for e in &store.events {
            let msg = e.message.as_str();
            let mut haystacks = vec![msg.to_string()];
            for (_, v) in &e.attrs {
                if let Val::Text(s) = v {
                    haystacks.push(s.to_string());
                }
            }
            for h in &haystacks {
                for d in &self.domains {
                    if h.contains(d) {
                        findings.push(hit("ioc_domain", d, &e.evidence.path));
                    }
                }
                for p in &self.processes {
                    if h.contains(p) {
                        findings.push(hit("ioc_process", p, &e.evidence.path));
                    }
                }
                for p in &self.paths {
                    if h.contains(p) {
                        findings.push(hit("ioc_path", p, &e.evidence.path));
                    }
                }
                for b in &self.bundle_ids {
                    if h.contains(b) {
                        findings.push(hit("ioc_bundle", b, &e.evidence.path));
                    }
                }
                for em in &self.emails {
                    if h.contains(em) {
                        findings.push(hit("ioc_email", em, &e.evidence.path));
                    }
                }
            }
        }
        findings.truncate(500);
        findings
    }
}

fn hit(rule: &str, indicator: &str, evidence: &str) -> Finding {
    Finding {
        severity: "high".into(),
        rule_id: rule.into(),
        explanation: format!("matched indicator {indicator}"),
        evidence: vec![evidence.to_string(), indicator.to_string()],
    }
}

fn walk_json(v: &Value, set: &mut IocSet) {
    match v {
        Value::Object(m) => {
            let ty = m.get("type").and_then(|t| t.as_str()).unwrap_or("");
            let val = m
                .get("value")
                .or_else(|| m.get("pattern"))
                .and_then(|x| x.as_str());
            if let Some(val) = val {
                match ty {
                    "domain-name" | "domain" => set.domains.push(val.into()),
                    "file" | "path" => set.paths.push(val.into()),
                    "process" => set.processes.push(val.into()),
                    "bundle-id" | "bundleid" => set.bundle_ids.push(val.into()),
                    "email-addr" | "email" => set.emails.push(val.into()),
                    _ => {}
                }
            }
            for (_k, child) in m {
                walk_json(child, set);
            }
        }
        Value::Array(a) => {
            for child in a {
                walk_json(child, set);
            }
        }
        _ => {}
    }
}
