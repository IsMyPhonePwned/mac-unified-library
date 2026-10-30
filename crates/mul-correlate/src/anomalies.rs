// SPDX-License-Identifier: GPL-3.0-only

use crate::overview::Finding;
use crate::store::Store;
use mul_core::event::EventKind;
use mul_core::Val;

pub fn find(store: &Store) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut crash_by_proc: hashbrown::HashMap<String, u64> = hashbrown::HashMap::new();

    for e in &store.events {
        if matches!(e.kind, EventKind::Crash) {
            let key = e
                .message
                .as_str()
                .split_whitespace()
                .next()
                .unwrap_or("unknown")
                .to_string();
            *crash_by_proc.entry(key).or_default() += 1;
        }
        for (_, v) in &e.attrs {
            if let Val::Text(s) = v {
                let s = s.as_ref();
                if s.starts_with("/var/tmp/")
                    || s.starts_with("/private/tmp/")
                    || s.contains("/Containers/Data/Application/") && s.contains("../")
                {
                    out.push(Finding {
                        severity: "medium".into(),
                        rule_id: "path_suspicious".into(),
                        explanation: format!("suspicious path in evidence: {s}"),
                        evidence: vec![e.evidence.path.clone()],
                    });
                }
            }
        }
    }

    for (proc, n) in crash_by_proc {
        if n >= 5 {
            out.push(Finding {
                severity: "high".into(),
                rule_id: "crash_burst".into(),
                explanation: format!("process {proc} crashed {n} times in this collection"),
                evidence: vec![proc],
            });
        }
    }

    out.truncate(100);
    out
}
