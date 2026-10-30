// SPDX-License-Identifier: GPL-3.0-only

//! Markdown summary across device, transparency, plists, security, shutdown, and MCState stubs.

use std::collections::HashMap;
use serde_json::{json, Value};
use std::collections::BTreeSet;


use super::common::{
    device_props_from_remotectl, parser_value, lockdown_mode_from_effective_settings,
    mcstate_stub_summary_lines, owner_emails_from_mobilecal, walk_transparency_contact_uris,
    
};

/// `(needle, label)` — longer needles first so substrings do not double-count.
const SECURITY_KEYWORD_HINTS: &[(&str, &str)] = &[
    ("circle of trust", "circle of trust"),
    ("keychain", "keychain"),
    ("icloud keychain", "iCloud Keychain"),
    ("escrow", "escrow"),
    ("pairing", "pairing"),
    ("certificate", "certificate"),
    ("trust cache", "trust cache"),
    ("trust", "trust"),
    ("wifi", "Wi‑Fi"),
    ("bluetooth", "Bluetooth"),
    ("face id", "Face ID"),
    ("touch id", "Touch ID"),
    ("sos", "SOS"),
    ("backup", "backup"),
    ("find my", "Find My"),
    ("sealed", "sealed"),
    ("recovery", "recovery"),
    ("icdp", "ICDP"),
];

fn truncate_one_line(s: &str, max: usize) -> String {
    let t = s.trim().replace('\t', " ");
    if t.len() <= max {
        return t;
    }
    format!(
        "{}…",
        t.chars().take(max.saturating_sub(1)).collect::<String>()
    )
}

fn security_sysdiagnose_summary_lines(v: &Value) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let Some(obj) = v.as_object() else {
        lines.push("Parser output is not an object.".to_string());
        return lines;
    };

    if obj.get("parser").and_then(|p| p.as_str()) == Some("security_sysdiagnose")
        && obj.get("events").is_some()
    {
        let events = obj
            .get("events")
            .and_then(|e| e.as_array())
            .cloned()
            .unwrap_or_default();
        if events.is_empty() {
            lines.push(
                "No `security-sysdiagnose.txt` (or empty parse) in this archive.".to_string(),
            );
            return lines;
        }
        lines.push(
            "- **Source**: `security-sysdiagnose.txt` → jsonl `events` (`security_sysdiagnose` parser)."
                .to_string(),
        );
        lines.push(format!(
            "- **Events** — {} rows (`datetime`, `message`, `data`, …).",
            events.len()
        ));
        let mut sections = BTreeSet::new();
        let mut blob = String::new();
        for ev in &events {
            if let Some(m) = ev.get("message").and_then(|x| x.as_str()) {
                blob.push_str(m);
                blob.push('\n');
            }
            if let Some(s) = ev.pointer("/data/section").and_then(|x| x.as_str()) {
                sections.insert(s.to_string());
            }
        }
        let lower = blob.to_ascii_lowercase();
        let mut hints: Vec<String> = Vec::new();
        for (needle, label) in SECURITY_KEYWORD_HINTS {
            let c = lower.matches(needle).count();
            if c > 0 {
                hints.push(format!("{label} ({c}×)"));
            }
        }
        if !hints.is_empty() {
            lines.push(format!(
                "  - **Topic hints** (case-insensitive, message + `data`): {}",
                hints.join(", ")
            ));
        }
        if !sections.is_empty() {
            lines.push(format!(
                "  - **`data.section` values** (sample, up to 24): {}",
                sections
                    .iter()
                    .take(24)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        lines.push("  - **Sample messages** (first 8):".to_string());
        for ev in events.iter().take(8) {
            let m = ev
                .get("message")
                .and_then(|x| x.as_str())
                .unwrap_or("(no message)");
            lines.push(format!("    > {}", truncate_one_line(m, 120)));
        }
        lines.push(
            "Structured output matches upstream `security_sysdiagnose` jsonl (`events` + meta-derived rows)."
                .to_string(),
        );
        return lines;
    }

    if obj.is_empty() {
        lines.push("No `security-sysdiagnose.txt` (or matching path) in this archive.".to_string());
        return lines;
    }
    for (path, val) in obj {
        match val {
            Value::String(text) => {
                let nlines = text.lines().count();
                let lower = text.to_ascii_lowercase();
                lines.push(format!(
                    "- **{}** — {} characters, {} lines",
                    path,
                    text.len(),
                    nlines
                ));
                let mut hints: Vec<String> = Vec::new();
                for (needle, label) in SECURITY_KEYWORD_HINTS {
                    let c = lower.matches(needle).count();
                    if c > 0 {
                        hints.push(format!("{label} ({c}×)"));
                    }
                }
                if !hints.is_empty() {
                    lines.push(format!(
                        "  - **Topic hints** (case-insensitive counts): {}",
                        hints.join(", ")
                    ));
                }
                let mut titles = BTreeSet::new();
                for line in text.lines() {
                    let t = line.trim();
                    if (4..=120).contains(&t.len())
                        && t.ends_with(':')
                        && t.matches(':').count() == 1
                    {
                        titles.insert(truncate_one_line(t, 100));
                    }
                }
                if !titles.is_empty() {
                    lines.push("  - **Colon-style headings** (first 18 unique):".to_string());
                    for t in titles.iter().take(18) {
                        lines.push(format!("    - `{t}`"));
                    }
                }
                lines.push("  - **Lead-in** (first 12 non-empty lines):".to_string());
                let mut n = 0usize;
                for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
                    lines.push(format!("    > {}", truncate_one_line(line, 120)));
                    n += 1;
                    if n >= 12 {
                        break;
                    }
                }
            }
            Value::Object(meta) => {
                if meta.get("skipped_oversized").and_then(|x| x.as_bool()) == Some(true) {
                    let sz = meta.get("size").cloned().unwrap_or(json!(null));
                    lines.push(format!("- **{path}** — skipped (oversized): `size` = {sz}"));
                } else {
                    lines.push(format!("- **{path}** — (structured entry, not raw text)"));
                }
            }
            _ => {
                lines.push(format!("- **{path}** — (unexpected value type)"));
            }
        }
    }
    lines.push(
        "Parser shape: path → raw UTF‑8 string. Prefer the current parser `events` jsonl output for Sigma / timelines."
            .to_string(),
    );
    lines
}

fn shutdownlogs_summary_lines(v: &Value) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    if let Some(note) = v.get("note").and_then(|n| n.as_str()) {
        if v.get("events")
            .and_then(|e| e.as_array())
            .map(|a| a.is_empty())
            .unwrap_or(true)
        {
            lines.push(format!("- {note}"));
            return lines;
        }
    }
    let Some(events) = v.get("events").and_then(|e| e.as_array()) else {
        lines.push("Parser JSON has no `events` array.".to_string());
        return lines;
    };
    if events.is_empty() {
        lines.push("**0** shutdown client events (empty `events`).".to_string());
        return lines;
    }
    let with_dt = events
        .iter()
        .filter(|e| {
            e.get("datetime")
                .and_then(|x| x.as_str())
                .map(|s| !s.is_empty())
                == Some(true)
        })
        .count();
    lines.push(format!(
        "- **Events**: {} total; **with `datetime`**: {} (SIGTERM timestamp applied when parsed).",
        events.len(),
        with_dt
    ));
    let max_wait = events
        .iter()
        .filter_map(|e| e.pointer("/data/time_waiting").and_then(|x| x.as_f64()))
        .fold(0.0_f64, f64::max);
    lines.push(format!(
        "- **Largest `data.time_waiting` (s)** across events: {:.3}",
        max_wait
    ));
    let mut uuids: BTreeSet<String> = BTreeSet::new();
    for e in events {
        if let Some(u) = e.pointer("/data/uuid").and_then(|x| x.as_str()) {
            if !u.is_empty() {
                uuids.insert(u.to_string());
            }
        }
    }
    lines.push(format!(
        "- **Distinct `data.uuid` values** (container / app bundle ids seen): {}",
        uuids.len()
    ));
    lines.push(String::new());
    lines.push("| pid | command (parent path) | `datetime` | `time_waiting` (s) |".to_string());
    lines.push("| ---: | --- | --- | ---: |".to_string());
    for ev in events.iter().take(20) {
        let pid = ev
            .pointer("/data/pid")
            .map(|x| x.to_string())
            .unwrap_or_else(|| "—".to_string());
        let cmd = ev
            .pointer("/data/command")
            .and_then(|x| x.as_str())
            .map(|s| truncate_one_line(s, 56).replace('|', "/"))
            .unwrap_or_else(|| "—".to_string());
        let dt = ev
            .get("datetime")
            .and_then(|x| x.as_str())
            .map(|s| truncate_one_line(s, 80))
            .unwrap_or_else(|| "—".to_string());
        let tw = ev
            .pointer("/data/time_waiting")
            .and_then(|x| x.as_f64())
            .map(|f| format!("{f:.2}"))
            .unwrap_or_else(|| "—".to_string());
        lines.push(format!("| {pid} | {cmd} | {dt} | {tw} |"));
    }
    if events.len() > 20 {
        lines.push(format!(
            "\n_Table truncated at 20 rows; {} more in parser JSON._",
            events.len() - 20
        ));
    }
    lines.push(
        "\nEach event is built from `shutdown.log` blocks (*these clients are still here* / *remaining client pid*) and the SIGTERM line timestamp. See `shutdownlogs` parser for full `message` and `data`."
            .to_string(),
    );
    lines
}

pub fn run(parsed: &HashMap<String, Value>) -> Value {
    let mut lines: Vec<String> = Vec::new();
    lines.push("## Device".to_string());
    let dev = device_props_from_remotectl(parsed);
    if dev.is_null() {
        lines.push("No remotectl device block found.".to_string());
    } else {
        lines.push(format!(
            "```json\n{}\n```",
            serde_json::to_string_pretty(&dev).unwrap_or_default()
        ));
    }

    lines.push("\n## Lockdown / calendar (from capped plists)".to_string());
    let plists_sum = parser_value(parsed, "plists");
    if let Some(files) = plists_sum.get("files").and_then(|f| f.as_object()) {
        let mut saw = false;
        for (path, val) in files {
            if path.contains("EffectiveUserSettings") {
                if let Some(b) = lockdown_mode_from_effective_settings(val) {
                    lines.push(format!(
                        "- Lockdown mode (`allowLockdownMode`): {b} (`{path}`)"
                    ));
                    saw = true;
                }
            }
            if path.contains("mobilecal.plist") {
                let emails = owner_emails_from_mobilecal(val);
                if !emails.is_empty() {
                    saw = true;
                    for e in emails {
                        lines.push(format!("- Calendar owner email: {e} (`{path}`)"));
                    }
                }
            }
        }
        if !saw {
            lines.push(
                "(no EffectiveUserSettings / mobilecal plist in capped `plists` set)".to_string(),
            );
        }
    } else {
        lines.push("(plists parser produced no `files` map)".to_string());
    }

    lines.push("\n## Transparency (transparency_json)".to_string());
    let trans = parser_value(parsed, "transparency_json");
    if trans.get("error").is_some() {
        lines.push("No or invalid transparency.log JSON.".to_string());
    } else if let Some(sm) = trans.get("stateMachine") {
        if let Some(sv) = sm.get("selfVerification").and_then(|v| v.get("server")) {
            if let Value::Object(m) = sv {
                lines.push("Accounts (server):".to_string());
                for k in m.keys().take(50) {
                    lines.push(format!("- {k}"));
                }
            }
        }
        let mut contact_uris = BTreeSet::new();
        walk_transparency_contact_uris(&trans, &mut contact_uris);
        if !contact_uris.is_empty() {
            lines.push("\nOwner / contact URIs (`im://mailto:` / `im://tel:`):".to_string());
            for u in contact_uris.iter().take(40) {
                lines.push(format!("- {u}"));
            }
        }
        if let Some(devs) = sm.get("devices") {
            lines.push("\nKnown devices:".to_string());
            lines.push("| serial | model | os | name |".to_string());
            lines.push("|---|---|---|---|".to_string());
            if let Value::Object(dm) = devs {
                for (_k, d) in dm.iter().take(40) {
                    if let Value::Object(o) = d {
                        lines.push(format!(
                            "| {} | {} | {} | {} |",
                            o.get("serial").unwrap_or(&Value::Null),
                            o.get("model").unwrap_or(&Value::Null),
                            o.get("osVersion").unwrap_or(&Value::Null),
                            o.get("name").unwrap_or(&Value::Null),
                        ));
                    }
                }
            }
        }
    } else {
        lines.push("(no stateMachine in transparency JSON)".to_string());
    }

    lines.push("\n## Security / keychain (`security_sysdiagnose`)".to_string());
    let sec = parser_value(parsed, "security_sysdiagnose");
    for ln in security_sysdiagnose_summary_lines(&sec) {
        lines.push(ln);
    }

    lines.push("\n## Shutdown clients (`shutdownlogs`)".to_string());
    let sd = parser_value(parsed, "shutdownlogs");
    for ln in shutdownlogs_summary_lines(&sd) {
        lines.push(ln);
    }

    lines.push("\n## MCState shared profiles (summary)".to_string());
    let mc = parser_value(parsed, "mcstate_shared_profile");
    if let Value::Object(paths) = &mc {
        if paths.is_empty() {
            lines.push("No profile stub files.".to_string());
        } else {
            lines.push(format!("{} stub file(s).", paths.len()));
            for (path, content) in paths.iter().take(12) {
                let Value::String(s) = content else { continue };
                let hints = mcstate_stub_summary_lines(s);
                if hints.is_empty() {
                    continue;
                }
                lines.push(format!("\n`{path}`:"));
                for h in hints.into_iter().take(24) {
                    lines.push(format!("- {h}"));
                }
            }
        }
    } else {
        lines.push("No mcstate data.".to_string());
    }

    let content = lines.join("\n");
    json!({
        "analyser": "summary",
        "format": "markdown",
        "content": content,
        "notes": "Markdown overview from parser output: device, lockdown, transparency, security-sysdiagnose highlights, and shutdownlogs table when present."
    })
}