// SPDX-License-Identifier: GPL-3.0-only
//! Device-user / Apple-account identity (compat with upstream `accounts` shape).
//!
//! Behaviour pinned by upstream analyser tests: MobileCal owner emails, MDM
//! CloudConfigurationDetails org email, ActivationLockUsername, transparency
//! contact URIs / selfVerification / linked devices, lockdown mode.

use super::common::unwrap_parser;
use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::{BTreeSet, HashMap};
use std::sync::OnceLock;

pub fn run(
    parsed: &HashMap<String, Value>,
    identity_plists: &HashMap<String, Value>,
    activation_lock_log_texts: &[String],
) -> Value {
    let mut owner_emails = Vec::new();
    collect_owner_emails(identity_plists, &mut owner_emails);
    let mut organization_emails = Vec::new();
    collect_organization_emails(identity_plists, &mut organization_emails);
    let mut activation_lock_usernames = Vec::new();
    collect_activation_lock(parsed, activation_lock_log_texts, &mut activation_lock_usernames);
    let mut lockdown_mode = collect_lockdown(identity_plists);

    if let Some(files) = unwrap_parser(parsed, "plists")
        .and_then(|p| p.get("files"))
        .and_then(|f| f.as_object())
    {
        let map: HashMap<String, Value> = files.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        collect_owner_emails(&map, &mut owner_emails);
        collect_organization_emails(&map, &mut organization_emails);
        if lockdown_mode.is_none() {
            lockdown_mode = collect_lockdown(&map);
        }
    }

    let null = Value::Null;
    let trans = unwrap_parser(parsed, "transparency_json").unwrap_or(&null);
    let (contacts, apple_accounts, linked_devices) = collect_from_transparency(trans);

    json!({
        "analyser": "accounts",
        "owner_emails": owner_emails,
        "organization_emails": organization_emails,
        "activation_lock_usernames": activation_lock_usernames,
        "contacts": contacts,
        "apple_accounts": apple_accounts,
        "linked_devices": linked_devices,
        "lockdown_mode": lockdown_mode,
        "counts": {
            "owner_emails": owner_emails.len(),
            "organization_emails": organization_emails.len(),
            "activation_lock_usernames": activation_lock_usernames.len(),
            "contacts": contacts.len(),
            "apple_accounts": apple_accounts.len(),
            "linked_devices": linked_devices.len(),
        }
    })
}


fn collect_owner_emails(files: &HashMap<String, Value>, out: &mut Vec<Value>) {
    let mut seen: BTreeSet<String> = out
        .iter()
        .filter_map(|v| v.get("email").and_then(|e| e.as_str()))
        .map(|e| e.to_ascii_lowercase())
        .collect();
    for (path, val) in files {
        if !path.to_ascii_lowercase().contains("mobilecal") {
            continue;
        }
        for email in owner_emails_from_mobilecal(val) {
            if !seen.insert(email.to_ascii_lowercase()) {
                continue;
            }
            out.push(json!({
                "email": email,
                "source": "mobilecal",
                "path": path,
            }));
        }
    }
}

fn owner_emails_from_mobilecal(v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let Some(arr) = v.get("OwnerEmailAddress").and_then(|x| x.as_array()) else {
        return out;
    };
    for e in arr {
        if let Some(s) = e.as_str() {
            let s = s.trim();
            if s.contains('@') {
                out.push(s.to_string());
            }
        }
    }
    out
}

fn collect_organization_emails(files: &HashMap<String, Value>, out: &mut Vec<Value>) {
    let mut seen: BTreeSet<String> = out
        .iter()
        .filter_map(|v| v.get("email").and_then(|e| e.as_str()))
        .map(|e| e.to_ascii_lowercase())
        .collect();
    for (path, val) in files {
        if !path.contains("CloudConfigurationDetails") {
            continue;
        }
        let email = val
            .get("OrganizationEmail")
            .and_then(|x| x.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty() && s.contains('@'));
        let Some(email) = email else { continue };
        if !seen.insert(email.to_ascii_lowercase()) {
            continue;
        }
        let mut row = Map::new();
        row.insert("email".into(), json!(email));
        row.insert("source".into(), json!("cloud_configuration"));
        row.insert("path".into(), json!(path));
        row.insert("account_type".into(), json!("organization_email"));
        if let Some(org) = val
            .get("OrganizationName")
            .and_then(|x| x.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            row.insert("organization_name".into(), json!(org));
        }
        if let Some(dept) = val
            .get("OrganizationDepartment")
            .and_then(|x| x.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            row.insert("organization_department".into(), json!(dept));
        }
        out.push(Value::Object(row));
    }
}

fn activation_lock_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)ActivationLockUsername\s*=\s*"([^"]+)""#).expect("re")
    })
}

fn push_activation_lock(email: &str, seen: &mut BTreeSet<String>, out: &mut Vec<Value>) {
    let email = email.trim();
    if email.is_empty() || !email.contains('@') {
        return;
    }
    if !seen.insert(email.to_ascii_lowercase()) {
        return;
    }
    out.push(json!({
        "email": email,
        "username": email,
        "source": "mobileactivation",
        "account_type": "activation_lock",
    }));
}

fn collect_activation_lock(
    parsed: &HashMap<String, Value>,
    log_texts: &[String],
    out: &mut Vec<Value>,
) {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let re = activation_lock_re();
    if let Some(ma) = unwrap_parser(parsed, "mobileactivation") {
        if let Some(events) = ma.get("events").and_then(|e| e.as_array()) {
            for ev in events {
                let Some(message) = ev.get("message").and_then(|m| m.as_str()) else {
                    continue;
                };
                for caps in re.captures_iter(message) {
                    if let Some(m) = caps.get(1) {
                        push_activation_lock(m.as_str(), &mut seen, out);
                    }
                }
            }
        }
    }
    // Fallback: raw mobileactivationd.log* (covers multiline / truncated parser rows).
    for text in log_texts {
        for caps in re.captures_iter(text) {
            if let Some(m) = caps.get(1) {
                push_activation_lock(m.as_str(), &mut seen, out);
            }
        }
    }
}

fn collect_lockdown(files: &HashMap<String, Value>) -> Option<bool> {
    for (path, val) in files {
        if !path.contains("EffectiveUserSettings") {
            continue;
        }
        if let Some(b) = val
            .pointer("/restrictedBool/allowLockdownMode/value")
            .and_then(|v| v.as_bool())
        {
            return Some(b);
        }
    }
    None
}

fn mailto_from_uri(uri: &str) -> Option<String> {
    let rest = uri
        .strip_prefix("im://mailto:")
        .or_else(|| uri.strip_prefix("mailto:"))?;
    let email = rest.trim();
    if email.is_empty() || !email.contains('@') {
        return None;
    }
    Some(email.to_string())
}

fn tel_from_uri(uri: &str) -> Option<String> {
    let rest = uri
        .strip_prefix("im://tel:")
        .or_else(|| uri.strip_prefix("tel:"))?;
    let tel = rest.trim();
    if tel.is_empty() {
        return None;
    }
    Some(tel.to_string())
}

fn walk_contact_uris(v: &Value, out: &mut BTreeSet<String>) {
    match v {
        Value::String(s) => {
            if s.contains("mailto:") || s.contains("tel:") || s.starts_with("im://") {
                out.insert(s.clone());
            }
        }
        Value::Array(a) => {
            for x in a {
                walk_contact_uris(x, out);
            }
        }
        Value::Object(m) => {
            for (_k, x) in m {
                walk_contact_uris(x, out);
            }
        }
        _ => {}
    }
}

fn collect_from_transparency(trans: &Value) -> (Vec<Value>, Vec<Value>, Vec<Value>) {
    let mut contacts = Vec::new();
    let mut apple_accounts = Vec::new();
    let mut linked_devices = Vec::new();
    if trans.get("error").is_some() || trans.is_null() {
        return (contacts, apple_accounts, linked_devices);
    }

    let mut uris = BTreeSet::new();
    walk_contact_uris(trans, &mut uris);
    for uri in uris {
        let kind = if uri.contains("mailto:") {
            "mailto"
        } else if uri.contains("tel:") {
            "tel"
        } else {
            "other"
        };
        let mut row = Map::new();
        row.insert("uri".into(), json!(uri.clone()));
        row.insert("kind".into(), json!(kind));
        row.insert("source".into(), json!("transparency"));
        if let Some(email) = mailto_from_uri(&uri) {
            row.insert("email".into(), json!(email));
        }
        if let Some(tel) = tel_from_uri(&uri) {
            row.insert("phone".into(), json!(tel));
        }
        contacts.push(Value::Object(row));
    }

    if let Some(server) = trans
        .pointer("/stateMachine/selfVerification/server")
        .and_then(|v| v.as_object())
    {
        for key in server.keys() {
            let id = key.trim();
            if id.is_empty() {
                continue;
            }
            apple_accounts.push(json!({
                "account_id": id,
                "account_type": "apple_transparency",
                "source": "transparency_selfVerification",
            }));
        }
    }

    if let Some(devs) = trans
        .pointer("/stateMachine/devices")
        .and_then(|v| v.as_object())
    {
        for (_k, d) in devs {
            let Some(o) = d.as_object() else { continue };
            linked_devices.push(json!({
                "serial": o.get("serial").and_then(|x| x.as_str()).unwrap_or("").trim(),
                "model": o.get("model").and_then(|x| x.as_str()).unwrap_or("").trim(),
                "os_version": o.get("osVersion").or_else(|| o.get("os_version")).and_then(|x| x.as_str()).unwrap_or("").trim(),
                "name": o.get("name").and_then(|x| x.as_str()).unwrap_or("").trim(),
                "source": "transparency_devices",
            }));
        }
    }

    (contacts, apple_accounts, linked_devices)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_mobilecal_and_transparency_identity() {
        let mut parsed = HashMap::new();
        parsed.insert(
            "plists".into(),
            json!({
                "files": {
                    "logs/Preferences/mobilecal.plist": {
                        "OwnerEmailAddress": ["alice@icloud.com", "work@example.com"]
                    },
                    "logs/EffectiveUserSettings.plist": {
                        "restrictedBool": { "allowLockdownMode": { "value": true } }
                    }
                }
            }),
        );
        parsed.insert(
            "transparency_json".into(),
            json!({
                "stateMachine": {
                    "selfVerification": {
                        "server": { "acct-abc": {}, "acct-def": {} }
                    },
                    "devices": {
                        "d1": {
                            "serial": "C02TEST",
                            "model": "MacBookPro18,1",
                            "osVersion": "15.0",
                            "name": "Alice's MacBook"
                        }
                    },
                    "contacts": [
                        "im://mailto:alice@icloud.com",
                        "im://tel:+15551212"
                    ]
                }
            }),
        );
        let v = run(&parsed, &HashMap::new(), &[]);
        assert_eq!(v["analyser"], "accounts");
        assert_eq!(v["counts"]["owner_emails"], 2);
        assert_eq!(v["counts"]["apple_accounts"], 2);
        assert_eq!(v["counts"]["linked_devices"], 1);
        assert_eq!(v["counts"]["contacts"], 2);
        assert_eq!(v["lockdown_mode"], true);
    }
}
