// SPDX-License-Identifier: GPL-3.0-only
//! Post-parse field normalization for analyser / timeline consumers.
//!
//! Mirrors mobipwn flatten helpers (battery, lock, MI versions, bundle_id aliases)
//! without depending on that tree.

use regex::Regex;
use serde_json::{json, Map, Value};
use std::sync::OnceLock;

use crate::analysers::common::extract_app_bundle_id_from_text;

/// Normalize all known parser JSON blobs in-place (events + nested data maps).
pub fn normalize_parsed_map(parsed: &mut std::collections::HashMap<String, Value>) {
    let keys: Vec<String> = parsed.keys().cloned().collect();
    for k in keys {
        if let Some(v) = parsed.get_mut(&k) {
            normalize_parser_value(&k, v);
        }
    }
}

pub fn normalize_parser_value(parser_id: &str, root: &mut Value) {
    match root {
        Value::Object(map) => {
            if let Some(Value::Array(events)) = map.get_mut("events") {
                for ev in events.iter_mut() {
                    finalize_event(parser_id, ev);
                }
            }
            // mobileinstallation may be path → log text or structured events
            if parser_id == "mobileinstallation" {
                for (path, val) in map.iter_mut() {
                    if path == "events" || path == "parser" || path == "format" {
                        continue;
                    }
                    if let Value::Array(arr) = val {
                        for ev in arr {
                            finalize_event(parser_id, ev);
                        }
                    }
                }
            }
        }
        Value::Array(arr) => {
            for ev in arr {
                finalize_event(parser_id, ev);
            }
        }
        _ => {}
    }
}

fn finalize_event(parser_id: &str, ev: &mut Value) {
    let Some(obj) = ev.as_object_mut() else {
        return;
    };
    let message = obj
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let desc = obj
        .get("timestamp_desc")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let datetime_missing = obj
        .get("datetime")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().is_empty())
        .unwrap_or(true);

    // Flatten nested data aliases onto both root and data.
    if let Some(Value::Object(data)) = obj.get_mut("data") {
        alias_fields(data);
        if parser_id == "powerlogs" {
            enrich_battery_fields(&message, &desc, data);
            enrich_lock_fields(&message, &desc, datetime_missing, data);
        }
        if parser_id == "knowledgec" {
            enrich_lock_fields(&message, &desc, datetime_missing, data);
        }
        stamp_bundle_id(parser_id, &message, data);
        if parser_id == "mobileinstallation" {
            enrich_mi_versions(&message, data);
        }
        // Promote lock datetime onto root when we filled it on data.
        if datetime_missing {
            if let Some(dt) = data.get("datetime").cloned() {
                // insert after borrow of data ends
                let _ = dt;
            }
        }
    } else {
        alias_fields(obj);
        if parser_id == "powerlogs" {
            enrich_battery_fields(&message, &desc, obj);
            enrich_lock_fields(&message, &desc, datetime_missing, obj);
        }
        stamp_bundle_id(parser_id, &message, obj);
        if parser_id == "mobileinstallation" {
            enrich_mi_versions(&message, obj);
        }
    }

    // Second pass: copy datetime from data → root if still missing.
    if datetime_missing {
        if let Some(dt) = obj
            .get("data")
            .and_then(|d| d.get("datetime"))
            .cloned()
        {
            obj.insert("datetime".into(), dt);
        }
    }
}

fn alias_fields(map: &mut Map<String, Value>) {
    const ALIASES: &[(&str, &str)] = &[
        ("BUNDLE ID", "bundle_id"),
        ("bundle id", "bundle_id"),
        ("PROCESS NAME", "process_name"),
        ("CLIENT", "client"),
        ("SERVICE", "service"),
        ("RAW LEVEL", "raw_level"),
        ("raw level", "raw_level"),
        ("RAWLEVEL", "raw_level"),
        ("LEVEL", "level"),
        ("IS CHARGING", "is_charging"),
        ("is charging", "is_charging"),
        ("FULLY CHARGED", "fully_charged"),
        ("fully charged", "fully_charged"),
        ("LOCK STATUS", "lock_status"),
        ("lock status", "lock_status"),
        ("IS LOCKED", "is_locked"),
        ("is locked", "is_locked"),
        ("AUTO LOCK TYPE", "auto_lock_type"),
        ("auto lock type", "auto_lock_type"),
        ("ADJUSTED_TIMESTAMP", "adjusted_timestamp"),
        ("adjusted_timestamp", "adjusted_timestamp"),
        ("adjusted timestamp", "adjusted_timestamp"),
    ];
    for (from, to) in ALIASES {
        if !map.contains_key(*to) {
            if let Some(v) = map.get(*from).cloned() {
                map.insert((*to).into(), v);
            }
        }
    }
}

fn scrape_message_float(message: &str, key: &str) -> Option<f64> {
    let patterns = [
        format!(", {key}="),
        format!(": {key}="),
        format!(":{key}="),
    ];
    let rest = patterns
        .iter()
        .find_map(|needle| message.split(needle.as_str()).nth(1))?;
    let token = rest.split(',').next()?.split_whitespace().next()?;
    token.parse().ok()
}

fn enrich_battery_fields(message: &str, desc: &str, data: &mut Map<String, Value>) {
    let desc = if desc.is_empty() {
        data.get("timestamp_desc")
            .and_then(|v| v.as_str())
            .unwrap_or("")
    } else {
        desc
    };
    let is_battery =
        desc.eq_ignore_ascii_case("Battery Level") || message.starts_with("Battery Level:");
    if !is_battery {
        return;
    }
    if data.get("raw_level").is_none() {
        if let Some(n) = scrape_message_float(message, "RAW LEVEL") {
            data.insert("raw_level".into(), json!(n));
        }
    }
    if data.get("level").is_none() {
        if let Some(n) = scrape_message_float(message, "LEVEL") {
            data.insert("level".into(), json!(n));
        }
    }
    if let Some(v) = data.get("is_charging").cloned() {
        data.insert("is_charging".into(), coerce_boolish(v));
    } else if let Some(n) = scrape_message_float(message, "IS CHARGING") {
        data.insert("is_charging".into(), json!(n != 0.0));
    }
}

fn coerce_boolish(v: Value) -> Value {
    if let Some(b) = v.as_bool() {
        return json!(b);
    }
    if let Some(n) = v.as_i64().or_else(|| v.as_u64().map(|u| u as i64)) {
        return json!(n != 0);
    }
    if let Some(s) = v.as_str() {
        let t = s.trim().to_ascii_lowercase();
        if matches!(t.as_str(), "1" | "true" | "yes" | "charging") {
            return json!(true);
        }
        if matches!(t.as_str(), "0" | "false" | "no") {
            return json!(false);
        }
    }
    v
}

fn enrich_lock_fields(
    message: &str,
    desc: &str,
    datetime_missing: bool,
    data: &mut Map<String, Value>,
) {
    let desc_l = if desc.is_empty() {
        data.get("timestamp_desc")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase()
    } else {
        desc.to_ascii_lowercase()
    };
    let apollo = data
        .get("apollo_module")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let is_lock = desc_l == "lock state"
        || desc_l == "screen unlock state"
        || message.starts_with("Lock State:")
        || message.starts_with("Screen Unlock State:")
        || apollo == "powerlog_device_lock_state"
        || apollo == "powerlog_device_screen_autolock";
    if !is_lock {
        return;
    }
    if data.get("lock_status").is_none() {
        if let Some(s) = scrape_message_token(message, "LOCK STATUS") {
            data.insert("lock_status".into(), json!(s));
        }
    }
    if data.get("is_locked").is_none() {
        if let Some(status) = data.get("lock_status").and_then(|v| v.as_str()) {
            let locked = status.to_ascii_uppercase().contains("LOCKED")
                && !status.to_ascii_uppercase().contains("UNLOCKED");
            data.insert("is_locked".into(), json!(locked));
        }
    }
    if datetime_missing && data.get("datetime").is_none() {
        for key in ["adjusted_timestamp", "ADJUSTED_TIMESTAMP", "adjusted timestamp"] {
            if let Some(v) = data.get(key).cloned() {
                if let Some(s) = v.as_str() {
                    if s.len() >= 19 {
                        data.insert("datetime".into(), json!(s));
                        break;
                    }
                } else if let Some(n) = v.as_i64().or_else(|| v.as_u64().map(|u| u as i64)) {
                    if n > 1_000_000_000 {
                        if let Some(dt) = chrono::DateTime::from_timestamp(n, 0) {
                            data.insert(
                                "datetime".into(),
                                json!(dt.format("%Y-%m-%d %H:%M:%S").to_string()),
                            );
                            break;
                        }
                    }
                }
            }
        }
    }
}

fn scrape_message_token(message: &str, key: &str) -> Option<String> {
    let patterns = [format!(", {key}="), format!(": {key}=")];
    let rest = patterns
        .iter()
        .find_map(|needle| message.split(needle.as_str()).nth(1))?;
    let token = rest.split(',').next()?.trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

fn stamp_bundle_id(parser_id: &str, message: &str, data: &mut Map<String, Value>) {
    if data.get("bundle_id").and_then(|v| v.as_str()).is_some() {
        return;
    }
    if let Some(v) = data
        .get("bundle id")
        .or_else(|| data.get("BUNDLE ID"))
        .cloned()
    {
        data.insert("bundle_id".into(), v);
        return;
    }
    if matches!(
        parser_id,
        "mobileinstallation" | "appinstallation" | "powerlogs" | "accessibility_tcc" | "knowledgec"
    ) {
        if let Some(bid) = extract_app_bundle_id_from_text(message) {
            data.insert("bundle_id".into(), json!(bid));
        }
    }
}

/// True for values that look like app versions (must contain a digit).
pub fn looks_like_app_version(value: &str) -> bool {
    let v = value.trim().trim_end_matches([',', ';', ')', '>']).trim();
    if v.is_empty() || v.len() > 64 {
        return false;
    }
    if !v.chars().any(|c| c.is_ascii_digit()) {
        return false;
    }
    if v
        .chars()
        .any(|c| c.is_whitespace() || c == '/' || c == '\\' || c == ',')
    {
        return false;
    }
    true
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MobileInstallVersions {
    pub short_version: Option<String>,
    pub version: Option<String>,
}

pub fn parse_mobile_install_versions(message: &str) -> MobileInstallVersions {
    fn pick(message: &str, re: &Regex) -> Option<String> {
        let raw = re
            .captures(message)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str())
            .unwrap_or("");
        let v = raw.trim().trim_end_matches([',', ';', ')', '>']).trim();
        if looks_like_app_version(v) {
            Some(v.to_string())
        } else {
            None
        }
    }
    static SHORT_EQ: OnceLock<Regex> = OnceLock::new();
    static SHORT_CF: OnceLock<Regex> = OnceLock::new();
    static VER_EQ: OnceLock<Regex> = OnceLock::new();
    static VER_CF: OnceLock<Regex> = OnceLock::new();
    let short_eq = SHORT_EQ
        .get_or_init(|| Regex::new(r"(?i)ShortVersion\s*=\s*([^;>\s,]+)").expect("ShortVersion"));
    let short_cf = SHORT_CF.get_or_init(|| {
        Regex::new(r"(?i)CFBundleShortVersionString\s*[=:]\s*([^\s;,>]+)")
            .expect("CFBundleShortVersionString")
    });
    let ver_eq = VER_EQ
        .get_or_init(|| Regex::new(r"(?i)(?:^|[;\s,])Version\s*=\s*([^;>\s,]+)").expect("Version="));
    let ver_cf = VER_CF
        .get_or_init(|| Regex::new(r"(?i)CFBundleVersion\s*[=:]\s*([^\s;,>]+)").expect("CFBundleVersion"));
    MobileInstallVersions {
        short_version: pick(message, short_eq).or_else(|| pick(message, short_cf)),
        version: pick(message, ver_eq).or_else(|| pick(message, ver_cf)),
    }
}

fn stamp_version_fields(map: &mut Map<String, Value>, parsed: &MobileInstallVersions) {
    for key in [
        "short_version",
        "CFBundleShortVersionString",
        "version",
        "CFBundleVersion",
    ] {
        if let Some(Value::String(s)) = map.get(key) {
            if !looks_like_app_version(s) {
                map.remove(key);
            }
        }
    }
    if let Some(s) = &parsed.short_version {
        map.insert("short_version".into(), json!(s));
        map.insert("CFBundleShortVersionString".into(), json!(s));
    }
    if let Some(s) = &parsed.version {
        map.insert("version".into(), json!(s));
        map.insert("CFBundleVersion".into(), json!(s));
    }
}

fn enrich_mi_versions(message: &str, data: &mut Map<String, Value>) {
    if message.is_empty() {
        return;
    }
    stamp_version_fields(data, &parse_mobile_install_versions(message));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_prose_version() {
        let v = parse_mobile_install_versions("version does not match");
        assert!(v.short_version.is_none());
        assert!(v.version.is_none());
    }

    #[test]
    fn parses_short_version() {
        let v = parse_mobile_install_versions("ShortVersion=7.12.0; Version=712");
        assert_eq!(v.short_version.as_deref(), Some("7.12.0"));
        assert_eq!(v.version.as_deref(), Some("712"));
    }

    #[test]
    fn battery_raw_level_from_message() {
        let mut data = serde_json::Map::new();
        enrich_battery_fields(
            "Battery Level: RAW LEVEL=79.5, LEVEL=80, IS CHARGING=0",
            "Battery Level",
            &mut data,
        );
        assert_eq!(data.get("raw_level").and_then(|v| v.as_f64()), Some(79.5));
    }
}
