// SPDX-License-Identifier: GPL-3.0-only

//! Unified MDM view: profile PayloadContent inventory, MCSettingsEvents, and MDM plist status.

use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};

use super::common::{parser_value, plist_top_keys, unwrap_parser};

pub fn run(parsed: &HashMap<String, Value>) -> Value {
    let mut payloads = Vec::new();
    let mut by_type: BTreeMap<String, usize> = BTreeMap::new();
    let mut settings_events = Vec::new();
    let mut mdm_status = Vec::new();
    let mut mdm_plists = Vec::new();
    let mut plist_files_parsed = 0usize;

    let profiles = parser_value(parsed, "mcstate_shared_profile");
    if let Some(events) = profiles.get("events").and_then(|e| e.as_array()) {
        for ev in events {
            let data = ev.get("data").cloned().unwrap_or(Value::Null);
            let typ = data
                .get("PayloadType")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if !typ.is_empty() {
                *by_type.entry(typ.clone()).or_insert(0) += 1;
            }
            payloads.push(json!({
                "datetime": ev.get("datetime"),
                "message": ev.get("message"),
                "timestamp_desc": ev.get("timestamp_desc"),
                "PayloadType": data.get("PayloadType"),
                "PayloadDisplayName": data.get("PayloadDisplayName"),
                "PayloadOrganization": data.get("PayloadOrganization"),
                "PayloadDescription": data.get("PayloadDescription"),
                "PayloadUUID": data.get("PayloadUUID"),
                "VPNType": data.get("VPNType"),
                "RemoteAddress": data.get("RemoteAddress"),
                "ServerURL": data.get("ServerURL"),
                "parent_PayloadType": data.get("parent_PayloadType"),
                "index": data.get("index"),
            }));
        }
    }

    let settings = parser_value(parsed, "mcsettingsevents");
    if let Some(events) = settings.get("events").and_then(|e| e.as_array()) {
        for ev in events.iter().take(500) {
            let data = ev.get("data").cloned().unwrap_or(Value::Null);
            settings_events.push(json!({
                "datetime": ev.get("datetime"),
                "message": ev.get("message"),
                "setting": data.get("setting"),
                "process": data.get("process"),
                "event": data.get("event"),
            }));
        }
    }

    if let Some(files) = unwrap_parser(parsed, "plists")
        .and_then(|p| p.get("files"))
        .and_then(|f| f.as_object())
    {
        plist_files_parsed = files.len();
        for (path, val) in files {
            let pl = path.to_ascii_lowercase();
            let is_mdm_path = path.contains("MCState") && path.contains("MDM");
            let is_related =
                pl.contains("mcstate") || pl.contains("mdm") || pl.contains("payloadmanifest");
            if !is_related {
                continue;
            }

            let mut row = Map::new();
            row.insert("path".into(), json!(path));
            row.insert("keys".into(), json!(plist_top_keys(val)));
            for key in [
                "ManagingProfileIdentifier",
                "AccessRights",
                "LastPollingAttempt",
                "PayloadType",
                "PayloadDisplayName",
            ] {
                if let Some(v) = val.get(key) {
                    row.insert(key.into(), v.clone());
                }
            }
            mdm_plists.push(Value::Object(row.clone()));

            // Former `plist` analyser: Shared_MDM / mdm.plist status highlights.
            if is_mdm_path {
                let mut m = Map::new();
                m.insert("source".into(), json!(path));
                if pl.contains("shared_mdm") || pl.ends_with("mdm.plist") {
                    m.insert("kind".into(), json!("mdm_profile_fields"));
                    m.insert(
                        "ManagingProfileIdentifier".into(),
                        val.get("ManagingProfileIdentifier")
                            .cloned()
                            .unwrap_or(Value::Null),
                    );
                    m.insert(
                        "AccessRights".into(),
                        val.get("AccessRights").cloned().unwrap_or(Value::Null),
                    );
                    m.insert(
                        "LastPollingAttempt".into(),
                        val.get("LastPollingAttempt")
                            .cloned()
                            .unwrap_or(Value::Null),
                    );
                } else {
                    m.insert("kind".into(), json!("mdm_plist_candidate"));
                }
                m.insert("keys".into(), json!(plist_top_keys(val)));
                mdm_status.push(Value::Object(m));
            }
        }
    }

    let counts = json!({
        "payloads": payloads.len(),
        "settings_events": settings_events.len(),
        "mdm_plists": mdm_plists.len(),
        "mdm_status": mdm_status.len(),
        "payload_types": by_type.len(),
        "plist_files_parsed": plist_files_parsed,
    });
    json!({
        "analyser": "mdm",
        "payloads": payloads,
        "settings_events": settings_events,
        "mdm_plists": mdm_plists,
        "mdm_status": mdm_status,
        "by_payload_type": by_type,
        "counts": counts,
        // Compat alias for old `plist` consumers that expected `events`.
        "events": mdm_status.clone(),
        "notes": "Unified MDM: PayloadContent inventory + MCSettingsEvents + Shared_MDM / MDM plist status."
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collects_payloads_and_status() {
        let mut parsed = HashMap::new();
        parsed.insert(
            "mcstate_shared_profile".into(),
            json!({
                "events": [{
                    "datetime": "2024-01-01T00:00:00Z",
                    "message": "payload VPN",
                    "data": {
                        "PayloadType": "com.apple.vpn.managed",
                        "PayloadDisplayName": "Corp VPN",
                        "RemoteAddress": "vpn.example.com"
                    }
                }]
            }),
        );
        parsed.insert(
            "plists".into(),
            json!({
                "files": {
                    "logs/MCState/Shared_MDM/mdm.plist": {
                        "ManagingProfileIdentifier": "abc",
                        "AccessRights": 8191
                    }
                }
            }),
        );
        let v = run(&parsed);
        assert_eq!(v["analyser"], "mdm");
        assert_eq!(v["counts"]["payloads"], 1);
        assert_eq!(v["by_payload_type"]["com.apple.vpn.managed"], 1);
        assert!(v["mdm_status"].as_array().unwrap().len() >= 1);
    }
}
