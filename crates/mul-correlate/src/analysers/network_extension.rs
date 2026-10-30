// SPDX-License-Identifier: GPL-3.0-only

//! Structured NetworkExtension / VPN / proxy / content-filter configs.

use serde_json::{json, Map, Value};
use std::collections::HashMap;

use super::common::{parser_value, plist_top_keys};

fn files_map(v: &Value) -> Option<&Map<String, Value>> {
    if let Some(files) = v.get("files").and_then(|f| f.as_object()) {
        return Some(files);
    }
    v.as_object().filter(|m| {
        !m.contains_key("parser")
            || m.keys().any(|k| k.contains("networkextension") || k.ends_with(".plist"))
    })
}

fn guess_kind(path: &str, val: &Value) -> &'static str {
    let blob = format!("{path}{}", val);
    let lower = blob.to_ascii_lowercase();
    if lower.contains("vpn") || lower.contains("ikev2") || lower.contains("ipsec") {
        "vpn"
    } else if lower.contains("dnsproxy") || lower.contains("dns_proxy") {
        "dns_proxy"
    } else if lower.contains("appproxy") || lower.contains("app_proxy") {
        "app_proxy"
    } else if lower.contains("contentfilter") || lower.contains("content_filter") {
        "content_filter"
    } else if lower.contains("relay") {
        "relay"
    } else {
        "network_extension"
    }
}

fn pick(val: &Value, keys: &[&str]) -> Option<Value> {
    for k in keys {
        if let Some(v) = val.get(*k) {
            if !v.is_null() {
                return Some(v.clone());
            }
        }
    }
    // one level deep
    if let Some(obj) = val.as_object() {
        for (_, child) in obj {
            if let Some(v) = pick(child, keys) {
                return Some(v);
            }
        }
    }
    None
}

fn collect_from_map(files: &Map<String, Value>, out: &mut Vec<Value>) {
    for (path, val) in files {
        if path.contains("uuidcache") || path.ends_with("NetworkInterfaces.plist") {
            continue;
        }
        let kind = guess_kind(path, val);
        out.push(json!({
            "path": path,
            "kind": kind,
            "provider": pick(val, &[
                "ProviderBundleIdentifier",
                "BundleIdentifier",
                "ProviderConfiguration",
            ]),
            "server": pick(val, &[
                "ServerAddress",
                "RemoteAddress",
                "ServerURL",
                "hostname",
            ]),
            "on_demand": pick(val, &["OnDemandEnabled", "OnDemandRules"]),
            "keys": plist_top_keys(val),
        }));
    }
}

pub fn run(parsed: &HashMap<String, Value>) -> Value {
    let mut configs = Vec::new();
    for id in ["networkextension", "networkextensioncache"] {
        let v = parser_value(parsed, id);
        if let Some(files) = files_map(&v) {
            collect_from_map(files, &mut configs);
        } else if v.is_object() {
            // single decoded plist without files wrapper
            configs.push(json!({
                "path": id,
                "kind": guess_kind(id, &v),
                "provider": pick(&v, &["ProviderBundleIdentifier", "BundleIdentifier"]),
                "server": pick(&v, &["ServerAddress", "RemoteAddress", "ServerURL"]),
                "keys": plist_top_keys(&v),
            }));
        }
    }
    let providers: Vec<_> = configs
        .iter()
        .filter_map(|c| c.get("provider").cloned())
        .filter(|v| !v.is_null())
        .collect();
    let servers: Vec<_> = configs
        .iter()
        .filter_map(|c| c.get("server").cloned())
        .filter(|v| !v.is_null())
        .collect();
    let count = configs.len();
    json!({
        "analyser": "network_extension",
        "configs": configs,
        "providers": providers,
        "servers": servers,
        "count": count,
        "notes": "Structured view of NetworkExtension plists (VPN / proxy / DNS / content filter)."
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_vpn_kind() {
        let mut parsed = HashMap::new();
        parsed.insert(
            "networkextension".into(),
            json!({
                "logs/Networking/com.apple.networkextension.plist": {
                    "VPNType": "IKEv2",
                    "ServerAddress": "vpn.example.com",
                    "ProviderBundleIdentifier": "com.example.vpn"
                }
            }),
        );
        let v = run(&parsed);
        assert_eq!(v["analyser"], "network_extension");
        assert!(v["count"].as_u64().unwrap() >= 1);
        assert_eq!(v["configs"][0]["kind"], "vpn");
    }
}
