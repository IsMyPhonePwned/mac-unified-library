// SPDX-License-Identifier: GPL-3.0-only

//! Mount integrity (sealed/read-only root) + OTA / restore activity.

use serde_json::{json, Value};
use std::collections::HashMap;

use super::common::parser_value;

pub fn run(parsed: &HashMap<String, Value>) -> Value {
    let mount = parser_value(parsed, "mount");
    let mut mounts = Vec::new();
    let mut sealed_or_readonly_roots = Vec::new();

    if let Some(events) = mount.get("events").and_then(|e| e.as_array()) {
        for ev in events.iter().take(500) {
            let data = ev.get("data").cloned().unwrap_or(Value::Null);
            let row = json!({
                "message": ev.get("message"),
                "mountpoint": data.get("mountpoint"),
                "fs": data.get("fs").or_else(|| data.get("filesystem")),
                "opts": data.get("opts").or_else(|| data.get("options")),
                "sealed": data.get("sealed"),
                "read_only": data.get("read_only").or_else(|| data.get("readonly")),
            });
            let is_root = data
                .get("mountpoint")
                .and_then(|m| m.as_str())
                .map(|m| m == "/")
                .unwrap_or(false);
            let sealed = data
                .get("sealed")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
                || ev
                    .get("message")
                    .and_then(|m| m.as_str())
                    .map(|m| m.contains("sealed") || m.contains("read-only"))
                    .unwrap_or(false);
            if is_root || sealed {
                sealed_or_readonly_roots.push(row.clone());
            }
            mounts.push(row);
        }
    }
    let root_mounts = mount
        .get("root_mounts")
        .cloned()
        .unwrap_or_else(|| json!(sealed_or_readonly_roots.clone()));

    let ota = parser_value(parsed, "ota_update");
    let ota_files = ota
        .get("files_index")
        .cloned()
        .or_else(|| {
            ota.get("files").and_then(|f| f.as_object()).map(|m| {
                json!(m
                    .iter()
                    .map(|(p, v)| json!({
                        "path": p,
                        "char_count": v.as_str().map(|s| s.len()).unwrap_or(0),
                        "is_ips": p.ends_with(".ips"),
                    }))
                    .collect::<Vec<_>>())
            })
        })
        .unwrap_or(json!([]));
    let restore_hints = ota
        .get("restore_hints")
        .cloned()
        .unwrap_or(json!([]));

    let counts = json!({
        "mounts": mounts.len(),
        "sealed_or_readonly_roots": sealed_or_readonly_roots.len(),
        "ota_files": ota_files.as_array().map(|a| a.len()).unwrap_or(0),
        "restore_hints": restore_hints.as_array().map(|a| a.len()).unwrap_or(0),
    });
    json!({
        "analyser": "device_integrity",
        "mounts": mounts,
        "root_mounts": root_mounts,
        "sealed_or_readonly_roots": sealed_or_readonly_roots,
        "ota_files": ota_files,
        "restore_hints": restore_hints,
        "counts": counts,
        "notes": "Root/sealed mounts + OTAUpdateLogs / restore_perform hints."
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sees_sealed_root() {
        let mut parsed = HashMap::new();
        parsed.insert(
            "mount".into(),
            json!({
                "events": [{
                    "message": "/dev/disk0s1s1 on / (apfs, sealed, read-only)",
                    "data": {"mountpoint": "/", "sealed": true, "read_only": true}
                }],
                "root_mounts": [{"mountpoint": "/", "sealed": true}]
            }),
        );
        parsed.insert("ota_update".into(), json!({"files_index": [], "restore_hints": []}));
        let v = run(&parsed);
        assert_eq!(v["analyser"], "device_integrity");
        assert!(v["counts"]["sealed_or_readonly_roots"].as_u64().unwrap() >= 1);
    }
}
