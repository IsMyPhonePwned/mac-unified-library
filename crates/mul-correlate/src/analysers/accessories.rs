// SPDX-License-Identifier: GPL-3.0-only

//! Bluetooth / AWDL pairings and USB accessory inventory.

use serde_json::{json, Map, Value};
use std::collections::HashMap;

use super::common::parser_value;

fn walk_usb(node: &Value, path: &str, out: &mut Vec<Value>) {
    let Value::Object(map) = node else {
        return;
    };
    let interesting_keys = [
        "USB Vendor Name",
        "USB Product Name",
        "USBVendorName",
        "USBProductName",
        "idVendor",
        "idProduct",
        "USB Serial Number",
        "kUSBSerialNumberString",
        "USB Address",
        "sessionID",
    ];
    let has = interesting_keys.iter().any(|k| map.contains_key(*k));
    if has {
        let mut row = Map::new();
        row.insert("ioreg_path".into(), json!(path));
        for k in interesting_keys {
            if let Some(v) = map.get(k) {
                row.insert(k.into(), v.clone());
            }
        }
        // class name often in IOObjectClass / name
        if let Some(v) = map.get("IOObjectClass").or_else(|| map.get("name")) {
            row.insert("class".into(), v.clone());
        }
        out.push(Value::Object(row));
    }
    for (k, child) in map {
        if child.is_object() {
            let child_path = if path.is_empty() {
                k.clone()
            } else {
                format!("{path}/{k}")
            };
            walk_usb(child, &child_path, out);
        }
    }
}

pub fn run(parsed: &HashMap<String, Value>) -> Value {
    let bt = parser_value(parsed, "bluetooth");
    let bluetooth = json!({
        "summary": bt.get("summary").cloned().unwrap_or(Value::Null),
        "devices": bt.get("devices").cloned().unwrap_or(json!([])),
        "event_count": bt.get("events").and_then(|e| e.as_array()).map(|a| a.len()).unwrap_or(0),
        "file_count": bt.get("files").and_then(|f| f.as_object()).map(|m| m.len()).unwrap_or(0),
    });

    let usb = parser_value(parsed, "iousb");
    let mut usb_devices = Vec::new();
    if let Some(tree) = usb.get("tree") {
        walk_usb(tree, "", &mut usb_devices);
    }
    usb_devices.truncate(500);
    let counts = json!({
        "bluetooth_devices": bluetooth.get("devices").and_then(|d| d.as_array()).map(|a| a.len()).unwrap_or(0),
        "usb_devices": usb_devices.len(),
    });

    json!({
        "analyser": "accessories",
        "bluetooth": bluetooth,
        "usb_devices": usb_devices,
        "counts": counts,
        "notes": "Bluetooth status summary/devices + USB IORegistry accessory walk."
    })
}
