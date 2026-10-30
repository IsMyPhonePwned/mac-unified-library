// SPDX-License-Identifier: GPL-3.0-only
//! wasm-bindgen bindings for mac-unified-library.

#![forbid(unsafe_code)]

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn version() -> String {
    mac_unified_library::VERSION.to_string()
}

#[wasm_bindgen]
pub fn module_count() -> u32 {
    mac_unified_library::ModuleRegistry::global().module_count() as u32
}

#[wasm_bindgen]
pub fn module_ids() -> js_sys::Array {
    let arr = js_sys::Array::new();
    for m in mac_unified_library::ModuleRegistry::global().modules() {
        arr.push(&JsValue::from_str(&m.id));
    }
    arr
}

/// Parse an NSPredicate subset string; returns ok/err as JSON.
#[wasm_bindgen]
pub fn parse_predicate(predicate: &str) -> String {
    match mac_unified_library::Filter::parse_predicate(predicate) {
        Ok(_) => serde_json::json!({ "ok": true }).to_string(),
        Err(e) => serde_json::json!({ "ok": false, "error": e.to_string() }).to_string(),
    }
}

/// Detect input kind for a path (native-oriented; on wasm often "unknown").
#[wasm_bindgen]
pub fn detect_kind(path: &str) -> String {
    match mac_unified_library::Input::detect(path) {
        Ok(i) => format!("{:?}", i.kind),
        Err(e) => format!("error:{e}"),
    }
}

/// Run info() against a filesystem path (available when FS is mounted / Node).
#[wasm_bindgen]
pub fn session_info(path: &str) -> Result<String, JsValue> {
    let mut session = mac_unified_library::Session::builder()
        .input(
            mac_unified_library::Input::detect(path)
                .map_err(|e| JsValue::from_str(&e.to_string()))?,
        )
        .build()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let info = session
        .info()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_json::to_string_pretty(&info).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Build a system overview JSON for a path.
#[wasm_bindgen]
pub fn session_overview(path: &str) -> Result<String, JsValue> {
    let mut session = mac_unified_library::Session::builder()
        .input(
            mac_unified_library::Input::detect(path)
                .map_err(|e| JsValue::from_str(&e.to_string()))?,
        )
        .log_event_cap(5_000)
        .build()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let _ = session.info();
    let ov = session
        .overview()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_json::to_string(&ov).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}
