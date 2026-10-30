// SPDX-License-Identifier: GPL-3.0-only
//! Python bindings for mac-unified-library.

use mac_unified_library::{
    AnalyserId, Input, ModuleRegistry, Session, SystemOverview, VERSION,
};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use serde_json::Value;

#[pyfunction]
fn version() -> &'static str {
    VERSION
}

#[pyfunction]
fn list_modules() -> Vec<String> {
    ModuleRegistry::global()
        .modules()
        .iter()
        .map(|m| m.id.clone())
        .collect()
}

#[pyfunction]
fn module_count() -> usize {
    ModuleRegistry::global().module_count()
}

#[pyfunction]
fn list_parsers() -> Vec<String> {
    Session::list_parsers()
}

#[pyfunction]
fn list_analysers() -> Vec<String> {
    AnalyserId::all()
        .iter()
        .map(|a| a.as_str().to_string())
        .collect()
}

#[pyfunction]
fn list_compat_analysers() -> Vec<String> {
    AnalyserId::compat_ids()
        .iter()
        .map(|a| a.as_str().to_string())
        .collect()
}

fn session_for(path: &str) -> PyResult<Session> {
    Session::builder()
        .input(
            Input::detect(path).map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?,
        )
        .build()
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}

fn resolve_analyser_ids(names: Option<Vec<String>>) -> Vec<AnalyserId> {
    match names {
        Some(names) => names.iter().filter_map(|s| AnalyserId::parse(s)).collect(),
        None => AnalyserId::compat_ids().to_vec(),
    }
}

#[pyfunction]
fn info(py: Python<'_>, path: &str) -> PyResult<PyObject> {
    let mut session = session_for(path)?;
    let v = session
        .info()
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
    json_to_py(py, &v)
}

#[pyfunction]
fn overview(py: Python<'_>, path: &str) -> PyResult<PyObject> {
    let mut session = session_for(path)?;
    let ov: SystemOverview = session
        .overview()
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
    let v = serde_json::to_value(&ov)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
    json_to_py(py, &v)
}

#[pyfunction]
#[pyo3(signature = (path, analysers=None, install_rules_toml=None))]
fn analyse(
    py: Python<'_>,
    path: &str,
    analysers: Option<Vec<String>>,
    install_rules_toml: Option<String>,
) -> PyResult<PyObject> {
    let mut session = session_for(path)?;
    if let Some(toml) = install_rules_toml {
        session.set_install_enrichment_rules_toml(Some(toml));
    }
    let ids = resolve_analyser_ids(analysers);
    if ids.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "no matching analysers (see mac_unified.list_analysers())",
        ));
    }
    let map = session
        .analyse(&ids)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
    let v = serde_json::to_value(&map)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
    json_to_py(py, &v)
}

#[pyfunction]
#[pyo3(signature = (path, parsers=None, decode_logarchive=false))]
fn parse(
    py: Python<'_>,
    path: &str,
    parsers: Option<Vec<String>>,
    decode_logarchive: bool,
) -> PyResult<PyObject> {
    let mut session = session_for(path)?;
    let names = parsers.unwrap_or_default();
    let report = session
        .parse_parsers(&names, decode_logarchive)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
    let mut envelope = serde_json::Map::new();
    for (k, v) in report.values {
        let ms = report.timings_ms.get(&k).copied().unwrap_or(0.0);
        envelope.insert(
            k,
            serde_json::json!({
                "ok": true,
                "duration_ms": ms,
                "data": v,
            }),
        );
    }
    for (k, e) in report.errors {
        let ms = report.timings_ms.get(&k).copied().unwrap_or(0.0);
        envelope.insert(
            k,
            serde_json::json!({
                "ok": false,
                "duration_ms": ms,
                "error": e,
            }),
        );
    }
    envelope.insert(
        "_meta".into(),
        serde_json::json!({
            "wall_ms": report.wall_ms,
            "parser_count": report.timings_ms.len(),
        }),
    );
    json_to_py(py, &Value::Object(envelope))
}

#[pyfunction]
fn apollo_run(py: Python<'_>, module_id: &str, db_path: &str) -> PyResult<PyObject> {
    let session = Session::builder()
        .input(Input::detect(".").map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?)
        .build()
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
    let (status, rows) = session
        .apollo_run_module_on_path(module_id, db_path)
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
    let dict = PyDict::new(py);
    dict.set_item("status", format!("{status:?}"))?;
    dict.set_item("rows", rows.len())?;
    let events: Vec<Value> = rows
        .iter()
        .map(|e| {
            serde_json::json!({
                "ts": e.ts,
                "ts_quality": format!("{:?}", e.ts_quality),
                "message": e.message.as_str(),
                "source": e.source.0,
            })
        })
        .collect();
    dict.set_item("events", json_to_py(py, &Value::Array(events))?)?;
    Ok(dict.into())
}

fn json_to_py(py: Python<'_>, v: &Value) -> PyResult<PyObject> {
    let s = serde_json::to_string(v).unwrap_or_else(|_| "null".into());
    let json = py.import("json")?;
    Ok(json.call_method1("loads", (s,))?.into())
}

#[pymodule]
fn mac_unified(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(list_modules, m)?)?;
    m.add_function(wrap_pyfunction!(module_count, m)?)?;
    m.add_function(wrap_pyfunction!(list_parsers, m)?)?;
    m.add_function(wrap_pyfunction!(list_analysers, m)?)?;
    m.add_function(wrap_pyfunction!(list_compat_analysers, m)?)?;
    m.add_function(wrap_pyfunction!(info, m)?)?;
    m.add_function(wrap_pyfunction!(overview, m)?)?;
    m.add_function(wrap_pyfunction!(analyse, m)?)?;
    m.add_function(wrap_pyfunction!(parse, m)?)?;
    m.add_function(wrap_pyfunction!(apollo_run, m)?)?;
    Ok(())
}
