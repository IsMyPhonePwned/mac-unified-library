// SPDX-License-Identifier: GPL-3.0-only

//! Unified process inventory + per-PID source matrix across sysdiagnose parsers.

use std::collections::HashMap;
use serde_json::{json, Map, Value};
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashSet};

use super::common::{
    collect_remotectl_service_paths, first_word_command, logdata_line_context,
    logdata_line_process, parser_value, pid_from_row, spindump_pid_name_map, uuid2path_strings,
    value_looks_like_hard_error,
};

const ROW_METADATA_KEYS: &[&str] = &[
    "user",
    "pid",
    "ppid",
    "uid",
    "gid",
    "tty",
    "stat",
    "cpu",
    "mem",
    "vsz",
    "rss",
    "etime",
    "start",
    "nice",
    "pri",
    "wchan",
    "flag",
    "flags",
    "threads",
    "timestamp_info",
];

fn pid_from_json(v: &Value) -> Option<i64> {
    v.as_i64().or_else(|| v.as_str()?.parse().ok())
}

fn is_emptyish(v: &Value) -> bool {
    v.is_null() || v.as_str().map(|s| s.is_empty()).unwrap_or(false)
}

fn merge_if_absent(dst: &mut Map<String, Value>, key: &str, val: Value) {
    if is_emptyish(&val) {
        return;
    }
    let replace = match dst.get(key) {
        None => true,
        Some(x) => is_emptyish(x),
    };
    if replace {
        dst.insert(key.to_string(), val);
    }
}

fn push_source(dst: &mut Map<String, Value>, source: &'static str) {
    let arr = dst
        .entry("sources".to_string())
        .or_insert_with(|| json!([]));
    if let Value::Array(a) = arr {
        let j = json!(source);
        if !a.iter().any(|x| x == &j) {
            a.push(j);
        }
    }
}

fn new_entry(cmd: String, source: &'static str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("message".into(), json!(cmd.clone()));
    m.insert("command".into(), json!(cmd));
    m.insert("source".into(), json!(source));
    m.insert("sources".into(), json!([source]));
    m
}

fn merge_longer_command(dst: &mut Map<String, Value>, cmd: &str) {
    let cur = dst.get("command").and_then(|v| v.as_str()).unwrap_or("");
    if cmd.len() > cur.len() && !cmd.trim().is_empty() {
        let t = cmd.to_string();
        dst.insert("command".into(), json!(t.clone()));
        dst.insert("message".into(), json!(t));
    }
}

fn patch_from_ps_like_row(row: &Value) -> Map<String, Value> {
    let mut p = Map::new();
    let Some(obj) = row.as_object() else {
        return p;
    };
    for &k in ROW_METADATA_KEYS {
        if let Some(v) = obj.get(k) {
            if !is_emptyish(v) {
                p.insert(k.to_string(), v.clone());
            }
        }
    }
    p
}

fn merge_named_if_present(dst: &mut Map<String, Value>, src: &Map<String, Value>, from: &str, to: &str) {
    if let Some(v) = src.get(from) {
        merge_if_absent(dst, to, v.clone());
    }
}

fn patch_from_taskinfo_event(ev: &Value) -> Option<(String, Option<i64>, Map<String, Value>)> {
    let data = ev.get("data")?.as_object()?;
    let name = data
        .get("name")
        .or_else(|| data.get("process"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())?
        .to_string();

    let mut patch = Map::new();
    for key in [
        "pid",
        "ppid",
        "uid",
        "parent",
        "path",
        "file_path",
        "footprint",
        "run time",
        "started",
    ] {
        merge_named_if_present(&mut patch, data, key, key);
    }
    merge_named_if_present(&mut patch, data, "process_line", "taskinfo_process_line");
    merge_named_if_present(&mut patch, data, "process", "taskinfo_process");
    if let Some(n) = data
        .get("threads")
        .and_then(|t| t.as_array())
        .map(|a| a.len() as u64)
    {
        merge_if_absent(&mut patch, "threads", json!(n));
        merge_if_absent(&mut patch, "taskinfo_thread_blocks", json!(n));
    }
    if let Some(dt) = ev.get("datetime") {
        merge_if_absent(&mut patch, "datetime", dt.clone());
    }

    Some((name, data.get("pid").and_then(pid_from_json), patch))
}

fn patch_from_spindump_event(ev: &Value) -> Option<(String, Option<i64>, Map<String, Value>)> {
    if ev.get("timestamp_desc").and_then(|t| t.as_str()) != Some("process running during spindump") {
        return None;
    }
    let data = ev.get("data")?.as_object()?;
    let name = data
        .get("process")
        .or_else(|| data.get("name"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())?
        .to_string();

    let mut patch = Map::new();
    for key in ["pid", "ppid", "uid", "parent", "path", "file_path", "footprint", "time_since_fork"] {
        merge_named_if_present(&mut patch, data, key, key);
    }
    if let Some(dt) = ev.get("datetime") {
        merge_if_absent(&mut patch, "datetime", dt.clone());
    }
    if let Some(threads) = data.get("threads").and_then(|t| t.as_array()) {
        merge_if_absent(&mut patch, "threads", json!(threads.len()));
    }

    Some((name, data.get("pid").and_then(pid_from_json), patch))
}

fn dedup_key(pid: Option<i64>, cmd: &str) -> Option<String> {
    let base = first_word_command(cmd);
    if base.is_empty() {
        return None;
    }
    Some(if let Some(p) = pid.filter(|x| *x > 0) {
        format!("pid:{p}")
    } else {
        format!("base:{base}")
    })
}

fn register(
    by_key: &mut BTreeMap<String, Map<String, Value>>,
    cmd: &str,
    source: &'static str,
    pid_hint: Option<i64>,
    patch: Map<String, Value>,
) {
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return;
    }
    let pid = pid_hint
        .or_else(|| patch.get("pid").and_then(pid_from_json))
        .filter(|p| *p > 0);
    let Some(key) = dedup_key(pid, cmd) else {
        return;
    };

    match by_key.entry(key) {
        Entry::Vacant(v) => {
            let mut m = new_entry(cmd.to_string(), source);
            for (k, val) in patch {
                merge_if_absent(&mut m, &k, val);
            }
            v.insert(m);
        }
        Entry::Occupied(mut o) => {
            let dst = o.get_mut();
            push_source(dst, source);
            merge_longer_command(dst, cmd);
            for (k, val) in patch {
                merge_if_absent(dst, &k, val);
            }
        }
    }
}

fn sort_entries(mut maps: Vec<Map<String, Value>>) -> Vec<Value> {
    maps.sort_by(|a, b| {
        let pa = a
            .get("pid")
            .and_then(pid_from_json)
            .filter(|p| *p > 0)
            .unwrap_or(0);
        let pb = b
            .get("pid")
            .and_then(pid_from_json)
            .filter(|p| *p > 0)
            .unwrap_or(0);
        pa.cmp(&pb).then_with(|| {
            let ca = a.get("command").and_then(|v| v.as_str()).unwrap_or("");
            let cb = b.get("command").and_then(|v| v.as_str()).unwrap_or("");
            ca.cmp(cb)
        })
    });
    maps.into_iter().map(Value::Object).collect()
}

fn entry_pid(map: &Map<String, Value>) -> Option<i64> {
    map.get("pid").and_then(pid_from_json).filter(|p| *p > 0)
}

fn entry_name(map: &Map<String, Value>) -> Option<String> {
    map.get("process_name")
        .or_else(|| map.get("name"))
        .or_else(|| map.get("process"))
        .or_else(|| map.get("command"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(process_short_name)
        .filter(|s| !s.is_empty())
}

fn backfill_parent_processes(by_key: &mut BTreeMap<String, Map<String, Value>>) {
    let pid_to_name: BTreeMap<i64, String> = by_key
        .values()
        .filter_map(|row| Some((entry_pid(row)?, entry_name(row)?)))
        .collect();

    for row in by_key.values_mut() {
        let Some(ppid) = row.get("ppid").and_then(pid_from_json).filter(|p| *p > 0) else {
            continue;
        };
        merge_if_absent(row, "parent_pid", json!(ppid));
        if row
            .get("parent")
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.trim().is_empty())
        {
            continue;
        }
        if let Some(parent_name) = pid_to_name.get(&ppid) {
            merge_if_absent(row, "parent", json!(parent_name));
        }
    }
}

fn entry_executable_path(map: &Map<String, Value>) -> Option<String> {
    if let Some(p) = map
        .get("path")
        .or_else(|| map.get("file_path"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| s.starts_with('/'))
    {
        return Some(normalize_process_path(p));
    }
    let cmd = map
        .get("command")
        .or_else(|| map.get("command_line"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let (exe, _) = split_process_command(cmd);
    if exe.starts_with('/') {
        Some(normalize_process_path(&exe))
    } else {
        None
    }
}

fn entry_args(map: &Map<String, Value>) -> String {
    if let Some(a) = map.get("args").and_then(|v| v.as_str()).map(str::trim) {
        if !a.is_empty() {
            return a.to_string();
        }
    }
    let cmd = map
        .get("command")
        .or_else(|| map.get("command_line"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    split_process_command(cmd).1
}

/// Attach the longest argv seen for an executable path onto rows that share that path
/// but only have a short taskinfo/spindump name (different PIDs across snapshots).
fn backfill_args_by_path(by_key: &mut BTreeMap<String, Map<String, Value>>) {
    let mut path_args: BTreeMap<String, String> = BTreeMap::new();
    for row in by_key.values() {
        let Some(path) = entry_executable_path(row) else {
            continue;
        };
        let args = entry_args(row);
        if args.is_empty() {
            continue;
        }
        match path_args.entry(path) {
            Entry::Vacant(v) => {
                v.insert(args);
            }
            Entry::Occupied(mut o) => {
                if args.len() > o.get().len() {
                    o.insert(args);
                }
            }
        }
    }
    if path_args.is_empty() {
        return;
    }
    for row in by_key.values_mut() {
        let Some(path) = entry_executable_path(row) else {
            continue;
        };
        let Some(args) = path_args.get(&path) else {
            continue;
        };
        let cur = entry_args(row);
        if args.len() > cur.len() {
            row.insert("args".to_string(), json!(args));
            // Keep a forensic command_line that includes argv when we only had a bare name.
            let exe = row
                .get("path")
                .or_else(|| row.get("file_path"))
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| path.clone());
            let full = format!("{exe} {args}");
            merge_longer_command(row, &full);
            if !row.contains_key("command_line") {
                row.insert("command_line".to_string(), json!(full));
            } else if row
                .get("command_line")
                .and_then(|v| v.as_str())
                .map(|s| s.len() < full.len())
                .unwrap_or(true)
            {
                row.insert("command_line".to_string(), json!(full));
            }
        }
    }
}

fn finalize_entries(by_key: &mut BTreeMap<String, Map<String, Value>>) {
    for row in by_key.values_mut() {
        enrich_merged_process_row(row);
    }
    backfill_args_by_path(by_key);
    // Re-stamp names after args/command_line may have grown.
    for row in by_key.values_mut() {
        enrich_merged_process_row(row);
    }
}

pub fn run(parsed: &HashMap<String, Value>) -> Value {
    let mut by_key: BTreeMap<String, Map<String, Value>> = BTreeMap::new();

    let ps = parser_value(parsed, "ps");
    if let Some(rows) = ps.get("rows").and_then(|r| r.as_array()) {
        for row in rows {
            let cmd = row.get("command").and_then(|v| v.as_str()).unwrap_or("");
            let patch = patch_from_ps_like_row(row);
            register(&mut by_key, cmd, "ps", pid_from_row(row), patch);
        }
    }

    let psthread = parser_value(parsed, "psthread");
    if let Some(ent) = psthread.get("entries").and_then(|r| r.as_array()) {
        for row in ent {
            let cmd = row.get("command").and_then(|v| v.as_str()).unwrap_or("");
            let patch = patch_from_ps_like_row(row);
            register(&mut by_key, cmd, "psthread", pid_from_row(row), patch);
        }
    }

    let taskinfo = parser_value(parsed, "taskinfo");
    if let Some(events) = taskinfo.get("events").and_then(|r| r.as_array()) {
        for ev in events {
            let Some((name, pid, patch)) = patch_from_taskinfo_event(ev) else {
                continue;
            };
            register(&mut by_key, &name, "taskinfo", pid, patch);
        }
    }

    let shutdown = parser_value(parsed, "shutdownlogs");
    if let Some(events) = shutdown.get("events").and_then(|r| r.as_array()) {
        for ev in events {
            if let Some(data) = ev.get("data").and_then(|d| d.as_object()) {
                if let Some(cmd) = data.get("command").and_then(|v| v.as_str()) {
                    let mut patch = Map::new();
                    for (k, v) in data.iter() {
                        if k == "command" {
                            continue;
                        }
                        if !is_emptyish(v) {
                            patch.insert(k.clone(), v.clone());
                        }
                    }
                    if let Some(dt) = ev.get("datetime") {
                        merge_if_absent(&mut patch, "datetime", dt.clone());
                    }
                    register(
                        &mut by_key,
                        cmd,
                        "shutdownlogs",
                        data.get("pid").and_then(pid_from_json),
                        patch,
                    );
                }
            }
        }
    }

    let logdata = parser_value(parsed, "logdata_statistics");
    if let Value::Object(paths) = &logdata {
        for (_p, lines) in paths {
            let Some(arr) = lines.as_array() else {
                continue;
            };
            for line in arr {
                if let Some(proc) = logdata_line_process(line) {
                    let patch = logdata_line_context(line);
                    let pid = patch.get("pid").and_then(pid_from_json);
                    register(&mut by_key, &proc, "logdata_statistics", pid, patch);
                }
            }
        }
    }

    let u2p = parser_value(parsed, "uuid2path");
    if !value_looks_like_hard_error(&u2p) {
        if let Value::Object(files) = &u2p {
            for (_path, root) in files {
                for s in uuid2path_strings(&root) {
                    register(&mut by_key, &s, "uuid2path", None, Map::new());
                }
            }
        }
    }

    let rctl = parser_value(parsed, "remotectl_dumpstate");
    let mut svc_paths = Vec::new();
    collect_remotectl_service_paths(&rctl, &mut svc_paths);
    for s in svc_paths {
        register(&mut by_key, &s, "remotectl_dumpstate", None, Map::new());
    }

    let spin = parser_value(parsed, "spindumpnosymbols");
    if let Some(events) = spin.get("events").and_then(|r| r.as_array()) {
        for ev in events {
            let Some((name, pid, patch)) = patch_from_spindump_event(ev) else {
                continue;
            };
            register(&mut by_key, &name, "spindumpnosymbols", pid, patch);
        }
    }
    for (pid, name) in spindump_pid_name_map(&spin) {
        register(
            &mut by_key,
            &name,
            "spindumpnosymbols",
            Some(pid),
            Map::new(),
        );
    }

    backfill_parent_processes(&mut by_key);
    finalize_entries(&mut by_key);
    let entries = sort_entries(by_key.into_values().collect());
    let matrix = build_matrix(parsed);

    json!({
        "analyser": "processes",
        "entries": entries,
        "count": entries.len(),
        "matrix": matrix,
        "notes": "Merges ps/psthread/taskinfo/shutdownlogs/logdata_statistics/uuid2path/remotectl/spindump-nosymbols into `entries`; `matrix` is the per-PID presence table across ps/psthread/taskinfo/spindump."
    })
}

/// Per-PID presence across the core process parsers.
fn build_matrix(parsed: &HashMap<String, Value>) -> Vec<Value> {
    let ps = parser_value(parsed, "ps");
    let psthread = parser_value(parsed, "psthread");
    let taskinfo = parser_value(parsed, "taskinfo");

    let mut ps_by: BTreeMap<i64, Value> = BTreeMap::new();
    if let Some(rows) = ps.get("rows").and_then(|r| r.as_array()) {
        for row in rows {
            if let Some(pid) = pid_from_row(row) {
                ps_by.insert(pid, row.clone());
            }
        }
    }

    let mut pt_by: BTreeMap<i64, Value> = BTreeMap::new();
    if let Some(rows) = psthread.get("entries").and_then(|r| r.as_array()) {
        for row in rows {
            if let Some(pid) = pid_from_row(row) {
                pt_by.insert(pid, row.clone());
            }
        }
    }

    let mut ti_by: BTreeMap<i64, Value> = BTreeMap::new();
    if let Some(events) = taskinfo.get("events").and_then(|r| r.as_array()) {
        for ev in events {
            if let Some(data) = ev.get("data") {
                if let Some(pid) = pid_from_row(data) {
                    ti_by.insert(pid, data.clone());
                }
            }
        }
    }

    let mut spin_by: BTreeMap<i64, String> = BTreeMap::new();
    let spin = parser_value(parsed, "spindumpnosymbols");
    for (pid, name) in spindump_pid_name_map(&spin) {
        spin_by.entry(pid).or_insert(name);
    }

    let mut all_pids: Vec<i64> = ps_by
        .keys()
        .chain(pt_by.keys())
        .chain(ti_by.keys())
        .chain(spin_by.keys())
        .copied()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    all_pids.sort_unstable();

    let mut matrix = Vec::new();
    for pid in all_pids {
        let ps_val = ps_by.get(&pid).map(|_| "ps").unwrap_or("-");
        let pt_val = pt_by.get(&pid).map(|_| "psthread").unwrap_or("-");
        let ti_val = ti_by.get(&pid).map(|_| "taskinfo").unwrap_or("-");
        let sd_val = spin_by
            .get(&pid)
            .map(|_| "spindumpnosymbols")
            .unwrap_or("-");
        let ps_pid = ps_by.get(&pid).and_then(pid_from_row);
        let pt_pid = pt_by.get(&pid).and_then(pid_from_row);
        let ti_pid = ti_by.get(&pid).and_then(pid_from_row);
        let sd_pid = spin_by.get(&pid).map(|_| pid);
        let pid_consistent = [ps_pid, pt_pid, ti_pid, sd_pid]
            .into_iter()
            .flatten()
            .all(|p| p == pid);
        matrix.push(json!({
            "pid": pid,
            "in_ps": ps_by.contains_key(&pid),
            "in_psthread": pt_by.contains_key(&pid),
            "in_taskinfo": ti_by.contains_key(&pid),
            "in_spindumpnosymbols": spin_by.contains_key(&pid),
            "pid_field_consistent": pid_consistent,
            "ps_command": ps_by.get(&pid).and_then(|r| r.get("command")),
            "psthread_command": pt_by.get(&pid).and_then(|r| r.get("command")),
            "taskinfo_name": ti_by.get(&pid).and_then(|r| r.get("name")),
            "spindump_process": spin_by.get(&pid),
            "sources_present": format!("{ps_val} / {pt_val} / {ti_val} / {sd_val}"),
        }));
    }
    matrix
}
fn process_short_name(command: &str) -> String {
    let cleaned = command.trim();
    if cleaned.is_empty() {
        return String::new();
    }
    let token = cleaned.split_whitespace().next().unwrap_or(cleaned);
    let base = token.rsplit('/').next().unwrap_or(token);
    let base = base.trim_matches(|c| c == '(' || c == ')');
    if let Some((head, _)) = base.split_once(':') {
        if !head.is_empty() {
            return head.to_string();
        }
    }
    base.to_string()
}

fn split_process_command(command: &str) -> (String, String) {
    let cmd = command.trim();
    if cmd.is_empty() {
        return (String::new(), String::new());
    }
    let first = cmd.split_whitespace().next().unwrap_or(cmd);
    if first.contains(':') && !first.starts_with('/') {
        return (cmd.to_string(), String::new());
    }
    if let Some((exe, rest)) = cmd.split_once(char::is_whitespace) {
        let rest = rest.trim();
        if !rest.is_empty() {
            return (exe.to_string(), rest.to_string());
        }
    }
    (cmd.to_string(), String::new())
}

fn normalize_process_path(path: &str) -> String {
    let t = path.trim();
    t.strip_prefix("/private").unwrap_or(t).trim_end_matches('/').to_string()
}

fn enrich_merged_process_row(obj: &mut Map<String, Value>) {
    let command = obj
        .get("command")
        .or_else(|| obj.get("command_line"))
        .or_else(|| obj.get("message"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if command.is_empty() {
        return;
    }
    if !obj.contains_key("command_line") {
        obj.insert("command_line".to_string(), json!(command.clone()));
    }
    let (exe, args) = split_process_command(&command);
    if !args.is_empty() {
        let cur = obj.get("args").and_then(|v| v.as_str()).unwrap_or("");
        if args.len() >= cur.len() {
            obj.insert("args".to_string(), json!(args));
        }
    }
    if exe.starts_with('/') {
        let path_empty = obj
            .get("path")
            .or_else(|| obj.get("file_path"))
            .and_then(|v| v.as_str())
            .map(|s| s.is_empty())
            .unwrap_or(true);
        if path_empty {
            obj.insert("path".to_string(), json!(exe));
        }
    }
    let name = process_short_name(&command);
    if !name.is_empty() {
        obj.insert("name".to_string(), json!(name.clone()));
        obj.insert("process".to_string(), json!(name.clone()));
        obj.insert("process_name".to_string(), json!(name));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_aligns_ps_psthread_taskinfo() {
        let mut parsed = HashMap::new();
        parsed.insert(
            "ps".into(),
            json!({
                "parser": "ps",
                "rows": [{"user": "root", "pid": 1, "command": "/sbin/launchd"}]
            }),
        );
        parsed.insert(
            "psthread".into(),
            json!({
                "parser": "psthread",
                "entries": [{"user": "root", "pid": 1, "command": "/sbin/launchd"}]
            }),
        );
        parsed.insert(
            "taskinfo".into(),
            json!({
                "parser": "taskinfo",
                "events": [{"data": {"pid": 1, "name": "/sbin/launchd"}}]
            }),
        );
        let v = run(&parsed);
        assert_eq!(v["analyser"], "processes");
        let rows = v["matrix"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["sources_present"], "ps / psthread / taskinfo / -");
        assert!(v["count"].as_u64().unwrap() >= 1);
    }
}
