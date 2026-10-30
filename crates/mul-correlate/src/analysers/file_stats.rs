// SPDX-License-Identifier: GPL-3.0-only

//! File and directory statistics for the archive.

use std::collections::HashMap;
use serde_json::{json, Value};
use std::collections::BTreeMap;


use super::common::mime_hint_by_extension;

pub fn run(parsed: &HashMap<String, Value>, ctx: &super::AnalyseCtx) -> Value {
    let device = super::common::device_props_from_remotectl(parsed);
    let mut by_top: BTreeMap<String, usize> = BTreeMap::new();
    let mut extensions: BTreeMap<String, usize> = BTreeMap::new();
    let mut dir_agg: BTreeMap<String, (usize, BTreeMap<String, usize>)> = BTreeMap::new();
    for path in &ctx.archive_paths {
        let top = path.split('/').next().unwrap_or("").to_string();
        if !top.is_empty() {
            *by_top.entry(top).or_insert(0) += 1;
        }
        let ext = std::path::Path::new(path)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        let ext_key = if ext.is_empty() {
            "(none)".to_string()
        } else {
            format!(".{ext}")
        };
        *extensions.entry(ext_key).or_insert(0) += 1;

        let parent = path
            .rfind('/')
            .map(|i| path[..i].to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| ".".to_string());
        let mime = mime_hint_by_extension(path);
        let ent = dir_agg
            .entry(parent)
            .or_insert_with(|| (0, BTreeMap::new()));
        ent.0 += 1;
        *ent.1.entry(mime.to_string()).or_insert(0) += 1;
    }
    let mut dir_rows: Vec<Value> = Vec::new();
    let mut dir_list: Vec<(String, (usize, BTreeMap<String, usize>))> =
        dir_agg.into_iter().collect();
    dir_list.sort_by(|a, b| b.1 .0.cmp(&a.1 .0));
    for (dir_path, (count, mimes)) in dir_list.into_iter().take(100) {
        dir_rows.push(json!({
            "directory": dir_path,
            "file_count": count,
            "mime_by_extension_hint": mimes,
        }));
    }
    json!({
        "analyser": "file_stats",
        "device": device,
        "archive_total_files": ctx.archive_paths.len(),
        "by_top_level_segment": by_top,
        "extensions": extensions,
        "by_directory": dir_rows,
        "notes": "`mime_by_extension_hint` is extension-based (no libmagic); `by_directory` caps at 100 folders by file count."
    })
}