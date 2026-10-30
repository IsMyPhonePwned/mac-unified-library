// SPDX-License-Identifier: GPL-3.0-only

//! MCState shared profile stub summaries.

use serde_json::{json, Value};

use std::collections::HashMap;

pub fn run(_parsed: &HashMap<String, Value>, ctx: &super::AnalyseCtx) -> Value {
    let mut rows = Vec::new();
    for path in &ctx.archive_paths {
        if !path.contains("logs/MCState/Shared/profile-") || !path.ends_with(".stub") {
            continue;
        }
        if let Some(s) = ctx.archive_stub_texts.get(path) {
            rows.push(json!({
                "path": path,
                "char_count": s.len(),
                "line_count": s.lines().count(),
                "preview": s.chars().take(400).collect::<String>(),
            }));
        }
    }
    json!({
        "analyser": "mcstateshared",
        "rows": rows,
        "note": "MCState profile stubs are raw text; PayloadContent is not flattened to CSV.",
        "notes": "Lists per-file stub previews (path, size, line count, text preview)."
    })
}