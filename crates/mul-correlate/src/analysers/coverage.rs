// SPDX-License-Identifier: GPL-3.0-only

//! Parser coverage summary (JSON) vs HTML coverage reports.

use serde_json::{json, Value};
use std::collections::HashMap;

pub fn run(parsed: &HashMap<String, Value>, ctx: &super::AnalyseCtx) -> Value {
    let defined_total = ctx.parser_types_total;
    let present: std::collections::HashSet<_> = parsed.keys().cloned().collect();
    let mut not_in_run: Vec<_> = Vec::new();
    if defined_total > present.len() {
        not_in_run.push("(see parser_types_total vs parsed_keys_count)".to_string());
    }
    let mut present_sorted: Vec<_> = present.into_iter().collect();
    present_sorted.sort();
    json!({
        "analyser": "coverage",
        "parser_types_total": defined_total,
        "parsed_keys_count": parsed.len(),
        "parser_keys_present": present_sorted,
        "parser_types_not_in_map": not_in_run,
        "archive_file_count": ctx.archive_paths.len(),
        "notes": "Reports which parser IDs appear in the current parsed map plus archive file count."
    })
}