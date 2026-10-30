// SPDX-License-Identifier: GPL-3.0-only
//! Exporters: NDJSON, CSV, Timesketch, reports, SQLite.

#![forbid(unsafe_code)]

use mul_core::event::Event;
use mul_correlate::SystemOverview;
use serde_json::Value;
use std::io::{self, Write};

pub fn write_overview_json(out: &mut dyn Write, overview: &SystemOverview) -> io::Result<()> {
    serde_json::to_writer_pretty(out, overview)?;
    Ok(())
}

pub fn write_overview_markdown(out: &mut dyn Write, overview: &SystemOverview) -> io::Result<()> {
    writeln!(out, "# System overview")?;
    writeln!(out)?;
    writeln!(out, "Schema version: {}", overview.schema_version)?;
    writeln!(out, "Tool: {}", overview.collection.tool_version)?;
    if !overview.collection.inputs.is_empty() {
        writeln!(out, "## Inputs")?;
        for i in &overview.collection.inputs {
            writeln!(out, "- `{i}`")?;
        }
    }
    writeln!(out, "## Device")?;
    if let Some(model) = &overview.device.model {
        writeln!(out, "- Model: {model}")?;
    }
    if let Some(build) = &overview.device.os_build {
        writeln!(out, "- OS build: {build}")?;
    }
    if let Some(hw) = &overview.device.hardware_id {
        writeln!(out, "- Hardware: {hw}")?;
    }
    writeln!(out, "## Boots ({})", overview.boots.len())?;
    for b in &overview.boots {
        writeln!(out, "- `{}`", b.uuid)?;
    }
    writeln!(out, "## Apps ({})", overview.apps.len())?;
    for a in overview.apps.iter().take(40) {
        writeln!(out, "- {} ({})", a.bundle_id, a.event_count)?;
    }
    writeln!(out, "## Processes")?;
    writeln!(
        out,
        "- Unique executables: {}",
        overview.processes.unique_executables
    )?;
    writeln!(out, "## Logs")?;
    writeln!(out, "- Events: {}", overview.logs.event_estimate)?;
    writeln!(out, "## Anomalies ({})", overview.anomalies.len())?;
    for f in &overview.anomalies {
        writeln!(
            out,
            "- [{}] {}: {}",
            f.severity, f.rule_id, f.explanation
        )?;
    }
    Ok(())
}

pub fn write_overview_html(out: &mut dyn Write, overview: &SystemOverview) -> io::Result<()> {
    let json = serde_json::to_string(overview).unwrap_or_else(|_| "{}".into());
    let escaped = html_escape(&json);
    writeln!(out, "<!DOCTYPE html>")?;
    writeln!(out, "<html lang=\"en\"><head><meta charset=\"utf-8\">")?;
    writeln!(out, "<title>System overview</title>")?;
    writeln!(
        out,
        "<style>
body{{font-family:ui-sans-serif,system-ui,sans-serif;margin:2rem;background:#0f1419;color:#e7ecf1;}}
h1,h2{{font-weight:600}} .card{{background:#1a222c;padding:1rem 1.25rem;margin:1rem 0;border-radius:8px}}
code,pre{{font-family:ui-monospace,monospace;font-size:12px}} pre{{overflow:auto;max-height:40vh}}
.sev-high{{color:#ff6b6b}} .sev-medium{{color:#ffd166}} .muted{{opacity:.7}}
</style>"
    )?;
    writeln!(out, "</head><body>")?;
    writeln!(out, "<h1>System overview</h1>")?;
    writeln!(
        out,
        "<p class=\"muted\">schema {} · {}</p>",
        overview.schema_version, overview.collection.tool_version
    )?;
    writeln!(out, "<div class=\"card\"><h2>Device</h2><ul>")?;
    if let Some(m) = &overview.device.model {
        writeln!(out, "<li>Model: {}</li>", html_escape(m))?;
    }
    if let Some(b) = &overview.device.os_build {
        writeln!(out, "<li>Build: {}</li>", html_escape(b))?;
    }
    writeln!(out, "</ul></div>")?;
    writeln!(
        out,
        "<div class=\"card\"><h2>Logs</h2><p>{} events</p></div>",
        overview.logs.event_estimate
    )?;
    writeln!(
        out,
        "<div class=\"card\"><h2>Apps</h2><ul>"
    )?;
    for a in overview.apps.iter().take(30) {
        writeln!(
            out,
            "<li>{} <span class=\"muted\">({})</span></li>",
            html_escape(&a.bundle_id),
            a.event_count
        )?;
    }
    writeln!(out, "</ul></div>")?;
    writeln!(out, "<div class=\"card\"><h2>Anomalies</h2><ul>")?;
    for f in &overview.anomalies {
        writeln!(
            out,
            "<li class=\"sev-{}\">[{}] {}</li>",
            html_escape(&f.severity),
            html_escape(&f.rule_id),
            html_escape(&f.explanation)
        )?;
    }
    writeln!(out, "</ul></div>")?;
    writeln!(
        out,
        "<div class=\"card\"><h2>Raw JSON</h2><pre>{}</pre></div>",
        escaped
    )?;
    writeln!(out, "</body></html>")?;
    Ok(())
}

pub fn write_events_ndjson(out: &mut dyn Write, events: &[Event]) -> io::Result<()> {
    for e in events {
        let v = serde_json::json!({
            "timestamp": e.ts,
            "ts_quality": e.ts_quality,
            "source": e.source.0,
            "kind": e.kind,
            "message": e.message.as_str(),
        });
        serde_json::to_writer(&mut *out, &v)?;
        writeln!(out)?;
    }
    Ok(())
}

pub fn write_events_csv(out: &mut dyn Write, events: &[Event]) -> io::Result<()> {
    writeln!(out, "timestamp,source,kind,message")?;
    for e in events {
        writeln!(
            out,
            "{},{},{:?},\"{}\"",
            e.ts,
            csv_escape(&e.source.0),
            e.kind,
            csv_escape(e.message.as_str())
        )?;
    }
    Ok(())
}

pub fn write_timesketch_jsonl(out: &mut dyn Write, events: &[Event]) -> io::Result<()> {
    for e in events {
        if e.ts == i64::MIN {
            continue;
        }
        let v = serde_json::json!({
            "datetime": e.ts,
            "timestamp_desc": e.source.0,
            "message": e.message.as_str(),
            "data_type": format!("{:?}", e.kind),
        });
        serde_json::to_writer(&mut *out, &v)?;
        writeln!(out)?;
    }
    Ok(())
}

pub fn write_timesketch_csv(out: &mut dyn Write, events: &[Event]) -> io::Result<()> {
    writeln!(out, "datetime,timestamp_desc,message")?;
    for e in events {
        if e.ts == i64::MIN {
            continue;
        }
        writeln!(
            out,
            "{},{},\"{}\"",
            e.ts,
            csv_escape(&e.source.0),
            csv_escape(e.message.as_str())
        )?;
    }
    Ok(())
}

pub fn write_json_value(out: &mut dyn Write, v: &Value) -> io::Result<()> {
    serde_json::to_writer_pretty(out, v)?;
    Ok(())
}

/// Write a minimal APOLLO-compatible TSV (activity + timestamp + attrs).
pub fn write_apollo_tsv(out: &mut dyn Write, events: &[Event]) -> io::Result<()> {
    writeln!(out, "ACTIVITY\tTIMESTAMP\tSOURCE\tMESSAGE")?;
    for e in events {
        writeln!(
            out,
            "{:?}\t{}\t{}\t{}",
            e.kind,
            e.ts,
            e.source.0,
            e.message.as_str().replace('\t', " ")
        )?;
    }
    Ok(())
}

#[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
pub fn write_events_sqlite(path: &std::path::Path, events: &[Event]) -> io::Result<()> {
    use rusqlite::Connection;
    let conn = Connection::open(path).map_err(io::Error::other)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS events (
            ts INTEGER, source TEXT, kind TEXT, message TEXT, evidence TEXT
         );
         CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);",
    )
    .map_err(io::Error::other)?;
    let tx = conn.unchecked_transaction().map_err(io::Error::other)?;
    {
        let mut stmt = tx
            .prepare("INSERT INTO events (ts, source, kind, message, evidence) VALUES (?1,?2,?3,?4,?5)")
            .map_err(io::Error::other)?;
        for e in events {
            stmt.execute(rusqlite::params![
                e.ts,
                e.source.0,
                format!("{:?}", e.kind),
                e.message.as_str(),
                e.evidence.path,
            ])
            .map_err(io::Error::other)?;
        }
    }
    tx.commit().map_err(io::Error::other)?;
    Ok(())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn csv_escape(s: &str) -> String {
    s.replace('"', "\"\"")
}
