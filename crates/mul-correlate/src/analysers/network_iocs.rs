// SPDX-License-Identifier: GPL-3.0-only

//! Collect IPv4 addresses, hostnames, URLs, and Wi‑Fi SSIDs from parser JSON (network hunting).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use regex::Regex;
use std::collections::HashMap;
use serde_json::{json, Value};


use super::common::{parser_value};

const HITS_CAP: usize = 512;

const SOURCE_PARSERS: &[&str] = &[
    "powerlogs", "swcutil", "safari_history", "knowledgec", "netusage", "interactionc",
    "quarantine_events", "screentime", "networkextension", "networkextensioncache", "plists",
    "logarchive", "transparency_json", "crashlogs", "logdata_statistics", "logdata_statistics_txt",
    "taskinfo", "shutdownlogs", "wifi_known_networks", "wifinetworks", "wifiscan",
];

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct HitKey {
    kind: String,
    value: String,
    source_parser: String,
    json_path: String,
}

fn ipv4_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?x)
            \b
            (?:
                (?:25[0-5]|2[0-4]\d|[01]?\d\d?)
                \.
            ){3}
            (?:25[0-5]|2[0-4]\d|[01]?\d\d?)
            \b",
        )
        .expect("ipv4 regex")
    })
}

fn url_host_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)(?:https?|ftp)://([^/?#\s]+)").expect("url host regex"))
}

fn domain_like_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?xi)
            ^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+
            [a-z]{2,63}$
            ",
        )
        .expect("domain regex")
    })
}

fn normalize_host(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host == "localhost" {
        return None;
    }
    if ipv4_re().is_match(&host) {
        return None;
    }
    if domain_like_re().is_match(&host) {
        return Some(host);
    }
    None
}

fn hosts_from_url(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    for cap in url_host_re().captures_iter(s) {
        if let Some(h) = cap.get(1) {
            let raw = h.as_str();
            let host = raw.split('@').next().unwrap_or(raw);
            let host = host.split(':').next().unwrap_or(host);
            if let Some(d) = normalize_host(host) {
                out.push(d);
            }
        }
    }
    out
}

fn key_suggests_wifi_identifier_field(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    k == "ssid" || k == "bssid" || k == "access point" || k.ends_with("ssid")
}

fn key_suggests_network_field(key: &str) -> bool {
    if key_suggests_wifi_identifier_field(key) {
        return false;
    }
    let k = key.to_ascii_lowercase();
    k.contains("domain")
        || k.contains("hostname")
        || k.contains("host")
        || k.contains("url")
        || k.contains("server")
}

fn record_hit(
    hits: &mut Vec<Value>,
    seen: &mut BTreeSet<HitKey>,
    kind: &str,
    value: &str,
    source_parser: &str,
    json_path: &str,
) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    let key = HitKey {
        kind: kind.to_string(),
        value: value.to_string(),
        source_parser: source_parser.to_string(),
        json_path: json_path.to_string(),
    };
    if !seen.insert(key) {
        return;
    }
    if hits.len() >= HITS_CAP {
        return;
    }
    hits.push(json!({
        "kind": kind,
        "value": value,
        "source_parser": source_parser,
        "json_path": json_path,
    }));
}

fn record_wifi_identifier(
    hits: &mut Vec<Value>,
    seen: &mut BTreeSet<HitKey>,
    key: &str,
    value: &str,
    source_parser: &str,
    json_path: &str,
) {
    let value = value.trim();
    if value.is_empty() || value.eq_ignore_ascii_case("unknown") {
        return;
    }
    let kind = if key.to_ascii_lowercase().contains("bssid") {
        "bssid"
    } else {
        "ssid"
    };
    record_hit(hits, seen, kind, value, source_parser, json_path);
}

fn scan_string(
    s: &str,
    key: Option<&str>,
    source_parser: &str,
    json_path: &str,
    hits: &mut Vec<Value>,
    seen: &mut BTreeSet<HitKey>,
) {
    for m in ipv4_re().find_iter(s) {
        record_hit(
            hits,
            seen,
            "ipv4",
            m.as_str(),
            source_parser,
            json_path,
        );
    }
    if s.contains("://") {
        for host in hosts_from_url(s) {
            record_hit(
                hits,
                seen,
                "domain",
                &host,
                source_parser,
                json_path,
            );
        }
        if s.starts_with("http://") || s.starts_with("https://") || s.starts_with("ftp://") {
            record_hit(hits, seen, "url", s, source_parser, json_path);
        }
    }
    if let Some(k) = key {
        if key_suggests_wifi_identifier_field(k) {
            record_wifi_identifier(hits, seen, k, s, source_parser, json_path);
        } else if key_suggests_network_field(k) {
            if k.contains("url") || s.contains("://") {
                for host in hosts_from_url(s) {
                    record_hit(
                        hits,
                        seen,
                        "domain",
                        &host,
                        source_parser,
                        json_path,
                    );
                }
                if s.contains("://") {
                    record_hit(hits, seen, "url", s, source_parser, json_path);
                }
            } else if k.contains("ip") {
                for m in ipv4_re().find_iter(s) {
                    record_hit(
                        hits,
                        seen,
                        "ipv4",
                        m.as_str(),
                        source_parser,
                        json_path,
                    );
                }
            } else if let Some(d) = normalize_host(s) {
                record_hit(hits, seen, "domain", &d, source_parser, json_path);
            }
        }
    }
}

fn walk_value(
    val: &Value,
    source_parser: &str,
    path: &str,
    hits: &mut Vec<Value>,
    seen: &mut BTreeSet<HitKey>,
) {
    match val {
        Value::String(s) => {
            let key = path.rsplit('.').next();
            scan_string(s, key, source_parser, path, hits, seen);
        }
        Value::Array(a) => {
            for (i, item) in a.iter().enumerate() {
                walk_value(
                    item,
                    source_parser,
                    &format!("{path}[{i}]"),
                    hits,
                    seen,
                );
            }
        }
        Value::Object(m) => {
            for (k, v) in m {
                let p = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                if let Value::String(s) = v {
                    scan_string(s, Some(k), source_parser, &p, hits, seen);
                } else {
                    walk_value(v, source_parser, &p, hits, seen);
                }
            }
        }
        _ => {}
    }
}

fn logarchive_has_events(v: &Value) -> bool {
    v.get("events")
        .and_then(|e| e.as_array())
        .is_some_and(|a| !a.is_empty())
}

fn scan_logarchive(
    parsed: &HashMap<String, Value>,
    hits: &mut Vec<Value>,
    seen: &mut BTreeSet<HitKey>,
    logarchive_decode: &mut Value,
) {
    let v = parser_value(parsed, "logarchive");
    walk_value(&v, "logarchive", "", hits, seen);

    if logarchive_has_events(&v) {
        *logarchive_decode = json!({
            "status": v.get("decode").cloned().unwrap_or(json!("from_parser")),
            "source": "parser_output",
        });
        return;
    }

    *logarchive_decode = json!({
        "status": v.get("decode").cloned().unwrap_or(json!("deferred")),
        "source": "parser_output",
        "note": "Unified log IOC scan uses mul-unifiedlog when IngestPlan.decode_logarchive is set (enabled for network_iocs).",
    });
}

pub fn run(parsed: &HashMap<String, Value>) -> Value {
    let mut hits: Vec<Value> = Vec::new();
    let mut seen: BTreeSet<HitKey> = BTreeSet::new();
    let mut logarchive_decode = Value::Null;

    for parser_id in SOURCE_PARSERS {
        if *parser_id == "logarchive" {
            scan_logarchive(parsed, &mut hits, &mut seen, &mut logarchive_decode);
            continue;
        }
        let v = parser_value(parsed, parser_id);
        walk_value(&v, parser_id, "", &mut hits, &mut seen);
    }

    let mut ipv4: BTreeSet<String> = BTreeSet::new();
    let mut domains: BTreeSet<String> = BTreeSet::new();
    let mut urls: BTreeSet<String> = BTreeSet::new();
    let mut ssids: BTreeSet<String> = BTreeSet::new();
    let mut bssids: BTreeSet<String> = BTreeSet::new();
    for h in &hits {
        let kind = h.get("kind").and_then(|x| x.as_str()).unwrap_or("");
        let value = h.get("value").and_then(|x| x.as_str()).unwrap_or("");
        match kind {
            "ipv4" => {
                ipv4.insert(value.to_string());
            }
            "domain" => {
                domains.insert(value.to_string());
            }
            "url" => {
                urls.insert(value.to_string());
            }
            "ssid" => {
                ssids.insert(value.to_string());
            }
            "bssid" => {
                bssids.insert(value.to_string());
            }
            _ => {}
        }
    }

    let by_parser: BTreeMap<String, usize> = hits.iter().fold(BTreeMap::new(), |mut m, h| {
        if let Some(p) = h.get("source_parser").and_then(|x| x.as_str()) {
            *m.entry(p.to_string()).or_insert(0) += 1;
        }
        m
    });

    json!({
        "analyser": "network_iocs",
        "ipv4": ipv4.into_iter().collect::<Vec<_>>(),
        "domains": domains.into_iter().collect::<Vec<_>>(),
        "urls": urls.into_iter().collect::<Vec<_>>(),
        "ssids": ssids.into_iter().collect::<Vec<_>>(),
        "bssids": bssids.into_iter().collect::<Vec<_>>(),
        "hits": hits,
        "hits_cap": HITS_CAP,
        "hits_truncated": seen.len() > HITS_CAP,
        "hits_per_parser": by_parser,
        "logarchive_decode": logarchive_decode,
        "source_parsers": SOURCE_PARSERS,
        "notes": "Heuristic scan of parser JSON (IPv4 regex, URL hosts, domain-like keys, Wi‑Fi SSID/BSSID fields). logarchive decode uses mul-unifiedlog in-process when the ingest plan enables it (default for this analyser). Does not replace dedicated DNS or PCAP analysis.",
    })
}

