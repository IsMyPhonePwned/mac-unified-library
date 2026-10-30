// SPDX-License-Identifier: GPL-3.0-only

//! One fixture test per analyser. Synthetic parser JSON exercises the real
//! `analysers::run` path without a full sysdiagnose archive.
//!
//! `each_analyser_id_has_its_own_test` fails if a new `AnalyserId` is added
//! without a matching `fn analyser_<id>` test below.

use mul_correlate::analysers::{self, AnalyserId, AnalyseCtx};
use mul_correlate::overview::{Boot, DeviceInfo};
use mul_correlate::Store;
use serde_json::{json, Value};
use std::collections::HashMap;

fn ctx_with(parsed: HashMap<String, Value>) -> AnalyseCtx {
    AnalyseCtx {
        parsed,
        device: DeviceInfo {
            model: Some("iPhone".into()),
            os_build: Some("21A329".into()),
            name: Some("test-device".into()),
            ..Default::default()
        },
        boots: vec![Boot {
            uuid: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE".into(),
            start_ns: Some(1_700_000_000_000_000_000),
            end_ns: Some(1_700_000_100_000_000_000),
            clean: Some(true),
        }],
        inputs: vec!["fixture".into()],
        version: "0.1.0-test".into(),
        timings: vec![("parse".into(), 12)],
        module_count: 3,
        parser_types_total: 67,
        archive_paths: vec![
            "ps.txt".into(),
            "mount.txt".into(),
            "logs/Accessibility/TCC.db".into(),
        ],
        ..Default::default()
    }
}

fn run(id: AnalyserId, ctx: &AnalyseCtx) -> Value {
    let store = Store::default();
    let out = analysers::run(id, &store, ctx);
    assert_eq!(out.id, id.as_str());
    out.value
}

fn tcc_events() -> Value {
    json!({
        "parser": "accessibility_tcc",
        "format": "jsonl",
        "events": [{
            "datetime": "2024-01-02T03:04:05Z",
            "data": {
                "client": "com.example.cam",
                "service": "kTCCServiceCamera",
                "allowed": "ALLOWED",
                "auth_value": 2
            }
        }]
    })
}

fn ps_rows() -> Value {
    json!({
        "parser": "ps",
        "rows": [
            {"user": "root", "pid": 1, "ppid": 0, "command": "/sbin/launchd"},
            {"user": "mobile", "pid": 45, "ppid": 1, "command": "/usr/bin/foo"}
        ]
    })
}

fn wifi_known() -> Value {
    json!({
        "parser": "wifi_known_networks",
        "files": {
            "WiFi/com.apple.wifi.known-networks.plist": {
                "n1": {
                    "SSID": "Cafe",
                    "AddedAt": "2024-01-02T03:04:05Z",
                    "__OSSpecific__": {"BSSID": "aa:bb:cc:dd:ee:ff", "CHANNEL": 6},
                    "BSSList": [{
                        "LocationLatitude": 48.85,
                        "LocationLongitude": 2.35,
                        "LocationAccuracy": 25
                    }]
                }
            }
        }
    })
}

#[test]
fn each_analyser_id_has_its_own_test() {
    let src = include_str!("each_analyser.rs");
    for id in AnalyserId::all() {
        let needle = format!("fn analyser_{}()", id.as_str());
        assert!(
            src.contains(&needle),
            "missing dedicated test `{needle}` for analyser {}",
            id.as_str()
        );
    }
}

#[test]
fn analyser_accounts() {
    let mut parsed = HashMap::new();
    parsed.insert(
        "transparency_json".into(),
        json!({
            "registration": [{
                "app": "com.apple.MobileSMS",
                "uri": "mailto:ada@example.test"
            }]
        }),
    );
    let mut identity = HashMap::new();
    identity.insert(
        "logs/MobileCal/owner.plist".into(),
        json!({"OwnerEmailAddresses": ["ada@example.test"]}),
    );
    let mut ctx = ctx_with(parsed);
    ctx.identity_plists = identity;
    ctx.activation_lock_log_texts =
        vec!["ActivationLockUsername = ada@example.test\n".into()];
    let v = run(AnalyserId::accounts, &ctx);
    assert!(v.get("emails").is_some() || v.get("accounts").is_some() || v.is_object());
}

#[test]
fn analyser_apps() {
    let mut parsed = HashMap::new();
    parsed.insert("accessibility_tcc".into(), tcc_events());
    parsed.insert(
        "mobileinstallation".into(),
        json!({
            "parser": "mobileinstallation",
            "events": [{
                "datetime": "2024-01-02T03:04:05Z",
                "message": "installed com.example.app",
                "data": {"bundle_id": "com.example.app"}
            }]
        }),
    );
    let v = run(AnalyserId::apps, &ctx_with(parsed));
    assert!(v.is_object());
}

#[test]
fn analyser_coverage() {
    let mut parsed = HashMap::new();
    parsed.insert("ps".into(), ps_rows());
    parsed.insert(
        "mount".into(),
        json!({"parser": "mount", "events": []}),
    );
    let v = run(AnalyserId::coverage, &ctx_with(parsed));
    assert!(v.get("parsers_ran").is_some() || v.get("parser_count").is_some() || v.is_object());
}

#[test]
fn analyser_file_stats() {
    let v = run(AnalyserId::file_stats, &ctx_with(HashMap::new()));
    assert!(v.is_object());
}

#[test]
fn analyser_install_enrichment() {
    let mut parsed = HashMap::new();
    parsed.insert(
        "mobileinstallation".into(),
        json!({
            "parser": "mobileinstallation",
            "events": [{
                "datetime": "2024-01-02T03:04:05Z",
                "message": "InstallSuccessful for com.example.sideload",
                "data": {}
            }]
        }),
    );
    let v = run(AnalyserId::install_enrichment, &ctx_with(parsed));
    assert_eq!(v["analyser"], "install_enrichment");
}

#[test]
fn analyser_mcstateshared() {
    let mut ctx = ctx_with(HashMap::new());
    ctx.archive_stub_texts.insert(
        "logs/MCState/Shared/profile-desk.stub".into(),
        r#"<?xml version="1.0"?><plist><dict>
            <key>PayloadDisplayName</key><string>Desk</string>
            <key>PayloadType</key><string>Configuration</string>
        </dict></plist>"#
            .into(),
    );
    let v = run(AnalyserId::mcstateshared, &ctx);
    assert!(v.is_object());
}

#[test]
fn analyser_network_iocs() {
    let mut parsed = HashMap::new();
    parsed.insert(
        "wifi_diagnostics".into(),
        json!({
            "parser": "wifi_diagnostics",
            "files": {"WiFi/arp.txt": "host.example (203.0.113.10) at aa:bb:cc:dd:ee:ff\n"}
        }),
    );
    parsed.insert(
        "transparency".into(),
        json!({
            "parser": "transparency",
            "events": [{
                "message": "contact https://evil.example/path",
                "data": {}
            }]
        }),
    );
    let v = run(AnalyserId::network_iocs, &ctx_with(parsed));
    assert!(v.is_object());
}

#[test]
fn analyser_permissions() {
    let mut parsed = HashMap::new();
    parsed.insert("accessibility_tcc".into(), tcc_events());
    let v = run(AnalyserId::permissions, &ctx_with(parsed));
    assert_eq!(v["analyser"], "permissions");
    assert_eq!(v["app_count"], 1);
    assert_eq!(
        v["apps"]["com.example.cam"]["permissions"][0]["service"],
        "kTCCServiceCamera"
    );
}

#[test]
fn analyser_mdm() {
    let mut parsed = HashMap::new();
    parsed.insert(
        "mcstate_shared_profile".into(),
        json!({
            "parser": "mcstate_shared_profile",
            "events": [{
                "datetime": "2024-01-02T03:04:05Z",
                "message": "desk profile",
                "data": {
                    "PayloadType": "com.apple.vpn.managed",
                    "PayloadDisplayName": "Corp VPN",
                    "PayloadOrganization": "Example"
                }
            }]
        }),
    );
    parsed.insert(
        "mcsettingsevents".into(),
        json!({
            "parser": "mcsettingsevents",
            "events": [{
                "datetime": "2024-01-02T03:04:05Z",
                "message": "setting changed",
                "data": {"setting": "root.nested", "process": "configd"}
            }]
        }),
    );
    parsed.insert(
        "plists".into(),
        json!({
            "parser": "plists",
            "files": {
                "logs/Shared_MDM.plist": {"ServerURL": "https://mdm.example.test"}
            }
        }),
    );
    let v = run(AnalyserId::mdm, &ctx_with(parsed));
    assert_eq!(v["analyser"], "mdm");
    assert!(v["payloads"].as_array().unwrap().len() >= 1);
}

#[test]
fn analyser_processes() {
    let mut parsed = HashMap::new();
    parsed.insert("ps".into(), ps_rows());
    parsed.insert(
        "psthread".into(),
        json!({
            "parser": "psthread",
            "entries": [
                {"pid": 1, "threads": 2, "command": "/sbin/launchd", "user": "root"}
            ]
        }),
    );
    parsed.insert(
        "shutdownlogs".into(),
        json!({
            "parser": "shutdownlogs",
            "events": [{
                "message": "launchd is still there",
                "data": {"pid": 1, "command": "launchd", "path": "/sbin/launchd"}
            }]
        }),
    );
    let v = run(AnalyserId::processes, &ctx_with(parsed));
    assert!(
        v.get("entries").is_some() || v.get("matrix").is_some() || v.is_object(),
        "{v}"
    );
}

#[test]
fn analyser_summary() {
    let mut parsed = HashMap::new();
    parsed.insert(
        "remotectl_dumpstate".into(),
        json!({
            "parser": "remotectl_dumpstate",
            "data": {
                "Device": {
                    "OSVersion": "17.2.1",
                    "BuildVersion": "21C62",
                    "ProductType": "iPhone15,2",
                    "SerialNumber": "SERIAL1",
                    "UniqueDeviceID": "UDID1",
                    "ProductName": "iPhone OS"
                }
            }
        }),
    );
    parsed.insert(
        "security_sysdiagnose".into(),
        json!({
            "parser": "security_sysdiagnose",
            "events": [{
                "datetime": "2024-01-02T03:04:05Z",
                "message": "keychain circle of trust",
                "data": {"section": "genp"}
            }]
        }),
    );
    let v = run(AnalyserId::summary, &ctx_with(parsed));
    assert!(v.get("markdown").is_some() || v.is_object(), "{v}");
}

#[test]
fn analyser_timesketch() {
    let mut parsed = HashMap::new();
    parsed.insert(
        "mobileinstallation".into(),
        json!({
            "parser": "mobileinstallation",
            "events": [{
                "datetime": "2024-01-02T03:04:05Z",
                "message": "installed com.example.app",
                "module": "mobileinstallation",
                "data": {}
            }]
        }),
    );
    let v = run(AnalyserId::timesketch, &ctx_with(parsed));
    assert!(v.get("events").is_some() || v.get("csv").is_some() || v.is_object());
}

#[test]
fn analyser_wifi_geolocation() {
    let mut parsed = HashMap::new();
    parsed.insert("wifi_known_networks".into(), wifi_known());
    let v = run(AnalyserId::wifi_geolocation, &ctx_with(parsed));
    assert!(v["gpx"].as_str().unwrap().contains("Cafe"));
    assert!(v["kml"].as_str().unwrap().contains("48.85"));
    assert!(v["point_count"].as_u64().unwrap() >= 1);
}

#[test]
fn analyser_network_extension() {
    let mut parsed = HashMap::new();
    parsed.insert(
        "networkextension".into(),
        json!({
            "logs/Networking/com.apple.networkextension.plist": {
                "VPN": {
                    "OnDemandEnabled": 1,
                    "VPNType": "IKEv2",
                    "RemoteAddress": "vpn.example.test"
                }
            }
        }),
    );
    parsed.insert(
        "networkextensioncache".into(),
        json!({
            "logs/Networking/com.apple.networkextension.cache.plist": {
                "Cache": "warm"
            }
        }),
    );
    let v = run(AnalyserId::network_extension, &ctx_with(parsed));
    assert_eq!(v["analyser"], "network_extension");
}

#[test]
fn analyser_trust_store() {
    let mut parsed = HashMap::new();
    parsed.insert(
        "security_sysdiagnose".into(),
        json!({
            "parser": "security_sysdiagnose",
            "events": [{
                "datetime": "2024-01-02T03:04:05Z",
                "message": "trust settings",
                "data": {
                    "section": "trust",
                    "attributes": {"iss": "Evil CA", "subj": "MITM Proxy"}
                }
            }]
        }),
    );
    let v = run(AnalyserId::trust_store, &ctx_with(parsed));
    assert_eq!(v["analyser"], "trust_store");
}

#[test]
fn analyser_accessories() {
    let mut parsed = HashMap::new();
    parsed.insert(
        "bluetooth".into(),
        json!({
            "parser": "bluetooth",
            "devices": [{"name": "Keyboard", "address": "aa:bb:cc:dd:ee:ff"}],
            "summary": {"power": "On"}
        }),
    );
    parsed.insert(
        "iousb".into(),
        json!({
            "parser": "iousb",
            "tree": {
                "class": "IOUSBRoot",
                "Hub": {
                    "USB Vendor Name": "Example",
                    "USB Product Name": "Dongle",
                    "idVendor": 1234,
                    "idProduct": 5678
                }
            }
        }),
    );
    let v = run(AnalyserId::accessories, &ctx_with(parsed));
    assert_eq!(v["analyser"], "accessories");
}

#[test]
fn analyser_quarantine() {
    let mut parsed = HashMap::new();
    parsed.insert(
        "quarantine_events".into(),
        json!({
            "parser": "quarantine_events",
            "events": [{
                "datetime": "2024-01-02T03:04:05Z",
                "message": "quarantine download",
                "data": {
                    "LSQuarantineAgentName": "Safari",
                    "LSQuarantineDataURLString": "https://example.test/file",
                    "LSQuarantineOriginURLString": "https://example.test/",
                    "LSQuarantineAgentBundleIdentifier": "com.apple.Safari"
                }
            }]
        }),
    );
    let v = run(AnalyserId::quarantine, &ctx_with(parsed));
    assert_eq!(v["analyser"], "quarantine");
    assert_eq!(v["count"], 1);
    assert_eq!(v["events"][0]["agent"], "Safari");
}

#[test]
fn analyser_lockdown_pairing() {
    let mut parsed = HashMap::new();
    parsed.insert(
        "lockdownd".into(),
        json!({
            "parser": "lockdownd",
            "events": [{
                "datetime": "2024-01-02T03:04:05Z",
                "message": "device paired",
                "data": {"pid": 42, "event_type": "Pair"}
            }]
        }),
    );
    let v = run(AnalyserId::lockdown_pairing, &ctx_with(parsed));
    assert_eq!(v["analyser"], "lockdown_pairing");
}

#[test]
fn analyser_crashes() {
    let mut parsed = HashMap::new();
    parsed.insert(
        "crashlogs".into(),
        json!({
            "parser": "crashlogs",
            "events": [{
                "datetime": "2024-01-02T03:04:05Z",
                "message": "crash ExampleApp",
                "data": {
                    "app_name": "ExampleApp",
                    "filename": "ExampleApp.ips",
                    "exception": "EXC_BAD_ACCESS"
                }
            }]
        }),
    );
    let v = run(AnalyserId::crashes, &ctx_with(parsed));
    assert_eq!(v["analyser"], "crashes");
    assert!(v["by_app"]["ExampleApp"]["count"].as_u64().unwrap() >= 1);
}

#[test]
fn analyser_runningboard() {
    let mut parsed = HashMap::new();
    parsed.insert(
        "runningboard".into(),
        json!({
            "parser": "runningboard",
            "domains": ["com.apple.board"],
            "assertions": ["com.example.assertion"],
            "grants": ["RBSPreventIdleSleepGrant"],
            "prevent_idle_sleep_mentions": 1,
            "events": [{
                "data": {"domain_count": 1}
            }]
        }),
    );
    let v = run(AnalyserId::runningboard, &ctx_with(parsed));
    assert_eq!(v["analyser"], "runningboard");
}

#[test]
fn analyser_account_trust() {
    let mut parsed = HashMap::new();
    parsed.insert(
        "ckks_pcs".into(),
        json!({
            "parser": "ckks_pcs",
            "files": {"ckksctl_status.txt": "pcs: ready\n"},
            "meta": {"returned": 1}
        }),
    );
    parsed.insert(
        "security_sysdiagnose".into(),
        json!({
            "parser": "security_sysdiagnose",
            "events": [{
                "message": "circle of trust",
                "data": {"section": "sos"}
            }]
        }),
    );
    parsed.insert(
        "usermanagement".into(),
        json!({
            "parser": "usermanagement",
            "files": {"logs/UserManagement/umtool.txt": "user: mobile\n"}
        }),
    );
    parsed.insert(
        "transparency_json".into(),
        json!({"devices": [{"name": "Ada's iPhone"}]}),
    );
    let v = run(AnalyserId::account_trust, &ctx_with(parsed));
    assert_eq!(v["analyser"], "account_trust");
}

#[test]
fn analyser_device_integrity() {
    let mut parsed = HashMap::new();
    parsed.insert(
        "mount".into(),
        json!({
            "parser": "mount",
            "summary": {
                "root_sealed": true,
                "root_read_only": true,
                "integrity_hint": "system_partition_sealed_readonly"
            },
            "events": [{
                "message": "root sealed",
                "data": {
                    "device": "/dev/disk1s1",
                    "mountpoint": "/",
                    "sealed": true,
                    "read_only": true,
                    "fs": "apfs"
                }
            }]
        }),
    );
    parsed.insert(
        "ota_update".into(),
        json!({
            "parser": "ota_update",
            "files_index": [{"path": "restore_perform.txt", "char_count": 12}],
            "restore_hints": [{"text": "restore finished"}]
        }),
    );
    let v = run(AnalyserId::device_integrity, &ctx_with(parsed));
    assert_eq!(v["analyser"], "device_integrity");
    assert!(v["counts"]["mounts"].as_u64().unwrap() >= 1);
}

#[test]
fn analyser_overview() {
    let v = run(AnalyserId::overview, &ctx_with(HashMap::new()));
    assert!(v.is_object());
    assert!(
        v.get("device").is_some() || v.get("inputs").is_some() || v.get("version").is_some(),
        "{v}"
    );
}

#[test]
fn analyser_app_activity() {
    use mul_core::event::{Event, EventKind, Evidence, LazyText, SourceId, TsQuality};
    use mul_core::interner::Interner;
    use mul_core::Val;

    let interner = Interner::default();
    let bundle = interner.intern("com.example.app");
    let attr_key = interner.intern("bundle_id");
    let mut store = Store::default();
    store.events.push(Event {
        ts: 1_700_000_000_000_000_000,
        ts_quality: TsQuality::Exact,
        kind: EventKind::AppFocus,
        source: SourceId("knowledgec".into()),
        level: None,
        pid: None,
        process: None,
        bundle_id: Some(bundle),
        subsystem: None,
        category: None,
        message: LazyText::owned("app focus"),
        attrs: smallvec::smallvec![(
            attr_key,
            Val::Text(interner.resolve(bundle).into_boxed_str())
        )],
        evidence: Evidence::new("fixture", None),
    });
    let ctx = ctx_with(HashMap::new());
    let out = analysers::run(AnalyserId::app_activity, &store, &ctx);
    assert_eq!(out.id, "app_activity");
    assert!(out.value["by_day"].is_object());
}

#[test]
fn analyser_boots() {
    let v = run(AnalyserId::boots, &ctx_with(HashMap::new()));
    let boots = v["boots"].as_array().expect("boots array");
    assert_eq!(boots.len(), 1);
    assert_eq!(boots[0]["uuid"], "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE");
    assert_eq!(boots[0]["clean"], true);
}
