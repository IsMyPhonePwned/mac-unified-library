// SPDX-License-Identifier: GPL-3.0-only
//! Human labels and sensitive-service set for Apple TCC `kTCCService*` ids.
//!
//! Best-effort community mappings (Apple does not publish an official dictionary).
//! Ported for analyser/overview use from mobipwn's `iosTccServices` /
//! `iosSensitivePermissions` (additive; those trees are untouched).

use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy)]
pub struct TccServiceInfo {
    pub id: &'static str,
    pub label: &'static str,
    pub description: &'static str,
}

const BY_SUFFIX: &[(&str, TccServiceInfo)] = &[
    (
        "addressbook",
        TccServiceInfo {
            id: "kTCCServiceAddressBook",
            label: "Contacts",
            description: "Access to Contacts (Address Book).",
        },
    ),
    (
        "appleevents",
        TccServiceInfo {
            id: "kTCCServiceAppleEvents",
            label: "Automation",
            description: "Control other apps via Apple Events (macOS Automation).",
        },
    ),
    (
        "bluetoothalways",
        TccServiceInfo {
            id: "kTCCServiceBluetoothAlways",
            label: "Bluetooth",
            description: "Bluetooth access while the app is in use or in the background.",
        },
    ),
    (
        "bluetoothperipheral",
        TccServiceInfo {
            id: "kTCCServiceBluetoothPeripheral",
            label: "Bluetooth peripheral",
            description: "Act as a Bluetooth peripheral / LE accessory.",
        },
    ),
    (
        "calendar",
        TccServiceInfo {
            id: "kTCCServiceCalendar",
            label: "Calendars",
            description: "Access to Calendar data.",
        },
    ),
    (
        "camera",
        TccServiceInfo {
            id: "kTCCServiceCamera",
            label: "Camera",
            description: "Access to the device camera.",
        },
    ),
    (
        "faceid",
        TccServiceInfo {
            id: "kTCCServiceFaceID",
            label: "Face ID",
            description: "Use Face ID / biometrics.",
        },
    ),
    (
        "focusstatus",
        TccServiceInfo {
            id: "kTCCServiceFocusStatus",
            label: "Focus",
            description: "Read Focus / Do Not Disturb status.",
        },
    ),
    (
        "health",
        TccServiceInfo {
            id: "kTCCServiceHealth",
            label: "Health",
            description: "HealthKit access (generic).",
        },
    ),
    (
        "healthshare",
        TccServiceInfo {
            id: "kTCCServiceHealthShare",
            label: "Health (share)",
            description: "Read HealthKit data shared with the app.",
        },
    ),
    (
        "healthupdate",
        TccServiceInfo {
            id: "kTCCServiceHealthUpdate",
            label: "Health (write)",
            description: "Write HealthKit data.",
        },
    ),
    (
        "homekit",
        TccServiceInfo {
            id: "kTCCServiceHomeKit",
            label: "HomeKit",
            description: "Access to HomeKit home / accessory data.",
        },
    ),
    (
        "liverpool",
        TccServiceInfo {
            id: "kTCCServiceLiverpool",
            label: "CloudKit",
            description:
                "Undocumented TCC service (kTCCServiceLiverpool), widely mapped to CloudKit / iCloud-backed data.",
        },
    ),
    (
        "location",
        TccServiceInfo {
            id: "kTCCServiceLocation",
            label: "Location",
            description: "Location Services access (when gated via TCC on this OS).",
        },
    ),
    (
        "localnetwork",
        TccServiceInfo {
            id: "kTCCServiceLocalNetwork",
            label: "Local network",
            description: "Discover and connect to devices on the local network.",
        },
    ),
    (
        "medialibrary",
        TccServiceInfo {
            id: "kTCCServiceMediaLibrary",
            label: "Media library",
            description: "Access to the Apple Music / media library.",
        },
    ),
    (
        "microphone",
        TccServiceInfo {
            id: "kTCCServiceMicrophone",
            label: "Microphone",
            description: "Access to the microphone.",
        },
    ),
    (
        "motion",
        TccServiceInfo {
            id: "kTCCServiceMotion",
            label: "Motion & fitness",
            description: "Motion / accelerometer / fitness-related sensors.",
        },
    ),
    (
        "photos",
        TccServiceInfo {
            id: "kTCCServicePhotos",
            label: "Photos",
            description: "Read access to the Photo Library.",
        },
    ),
    (
        "photosadd",
        TccServiceInfo {
            id: "kTCCServicePhotosAdd",
            label: "Photos (add)",
            description: "Add-only access to the Photo Library.",
        },
    ),
    (
        "reminders",
        TccServiceInfo {
            id: "kTCCServiceReminders",
            label: "Reminders",
            description: "Access to Reminders.",
        },
    ),
    (
        "screencapture",
        TccServiceInfo {
            id: "kTCCServiceScreenCapture",
            label: "Screen recording",
            description: "Screen capture / recording.",
        },
    ),
    (
        "siri",
        TccServiceInfo {
            id: "kTCCServiceSiri",
            label: "Siri",
            description: "Siri / voice assistant integration.",
        },
    ),
    (
        "speechrecognition",
        TccServiceInfo {
            id: "kTCCServiceSpeechRecognition",
            label: "Speech recognition",
            description: "On-device or server speech recognition.",
        },
    ),
    (
        "systempolicyallfiles",
        TccServiceInfo {
            id: "kTCCServiceSystemPolicyAllFiles",
            label: "Full Disk Access",
            description: "Full Disk Access (macOS System Policy).",
        },
    ),
    (
        "systempolicydesktopfolder",
        TccServiceInfo {
            id: "kTCCServiceSystemPolicyDesktopFolder",
            label: "Desktop folder",
            description: "Access to the Desktop folder (macOS).",
        },
    ),
    (
        "systempolicydocumentsfolder",
        TccServiceInfo {
            id: "kTCCServiceSystemPolicyDocumentsFolder",
            label: "Documents folder",
            description: "Access to the Documents folder (macOS).",
        },
    ),
    (
        "systempolicydownloadsfolder",
        TccServiceInfo {
            id: "kTCCServiceSystemPolicyDownloadsFolder",
            label: "Downloads folder",
            description: "Access to the Downloads folder (macOS).",
        },
    ),
    (
        "systempolicynetworkvolumes",
        TccServiceInfo {
            id: "kTCCServiceSystemPolicyNetworkVolumes",
            label: "Network volumes",
            description: "Access to network volumes (macOS).",
        },
    ),
    (
        "systempolicyremovablevolumes",
        TccServiceInfo {
            id: "kTCCServiceSystemPolicyRemovableVolumes",
            label: "Removable volumes",
            description: "Access to removable volumes (macOS).",
        },
    ),
    (
        "ubiquity",
        TccServiceInfo {
            id: "kTCCServiceUbiquity",
            label: "iCloud Drive",
            description: "Undocumented TCC service for iCloud Drive / ubiquity container access.",
        },
    ),
    (
        "usertracking",
        TccServiceInfo {
            id: "kTCCServiceUserTracking",
            label: "Tracking",
            description: "App Tracking Transparency — track the user across apps/websites.",
        },
    ),
    (
        "watchkit",
        TccServiceInfo {
            id: "kTCCServiceWatchKit",
            label: "WatchKit",
            description: "WatchKit / Apple Watch companion access.",
        },
    ),
    (
        "willow",
        TccServiceInfo {
            id: "kTCCServiceWillow",
            label: "Home / HomeKit data",
            description:
                "Undocumented TCC service (kTCCServiceWillow), generally associated with Home / HomeKit-related private data.",
        },
    ),
];

const SENSITIVE_RAW: &[&str] = &[
    "kTCCServiceCamera",
    "kTCCServiceMicrophone",
    "kTCCServicePhotos",
    "kTCCServicePhotosAdd",
    "kTCCServiceAddressBook",
    "kTCCServiceCalendar",
    "kTCCServiceReminders",
    "kTCCServiceLocation",
    "kTCCServiceMotion",
    "kTCCServiceSpeechRecognition",
    "kTCCServiceMediaLibrary",
    "kTCCServiceFaceID",
    "kTCCServiceBluetoothAlways",
    "kTCCServiceBluetoothPeripheral",
    "kTCCServiceUserTracking",
    "kTCCServiceWillow",
    "kTCCServiceLiverpool",
    "kTCCServiceScreenCapture",
    "kTCCServiceFocusStatus",
    "kTCCServiceHealth",
    "kTCCServiceHealthUpdate",
    "kTCCServiceHealthShare",
    "kTCCServiceHomeKit",
    "kTCCServiceAppleEvents",
    "kTCCServiceSystemPolicyDesktopFolder",
    "kTCCServiceSystemPolicyDocumentsFolder",
    "kTCCServiceSystemPolicyDownloadsFolder",
    "kTCCServiceSystemPolicyNetworkVolumes",
    "kTCCServiceSystemPolicyRemovableVolumes",
    "kTCCServiceUbiquity",
    "kTCCServiceWatchKit",
    "kTCCServiceSiri",
    "kTCCServiceLocalNetwork",
];

fn sensitive_set() -> &'static HashSet<&'static str> {
    static SET: OnceLock<HashSet<&'static str>> = OnceLock::new();
    SET.get_or_init(|| SENSITIVE_RAW.iter().copied().collect())
}

/// Normalize any raw TCC service string to a lookup key (suffix, lowercased).
pub fn normalize_tcc_service_key(raw: &str) -> String {
    let t = raw.trim();
    if t.is_empty() {
        return String::new();
    }
    let without = t
        .strip_prefix("kTCCService")
        .or_else(|| t.strip_prefix("ktccservice"))
        .unwrap_or(t);
    without
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

fn fallback_label(raw: &str) -> String {
    let stripped = raw
        .trim()
        .strip_prefix("kTCCService")
        .or_else(|| raw.trim().strip_prefix("ktccservice"))
        .unwrap_or(raw.trim());
    if stripped.is_empty() {
        return raw.trim().to_string();
    }
    let mut out = String::new();
    for (i, c) in stripped.chars().enumerate() {
        if i > 0 && c.is_ascii_uppercase() {
            out.push(' ');
        }
        if c == '_' {
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    out.trim().to_string()
}

pub fn tcc_service_info(raw: &str) -> (String, String, String) {
    let trimmed = raw.trim().to_string();
    let key = normalize_tcc_service_key(&trimmed);
    if let Some((_, info)) = BY_SUFFIX.iter().find(|(k, _)| *k == key) {
        return (
            info.id.to_string(),
            info.label.to_string(),
            info.description.to_string(),
        );
    }
    let id = if trimmed.to_ascii_lowercase().starts_with("ktccservice") {
        trimmed.clone()
    } else if trimmed.is_empty() {
        "Unknown".into()
    } else {
        format!("kTCCService{trimmed}")
    };
    let label = fallback_label(&trimmed);
    let description = format!("TCC service {id}. Apple does not document every kTCCService* name.");
    (id, label, description)
}

pub fn tcc_service_label(raw: &str) -> String {
    tcc_service_info(raw).1
}

pub fn is_sensitive_tcc_service(raw: &str) -> bool {
    let (id, label, _) = tcc_service_info(raw);
    if sensitive_set().contains(id.as_str()) {
        return true;
    }
    let l = label.to_ascii_lowercase();
    [
        "camera",
        "microphone",
        "photo",
        "contact",
        "address book",
        "calendar",
        "reminder",
        "location",
        "motion",
        "speech",
        "media library",
        "face id",
        "bluetooth",
        "tracking",
        "screen",
        "health",
        "home",
        "siri",
        "local network",
        "cloudkit",
        "icloud",
    ]
    .iter()
    .any(|k| l.contains(k))
}

/// Enrich a permissions JSON object with `service_label`, `service_description`, `sensitive`.
pub fn enrich_permission_value(perm: &mut Value) {
    let Some(obj) = perm.as_object_mut() else {
        return;
    };
    let service = obj
        .get("service")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if service.is_empty() {
        return;
    }
    let (id, label, description) = tcc_service_info(&service);
    obj.insert("service_id".into(), json!(id));
    obj.insert("service_label".into(), json!(label));
    obj.insert("service_description".into(), json!(description));
    obj.insert("sensitive".into(), json!(is_sensitive_tcc_service(&service)));
}

/// Map modern TCC `auth_value` integers / strings to ALLOWED / NOT ALLOWED / PROMPT / UNKNOWN.
pub fn allowed_from_auth_value(v: &Value) -> Option<String> {
    if let Some(s) = v.as_str() {
        let t = s.trim();
        if t.is_empty() {
            return None;
        }
        let lower = t.to_ascii_lowercase();
        if lower == "allowed" || lower == "yes" || lower == "true" || t == "2" {
            return Some("ALLOWED".into());
        }
        if lower == "denied" || lower == "not allowed" || lower == "no" || lower == "false" || t == "0"
        {
            return Some("NOT ALLOWED".into());
        }
        if lower.contains("prompt") || t == "1" {
            return Some("PROMPT".into());
        }
        if t.eq_ignore_ascii_case("ALLOWED") {
            return Some("ALLOWED".into());
        }
        if t.eq_ignore_ascii_case("NOT ALLOWED") {
            return Some("NOT ALLOWED".into());
        }
        // Already a display string from Apollo
        if t.contains("ALLOW") || t.contains("DENY") || t.contains("PROMPT") {
            return Some(t.to_string());
        }
        return None;
    }
    let n = v.as_i64().or_else(|| v.as_u64().map(|u| u as i64))?;
    // TCC auth_value: 0 = denied, 1 = unknown/prompt, 2 = allowed (common modern mapping).
    Some(match n {
        0 => "NOT ALLOWED".into(),
        1 => "PROMPT".into(),
        2 => "ALLOWED".into(),
        _ => format!("auth_value={n}"),
    })
}
