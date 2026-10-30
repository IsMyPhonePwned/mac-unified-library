// SPDX-License-Identifier: GPL-3.0-only

use crate::input::InputKind;
use std::path::Path;

pub fn detect_input(path: &Path) -> InputKind {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if name.ends_with(".logarchive") || name.contains("logarchive") {
        return InputKind::Logarchive;
    }
    if name.contains("sysdiagnose")
        || name.ends_with(".tar.gz")
        || name.ends_with(".tgz")
        || name.ends_with(".tar.xz")
        || name.ends_with(".tar")
    {
        return InputKind::Sysdiagnose;
    }
    if path.is_dir() {
        // Heuristic: presence of system_logs.logarchive or private/var
        let logarchive = path.join("system_logs.logarchive");
        if logarchive.exists() {
            return InputKind::Sysdiagnose;
        }
        if path.join("private/var").exists() || path.join("private/var/db/diagnostics").exists() {
            return InputKind::FullFilesystem;
        }
        if path.join("Persist").exists() || path.join("timesync").exists() {
            return InputKind::Logarchive;
        }
    }
    InputKind::Unknown
}
