// SPDX-License-Identifier: GPL-3.0-only

use crate::interner::Sym;
use crate::val::Val;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TsQuality {
    Exact,
    Recorded,
    Aggregated,
    Approx,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SourceId(pub String);

impl SourceId {
    pub fn unifiedlog() -> Self {
        Self("unifiedlog".into())
    }
    pub fn apollo(module: &str) -> Self {
        Self(format!("apollo:{module}"))
    }
    pub fn ng(parser: &str) -> Self {
        Self(format!("ng:{parser}"))
    }
    pub fn biome(stream: &str) -> Self {
        Self(format!("biome:{stream}"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    ProcessStart,
    ProcessExit,
    AppInstall,
    AppUninstall,
    AppFocus,
    AppUsage,
    Crash,
    Network,
    PermissionChange,
    Location,
    Login,
    Lock,
    Unlock,
    Boot,
    Shutdown,
    Usb,
    Mount,
    ProfileInstall,
    Generic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Default,
    Info,
    Debug,
    Error,
    Fault,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub path: String,
    pub offset_or_row: Option<u64>,
}

impl Evidence {
    pub fn new(path: impl Into<String>, offset_or_row: Option<u64>) -> Self {
        Self {
            path: path.into(),
            offset_or_row,
        }
    }
}

/// Message text that may be owned or formatted lazily later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LazyText {
    Owned(String),
    Empty,
}

impl LazyText {
    pub fn as_str(&self) -> &str {
        match self {
            LazyText::Owned(s) => s,
            LazyText::Empty => "",
        }
    }

    pub fn owned(s: impl Into<String>) -> Self {
        LazyText::Owned(s.into())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub ts: i64,
    pub ts_quality: TsQuality,
    pub source: SourceId,
    pub kind: EventKind,
    pub level: Option<Level>,
    pub pid: Option<u32>,
    pub process: Option<Sym>,
    pub bundle_id: Option<Sym>,
    pub subsystem: Option<Sym>,
    pub category: Option<Sym>,
    pub message: LazyText,
    pub attrs: SmallVec<[(Sym, Val); 6]>,
    pub evidence: Evidence,
}

impl Event {
    pub fn unknown_time(source: SourceId, kind: EventKind, evidence: Evidence) -> Self {
        Self {
            ts: i64::MIN,
            ts_quality: TsQuality::Unknown,
            source,
            kind,
            level: None,
            pid: None,
            process: None,
            bundle_id: None,
            subsystem: None,
            category: None,
            message: LazyText::Empty,
            attrs: SmallVec::new(),
            evidence,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntityKey {
    Device,
    Boot(String),
    Process {
        boot: String,
        unique_pid: Option<u64>,
        pid: Option<u32>,
    },
    Executable(String),
    App(String),
    Account(String),
    Endpoint(String),
    WifiNetwork {
        ssid: String,
        bssid: String,
    },
    Profile(String),
    Permission {
        service: String,
        client: String,
    },
    File(String),
}
