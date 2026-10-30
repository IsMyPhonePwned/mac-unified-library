// SPDX-License-Identifier: GPL-3.0-only

use mul_io::bytes::Bytes;
use mul_io::source::{DirSource, LogSourceFiles, MapSource, SourceError};
use uuid::Uuid;

pub use mul_io::source::FileRef;

/// Unified-log archive view over uuidtext / dsc / tracev3 / timesync.
pub trait LogSource: Send + Sync {
    fn tracev3_files(&self) -> Vec<FileRef>;
    fn timesync_files(&self) -> Vec<FileRef>;
    fn uuidtext(&self, uuid: Uuid) -> Option<Bytes>;
    fn dsc(&self, uuid: Uuid) -> Option<Bytes>;
    fn open(&self, f: &FileRef) -> Result<Bytes, SourceError>;
}

fn is_tracev3(path: &str) -> bool {
    path.to_ascii_lowercase().ends_with(".tracev3")
}

fn is_timesync(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("timesync/") && lower.ends_with(".timesync")
}

fn uuid_hex(uuid: Uuid) -> String {
    uuid.as_bytes()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect()
}

/// Apple layout: `uuidtext/XX/YYYY…` or (sysdiagnose logarchive) `XX/YYYY…` at archive root.
fn uuidtext_candidates(uuid: Uuid) -> Vec<String> {
    let hex = uuid_hex(uuid);
    let (hd, rest) = hex.split_at(2);
    vec![
        format!("uuidtext/{hd}/{rest}"),
        format!("{hd}/{rest}"),
    ]
}

fn dsc_candidates(uuid: Uuid) -> Vec<String> {
    let hex = uuid_hex(uuid);
    vec![
        format!("uuidtext/dsc/{hex}"),
        format!("dsc/{hex}"),
    ]
}

pub struct DirLogSource {
    inner: DirSource,
}

impl DirLogSource {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, SourceError> {
        Ok(Self {
            inner: DirSource::open(path)?,
        })
    }
}

impl LogSource for DirLogSource {
    fn tracev3_files(&self) -> Vec<FileRef> {
        self.inner.list(&|p| is_tracev3(p))
    }

    fn timesync_files(&self) -> Vec<FileRef> {
        self.inner.list(&|p| is_timesync(p))
    }

    fn uuidtext(&self, uuid: Uuid) -> Option<Bytes> {
        for rel in uuidtext_candidates(uuid) {
            if let Ok(b) = self.inner.open(&FileRef::new(rel)) {
                return Some(b);
            }
        }
        None
    }

    fn dsc(&self, uuid: Uuid) -> Option<Bytes> {
        for rel in dsc_candidates(uuid) {
            if let Ok(b) = self.inner.open(&FileRef::new(rel)) {
                return Some(b);
            }
        }
        None
    }

    fn open(&self, f: &FileRef) -> Result<Bytes, SourceError> {
        self.inner.open(f)
    }
}

pub struct MapLogSource {
    inner: MapSource,
}

impl MapLogSource {
    pub fn new(inner: MapSource) -> Self {
        Self { inner }
    }

    pub fn insert(&mut self, path: impl Into<String>, data: Bytes) {
        self.inner.insert(path, data);
    }
}

impl Default for MapLogSource {
    fn default() -> Self {
        Self {
            inner: MapSource::new(),
        }
    }
}

impl LogSource for MapLogSource {
    fn tracev3_files(&self) -> Vec<FileRef> {
        self.inner.list(&|p| is_tracev3(p))
    }

    fn timesync_files(&self) -> Vec<FileRef> {
        self.inner.list(&|p| is_timesync(p))
    }

    fn uuidtext(&self, uuid: Uuid) -> Option<Bytes> {
        for rel in uuidtext_candidates(uuid) {
            if let Ok(b) = self.inner.open(&FileRef::new(rel)) {
                return Some(b);
            }
        }
        None
    }

    fn dsc(&self, uuid: Uuid) -> Option<Bytes> {
        for rel in dsc_candidates(uuid) {
            if let Ok(b) = self.inner.open(&FileRef::new(rel)) {
                return Some(b);
            }
        }
        None
    }

    fn open(&self, f: &FileRef) -> Result<Bytes, SourceError> {
        self.inner.open(f)
    }
}
