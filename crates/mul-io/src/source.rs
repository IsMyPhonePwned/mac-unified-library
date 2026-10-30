// SPDX-License-Identifier: GPL-3.0-only

use crate::bytes::Bytes;
use crate::path::norm_path;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SourceError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Msg(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FileRef {
    pub path: String,
}

impl FileRef {
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: norm_path(&path.into()),
        }
    }
}

/// Directory or in-memory map of files for unified-log / APOLLO sources.
pub trait LogSourceFiles: Send + Sync {
    fn list(&self, predicate: &dyn Fn(&str) -> bool) -> Vec<FileRef>;
    fn open(&self, f: &FileRef) -> Result<Bytes, SourceError>;
}

/// Filesystem directory (`.logarchive` or live diagnostics tree).
pub struct DirSource {
    root: PathBuf,
}

impl DirSource {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SourceError> {
        let root = path.as_ref().to_path_buf();
        if !root.exists() {
            return Err(SourceError::Msg(format!(
                "path does not exist: {}",
                root.display()
            )));
        }
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn walk(&self) -> Result<Vec<PathBuf>, SourceError> {
        let mut out = Vec::new();
        let mut stack = vec![self.root.clone()];
        while let Some(dir) = stack.pop() {
            let rd = std::fs::read_dir(&dir)?;
            for entry in rd {
                let entry = entry?;
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    out.push(p);
                }
            }
        }
        Ok(out)
    }

    fn rel(&self, abs: &Path) -> String {
        abs.strip_prefix(&self.root)
            .unwrap_or(abs)
            .to_string_lossy()
            .replace('\\', "/")
    }
}

impl LogSourceFiles for DirSource {
    fn list(&self, predicate: &dyn Fn(&str) -> bool) -> Vec<FileRef> {
        self.walk()
            .unwrap_or_default()
            .into_iter()
            .map(|p| FileRef::new(self.rel(&p)))
            .filter(|f| predicate(&f.path))
            .collect()
    }

    fn open(&self, f: &FileRef) -> Result<Bytes, SourceError> {
        let abs = self.root.join(&f.path);
        #[cfg(all(feature = "mmap", not(target_arch = "wasm32")))]
        {
            let file = std::fs::File::open(&abs)?;
            // For milestone 1, read into owned bytes; mmap wiring comes with feature use.
            let _ = file;
        }
        let data = std::fs::read(&abs)?;
        Ok(Bytes::from_owned(data))
    }
}

/// Path → bytes map (wasm / tests).
#[derive(Debug, Default, Clone)]
pub struct MapSource {
    files: BTreeMap<String, Bytes>,
}

impl MapSource {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, path: impl Into<String>, data: Bytes) {
        self.files.insert(norm_path(&path.into()), data);
    }
}

impl LogSourceFiles for MapSource {
    fn list(&self, predicate: &dyn Fn(&str) -> bool) -> Vec<FileRef> {
        self.files
            .keys()
            .filter(|p| predicate(p))
            .map(FileRef::new)
            .collect()
    }

    fn open(&self, f: &FileRef) -> Result<Bytes, SourceError> {
        self.files
            .get(&f.path)
            .cloned()
            .ok_or_else(|| SourceError::Msg(format!("missing {}", f.path)))
    }
}
