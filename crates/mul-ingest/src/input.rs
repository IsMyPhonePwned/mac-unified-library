// SPDX-License-Identifier: GPL-3.0-only

use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    Sysdiagnose,
    Logarchive,
    LiveMacos,
    FullFilesystem,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct Input {
    pub kind: InputKind,
    pub path: PathBuf,
}

impl Input {
    pub fn detect(path: impl Into<PathBuf>) -> mul_core::Result<Self> {
        let path = path.into();
        let kind = crate::detect::detect_input(&path);
        Ok(Self { kind, path })
    }
}
