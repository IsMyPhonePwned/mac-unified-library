// SPDX-License-Identifier: GPL-3.0-only

use std::ops::Deref;
use std::sync::Arc;

/// Shared byte buffer: owned arc or (native) mmap-backed arc slice.
#[derive(Clone)]
pub struct Bytes {
    inner: Arc<[u8]>,
}

impl Bytes {
    pub fn from_owned(v: Vec<u8>) -> Self {
        Self {
            inner: Arc::from(v.into_boxed_slice()),
        }
    }

    pub fn from_slice(s: &[u8]) -> Self {
        Self::from_owned(s.to_vec())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Deref for Bytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.inner
    }
}

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl std::fmt::Debug for Bytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bytes")
            .field("len", &self.len())
            .finish()
    }
}
