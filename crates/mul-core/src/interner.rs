// SPDX-License-Identifier: GPL-3.0-only

use ahash::AHasher;
use hashbrown::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;

/// Interned string id. High 8 bits = shard index; low 24 bits = local index. Sym(0) is `""`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Sym(pub u32);

impl Sym {
    pub const EMPTY: Sym = Sym(0);
}

#[derive(Debug, Default)]
struct Shard {
    map: HashMap<u64, Vec<(String, Sym)>>,
    strings: Vec<String>,
}

/// Append-only, sharded string interner.
#[derive(Debug)]
pub struct Interner {
    shards: Vec<Mutex<Shard>>,
}

impl Default for Interner {
    fn default() -> Self {
        Self::new()
    }
}

impl Interner {
    pub fn new() -> Self {
        Self::with_shards(16)
    }

    pub fn with_shards(n: usize) -> Self {
        let n = n.max(1);
        let mut shards = Vec::with_capacity(n);
        for i in 0..n {
            let mut shard = Shard::default();
            if i == 0 {
                // Sym(0) == ""
                shard.strings.push(String::new());
                let h = hash_str("");
                shard.map.insert(h, vec![(String::new(), Sym::EMPTY)]);
            }
            shards.push(Mutex::new(shard));
        }
        Self { shards }
    }

    fn shard_for(&self, s: &str) -> usize {
        (hash_str(s) as usize) % self.shards.len()
    }

    pub fn intern(&self, s: &str) -> Sym {
        if s.is_empty() {
            return Sym::EMPTY;
        }
        let h = hash_str(s);
        let idx = self.shard_for(s);
        let mut shard = self.shards[idx].lock().unwrap_or_else(|e| e.into_inner());
        if let Some(bucket) = shard.map.get(&h) {
            for (existing, sym) in bucket {
                if existing == s {
                    return *sym;
                }
            }
        }
        let local = shard.strings.len() as u32;
        assert!(local < 0x00FF_FFFF, "interner shard overflow");
        let id = ((idx as u32) << 24) | local;
        let owned = s.to_string();
        shard.strings.push(owned.clone());
        shard.map.entry(h).or_default().push((owned, Sym(id)));
        Sym(id)
    }

    pub fn get(&self, sym: Sym) -> String {
        if sym == Sym::EMPTY {
            return String::new();
        }
        let shard_idx = (sym.0 >> 24) as usize;
        let local = (sym.0 & 0x00FF_FFFF) as usize;
        if shard_idx >= self.shards.len() {
            return String::new();
        }
        let shard = self.shards[shard_idx]
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        shard.strings.get(local).cloned().unwrap_or_default()
    }

    /// Alias used by Val / Event APIs.
    pub fn resolve(&self, sym: Sym) -> String {
        self.get(sym)
    }
}

fn hash_str(s: &str) -> u64 {
    let mut h = AHasher::default();
    s.hash(&mut h);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interns_and_resolves() {
        let i = Interner::new();
        let a = i.intern("hello");
        let b = i.intern("hello");
        let c = i.intern("world");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(i.get(a), "hello");
        assert_eq!(i.get(c), "world");
        assert_eq!(i.get(Sym::EMPTY), "");
    }
}
