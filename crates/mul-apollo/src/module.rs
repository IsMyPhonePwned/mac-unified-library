// SPDX-License-Identifier: GPL-3.0-only

use crate::epoch::Epoch;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Ios,
    Ipados,
    Macos,
    Watchos,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceSpec {
    Sqlite {
        db_names: Vec<String>,
        path_globs: Vec<String>,
    },
    Segb {
        stream_globs: Vec<String>,
    },
    Plist {
        path_globs: Vec<String>,
    },
    UnifiedLog {
        predicate: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampSpec {
    pub column: String,
    pub epoch: Epoch,
    #[serde(default)]
    pub quality: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Requirements {
    #[serde(default)]
    pub tables: Vec<String>,
    #[serde(default)]
    pub columns: Vec<(String, String)>,
    #[serde(default)]
    pub min_os: Option<String>,
    #[serde(default)]
    pub max_os: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VariantBody {
    Sql(String),
    Fields { /* biome field map — milestone 9 */ },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Variant {
    pub label: String,
    pub requires: Requirements,
    pub body: VariantBody,
    /// Legacy VERSIONS list from `[SQL Query a,b,c]`.
    #[serde(default)]
    pub legacy_versions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyInfo {
    pub file_name: String,
    pub versions: Vec<String>,
    pub header_hash: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityMapping {
    pub kind: String,
    #[serde(default)]
    pub bundle_id: Option<String>,
    #[serde(default)]
    pub ts_quality: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Module {
    pub id: String,
    pub name: String,
    pub activity: String,
    pub author: Option<String>,
    pub notes: Option<String>,
    pub platforms: Vec<Platform>,
    pub source: SourceSpec,
    pub variants: Vec<Variant>,
    pub timestamp: TimestampSpec,
    pub mapping: Option<EntityMapping>,
    pub legacy: Option<LegacyInfo>,
    /// Original KEY_TIMESTAMP / column display names for APOLLO CSV export.
    #[serde(default)]
    pub original_columns: Vec<(String, String)>,
}

#[derive(Debug, Clone, Default)]
pub struct ModuleSet {
    modules: Vec<Module>,
}

impl ModuleSet {
    pub fn default_set() -> Self {
        crate::registry::ModuleRegistry::global().as_module_set()
    }

    pub fn empty() -> Self {
        Self {
            modules: Vec::new(),
        }
    }

    pub fn from_modules(modules: Vec<Module>) -> Self {
        Self { modules }
    }

    pub fn modules(&self) -> &[Module] {
        &self.modules
    }

    pub fn get(&self, id: &str) -> Option<&Module> {
        self.modules.iter().find(|m| m.id == id)
    }

    pub fn len(&self) -> usize {
        self.modules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.modules.is_empty()
    }

    /// Insert or replace by id (v2 wins over legacy).
    pub fn upsert(&mut self, module: Module) {
        if let Some(pos) = self.modules.iter().position(|m| m.id == module.id) {
            self.modules[pos] = module;
        } else {
            self.modules.push(module);
        }
    }
}
