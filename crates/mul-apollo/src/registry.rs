// SPDX-License-Identifier: GPL-3.0-only

use crate::legacy::import_all_legacy;
use crate::module::{Module, ModuleSet};
use crate::toml_v2;
use once_cell::sync::OnceCell;
use std::path::Path;

include!(concat!(env!("OUT_DIR"), "/legacy_modules.rs"));

pub struct ModuleRegistry {
    modules: Vec<Module>,
    legacy_errors: Vec<(String, String)>,
    toml_errors: Vec<(String, String)>,
}

impl ModuleRegistry {
    pub fn global() -> &'static ModuleRegistry {
        static REG: OnceCell<ModuleRegistry> = OnceCell::new();
        REG.get_or_init(ModuleRegistry::load_embedded)
    }

    pub fn load_embedded() -> Self {
        // TOML is the embedded source of truth. Optional LEGACY_MODULE_SOURCES
        // (empty in published trees) only fills ids not already covered.
        let mut modules = Vec::new();
        let mut toml_errors = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for (name, text) in TOML_MODULE_SOURCES {
            match toml_v2::parse_module_toml(text) {
                Ok(m) => {
                    if let Some(pos) = modules.iter().position(|x: &Module| x.id == m.id) {
                        modules[pos] = m;
                    } else {
                        seen.insert(m.id.clone());
                        modules.push(m);
                    }
                }
                Err(e) => toml_errors.push((name.to_string(), e.to_string())),
            }
        }
        let (legacy_modules, legacy_errors) = import_all_legacy(LEGACY_MODULE_SOURCES);
        for m in legacy_modules {
            if seen.contains(&m.id) {
                continue;
            }
            seen.insert(m.id.clone());
            modules.push(m);
        }
        Self {
            modules,
            legacy_errors,
            toml_errors,
        }
    }

    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    pub fn legacy_source_count() -> usize {
        LEGACY_MODULE_SOURCES.len()
    }

    pub fn toml_source_count() -> usize {
        TOML_MODULE_SOURCES.len()
    }

    pub fn legacy_errors(&self) -> &[(String, String)] {
        &self.legacy_errors
    }

    pub fn toml_errors(&self) -> &[(String, String)] {
        &self.toml_errors
    }

    pub fn modules(&self) -> &[Module] {
        &self.modules
    }

    pub fn get(&self, id: &str) -> Option<&Module> {
        self.modules.iter().find(|m| m.id == id)
    }

    pub fn as_module_set(&self) -> ModuleSet {
        ModuleSet::from_modules(self.modules.clone())
    }

    /// Merge v2 TOML modules from a directory (v2 wins by id).
    pub fn with_toml_dir(mut self, dir: impl AsRef<Path>) -> Result<Self, crate::ApolloError> {
        let dir = dir.as_ref();
        if !dir.exists() {
            return Ok(self);
        }
        for entry in walk_tomls(dir) {
            let text = std::fs::read_to_string(&entry)?;
            let m = toml_v2::parse_module_toml(&text)?;
            if let Some(pos) = self.modules.iter().position(|x| x.id == m.id) {
                self.modules[pos] = m;
            } else {
                self.modules.push(m);
            }
        }
        Ok(self)
    }
}

fn walk_tomls(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in rd.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk_tomls(&path));
        } else if path.extension().and_then(|e| e.to_str()) == Some("toml") {
            out.push(path);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_toml_modules_load() {
        let reg = ModuleRegistry::load_embedded();
        assert_eq!(
            ModuleRegistry::legacy_source_count(),
            0,
            "published build embeds TOML only"
        );
        assert!(
            ModuleRegistry::toml_source_count() >= 247,
            "expected ≥247 TOML sources, got {}",
            ModuleRegistry::toml_source_count()
        );
        assert!(
            reg.toml_errors.is_empty(),
            "toml import errors: {:?}",
            &reg.toml_errors[..reg.toml_errors.len().min(5)]
        );
        assert!(
            reg.legacy_errors.is_empty(),
            "legacy import errors: {:?}",
            &reg.legacy_errors[..reg.legacy_errors.len().min(5)]
        );
        assert!(
            reg.module_count() >= 244,
            "expected ≥244 unique modules, got {}",
            reg.module_count()
        );
    }
}
