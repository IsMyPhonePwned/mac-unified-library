// SPDX-License-Identifier: GPL-3.0-only
//! Lazy uuidtext / dsc cache (parse once per UUID).

use crate::dsc::Dsc;
use crate::source::LogSource;
use crate::uuidtext::UuidText;
use std::sync::{Arc, Mutex, OnceLock};
use uuid::Uuid;

type Slot<T> = OnceLock<Option<Arc<T>>>;

#[derive(Default)]
pub struct StringsCache {
    uuidtext: Mutex<hashbrown::HashMap<Uuid, Arc<Slot<UuidText>>>>,
    dsc: Mutex<hashbrown::HashMap<Uuid, Arc<Slot<Dsc>>>>,
}

impl StringsCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn uuidtext(&self, src: &dyn LogSource, uuid: Uuid) -> Option<Arc<UuidText>> {
        let slot = {
            let mut map = self.uuidtext.lock().unwrap_or_else(|e| e.into_inner());
            map.entry(uuid)
                .or_insert_with(|| Arc::new(OnceLock::new()))
                .clone()
        };
        slot.get_or_init(|| {
            let bytes = src.uuidtext(uuid)?;
            UuidText::parse(bytes.as_slice()).ok().map(Arc::new)
        })
        .clone()
    }

    pub fn dsc(&self, src: &dyn LogSource, uuid: Uuid) -> Option<Arc<Dsc>> {
        let slot = {
            let mut map = self.dsc.lock().unwrap_or_else(|e| e.into_inner());
            map.entry(uuid)
                .or_insert_with(|| Arc::new(OnceLock::new()))
                .clone()
        };
        slot.get_or_init(|| {
            let bytes = src.dsc(uuid)?;
            Dsc::parse(bytes.as_slice()).ok().map(Arc::new)
        })
        .clone()
    }
}
