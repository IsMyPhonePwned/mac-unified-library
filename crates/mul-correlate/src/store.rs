// SPDX-License-Identifier: GPL-3.0-only

use hashbrown::HashMap;
use mul_core::event::{EntityKey, Event, Evidence};
use mul_core::par;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntityRecord {
    pub key: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Default, Clone)]
pub struct PartialStore {
    pub entities: HashMap<String, EntityRecord>,
    pub events: Vec<Event>,
}

impl PartialStore {
    pub fn ingest_event(&mut self, event: Event) {
        if event.ts != i64::MIN {
            // entity evidence hooks later
        }
        self.events.push(event);
    }

    pub fn merge(mut self, other: PartialStore) -> Self {
        for (k, mut v) in other.entities {
            match self.entities.entry(k) {
                hashbrown::hash_map::Entry::Occupied(mut occ) => {
                    let e = occ.get_mut();
                    e.first_seen = e.first_seen.min(v.first_seen);
                    e.last_seen = e.last_seen.max(v.last_seen);
                    for ev in v.evidence.drain(..) {
                        if e.evidence.len() < 32 {
                            e.evidence.push(ev);
                        }
                    }
                }
                hashbrown::hash_map::Entry::Vacant(vac) => {
                    vac.insert(v);
                }
            }
        }
        self.events.extend(other.events);
        self
    }

    pub fn note_entity(&mut self, key: EntityKey, ts: i64, evidence: Evidence) {
        let k = format!("{key:?}");
        let rec = self.entities.entry(k.clone()).or_insert(EntityRecord {
            key: k,
            first_seen: ts,
            last_seen: ts,
            evidence: Vec::new(),
        });
        if ts != i64::MIN {
            if rec.first_seen == i64::MIN || ts < rec.first_seen {
                rec.first_seen = ts;
            }
            if ts > rec.last_seen {
                rec.last_seen = ts;
            }
        }
        if rec.evidence.len() < 32 {
            rec.evidence.push(evidence);
        }
    }
}

#[derive(Debug, Default)]
pub struct Store {
    pub entities: Vec<EntityRecord>,
    pub events: Vec<Event>,
}

impl Store {
    pub fn from_partials(partials: Vec<PartialStore>) -> Self {
        let merged = par::reduce(
            partials,
            PartialStore::default(),
            |p| p,
            |a, b| a.merge(b),
        );
        let mut entities: Vec<_> = merged.entities.into_values().collect();
        par::sort_by_key(&mut entities, |e| e.key.clone());
        let mut events = merged.events;
        par::sort_by_key(&mut events, |e| (e.ts, e.source.0.clone()));
        Self { entities, events }
    }
}
