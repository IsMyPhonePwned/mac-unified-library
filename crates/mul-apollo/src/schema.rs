// SPDX-License-Identifier: GPL-3.0-only

use hashbrown::{HashMap, HashSet};

#[derive(Debug, Clone, Default)]
pub struct Schema {
    pub tables: HashMap<String, HashSet<String>>,
}

impl Schema {
    pub fn has_table(&self, name: &str) -> bool {
        self.tables.keys().any(|t| t.eq_ignore_ascii_case(name))
    }

    pub fn has_column(&self, table: &str, column: &str) -> bool {
        self.tables.iter().any(|(t, cols)| {
            t.eq_ignore_ascii_case(table) && cols.iter().any(|c| c.eq_ignore_ascii_case(column))
        })
    }

    pub fn satisfies(&self, req: &crate::module::Requirements) -> bool {
        for t in &req.tables {
            if !self.has_table(t) {
                return false;
            }
        }
        for (table, col) in &req.columns {
            if !self.has_column(table, col) {
                return false;
            }
        }
        true
    }
}
