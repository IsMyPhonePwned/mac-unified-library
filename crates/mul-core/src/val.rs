// SPDX-License-Identifier: GPL-3.0-only

use crate::interner::Sym;
use serde::{Deserialize, Serialize};

/// Lightweight value — no `serde_json::Value` on hot paths.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Val {
    Null,
    Bool(bool),
    I64(i64),
    F64(f64),
    Str(Sym),
    Text(Box<str>),
    Bytes(Box<[u8]>),
    Time(i64),
}

impl Val {
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Val::I64(v) => Some(*v),
            Val::Time(v) => Some(*v),
            Val::F64(v) => Some(*v as i64),
            Val::Text(s) => s.parse().ok(),
            _ => None,
        }
    }

    pub fn as_text(&self, interner: &crate::Interner) -> Option<String> {
        match self {
            Val::Str(s) => Some(interner.resolve(*s)),
            Val::Text(s) => Some(s.to_string()),
            _ => None,
        }
    }

    pub fn from_json(v: &serde_json::Value) -> Self {
        match v {
            serde_json::Value::Null => Val::Null,
            serde_json::Value::Bool(b) => Val::Bool(*b),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Val::I64(i)
                } else if let Some(f) = n.as_f64() {
                    Val::F64(f)
                } else {
                    Val::Text(n.to_string().into())
                }
            }
            serde_json::Value::String(s) => Val::Text(s.clone().into()),
            other => Val::Text(other.to_string().into()),
        }
    }

    pub fn to_json(&self, interner: &crate::Interner) -> serde_json::Value {
        match self {
            Val::Null => serde_json::Value::Null,
            Val::Bool(b) => serde_json::Value::Bool(*b),
            Val::I64(i) => serde_json::json!(*i),
            Val::F64(f) => serde_json::json!(*f),
            Val::Str(s) => serde_json::Value::String(interner.resolve(*s)),
            Val::Text(s) => serde_json::Value::String(s.to_string()),
            Val::Bytes(b) => serde_json::Value::String(format!("base64:{}", b.len())),
            Val::Time(t) => serde_json::json!(*t),
        }
    }
}
