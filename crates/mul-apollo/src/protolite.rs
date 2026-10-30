// SPDX-License-Identifier: GPL-3.0-only
//! Schema-less protobuf wire-format decoder.

use mul_core::{Cur, FormatError};
use std::collections::BTreeMap;

const MAX_DEPTH: usize = 32;
const MAX_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub enum ProtoValue {
    Varint(u64),
    Fixed64(u64),
    Fixed32(u32),
    Bytes(Vec<u8>),
    String(String),
    Message(ProtoMessage),
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProtoMessage {
    pub fields: BTreeMap<u32, Vec<ProtoValue>>,
}

impl ProtoMessage {
    pub fn get_path(&self, path: &str) -> Option<&ProtoValue> {
        // "1.6" style
        let mut cur = self;
        let parts: Vec<&str> = path.split('.').collect();
        for (idx, part) in parts.iter().enumerate() {
            let num: u32 = part.parse().ok()?;
            let vals = cur.fields.get(&num)?;
            let last = vals.last()?;
            if idx + 1 == parts.len() {
                return Some(last);
            }
            match last {
                ProtoValue::Message(m) => cur = m,
                _ => return None,
            }
        }
        None
    }
}

pub fn decode(data: &[u8]) -> Result<ProtoMessage, FormatError> {
    if data.len() > MAX_BYTES {
        return Err(FormatError::new(0, "protobuf too large"));
    }
    decode_msg(data, 0)
}

fn decode_msg(data: &[u8], depth: usize) -> Result<ProtoMessage, FormatError> {
    if depth > MAX_DEPTH {
        return Err(FormatError::new(0, "protobuf depth exceeded"));
    }
    let mut c = Cur::new(data);
    let mut msg = ProtoMessage::default();
    while !c.is_empty() {
        let key = read_varint(&mut c)?;
        let field = (key >> 3) as u32;
        let wire = (key & 7) as u8;
        let val = match wire {
            0 => ProtoValue::Varint(read_varint(&mut c)?),
            1 => ProtoValue::Fixed64(c.u64_le()?),
            5 => ProtoValue::Fixed32(c.u32_le()?),
            2 => {
                let len = read_varint(&mut c)? as usize;
                let bytes = c.bytes(len)?.to_vec();
                // Prefer printable UTF-8 strings; many short strings are also valid
                // accidental nested protobuf (e.g. "hi" → field 13 varint).
                if let Ok(s) = std::str::from_utf8(&bytes) {
                    if !s.is_empty()
                        && s.chars()
                            .all(|ch| !ch.is_control() || ch == '\n' || ch == '\t')
                    {
                        ProtoValue::String(s.to_string())
                    } else if let Ok(inner) = decode_msg(&bytes, depth + 1) {
                        if !inner.fields.is_empty() {
                            ProtoValue::Message(inner)
                        } else {
                            ProtoValue::Bytes(bytes)
                        }
                    } else {
                        ProtoValue::Bytes(bytes)
                    }
                } else if let Ok(inner) = decode_msg(&bytes, depth + 1) {
                    if !inner.fields.is_empty() {
                        ProtoValue::Message(inner)
                    } else {
                        ProtoValue::Bytes(bytes)
                    }
                } else {
                    ProtoValue::Bytes(bytes)
                }
            }
            other => {
                return Err(FormatError::new(c.pos(), format!("bad wire type {other}")));
            }
        };
        msg.fields.entry(field).or_default().push(val);
    }
    Ok(msg)
}

fn read_varint(c: &mut Cur<'_>) -> Result<u64, FormatError> {
    let mut result = 0u64;
    for shift in (0..64).step_by(7) {
        let b = c.u8()? as u64;
        result |= (b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok(result);
        }
    }
    Err(FormatError::new(c.pos(), "varint overflow"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_simple() {
        // field 1, wire 0 (varint), value 42 → 0x08 0x2a
        let msg = decode(&[0x08, 0x2a]).unwrap();
        match msg.fields.get(&1).unwrap()[0] {
            ProtoValue::Varint(42) => {}
            ref o => panic!("{o:?}"),
        }
    }

    #[test]
    fn decodes_string() {
        // field 2, len-delim "hi" → 0x12 0x02 'h' 'i'
        let msg = decode(&[0x12, 0x02, b'h', b'i']).unwrap();
        match &msg.fields.get(&2).unwrap()[0] {
            ProtoValue::String(s) => assert_eq!(s, "hi"),
            o => panic!("{o:?}"),
        }
    }
}
