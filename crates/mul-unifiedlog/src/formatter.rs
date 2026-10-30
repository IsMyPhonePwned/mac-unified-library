// SPDX-License-Identifier: GPL-3.0-only
//! Printf + Apple `%{…}` format-string parser and renderer.

use crate::firehose::{DataItem, ItemValue};
use std::fmt::Write as _;

#[derive(Debug, Clone)]
pub enum FmtPiece {
    Literal(String),
    Spec(FmtSpec),
}

#[derive(Debug, Clone)]
pub struct FmtSpec {
    pub flags: String,
    pub width: Option<i32>,
    pub precision: Option<i32>,
    pub length: String,
    pub conv: char,
    pub decoder: Option<String>,
    pub star_width: bool,
    pub star_prec: bool,
}

/// Parse a format string once into pieces.
pub fn parse_format(fmt: &str) -> Vec<FmtPiece> {
    let mut out = Vec::new();
    let mut chars = fmt.chars().peekable();
    let mut lit = String::new();
    while let Some(ch) = chars.next() {
        if ch != '%' {
            lit.push(ch);
            continue;
        }
        if chars.peek() == Some(&'%') {
            chars.next();
            lit.push('%');
            continue;
        }
        if !lit.is_empty() {
            out.push(FmtPiece::Literal(std::mem::take(&mut lit)));
        }
        let mut flags = String::new();
        while matches!(chars.peek(), Some('+' | '-' | ' ' | '#' | '0')) {
            flags.push(chars.next().unwrap());
        }
        let mut star_width = false;
        let mut width = None;
        if chars.peek() == Some(&'*') {
            chars.next();
            star_width = true;
        } else {
            let mut w = String::new();
            while matches!(chars.peek(), Some('0'..='9')) {
                w.push(chars.next().unwrap());
            }
            if !w.is_empty() {
                width = w.parse().ok();
            }
        }
        let mut star_prec = false;
        let mut precision = None;
        if chars.peek() == Some(&'.') {
            chars.next();
            if chars.peek() == Some(&'*') {
                chars.next();
                star_prec = true;
            } else {
                let mut p = String::new();
                while matches!(chars.peek(), Some('0'..='9')) {
                    p.push(chars.next().unwrap());
                }
                precision = if p.is_empty() {
                    Some(0)
                } else {
                    p.parse().ok()
                };
            }
        }
        // optional %{decoder}
        let mut decoder = None;
        if chars.peek() == Some(&'{') {
            chars.next();
            let mut d = String::new();
            for ch in chars.by_ref() {
                if ch == '}' {
                    break;
                }
                d.push(ch);
            }
            decoder = Some(d);
        }
        let mut length = String::new();
        while matches!(
            chars.peek(),
            Some('h' | 'l' | 'L' | 'j' | 'z' | 't' | 'q')
        ) {
            length.push(chars.next().unwrap());
        }
        let conv = chars.next().unwrap_or('?');
        out.push(FmtPiece::Spec(FmtSpec {
            flags,
            width,
            precision,
            length,
            conv,
            decoder,
            star_width,
            star_prec,
        }));
    }
    if !lit.is_empty() {
        out.push(FmtPiece::Literal(lit));
    }
    out
}

/// Resolve item bytes into display args, then render.
pub fn render(
    pieces: &[FmtPiece],
    items: &[DataItem],
    values_data: &[u8],
    private_data: &[u8],
) -> String {
    let args = materialize_args(items, values_data, private_data);
    let mut out = String::new();
    let mut ai = 0usize;
    for piece in pieces {
        match piece {
            FmtPiece::Literal(s) => out.push_str(s),
            FmtPiece::Spec(spec) => {
                if spec.star_width {
                    ai += 1;
                }
                if spec.star_prec {
                    ai += 1;
                }
                let arg = args.get(ai);
                ai += 1;
                let rendered = match arg {
                    None => "<missing>".to_string(),
                    Some(a) => render_arg(spec, a),
                };
                out.push_str(&rendered);
            }
        }
    }
    out
}

#[derive(Debug, Clone)]
enum Arg {
    Bytes(Vec<u8>),
    Text(String),
    Private,
}

fn materialize_args(items: &[DataItem], values: &[u8], private: &[u8]) -> Vec<Arg> {
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        match &it.value {
            ItemValue::PrivatePlaceholder => out.push(Arg::Private),
            ItemValue::Inline(b) => out.push(Arg::Bytes(b.clone())),
            ItemValue::PublicRange { offset, size } => {
                let o = *offset as usize;
                let s = *size as usize;
                if o + s <= values.len() {
                    let slice = &values[o..o + s];
                    if let Ok(t) = std::str::from_utf8(slice) {
                        let t = t.trim_end_matches('\0');
                        out.push(Arg::Text(t.to_string()));
                    } else {
                        out.push(Arg::Bytes(slice.to_vec()));
                    }
                } else {
                    out.push(Arg::Text(String::new()));
                }
            }
            ItemValue::PrivateRange { offset, size } => {
                let o = *offset as usize;
                let s = *size as usize;
                if o + s <= private.len() {
                    let slice = &private[o..o + s];
                    if let Ok(t) = std::str::from_utf8(slice) {
                        out.push(Arg::Text(t.trim_end_matches('\0').to_string()));
                    } else {
                        out.push(Arg::Private);
                    }
                } else {
                    out.push(Arg::Private);
                }
            }
        }
    }
    out
}

fn render_arg(spec: &FmtSpec, arg: &Arg) -> String {
    if let Some(dec) = &spec.decoder {
        match dec.as_str() {
            "private" | "sensitive" => return "<private>".into(),
            "public" => {}
            "bool" | "BOOL" => {
                if let Some(n) = arg_as_i64(arg) {
                    return if n != 0 { "YES".into() } else { "NO".into() };
                }
            }
            _ => {
                // unknown decoder: still render raw
            }
        }
    }
    match arg {
        Arg::Private => "<private>".into(),
        Arg::Text(s) => s.clone(),
        Arg::Bytes(b) => match spec.conv {
            's' | '@' => {
                let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
                String::from_utf8_lossy(&b[..end]).into_owned()
            }
            'd' | 'i' => format!("{}", int_from_bytes(b, true)),
            'u' | 'x' | 'X' | 'o' | 'p' => {
                let n = int_from_bytes(b, false) as u64;
                match spec.conv {
                    'x' => format!("{n:x}"),
                    'X' => format!("{n:X}"),
                    'o' => format!("{n:o}"),
                    'p' => format!("0x{n:x}"),
                    _ => format!("{n}"),
                }
            }
            'f' | 'F' | 'e' | 'E' | 'g' | 'G' | 'a' | 'A' => {
                if b.len() >= 8 {
                    let bits = u64::from_le_bytes(b[..8].try_into().unwrap());
                    format!("{}", f64::from_bits(bits))
                } else if b.len() >= 4 {
                    let bits = u32::from_le_bytes(b[..4].try_into().unwrap());
                    format!("{}", f32::from_bits(bits))
                } else {
                    String::new()
                }
            }
            'c' => {
                let ch = b.first().copied().unwrap_or(0) as char;
                ch.to_string()
            }
            'm' => {
                // Darwin errno text — embed a few common; else number
                let n = int_from_bytes(b, true) as i32;
                errno_text(n)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| {
                        let mut s = String::new();
                        let _ = write!(s, "{n}");
                        s
                    })
            }
            _ => hex::encode_upper_or_debug(b),
        },
    }
}

fn arg_as_i64(arg: &Arg) -> Option<i64> {
    match arg {
        Arg::Bytes(b) => Some(int_from_bytes(b, true)),
        Arg::Text(s) => s.parse().ok(),
        Arg::Private => None,
    }
}

fn int_from_bytes(b: &[u8], signed: bool) -> i64 {
    match b.len() {
        0 => 0,
        1 => {
            if signed {
                b[0] as i8 as i64
            } else {
                b[0] as i64
            }
        }
        2 => {
            let v = u16::from_le_bytes([b[0], b[1]]);
            if signed {
                v as i16 as i64
            } else {
                v as i64
            }
        }
        3..=4 => {
            let mut tmp = [0u8; 4];
            tmp[..b.len().min(4)].copy_from_slice(&b[..b.len().min(4)]);
            let v = u32::from_le_bytes(tmp);
            if signed {
                v as i32 as i64
            } else {
                v as i64
            }
        }
        _ => {
            let mut tmp = [0u8; 8];
            tmp[..b.len().min(8)].copy_from_slice(&b[..b.len().min(8)]);
            u64::from_le_bytes(tmp) as i64
        }
    }
}

fn errno_text(n: i32) -> Option<&'static str> {
    // Subset of Darwin errno — expand later.
    Some(match n {
        1 => "Operation not permitted",
        2 => "No such file or directory",
        3 => "No such process",
        4 => "Interrupted system call",
        5 => "Input/output error",
        9 => "Bad file descriptor",
        11 => "Resource temporarily unavailable",
        12 => "Cannot allocate memory",
        13 => "Permission denied",
        14 => "Bad address",
        17 => "File exists",
        20 => "Not a directory",
        21 => "Is a directory",
        22 => "Invalid argument",
        28 => "No space left on device",
        35 => "Resource deadlock avoided",
        45 => "Operation not supported",
        60 => "Operation timed out",
        61 => "Connection refused",
        _ => return None,
    })
}

mod hex {
    pub fn encode_upper_or_debug(b: &[u8]) -> String {
        if b.is_empty() {
            return String::new();
        }
        let mut s = String::with_capacity(b.len() * 2);
        for byte in b {
            use std::fmt::Write;
            let _ = write!(s, "{byte:02x}");
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_renders_simple() {
        let pieces = parse_format("hello %s world %d");
        assert_eq!(pieces.len(), 4);
        let items = vec![
            DataItem {
                type_id: 0x20,
                value: ItemValue::Inline(b"foo\0".to_vec()),
            },
            DataItem {
                type_id: 0x00,
                value: ItemValue::Inline(42i32.to_le_bytes().to_vec()),
            },
        ];
        let msg = render(&pieces, &items, &[], &[]);
        assert_eq!(msg, "hello foo world 42");
    }

    #[test]
    fn private_decoder() {
        let pieces = parse_format("%{private}s");
        let items = vec![DataItem {
            type_id: 0x01,
            value: ItemValue::PrivatePlaceholder,
        }];
        assert_eq!(render(&pieces, &items, &[], &[]), "<private>");
    }
}
