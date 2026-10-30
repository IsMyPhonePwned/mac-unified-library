// SPDX-License-Identifier: GPL-3.0-only
//! Practical subset of Apple `log show --predicate` (NSPredicate-like) syntax.

use crate::error::{MulError, Result};
use crate::filter::Filter;

/// Parse a practical NSPredicate subset into a Filter AST.
pub fn parse_nspredicate(input: &str) -> Result<Filter> {
    let s = input.trim();
    if s.is_empty() {
        return Ok(Filter::True);
    }
    let bytes = s.as_bytes();
    let mut i = 0usize;
    let f = parse_or(bytes, &mut i)?;
    skip_ws(bytes, &mut i);
    if i < bytes.len() {
        return Err(MulError::Filter(format!(
            "trailing input near {:?}",
            &s[i..]
        )));
    }
    Ok(f)
}

fn skip_ws(b: &[u8], i: &mut usize) {
    while *i < b.len() && b[*i].is_ascii_whitespace() {
        *i += 1;
    }
}

fn peek(b: &[u8], i: usize) -> Option<u8> {
    b.get(i).copied()
}

fn match_kw(b: &[u8], i: &mut usize, kw: &str) -> bool {
    skip_ws(b, i);
    let kwb = kw.as_bytes();
    if b.len().saturating_sub(*i) < kwb.len() {
        return false;
    }
    if !b[*i..*i + kwb.len()].eq_ignore_ascii_case(kwb) {
        return false;
    }
    let after = *i + kwb.len();
    if kw.chars().all(|c| c.is_ascii_alphabetic())
        && after < b.len()
        && (b[after].is_ascii_alphanumeric() || b[after] == b'_')
    {
        return false;
    }
    *i = after;
    true
}

fn parse_or(b: &[u8], i: &mut usize) -> Result<Filter> {
    let mut left = parse_and(b, i)?;
    loop {
        skip_ws(b, i);
        if match_kw(b, i, "OR") || match_kw(b, i, "||") {
            let right = parse_and(b, i)?;
            left = Filter::Or(Box::new(left), Box::new(right));
        } else {
            break;
        }
    }
    Ok(left)
}

fn parse_and(b: &[u8], i: &mut usize) -> Result<Filter> {
    let mut left = parse_not(b, i)?;
    loop {
        skip_ws(b, i);
        if match_kw(b, i, "AND") || match_kw(b, i, "&&") {
            let right = parse_not(b, i)?;
            left = Filter::And(Box::new(left), Box::new(right));
        } else {
            break;
        }
    }
    Ok(left)
}

fn parse_not(b: &[u8], i: &mut usize) -> Result<Filter> {
    skip_ws(b, i);
    if match_kw(b, i, "NOT") || match_kw(b, i, "!") {
        let inner = parse_not(b, i)?;
        return Ok(Filter::Not(Box::new(inner)));
    }
    parse_primary(b, i)
}

fn parse_primary(b: &[u8], i: &mut usize) -> Result<Filter> {
    skip_ws(b, i);
    if peek(b, *i) == Some(b'(') {
        *i += 1;
        let inner = parse_or(b, i)?;
        skip_ws(b, i);
        if peek(b, *i) != Some(b')') {
            return Err(MulError::Filter("expected ')'".into()));
        }
        *i += 1;
        return Ok(inner);
    }
    parse_comparison(b, i)
}

fn parse_ident(b: &[u8], i: &mut usize) -> Result<String> {
    skip_ws(b, i);
    let start = *i;
    while *i < b.len() && (b[*i].is_ascii_alphanumeric() || b[*i] == b'_' || b[*i] == b'.') {
        *i += 1;
    }
    if start == *i {
        return Err(MulError::Filter("expected identifier".into()));
    }
    Ok(String::from_utf8_lossy(&b[start..*i]).into_owned())
}

fn parse_string(b: &[u8], i: &mut usize) -> Result<String> {
    skip_ws(b, i);
    let quote = match peek(b, *i) {
        Some(q @ (b'\'' | b'"')) => {
            *i += 1;
            q
        }
        _ => return Err(MulError::Filter("expected string literal".into())),
    };
    let start = *i;
    while *i < b.len() && b[*i] != quote {
        *i += 1;
    }
    if *i >= b.len() {
        return Err(MulError::Filter("unterminated string".into()));
    }
    let s = String::from_utf8_lossy(&b[start..*i]).into_owned();
    *i += 1;
    Ok(s)
}

fn parse_comparison(b: &[u8], i: &mut usize) -> Result<Filter> {
    let key = parse_ident(b, i)?;
    skip_ws(b, i);
    let op = if match_kw(b, i, "==") {
        "=="
    } else if match_kw(b, i, "!=") {
        "!="
    } else if match_kw(b, i, "BEGINSWITH") {
        "BEGINSWITH"
    } else if match_kw(b, i, "ENDSWITH") {
        "ENDSWITH"
    } else if match_kw(b, i, "CONTAINS[c]") {
        "CONTAINS[c]"
    } else if match_kw(b, i, "CONTAINS") {
        "CONTAINS"
    } else if match_kw(b, i, "LIKE") {
        "LIKE"
    } else if match_kw(b, i, "MATCHES") {
        "MATCHES"
    } else if match_kw(b, i, "IN") {
        return Err(MulError::Filter(
            "IN lists not fully expanded yet; use == / OR".into(),
        ));
    } else {
        return Err(MulError::Filter(format!(
            "unsupported operator after key {key}"
        )));
    };

    let value = parse_string(b, i)?;
    Ok(match (key.as_str(), op) {
        ("subsystem", "==") => Filter::SubsystemExact(value),
        ("category", "==") => Filter::CategoryExact(value),
        ("process" | "processImagePath", "==") => Filter::ProcessExact(value),
        ("sender" | "senderImagePath", "==") => Filter::SenderExact(value),
        ("eventMessage" | "composedMessage", "CONTAINS") => Filter::MessageContains(value),
        ("eventMessage" | "composedMessage", "CONTAINS[c]") => Filter::MessageContainsCi(value),
        ("eventMessage" | "composedMessage", "MATCHES") => Filter::MessageRegex(value),
        ("process" | "processImagePath", "BEGINSWITH") => Filter::ProcessPrefix(value),
        ("processIdentifier", "==") => {
            let pid: u32 = value
                .parse()
                .map_err(|_| MulError::Filter("bad pid".into()))?;
            Filter::Pid(pid)
        }
        (
            "subsystem"
            | "category"
            | "process"
            | "processImagePath"
            | "sender"
            | "senderImagePath"
            | "processIdentifier"
            | "threadIdentifier"
            | "eventMessage"
            | "messageType"
            | "eventType"
            | "composedMessage",
            _,
        ) => Filter::Predicate(format!("{key} {op} '{value}'")),
        (k, _) => Err(MulError::Filter(format!("unsupported predicate key: {k}")))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn and_or_not() {
        let f = parse_nspredicate(
            "subsystem == 'com.apple.runningboard' AND eventMessage CONTAINS 'assertion'",
        )
        .unwrap();
        assert!(matches!(f, Filter::And(_, _)));
    }

    #[test]
    fn parens() {
        let f = parse_nspredicate(
            "(subsystem == 'a' OR subsystem == 'b') AND NOT eventMessage CONTAINS 'x'",
        )
        .unwrap();
        assert!(matches!(f, Filter::And(_, _)));
    }

    #[test]
    fn unknown_key_errors() {
        assert!(parse_nspredicate("foo == 'bar'").is_err());
    }
}
