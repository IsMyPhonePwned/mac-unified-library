// SPDX-License-Identifier: GPL-3.0-only

use serde::{Deserialize, Serialize};

/// Epoch kinds for APOLLO timestamps. Never invent "now" on parse failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Epoch {
    Unix,
    UnixMs,
    UnixUs,
    /// Seconds since 2001-01-01 UTC.
    Cocoa,
    CocoaNs,
    Mach,
    /// Microseconds since 1601-01-01.
    Webkit,
    IsoText,
}

/// Cocoa epoch: 2001-01-01 00:00:00 UTC in Unix seconds.
const COCOA_UNIX_OFFSET: i64 = 978_307_200;
/// WebKit/FILETIME epoch: 1601-01-01 → Unix in microseconds.
const WEBKIT_UNIX_US_OFFSET: i64 = 11_644_473_600_000_000;

/// Convert a numeric epoch value to UTC nanoseconds. Returns `None` if unrepresentable.
pub fn to_utc_ns(epoch: Epoch, value: f64) -> Option<i64> {
    let secs_ns = |secs: f64| -> Option<i64> {
        if !secs.is_finite() {
            return None;
        }
        let ns = secs * 1_000_000_000.0;
        if ns < i64::MIN as f64 || ns > i64::MAX as f64 {
            return None;
        }
        Some(ns as i64)
    };
    match epoch {
        Epoch::Unix => secs_ns(value),
        Epoch::UnixMs => secs_ns(value / 1_000.0),
        Epoch::UnixUs => secs_ns(value / 1_000_000.0),
        Epoch::Cocoa => secs_ns(value + COCOA_UNIX_OFFSET as f64),
        Epoch::CocoaNs => {
            let unix_ns = value + (COCOA_UNIX_OFFSET as f64) * 1_000_000_000.0;
            if unix_ns < i64::MIN as f64 || unix_ns > i64::MAX as f64 {
                None
            } else {
                Some(unix_ns as i64)
            }
        }
        Epoch::Webkit => {
            let unix_us = value - WEBKIT_UNIX_US_OFFSET as f64;
            secs_ns(unix_us / 1_000_000.0)
        }
        Epoch::Mach | Epoch::IsoText => None,
    }
}

/// Parse ISO / Apple-style datetime text to UTC ns. No "now" fallback.
pub fn parse_iso_text(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // Try RFC3339-ish via chrono when clock feature off — use manual / timestamp parse.
    if let Ok(n) = s.parse::<i64>() {
        return to_utc_ns(Epoch::Unix, n as f64);
    }
    if let Ok(f) = s.parse::<f64>() {
        return to_utc_ns(Epoch::Unix, f);
    }
    // YYYY-MM-DD HH:MM:SS[.fff] [+ZZZZ]
    parse_simple_datetime(s)
}

fn parse_simple_datetime(s: &str) -> Option<i64> {
    // Minimal parser: "YYYY-MM-DD HH:MM:SS" or with T separator.
    let s = s.replace('T', " ");
    let (date, time) = s.split_once(' ')?;
    let mut dp = date.split('-');
    let y: i64 = dp.next()?.parse().ok()?;
    let mo: i64 = dp.next()?.parse().ok()?;
    let d: i64 = dp.next()?.parse().ok()?;
    let time = time.split(['+', '-', 'Z']).next()?.trim();
    let mut tp = time.split(':');
    let h: i64 = tp.next()?.parse().ok()?;
    let mi: i64 = tp.next()?.parse().ok()?;
    let sec_s = tp.next().unwrap_or("0");
    let (sec, frac) = if let Some((a, b)) = sec_s.split_once('.') {
        (a.parse::<i64>().ok()?, b)
    } else {
        (sec_s.parse::<i64>().ok()?, "")
    };
    let mut frac_ns: i64 = 0;
    if !frac.is_empty() {
        let mut padded = frac.chars().take(9).collect::<String>();
        while padded.len() < 9 {
            padded.push('0');
        }
        frac_ns = padded.parse().ok()?;
    }
    let days = days_from_civil(y, mo, d)?;
    let unix = days * 86400 + h * 3600 + mi * 60 + sec;
    Some(unix * 1_000_000_000 + frac_ns)
}

/// Howard Hinnant civil_from_days inverse (proleptic Gregorian) → days since Unix epoch.
fn days_from_civil(y: i64, m: i64, d: i64) -> Option<i64> {
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146097 + doe - 719468)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_epoch() {
        assert_eq!(to_utc_ns(Epoch::Unix, 0.0), Some(0));
    }

    #[test]
    fn iso_no_now_on_garbage() {
        assert!(parse_iso_text("not-a-date").is_none());
        assert!(parse_iso_text("").is_none());
    }

    #[test]
    fn iso_basic() {
        let ns = parse_iso_text("1970-01-01 00:00:00").unwrap();
        assert_eq!(ns, 0);
    }
}
