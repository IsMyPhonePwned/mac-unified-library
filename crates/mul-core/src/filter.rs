// SPDX-License-Identifier: GPL-3.0-only

use crate::error::Result;
use crate::event::Level;
use regex::Regex;

/// Predicate AST for unified-log / event queries.
#[derive(Debug, Clone)]
pub enum Filter {
    True,
    And(Box<Filter>, Box<Filter>),
    Or(Box<Filter>, Box<Filter>),
    Not(Box<Filter>),
    TimeRange { start_ns: Option<i64>, end_ns: Option<i64> },
    Pid(u32),
    Pids(Vec<u32>),
    ProcessExact(String),
    ProcessPrefix(String),
    SenderExact(String),
    SubsystemExact(String),
    CategoryExact(String),
    LevelAtLeast(Level),
    MessageContains(String),
    MessageContainsCi(String),
    MessageRegex(String),
    /// Opaque predicate string for later NSPredicate subset parsing.
    Predicate(String),
}

impl Filter {
    pub fn parse_predicate(s: &str) -> Result<Self> {
        crate::predicate::parse_nspredicate(s)
    }

    pub fn and(self, other: Filter) -> Filter {
        Filter::And(Box::new(self), Box::new(other))
    }

    pub fn matches_message(&self, msg: &str) -> bool {
        match self {
            Filter::True => true,
            Filter::And(a, b) => a.matches_message(msg) && b.matches_message(msg),
            Filter::Or(a, b) => a.matches_message(msg) || b.matches_message(msg),
            Filter::Not(a) => !a.matches_message(msg),
            Filter::MessageContains(s) => msg.contains(s),
            Filter::MessageContainsCi(s) => msg.to_ascii_lowercase().contains(&s.to_ascii_lowercase()),
            Filter::MessageRegex(pat) => Regex::new(pat)
                .map(|r| r.is_match(msg))
                .unwrap_or(false),
            Filter::TimeRange { .. }
            | Filter::Pid(_)
            | Filter::Pids(_)
            | Filter::ProcessExact(_)
            | Filter::ProcessPrefix(_)
            | Filter::SenderExact(_)
            | Filter::SubsystemExact(_)
            | Filter::CategoryExact(_)
            | Filter::LevelAtLeast(_)
            | Filter::Predicate(_) => true,
        }
    }

    /// Match an owned log-like row (post-decode).
    pub fn matches_event(
        &self,
        subsystem: Option<&str>,
        category: Option<&str>,
        process: Option<&str>,
        sender: Option<&str>,
        pid: Option<u32>,
        message: &str,
    ) -> bool {
        match self {
            Filter::True => true,
            Filter::And(a, b) => {
                a.matches_event(subsystem, category, process, sender, pid, message)
                    && b.matches_event(subsystem, category, process, sender, pid, message)
            }
            Filter::Or(a, b) => {
                a.matches_event(subsystem, category, process, sender, pid, message)
                    || b.matches_event(subsystem, category, process, sender, pid, message)
            }
            Filter::Not(a) => !a.matches_event(subsystem, category, process, sender, pid, message),
            Filter::SubsystemExact(s) => subsystem == Some(s.as_str()),
            Filter::CategoryExact(s) => category == Some(s.as_str()),
            Filter::ProcessExact(s) => process == Some(s.as_str()),
            Filter::ProcessPrefix(s) => process.map(|p| p.starts_with(s)).unwrap_or(false),
            Filter::SenderExact(s) => sender == Some(s.as_str()),
            Filter::Pid(p) => pid == Some(*p),
            Filter::Pids(ps) => pid.map(|p| ps.contains(&p)).unwrap_or(false),
            Filter::MessageContains(_)
            | Filter::MessageContainsCi(_)
            | Filter::MessageRegex(_) => self.matches_message(message),
            Filter::TimeRange { .. } | Filter::LevelAtLeast(_) | Filter::Predicate(_) => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_subsystem() {
        let f = Filter::parse_predicate("subsystem == 'com.apple.runningboard'").unwrap();
        match f {
            Filter::SubsystemExact(s) => assert_eq!(s, "com.apple.runningboard"),
            _ => panic!("expected subsystem"),
        }
    }
}
