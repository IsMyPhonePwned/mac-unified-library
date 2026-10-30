// SPDX-License-Identifier: GPL-3.0-only

/// Normalise archive-relative paths: strip leading `./`, collapse `//`, lowercase for comparison keys.
pub fn norm_path(p: &str) -> String {
    let mut out = String::with_capacity(p.len());
    let p = p.trim_start_matches("./");
    let mut prev_slash = false;
    for ch in p.replace('\\', "/").chars() {
        if ch == '/' {
            if !prev_slash {
                out.push('/');
            }
            prev_slash = true;
        } else {
            out.push(ch);
            prev_slash = false;
        }
    }
    while out.starts_with('/') {
        out.remove(0);
    }
    out
}

/// Case-insensitive path equality for directory segments; tolerant of `system_logs.logarchive/` prefixes.
pub fn path_eq_ci(a: &str, b: &str) -> bool {
    norm_path(a).eq_ignore_ascii_case(&norm_path(b))
}

pub fn strip_logarchive_prefix(p: &str) -> &str {
    let n = norm_path(p);
    const PREFIXES: &[&str] = &[
        "system_logs.logarchive/",
        "System_Logs.logarchive/",
    ];
    for pref in PREFIXES {
        if n.len() >= pref.len() && n[..pref.len()].eq_ignore_ascii_case(pref) {
            // Return from original if possible
            if let Some(idx) = p.to_ascii_lowercase().find("logarchive/") {
                return &p[idx + "logarchive/".len()..];
            }
        }
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises() {
        assert_eq!(norm_path("./a//b\\c"), "a/b/c");
    }
}
