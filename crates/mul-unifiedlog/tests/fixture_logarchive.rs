// SPDX-License-Identifier: GPL-3.0-only

use mul_core::Filter;
use mul_unifiedlog::{DirLogSource, Options, UnifiedLog};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

fn sample() -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/sample.logarchive");
    p.exists().then_some(p)
}

#[test]
fn info_stats_on_sample() {
    let Some(path) = sample() else {
        eprintln!("skip: testdata/sample.logarchive missing");
        return;
    };
    let src = DirLogSource::open(&path).unwrap();
    let log = UnifiedLog::open(src, Options::default()).unwrap();
    let s = log.stats();
    assert!(s.files >= 1, "expected tracev3 files");
    assert!(s.unit_count >= 1, "expected work units");
    assert!(s.boots >= 1 || !s.boot_uuids.is_empty());
    assert!(s.build.is_some());
}

#[test]
fn decode_sample_batch() {
    let Some(path) = sample() else {
        return;
    };
    let src = DirLogSource::open(&path).unwrap();
    let log = UnifiedLog::open(
        src,
        Options {
            ordered: false, // faster for smoke
            include_signposts: false,
            threads: 2,
        },
    )
    .unwrap();
    let n = AtomicUsize::new(0);
    let with_fmt = AtomicUsize::new(0);
    let with_msg = AtomicUsize::new(0);
    log.query(&Filter::True)
        .for_each_batch(|batch| {
            for e in batch {
                n.fetch_add(1, Ordering::Relaxed);
                if e.format_string.is_some() {
                    with_fmt.fetch_add(1, Ordering::Relaxed);
                }
                if e.event_message
                    .as_deref()
                    .map(|m| !m.is_empty() && !m.starts_with("<unknown"))
                    .unwrap_or(false)
                {
                    with_msg.fetch_add(1, Ordering::Relaxed);
                }
            }
            // Stop after we've seen enough by returning Ok but using a hack:
            // continue until at least 500; full archive is fine unordered for CI smoke.
            Ok(())
        })
        .unwrap();
    let n = n.load(Ordering::Relaxed);
    assert!(n > 100, "expected >100 events, got {n}");
    assert!(
        with_fmt.load(Ordering::Relaxed) > 0,
        "expected resolved format strings"
    );
    assert!(
        with_msg.load(Ordering::Relaxed) > 0,
        "expected formatted messages"
    );
}
