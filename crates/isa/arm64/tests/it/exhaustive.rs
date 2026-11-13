//! Every one of the 2^32 instruction words: decoded, formatted, and
//! explained, in parallel. No oracle: invariants that hold for any word.
//!
//! - decoding never panics, and gives the same answer twice;
//! - a decoded instruction keeps its word and address, names its encoding
//!   and class, and formats to text that starts with a mnemonic;
//! - explaining a word never panics.
//!
//! It takes minutes on a many-core machine (in release):
//!
//!     cargo test --release -p hexcavator-arm64 --test it -- --ignored --nocapture exhaustive::

#![allow(
    clippy::cast_possible_truncation,
    reason = "word arithmetic over the 32-bit space"
)]

use std::sync::atomic::{AtomicU64, Ordering};

/// How many words to explain (explaining is slower than decoding): every
/// one whose low bits are these.
const EXPLAIN_EVERY: u32 = 1 << 12;

fn check(word: u32, decoded: &AtomicU64, failures: &std::sync::Mutex<Vec<String>>) {
    let address = u64::from(word) << 2;
    let first = hexcavator_arm64::decode(word, address);
    let again = hexcavator_arm64::decode(word, address);
    let fail = |why: String| {
        let mut f = failures.lock().unwrap();
        if f.len() < 100 {
            f.push(format!("{word:08x}: {why}"));
        }
    };
    if let Some(e) = hexcavator_arm64::validity_disagrees(word) {
        fail(format!(
            "{e}: the quick validity check disagrees with formatting"
        ));
    }
    if first.is_some() != again.is_some() {
        fail("decoded once but not twice".into());
        return;
    }
    if let Some(inst) = first {
        decoded.fetch_add(1, Ordering::Relaxed);
        if inst.word() != word || inst.address() != address {
            fail(format!("kept {:08x} at {:#x}", inst.word(), inst.address()));
        }
        if inst.encoding_name().is_empty() || inst.class().is_empty() {
            fail("no encoding or class name".into());
        }
        let text = hexcavator_arm64::format(&inst);
        // (A leading `?` marks a CONSTRAINED UNPREDICTABLE encoding.)
        if !text
            .trim_start_matches('?')
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
            || (text.starts_with('?') != inst.is_unpredictable())
        {
            fail(format!("formats as {text:?}"));
        }
        if again.map(|i| hexcavator_arm64::format(&i)) != Some(text) {
            fail("formats differently twice".into());
        }
    }
    if word.is_multiple_of(EXPLAIN_EVERY) {
        let _ = hexcavator_arm64::explain(word);
    }
}

#[test]
#[ignore = "all 2^32 words: minutes, in release"]
fn every_word() {
    let threads = std::thread::available_parallelism().map_or(8, std::num::NonZero::get);
    let decoded = AtomicU64::new(0);
    let failures = std::sync::Mutex::new(Vec::new());
    let next = AtomicU64::new(0);
    // Chunks of 2^20 words, taken in turn.
    const CHUNK: u64 = 1 << 20;
    let start = std::time::Instant::now();
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                loop {
                    let from = next.fetch_add(CHUNK, Ordering::Relaxed);
                    if from >= 1 << 32 {
                        break;
                    }
                    for w in from..from + CHUNK {
                        check(w as u32, &decoded, &failures);
                    }
                }
            });
        }
    });
    let decoded = decoded.load(Ordering::Relaxed);
    let failures = failures.into_inner().unwrap();
    println!(
        "{decoded} of 2^32 words decode ({:.1}%), in {:?} on {threads} threads",
        decoded as f64 * 100.0 / 4_294_967_296.0,
        start.elapsed()
    );
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The same checks on a sample of every 65,537th word (a prime stride:
/// every bit pattern's neighborhood), to run with the other tests.
#[test]
fn a_sample_of_words() {
    let decoded = AtomicU64::new(0);
    let failures = std::sync::Mutex::new(Vec::new());
    let mut w: u64 = 0;
    while w < 1 << 32 {
        check(w as u32, &decoded, &failures);
        w += 65_537;
    }
    let failures = failures.into_inner().unwrap();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(decoded.load(Ordering::Relaxed) > 10_000);
}
