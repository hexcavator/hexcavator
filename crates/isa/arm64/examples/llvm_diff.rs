//! Compares hexcavator-arm64 with LLVM's disassembler (llvm-objdump, every
//! feature on) over a range of words, up to all 2^32: whether each word is
//! an instruction at all, and its mnemonic. Prints the differences by our
//! encoding (or LLVM's mnemonic, for words only it decodes), with examples:
//! a classification to review, not a verdict (LLVM is an oracle, not the
//! specification).
//!
//!     cargo run --release -p hexcavator-arm64 --example llvm_diff -- \
//!         <llvm-objdump> [start] [count] [stride] [threads]
//!
//! (count 0x100000000 and stride 1: every word.) Words go to llvm-objdump
//! in chunks, each wrapped in a minimal ELF, and its output is read as it
//! comes: nothing is stored.

#![allow(
    clippy::cast_possible_truncation,
    reason = "word arithmetic over a 32-bit space"
)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// Words per llvm-objdump run.
const CHUNK: u64 = 1 << 22;

/// A minimal ELF64 relocatable file for AArch64 holding `text` as `.text`.
fn elf(text: &[u8]) -> Vec<u8> {
    let shstr = b"\0.text\0.shstrtab\0";
    let off_text = 64u64;
    let off_shstr = off_text + text.len() as u64;
    let off_sh = (off_shstr + shstr.len() as u64 + 7) & !7;
    let mut d = Vec::with_capacity(off_sh as usize + 3 * 64);
    d.extend_from_slice(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0");
    d.extend_from_slice(&1u16.to_le_bytes()); // ET_REL
    d.extend_from_slice(&183u16.to_le_bytes()); // EM_AARCH64
    d.extend_from_slice(&1u32.to_le_bytes());
    d.extend_from_slice(&0u64.to_le_bytes()); // entry
    d.extend_from_slice(&0u64.to_le_bytes()); // phoff
    d.extend_from_slice(&off_sh.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes()); // flags
    for v in [64u16, 0, 0, 64, 3, 2] {
        d.extend_from_slice(&v.to_le_bytes());
    }
    d.extend_from_slice(text);
    d.extend_from_slice(shstr);
    d.resize(off_sh as usize, 0);
    let sh = |d: &mut Vec<u8>, name: u32, typ: u32, flags: u64, off: u64, size: u64, align: u64| {
        d.extend_from_slice(&name.to_le_bytes());
        d.extend_from_slice(&typ.to_le_bytes());
        for v in [flags, 0, off, size] {
            d.extend_from_slice(&v.to_le_bytes());
        }
        d.extend_from_slice(&0u32.to_le_bytes());
        d.extend_from_slice(&0u32.to_le_bytes());
        d.extend_from_slice(&align.to_le_bytes());
        d.extend_from_slice(&0u64.to_le_bytes());
    };
    sh(&mut d, 0, 0, 0, 0, 0, 0);
    sh(&mut d, 1, 1, 6, off_text, text.len() as u64, 4);
    sh(&mut d, 7, 3, 0, off_shstr, shstr.len() as u64, 1);
    d
}

/// What we and LLVM disagree on, by class: (count, examples).
type Classes = BTreeMap<String, (u64, Vec<String>)>;

fn note(classes: &mut Classes, class: String, example: String) {
    let e = classes.entry(class).or_default();
    e.0 += 1;
    if e.1.len() < 4 {
        e.1.push(example);
    }
}

/// Our mnemonic for an instruction (lower case), and whether we mark it
/// CONSTRAINED UNPREDICTABLE.
fn ours(word: u32) -> Option<(String, bool)> {
    let inst = hexcavator_arm64::decode(word, 0)?;
    let text = hexcavator_arm64::format(&inst);
    let m = text
        .trim_start_matches('?')
        .split_whitespace()
        .next()?
        .to_ascii_lowercase();
    Some((m, text.starts_with('?')))
}

const CONDITIONS: &[&str] = &[
    "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv",
    "cs", "cc",
];

/// Whether two mnemonics are one in different conventions: dumpbin's
/// `beq` and `csincge` (the condition joined on) for LLVM's `b.eq` and
/// `csinc` (the condition an operand); `b`/`bc` for `.al`/`.nv`.
fn same_mnemonic(ours: &str, theirs: &str) -> bool {
    if ours == theirs || ours == theirs.replace('.', "") {
        return true;
    }
    if let Some((base, cond)) = theirs.split_once('.')
        && (cond == "al" || cond == "nv")
        && ours == base
    {
        return true;
    }
    ours.strip_prefix(theirs)
        .is_some_and(|rest| CONDITIONS.contains(&rest))
}

fn run_chunk(
    objdump: &str,
    words: &[u32],
    dir: &std::path::Path,
    n: u64,
    classes: &Mutex<Classes>,
    agree: &AtomicU64,
) {
    let text: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let path = dir.join(format!("chunk-{n}.o"));
    std::fs::write(&path, elf(&text)).expect("writing a chunk");
    let mut child = Command::new(objdump)
        .args(["-d", "--mattr=+all", "--no-show-raw-insn"])
        .arg(&path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("running llvm-objdump");
    let out = BufReader::new(child.stdout.take().expect("its output"));
    let mut local = Classes::new();
    let mut same = 0u64;
    for line in out.lines().map_while(Result::ok) {
        // "      1c: \tadd\tx0, x1, #0x1"
        let Some((addr, rest)) = line.split_once(':') else {
            continue;
        };
        let Ok(offset) = u64::from_str_radix(addr.trim(), 16) else {
            continue;
        };
        let Some(&word) = words.get((offset / 4) as usize) else {
            continue;
        };
        let theirs = rest
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        let theirs = if theirs == "<unknown>" {
            None
        } else {
            Some(theirs)
        };
        let ours = ours(word);
        match (&ours, &theirs) {
            (None, None) => same += 1,
            (Some((a, _)), Some(b)) if same_mnemonic(a, b) => same += 1,
            (Some((a, marked)), None) => {
                let enc = hexcavator_arm64::decode(word, 0).map_or("?", |i| i.encoding_name());
                let how = if *marked {
                    "only ours (marked unpredictable)"
                } else {
                    "only ours"
                };
                note(
                    &mut local,
                    format!("{how}: {enc}"),
                    format!("{word:08x} {a}"),
                );
            }
            (None, Some(b)) => note(
                &mut local,
                format!("only LLVM's: {b}"),
                format!("{word:08x} {}", rest.trim()),
            ),
            (Some((a, _)), Some(b)) => {
                let enc = hexcavator_arm64::decode(word, 0).map_or("?", |i| i.encoding_name());
                note(
                    &mut local,
                    format!("mnemonic: {enc}: {a} vs {b}"),
                    format!("{word:08x} {}", rest.trim()),
                );
            }
        }
    }
    let _ = child.wait();
    let _ = std::fs::remove_file(&path);
    agree.fetch_add(same, Ordering::Relaxed);
    let mut all = classes.lock().expect("the classes");
    for (k, (count, examples)) in local {
        let e = all.entry(k).or_default();
        e.0 += count;
        for x in examples {
            if e.1.len() < 4 {
                e.1.push(x);
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let num = |i: usize, default: u64| {
        args.get(i).map_or(default, |a| {
            let a = a.trim_start_matches("0x");
            u64::from_str_radix(a, if args[i].starts_with("0x") { 16 } else { 10 })
                .expect("a number")
        })
    };
    let objdump = args.first().cloned().expect("the path to llvm-objdump");
    let start = num(1, 0);
    let count = num(2, 1 << 20);
    let stride = num(3, 1).max(1);
    let threads = num(
        4,
        std::thread::available_parallelism().map_or(8, |n| n.get() as u64),
    ) as usize;
    let dir = std::env::temp_dir().join(format!("hexcavator-llvm-diff-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let classes = Mutex::new(Classes::new());
    let agree = AtomicU64::new(0);
    let next = AtomicU64::new(0);
    let total = count.div_ceil(stride);
    let began = std::time::Instant::now();
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                loop {
                    let n = next.fetch_add(1, Ordering::Relaxed);
                    let first = n * CHUNK;
                    if first >= total {
                        break;
                    }
                    let words: Vec<u32> = (first..(first + CHUNK).min(total))
                        .map(|k| (start + k * stride) as u32)
                        .collect();
                    run_chunk(&objdump, &words, &dir, n, &classes, &agree);
                    if n.is_multiple_of(64) {
                        eprintln!(
                            "{:.1}% after {:?}",
                            (first as f64) * 100.0 / total as f64,
                            began.elapsed()
                        );
                    }
                }
            });
        }
    });
    let _ = std::fs::remove_dir_all(&dir);
    let classes = classes.into_inner().expect("the classes");
    let differ: u64 = classes.values().map(|c| c.0).sum();
    println!(
        "{total} words: {} agree, {differ} differ, in {:?}",
        agree.load(Ordering::Relaxed),
        began.elapsed()
    );
    let mut list: Vec<_> = classes.into_iter().collect();
    list.sort_by_key(|c| std::cmp::Reverse(c.1.0));
    for (class, (count, examples)) in list {
        println!("{count:>12}  {class}");
        for e in examples {
            println!("{:>14}{e}", "");
        }
    }
}
