//! Hexcavator's fuzzer.
//!
//!     hexcavator-fuzz list
//!     hexcavator-fuzz run <target>... [-seconds N] [-seed S] [-batch N] [-timeout S]
//!     hexcavator-fuzz replay <target> <file>
//!
//! `run` mutates the corpus's inputs (the repository's `testdata`, each file
//! seeding the targets that read its kind) and runs each in a child process,
//! in batches. A finding is an input that makes the child panic, overflow
//! its stack, run longer than the timeout, or allocate more than its cap
//! (a counting allocator aborts it): each is saved under `fuzz-findings/`
//! with what happened, to `replay`.
//!
//! A child writes each input to a file before it runs it, so that the
//! supervisor has the one it died on. Built with coverage (see
//! `README.md`), a child keeps the inputs that reach new code: they join
//! its pool, and `fuzz-corpus/<target>/` for later runs.

#![allow(
    clippy::cast_possible_truncation,
    reason = "random bytes and indexes, truncated on purpose"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use hexcavator_fuzz::{Scratch, TARGETS, Target, target};

// ------------------------------------------------------------ allocation

/// The system allocator, counting live bytes; past the cap it aborts the
/// process (a finding: an input that makes a parser ask for too much).
struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static CAP: AtomicUsize = AtomicUsize::new(usize::MAX);

/// The exit code of an allocation over the cap.
const OVER_CAP: i32 = 77;

#[allow(unsafe_code, reason = "a global allocator is unsafe to implement")]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
        if live > CAP.load(Ordering::Relaxed) {
            over_cap(live);
        }
        // SAFETY: the caller's contract is the system allocator's.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        // SAFETY: as above.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new: usize) -> *mut u8 {
        if new > layout.size() {
            let live = LIVE.fetch_add(new - layout.size(), Ordering::Relaxed) + new - layout.size();
            if live > CAP.load(Ordering::Relaxed) {
                over_cap(live);
            }
        } else {
            LIVE.fetch_sub(layout.size() - new, Ordering::Relaxed);
        }
        // SAFETY: as above.
        unsafe { System.realloc(ptr, layout, new) }
    }
}

fn over_cap(live: usize) -> ! {
    // (No allocating here: write what is known and leave.)
    let _ = std::io::stderr().write_all(b"\x01over-cap\n");
    let _ = live;
    std::process::exit(OVER_CAP);
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

// ------------------------------------------------------------- mutations

/// A small, fast, deterministic generator (xorshift64*).
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Below `n` (which must not be 0).
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Values that make parsers' arithmetic and loops go wrong.
const INTERESTING: &[u64] = &[
    0,
    1,
    2,
    0x7F,
    0x80,
    0xFF,
    0x100,
    0x7FFF,
    0x8000,
    0xFFFF,
    0x1_0000,
    0x7FFF_FFFF,
    0x8000_0000,
    0xFFFF_FFFE,
    0xFFFF_FFFF,
    0x1000,
    0x1001,
    0x10_0000,
    u64::MAX,
];

/// A mutation of `base` (with `other`, another seed, to splice from).
fn mutate(base: &[u8], other: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut d = base.to_vec();
    let many = rng.below(4) == 0;
    let rounds = 1 + rng.below(if many { 16 } else { 4 });
    for _ in 0..rounds {
        if d.is_empty() {
            d.push(rng.next() as u8);
            continue;
        }
        let at = rng.below(d.len());
        match rng.below(10) {
            // A bit, a byte.
            0 => d[at] ^= 1 << rng.below(8),
            1 => d[at] = rng.next() as u8,
            // A field set to a value that makes trouble (1, 2, 4, or 8
            // bytes, either endianness).
            2 | 3 => {
                let width = [1usize, 2, 4, 8][rng.below(4)];
                let v = INTERESTING[rng.below(INTERESTING.len())];
                let v = if rng.below(2) == 0 {
                    v
                } else {
                    v.wrapping_neg()
                };
                let bytes = if rng.below(4) == 0 {
                    v.to_be_bytes()
                } else {
                    v.to_le_bytes()
                };
                let src = if rng.below(4) == 0 {
                    &bytes[8 - width..]
                } else {
                    &bytes[..width]
                };
                for (i, b) in src.iter().enumerate() {
                    if let Some(x) = d.get_mut(at + i) {
                        *x = *b;
                    }
                }
            }
            // A field near another nudged by a little.
            4 => {
                let delta = (rng.below(33) as i64 - 16) as i8;
                d[at] = d[at].wrapping_add_signed(delta);
            }
            // Bytes removed, repeated, or copied from elsewhere.
            5 => {
                let n = 1 + rng.below(64.min(d.len() - at));
                d.drain(at..at + n);
            }
            6 => {
                let n = 1 + rng.below(64.min(d.len() - at));
                let chunk = d[at..at + n].to_vec();
                let to = rng.below(d.len());
                d.splice(to..to, chunk);
            }
            7 => {
                let n = 1 + rng.below(64.min(d.len() - at));
                let from = rng.below(d.len() - n + 1);
                // (n fits from `at`: it is at most what is left there.)
                d.copy_within(from..from + n, at);
            }
            // Another seed's bytes spliced in.
            8 if !other.is_empty() => {
                let from = rng.below(other.len());
                let n = 1 + rng.below(256.min(other.len() - from));
                let end = (at + n).min(d.len());
                let chunk = &other[from..from + n];
                d.splice(at..end, chunk.iter().copied());
            }
            // Cut short.
            _ => d.truncate(at.max(1)),
        }
    }
    d
}

// ---------------------------------------------------------------- corpus

/// The repository's `testdata`, from here up.
fn testdata() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        if dir.join("testdata").is_dir() {
            return Some(dir.join("testdata"));
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = entries.flatten().map(|e| e.path()).collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            files(&p, out);
        } else {
            out.push(p);
        }
    }
}

/// Short inputs for the targets that read names or queries.
const QUERIES: &[&str] = &[
    "kind=function file>4k sort by file desc limit 20",
    "group by library",
    "name~'^std::' group by compiland limit 10",
    "section=.rdata static group by name sort by count desc",
    "(kind=data or kind=public) and not name~'x' select name, file",
];

/// The target's seeds: the corpus's files it reads (whole, or, for those
/// that read names and queries, by line).
fn seeds(t: &Target) -> Vec<Vec<u8>> {
    let mut all = Vec::new();
    if let Some(dir) = testdata() {
        files(&dir, &mut all);
    }
    let by_line = matches!(t.name, "demangle" | "query");
    let mut out: Vec<Vec<u8>> = Vec::new();
    for p in all {
        let Ok(data) = std::fs::read(&p) else {
            continue;
        };
        if data.len() > (64 << 20) || !(t.seeds)(&p, &data) {
            continue;
        }
        if by_line {
            for line in data
                .split(|&b| b == b'\n')
                .filter(|l| (4..4096).contains(&l.len()))
            {
                // (Names: the words of the line that look mangled.)
                for word in line.split(u8::is_ascii_whitespace) {
                    if word.len() > 3
                        && (word.starts_with(b"?")
                            || word.starts_with(b"_Z")
                            || word.starts_with(b"_R")
                            || word.starts_with(b"$s")
                            || word.starts_with(b"_$s")
                            || word.starts_with(b"_T"))
                    {
                        out.push(word.to_vec());
                    }
                }
            }
        } else {
            out.push(data);
        }
    }
    if t.name == "query" {
        out.extend(QUERIES.iter().map(|q| q.as_bytes().to_vec()));
    }
    if t.name == "demangle" {
        // The Swift project's test names (testdata has few Swift binaries).
        for file in [
            include_str!("../../../crates/symbols/demangle/tests/data/swift-manglings.txt"),
            include_str!(
                "../../../crates/symbols/demangle/tests/data/swift-simplified-manglings.txt"
            ),
        ] {
            out.extend(
                file.lines()
                    .filter_map(|l| l.split_once(" ---> "))
                    .map(|(name, _)| name.as_bytes().to_vec()),
            );
        }
    }
    if out.is_empty() {
        out.push(b"seed".to_vec());
    }
    out.sort();
    out.dedup();
    out
}

// -------------------------------------------------------------- coverage

/// The process's own coverage counters, where it was built with
/// `-C instrument-coverage` and the `coverage` feature (LLVM's profiling
/// runtime keeps them; we read and reset them between inputs). Elsewhere,
/// none: fuzzing is blind.
#[cfg(feature = "coverage")]
#[allow(unsafe_code, reason = "the profiling runtime's counters are a C array")]
mod coverage {
    unsafe extern "C" {
        fn __llvm_profile_begin_counters() -> *mut u8;
        fn __llvm_profile_end_counters() -> *mut u8;
    }

    fn section() -> (*mut u8, usize) {
        // SAFETY: the runtime's counter section's bounds, live for the
        // process.
        unsafe {
            let begin = __llvm_profile_begin_counters();
            let end = __llvm_profile_end_counters();
            (begin, usize::try_from(end.offset_from(begin)).unwrap_or(0))
        }
    }

    /// How many counters there are.
    pub fn len() -> usize {
        section().1
    }

    /// Each counter's value (by its place), then zeroes it. (No reference
    /// to the counters is made: instrumented code writes them as it runs,
    /// so each is read and written through a raw pointer, once.)
    pub fn take_each(mut f: impl FnMut(usize, u8)) {
        let (begin, len) = section();
        for i in 0..len {
            // SAFETY: `i` is within the section.
            unsafe {
                let p = begin.add(i);
                f(i, p.read_volatile());
                p.write_volatile(0);
            }
        }
    }
}

#[cfg(not(feature = "coverage"))]
mod coverage {
    pub fn len() -> usize {
        0
    }

    pub fn take_each(_: impl FnMut(usize, u8)) {}
}

/// A counter's value as a bucket (AFL's: 1, 2, 3, 4-7, 8-15, 16-31,
/// 32-127, 128+), a bit.
fn bucket(v: u8) -> u8 {
    match v {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        4..=7 => 8,
        8..=15 => 16,
        16..=31 => 32,
        32..=127 => 64,
        _ => 128,
    }
}

/// The buckets each counter has reached; and whether an input reached a
/// new one.
struct Seen(Vec<u8>);

impl Seen {
    fn new() -> Self {
        Self(vec![0; coverage::len()])
    }

    /// After an input: whether it reached anything new (and the counters
    /// zeroed for the next).
    fn take(&mut self) -> bool {
        let mut new = false;
        let seen = &mut self.0;
        coverage::take_each(|i, c| {
            let Some(seen) = seen.get_mut(i) else {
                return;
            };
            let b = bucket(c);
            if b & !*seen != 0 {
                *seen |= b;
                new = true;
            }
        });
        new
    }
}

// ----------------------------------------------------------------- child

/// The cap for an input: generous for what the input is (a parser may
/// build structures several times its size), and no more.
fn cap_for(len: usize) -> usize {
    (512 << 20) + len.saturating_mul(64)
}

/// Where a target's inputs that reached new code are kept.
fn corpus_dir(t: &Target) -> PathBuf {
    PathBuf::from("fuzz-corpus").join(t.name)
}

fn fingerprint(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    })
}

/// A child: `count` mutations of the pool (the target's seeds, and its
/// corpus), each written to `current` before it runs (so that if it kills
/// the child, the supervisor has it). With coverage, an input that reaches
/// new code joins the pool, and the corpus.
fn child(t: &Target, seed: u64, batch: u64, count: u64, current: &Path) -> ExitCode {
    let mut pool = seeds(t);
    let seeded = pool.len();
    let mut kept = Vec::new();
    files(&corpus_dir(t), &mut kept);
    pool.extend(kept.iter().filter_map(|p| std::fs::read(p).ok()));
    let mut rng =
        Rng::new(seed ^ batch.wrapping_mul(0x1000_0000_01B3) ^ u64::from(std::process::id()));
    let scratch = Scratch { dir: scratch_dir() };
    let mut seen = Seen::new();
    // What the pool reaches already isn't new.
    for data in pool.iter().take(4096) {
        run_one(t, data, &scratch);
        seen.take();
    }
    let mut err = std::io::stderr();
    let _ = std::fs::create_dir_all(corpus_dir(t));
    for i in 0..count {
        // Half the time from what was found (when there is some).
        let found = pool.len() - seeded;
        let base = if found > 0 && rng.below(2) == 0 {
            seeded + rng.below(found)
        } else {
            rng.below(pool.len())
        };
        let other = rng.below(pool.len());
        let data = mutate(&pool[base], &pool[other], &mut rng);
        let _ = std::fs::write(current, &data);
        let _ = writeln!(err, "\x01@{i}");
        let _ = err.flush();
        run_one(t, &data, &scratch);
        if seen.take() {
            let _ = std::fs::write(
                corpus_dir(t).join(format!("{:016x}", fingerprint(&data))),
                &data,
            );
            let _ = writeln!(err, "\x01new");
            pool.push(data);
        }
    }
    let _ = std::fs::remove_dir_all(&scratch.dir);
    let _ = writeln!(err, "\x01done");
    ExitCode::SUCCESS
}

fn scratch_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hexcavator-fuzz-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Runs one input, under its allocation cap.
fn run_one(t: &Target, data: &[u8], scratch: &Scratch) {
    CAP.store(
        LIVE.load(Ordering::Relaxed) + cap_for(data.len()),
        Ordering::Relaxed,
    );
    (t.run)(data, scratch);
    CAP.store(usize::MAX, Ordering::Relaxed);
}

/// A child that runs the one file `path`.
fn child_file(t: &Target, path: &Path) -> ExitCode {
    let data = std::fs::read(path).unwrap_or_default();
    let scratch = Scratch { dir: scratch_dir() };
    let mut err = std::io::stderr();
    let _ = writeln!(err, "\x01@0");
    let _ = err.flush();
    run_one(t, &data, &scratch);
    let _ = std::fs::remove_dir_all(&scratch.dir);
    let _ = writeln!(err, "\x01done");
    ExitCode::SUCCESS
}

// ------------------------------------------------------------ supervisor

struct Options {
    targets: Vec<&'static Target>,
    seconds: u64,
    seed: u64,
    batch: u64,
    timeout: Duration,
    jobs: usize,
}

/// What became of a child.
enum Outcome {
    /// It ran its inputs; this many reached new code.
    Done(u64),
    /// It died (or was killed) on an input, and why.
    Finding(String),
}

/// Runs a child with `args`, watching it: done, or why it died.
fn supervise(exe: &Path, args: &[String], timeout: Duration) -> Outcome {
    let mut c = Command::new(exe)
        .args(args)
        // (The profiling runtime's file, where it writes its counters at
        // exit: none.)
        .env(
            "LLVM_PROFILE_FILE",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("starting the child");
    let stderr = c.stderr.take().expect("the child's stderr");
    // Read progress on a thread; the supervisor watches the clock.
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if let Some(m) = line.strip_prefix('\x01')
                && tx.send(m.to_string()).is_err()
            {
                break;
            }
        }
    });
    let mut running = false;
    let mut over_cap = false;
    let mut new = 0;
    let mut since = Instant::now();
    loop {
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(m) => {
                if m.starts_with('@') {
                    running = true;
                    since = Instant::now();
                } else if m == "new" {
                    new += 1;
                } else if m == "over-cap" {
                    over_cap = true;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                let status = c.wait().expect("waiting for the child");
                if status.success() {
                    return Outcome::Done(new);
                }
                let why = if over_cap || status.code() == Some(OVER_CAP) {
                    "allocated more than its cap".to_string()
                } else {
                    match status.code() {
                        Some(101) => "panicked".to_string(),
                        Some(c) if c as u32 == 0xC000_00FD => "overflowed its stack".to_string(),
                        Some(c) => format!("exited with {c:#x}"),
                        None => "was killed by a signal (a stack overflow, likely)".to_string(),
                    }
                };
                return Outcome::Finding(why);
            }
        }
        if running && since.elapsed() > timeout {
            let _ = c.kill();
            let _ = c.wait();
            return Outcome::Finding(format!("ran longer than {timeout:?}"));
        }
    }
}

fn save(t: &Target, data: &[u8], why: &str) -> PathBuf {
    let dir = PathBuf::from("fuzz-findings");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(format!("{}-{:016x}.bin", t.name, fingerprint(data)));
    let _ = std::fs::write(&path, data);
    let _ = std::fs::write(
        path.with_extension("txt"),
        format!(
            "target: {}\nwhat: {why}\nreplay: hexcavator-fuzz replay {} {}\n",
            t.name,
            t.name,
            path.display()
        ),
    );
    path
}

/// A target's totals.
#[derive(Default)]
struct Totals {
    batches: u64,
    new: u64,
    findings: u64,
}

fn run(o: &Options) -> ExitCode {
    let exe = std::env::current_exe().expect("this program's path");
    let deadline = Instant::now() + Duration::from_secs(o.seconds);
    let totals: Vec<std::sync::Mutex<Totals>> = o
        .targets
        .iter()
        .map(|_| std::sync::Mutex::default())
        .collect();
    let next = std::sync::atomic::AtomicUsize::new(0);
    let tmp = std::env::temp_dir();
    // Workers take the targets in turn, a child (batch) at a time.
    std::thread::scope(|s| {
        for _ in 0..o.jobs.max(1) {
            s.spawn(|| {
                while Instant::now() < deadline {
                    let k = next.fetch_add(1, Ordering::Relaxed) % o.targets.len();
                    let t = o.targets[k];
                    let batch = {
                        let mut tot = totals[k].lock().expect("the totals");
                        tot.batches += 1;
                        tot.batches
                    };
                    let current = tmp.join(format!(
                        "hexcavator-fuzz-current-{}-{k}-{batch}.bin",
                        std::process::id()
                    ));
                    let args = [
                        "child".to_string(),
                        t.name.to_string(),
                        o.seed.to_string(),
                        batch.to_string(),
                        o.batch.to_string(),
                        current.to_string_lossy().into_owned(),
                    ];
                    match supervise(&exe, &args, o.timeout) {
                        Outcome::Done(new) => totals[k].lock().expect("the totals").new += new,
                        Outcome::Finding(why) => {
                            let data = std::fs::read(&current).unwrap_or_default();
                            let path = save(t, &data, &why);
                            totals[k].lock().expect("the totals").findings += 1;
                            println!(
                                "FINDING {}: {why} ({} bytes): {}",
                                t.name,
                                data.len(),
                                path.display()
                            );
                        }
                    }
                    let _ = std::fs::remove_file(&current);
                }
            });
        }
    });
    let mut findings = 0;
    for (k, t) in o.targets.iter().enumerate() {
        let tot = totals[k].lock().expect("the totals");
        let corpus = std::fs::read_dir(corpus_dir(t)).map_or(0, std::iter::Iterator::count);
        println!(
            "{:10} {:8} inputs, {:5} new ({corpus} in the corpus), {} findings",
            t.name,
            tot.batches * o.batch,
            tot.new,
            tot.findings
        );
        findings += tot.findings;
    }
    println!(
        "{findings} findings{}",
        if cfg!(feature = "coverage") {
            ""
        } else {
            " (blind: built without coverage)"
        }
    );
    if findings > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn replay(t: &Target, path: &Path) -> ExitCode {
    let data = std::fs::read(path).expect("reading the input");
    let scratch =
        std::env::temp_dir().join(format!("hexcavator-fuzz-replay-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&scratch);
    CAP.store(cap_for(data.len()), Ordering::Relaxed);
    let start = Instant::now();
    (t.run)(
        &data,
        &Scratch {
            dir: scratch.clone(),
        },
    );
    let _ = std::fs::remove_dir_all(&scratch);
    eprintln!("ok: {} in {:?}", path.display(), start.elapsed());
    ExitCode::SUCCESS
}

/// Checks that the harness finds what it should: each way an input can go
/// wrong, run in a child as a fuzzed input would be.
fn selftest() -> ExitCode {
    let exe = std::env::current_exe().expect("this program's path");
    let dir = std::env::temp_dir().join(format!("hexcavator-fuzz-selftest-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let mut ok = true;
    for (input, expect) in [
        ("P", "panicked"),
        ("S", "stack"),
        ("A", "cap"),
        ("L", "longer"),
        ("fine", ""),
    ] {
        let path = dir.join(input);
        let _ = std::fs::write(&path, input);
        let args = [
            "child-file".to_string(),
            "selftest".to_string(),
            path.to_string_lossy().into_owned(),
        ];
        let got = match supervise(&exe, &args, Duration::from_secs(2)) {
            Outcome::Done(_) => String::new(),
            Outcome::Finding(why) => why,
        };
        let pass = if expect.is_empty() {
            got.is_empty()
        } else {
            got.contains(expect)
        };
        println!(
            "{} {input:5} {}",
            if pass { "ok  " } else { "FAIL" },
            if got.is_empty() { "returned" } else { &got }
        );
        ok &= pass;
    }
    let _ = std::fs::remove_dir_all(&dir);
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

const USAGE: &str = "usage:
  hexcavator-fuzz list
  hexcavator-fuzz run <target>...|all [-seconds N] [-seed S] [-batch N] [-timeout S] [-jobs N]
  hexcavator-fuzz replay <target> <file>       (in a capped, timed child)
  hexcavator-fuzz replay-here <target> <file>  (in this process, capped: to debug)
  hexcavator-fuzz selftest";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let arg = |i: usize| args.get(i).map(String::as_str);
    match arg(0) {
        Some("list") => {
            for t in TARGETS {
                println!("{:10} {}", t.name, t.about);
            }
            ExitCode::SUCCESS
        }
        Some("child") => {
            let (Some(t), Some(seed), Some(batch), Some(count), Some(current)) =
                (arg(1).and_then(target), arg(2), arg(3), arg(4), arg(5))
            else {
                return ExitCode::from(2);
            };
            child(
                t,
                seed.parse().unwrap_or(0),
                batch.parse().unwrap_or(0),
                count.parse().unwrap_or(0),
                Path::new(current),
            )
        }
        Some("child-file") => match (arg(1).and_then(target), arg(2)) {
            (Some(t), Some(p)) => child_file(t, Path::new(p)),
            _ => ExitCode::from(2),
        },
        Some("selftest") => selftest(),
        // In a supervised child: capped, and timed out (a finding can hang
        // or eat memory; never run one unguarded).
        Some("replay") => match (arg(1).and_then(target), arg(2)) {
            (Some(t), Some(p)) => {
                let exe = std::env::current_exe().expect("this program's path");
                let args = ["child-file".to_string(), t.name.to_string(), p.to_string()];
                let started = Instant::now();
                match supervise(&exe, &args, Duration::from_secs(60)) {
                    Outcome::Done(_) => {
                        eprintln!("ok: {p} in {:?}", started.elapsed());
                        ExitCode::SUCCESS
                    }
                    Outcome::Finding(why) => {
                        eprintln!("{p}: {why}");
                        ExitCode::FAILURE
                    }
                }
            }
            _ => {
                eprintln!("{USAGE}");
                ExitCode::from(2)
            }
        },
        // In this process (to debug): still under the allocation cap.
        Some("replay-here") => match (arg(1).and_then(target), arg(2)) {
            (Some(t), Some(p)) => replay(t, Path::new(p)),
            _ => {
                eprintln!("{USAGE}");
                ExitCode::from(2)
            }
        },
        Some("run") => {
            let mut o = Options {
                targets: Vec::new(),
                seconds: 60,
                seed: 1,
                batch: 2000,
                timeout: Duration::from_secs(20),
                jobs: std::thread::available_parallelism().map_or(4, |n| n.get() / 2),
            };
            let mut i = 1;
            while let Some(a) = arg(i) {
                let mut num = |what: &str| -> Option<u64> {
                    i += 1;
                    let v = arg(i).and_then(|v| v.parse().ok());
                    if v.is_none() {
                        eprintln!("{what} needs a number");
                    }
                    v
                };
                match a {
                    "-seconds" => o.seconds = num("-seconds").unwrap_or(o.seconds),
                    "-seed" => o.seed = num("-seed").unwrap_or(o.seed),
                    "-batch" => o.batch = num("-batch").unwrap_or(o.batch).max(1),
                    "-timeout" => o.timeout = Duration::from_secs(num("-timeout").unwrap_or(20)),
                    "-jobs" => o.jobs = num("-jobs").unwrap_or(1) as usize,
                    "all" => o.targets.extend(TARGETS.iter()),
                    name => match target(name) {
                        Some(t) => o.targets.push(t),
                        None => {
                            eprintln!("no target named '{name}' (hexcavator-fuzz list)");
                            return ExitCode::from(2);
                        }
                    },
                }
                i += 1;
            }
            if o.targets.is_empty() {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
            run(&o)
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}
