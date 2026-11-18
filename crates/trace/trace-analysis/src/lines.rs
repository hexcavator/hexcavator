//! Time by source line: each line's weight where it is the innermost
//! frame (exclusive) and where it is on the stack (inclusive), from the
//! symbols' line tables.

use rustc_hash::FxHashMap;

use hexcavator_trace::{ProcessIx, Trace};

use crate::keys::{Resolver, Symbolizer};
use crate::sources::Run;
use crate::tree::BinTotals;

/// The source lines events were at, and their totals.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LineTotals {
    /// The source files, as the symbols name them.
    pub files: Vec<String>,
    /// Each (file, line)'s totals.
    pub lines: FxHashMap<(u32, u32), BinTotals>,
    /// Each file's totals: as for a line, a file counted once per stack.
    pub by_file: Vec<BinTotals>,
}

/// Buckets a worker takes at a time.
const CHUNK: usize = 1 << 12;

/// Each source line's weight in `buckets` (from
/// [`crate::sources::sample_buckets`] or
/// [`crate::sources::switch_buckets`]): exclusive where its address is a
/// stack's innermost frame, inclusive where it is any frame (a return
/// address looked up a byte back, so a call's line), once per stack. On
/// every core, in chunks; each worker remembers each (process, address)'s
/// line.
pub fn line_totals(
    trace: &Trace,
    resolver: &Resolver,
    symbols: &dyn Symbolizer,
    buckets: &Run,
) -> LineTotals {
    let chunks = buckets.len().div_ceil(CHUNK);
    let next = std::sync::atomic::AtomicUsize::new(0);
    let threads = std::thread::available_parallelism()
        .map_or(4, std::num::NonZero::get)
        .min(chunks);
    // Each worker's lines, by its own file numbers.
    type Partial = (
        Vec<String>,
        FxHashMap<(u32, u32), BinTotals>,
        Vec<BinTotals>,
    );
    let partials: Vec<Partial> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                scope.spawn(|| {
                    let mut files: Vec<String> = Vec::new();
                    let mut file_ids: FxHashMap<String, u32> = FxHashMap::default();
                    let mut cache: FxHashMap<(ProcessIx, u64), Option<(u32, u32)>> =
                        FxHashMap::default();
                    let mut lines: FxHashMap<(u32, u32), BinTotals> = FxHashMap::default();
                    let mut by_file: Vec<BinTotals> = Vec::new();
                    let mut seen_lines: Vec<(u32, u32)> = Vec::new();
                    let mut seen_files: Vec<u32> = Vec::new();
                    let mut frames: Vec<u64> = Vec::new();
                    let mut line_at = |process: ProcessIx, lookup: u64| {
                        *cache.entry((process, lookup)).or_insert_with(|| {
                            let image = resolver.image(process, lookup)?;
                            let offset = lookup - trace.images[image.index()].base;
                            let (file, line) = symbols.line(trace, image, offset)?;
                            let next = u32::try_from(files.len()).expect("fewer than 4G files");
                            let id = *file_ids.entry(file.clone()).or_insert_with(|| {
                                files.push(file);
                                next
                            });
                            Some((id, line))
                        })
                    };
                    loop {
                        let c = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if c >= chunks {
                            return (files, lines, by_file);
                        }
                        for &((thread, _, stack, ip), (weight, count)) in
                            &buckets[c * CHUNK..((c + 1) * CHUNK).min(buckets.len())]
                        {
                            let process = trace.thread_process(thread);
                            seen_lines.clear();
                            seen_files.clear();
                            // The innermost frame (as is), then the
                            // callers (return addresses: a byte back).
                            frames.clear();
                            if stack.is_empty() {
                                if ip != 0 {
                                    frames.push(ip);
                                }
                            } else {
                                frames.extend(trace.stacks.frames(stack));
                            }
                            for (i, &f) in frames.iter().enumerate() {
                                let lookup = if i == 0 { f } else { f.wrapping_sub(1) };
                                let Some(at) = line_at(process, lookup) else {
                                    continue;
                                };
                                if i == 0 {
                                    lines.entry(at).or_default().exclusive += weight;
                                    if by_file.len() <= at.0 as usize {
                                        by_file.resize(at.0 as usize + 1, BinTotals::default());
                                    }
                                    by_file[at.0 as usize].exclusive += weight;
                                }
                                if !seen_lines.contains(&at) {
                                    seen_lines.push(at);
                                    let t = lines.entry(at).or_default();
                                    t.inclusive += weight;
                                    t.count += count;
                                }
                                if !seen_files.contains(&at.0) {
                                    seen_files.push(at.0);
                                    if by_file.len() <= at.0 as usize {
                                        by_file.resize(at.0 as usize + 1, BinTotals::default());
                                    }
                                    let t = &mut by_file[at.0 as usize];
                                    t.inclusive += weight;
                                    t.count += count;
                                }
                            }
                        }
                    }
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|w| w.join().expect("a lines worker"))
            .collect()
    });
    // The workers' files numbered as one, in order of name.
    let mut names: Vec<String> = partials.iter().flat_map(|p| p.0.iter().cloned()).collect();
    names.sort_unstable();
    names.dedup();
    let id_of = |name: &str| {
        u32::try_from(
            names
                .binary_search_by(|n| n.as_str().cmp(name))
                .expect("a file"),
        )
        .expect("a file")
    };
    let mut out = LineTotals {
        by_file: vec![BinTotals::default(); names.len()],
        ..LineTotals::default()
    };
    for (files, lines, by_file) in partials {
        let rename: Vec<u32> = files.iter().map(|f| id_of(f)).collect();
        for ((file, line), t) in lines {
            let o = out.lines.entry((rename[file as usize], line)).or_default();
            o.exclusive += t.exclusive;
            o.inclusive += t.inclusive;
            o.count += t.count;
        }
        for (file, t) in by_file.into_iter().enumerate() {
            let o = &mut out.by_file[rename[file] as usize];
            o.exclusive += t.exclusive;
            o.inclusive += t.inclusive;
            o.count += t.count;
        }
    }
    out.files = names;
    out
}
