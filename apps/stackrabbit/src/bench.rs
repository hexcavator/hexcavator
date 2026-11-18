//! `stackrabbit bench`: times opening and querying traces.
//!
//! For each trace: importing it, writing and reading its index, and
//! building and expanding the stack trees the first views show. It prints
//! timings and counts only (file names and numbers), never what a trace
//! holds, so its output can be shared about private traces.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use hexcavator_etl::Etl;
use hexcavator_mmap::Mmap;
use hexcavator_symbolize::SymbolPath;
use hexcavator_trace::{Trace, etw, index};
use hexcavator_trace_analysis::{
    FrameMode, GroupBy, NoSymbols, NodeId, PdbSymbolizer, Resolver, Symbolizer,
};
use serde_json::json;

use crate::Args;
use crate::views::{Source, TreeSpec, TreeView};

const USAGE: &str = "\
usage: stackrabbit bench <trace or directory>... [options]

Times, for each trace (a directory's *.etl files, by name): importing it (from the disk: it is
evicted from the system's cache first, where the host allows); writing and reading
its index; and building the first stack trees (CPU samples by process, inverted, and waits),
expanding the top level and the hot path. Prints timings and counts only.

Options:
  -symbols   Name functions with the PDBs _NT_SYMBOL_PATH finds (default: by module); then
             also time saving their names for the trace, and its first tree from those.
  -json      One JSON object per trace instead of a table.
  -phases    Instead, time the import's phases: reading the events in time order
             (buffers merged, decompressed), then decoding them too, then the import.
  -digest    Instead, print a digest of each trace's import: a hash of what it holds (rows,
             their stacks' frames, processes, threads, images), not of how it is stored;
             two imports that agree have the same digest.
  -read      Instead, time reading each file from the disk (evicted from the cache
             first, where the host allows): page faults through a mapping, one thread;
             then reads of 1, 4 and 16 MB on 1, 2, 4 and 8 threads.
  -stacks    Instead, count each trace's samples by what their stacks hold: kernel and user
             frames (joined), kernel only, user only, or no stack; and how often the
             innermost frame is the sample's instruction pointer.
  -events    Instead, count each trace's events by provider and opcode (the 40 most
             numerous, and every StackWalk opcode), with their payloads' smallest and
             largest sizes.";

/// Runs `stackrabbit bench`.
pub fn run(args: &[String]) -> ExitCode {
    let mut a = Args::new(args);
    let mut paths = Vec::new();
    let mut symbols = false;
    let mut as_json = false;
    let mut phases = false;
    let mut read = false;
    let mut digest = false;
    let mut stacks = false;
    let mut events = false;
    while let Some(arg) = a.next() {
        match arg {
            "-h" | "-help" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "-symbols" => symbols = true,
            "-json" => as_json = true,
            "-phases" => phases = true,
            "-read" => read = true,
            "-digest" => digest = true,
            "-stacks" => stacks = true,
            "-events" => events = true,
            o if o.starts_with('-') => {
                eprintln!("stackrabbit bench: unknown option '{o}'\n\n{USAGE}");
                return ExitCode::from(2);
            }
            p => paths.push(PathBuf::from(p)),
        }
    }
    if paths.is_empty() {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    let traces = match expand(&paths) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("stackrabbit bench: {e}");
            return ExitCode::FAILURE;
        }
    };
    if phases {
        return phase_table(&traces);
    }
    if read {
        return read_table(&traces);
    }
    if digest {
        return digest_table(&traces);
    }
    if stacks {
        return stacks_table(&traces);
    }
    if events {
        return events_table(&traces);
    }
    if !as_json {
        println!(
            "{:<28} {:>9} {:>8} {:>9} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}",
            "trace",
            "MB",
            "dur s",
            "Mevents",
            "import",
            "MB/s",
            "idx MB",
            "idx wr",
            "idx rd",
            "tree",
            "expand",
            "waits"
        );
    }
    let mut failed = false;
    for path in &traces {
        match measure(path, symbols) {
            Ok(m) => {
                if as_json {
                    println!("{}", m.to_json(path));
                } else {
                    println!("{}", m.line(path));
                    if let Some(n) = &m.saved {
                        println!(
                            "    names saved: {} PDBs, {:.1} KB, in {:.3} s; first tree from them {:.3} s",
                            n.pdbs,
                            mb(n.bytes) * 1e3,
                            n.save.as_secs_f64(),
                            n.tree.as_secs_f64()
                        );
                    }
                }
            }
            Err(e) => {
                failed = true;
                eprintln!("stackrabbit bench: {}: {e}", path.display());
            }
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// The traces `paths` name: files as given, and directories' `*.etl`
/// files, by name.
fn expand(paths: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    for p in paths {
        if p.is_dir() {
            let mut found: Vec<PathBuf> = std::fs::read_dir(p)
                .map_err(|e| format!("{}: {e}", p.display()))?
                .flatten()
                .map(|e| e.path())
                .filter(|f| {
                    f.is_file() && f.extension().is_some_and(|x| x.eq_ignore_ascii_case("etl"))
                })
                .collect();
            found.sort();
            out.extend(found);
        } else {
            out.push(p.clone());
        }
    }
    Ok(out)
}

/// What one trace measured.
struct Measured {
    size: u64,
    duration_ns: i64,
    events: u64,
    samples: usize,
    switches: usize,
    import: Duration,
    index_size: usize,
    index_write: Duration,
    index_read: Duration,
    tree: Duration,
    expand: Duration,
    waits: Duration,
    stacks_unmatched: u64,
    /// With symbols: the names saved for the trace.
    saved: Option<SavedNames>,
}

/// Saving a trace's function names, and its first tree from them.
struct SavedNames {
    /// PDBs found.
    pdbs: usize,
    /// The saved file's size.
    bytes: u64,
    /// Finding the frames' addresses, cutting the tables down and writing them.
    save: Duration,
    /// Reading them back and the first tree (as a reopened trace does).
    tree: Duration,
}

fn mb(n: u64) -> f64 {
    #[allow(clippy::cast_precision_loss)]
    let x = n as f64 / 1e6;
    x
}

impl Measured {
    fn line(&self, path: &Path) -> String {
        let name = path
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        let secs = |d: Duration| format!("{:.3}", d.as_secs_f64());
        let throughput = mb(self.size) / self.import.as_secs_f64().max(1e-9);
        #[allow(clippy::cast_precision_loss)]
        let dur = self.duration_ns as f64 / 1e9;
        format!(
            "{:<28} {:>9.1} {:>8.2} {:>9.2} {:>8} {:>8.0} {:>8.1} {:>8} {:>8} {:>8} {:>8} {:>8}",
            name,
            mb(self.size),
            dur,
            mb(self.events),
            secs(self.import),
            throughput,
            mb(self.index_size as u64),
            secs(self.index_write),
            secs(self.index_read),
            secs(self.tree),
            secs(self.expand),
            secs(self.waits),
        )
    }

    fn to_json(&self, path: &Path) -> serde_json::Value {
        let name = path
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        json!({
            "trace": name,
            "bytes": self.size,
            "durationNs": self.duration_ns,
            "events": self.events,
            "samples": self.samples,
            "switches": self.switches,
            "stacksUnmatched": self.stacks_unmatched,
            "importSeconds": self.import.as_secs_f64(),
            "indexBytes": self.index_size,
            "indexWriteSeconds": self.index_write.as_secs_f64(),
            "indexReadSeconds": self.index_read.as_secs_f64(),
            "treeSeconds": self.tree.as_secs_f64(),
            "expandSeconds": self.expand.as_secs_f64(),
            "waitsSeconds": self.waits.as_secs_f64(),
            "savedNames": self.saved.as_ref().map(|n| json!({
                "pdbs": n.pdbs,
                "bytes": n.bytes,
                "saveSeconds": n.save.as_secs_f64(),
                "treeSeconds": n.tree.as_secs_f64(),
            })),
        })
    }
}

fn measure(path: &Path, symbols: bool) -> Result<Measured, String> {
    // From the disk, as a trace is first opened (where the host can evict
    // it from the cache).
    let _ = hexcavator_mmap::evict_from_cache(path);
    let map = Mmap::open(path).map_err(|e| e.to_string())?;
    let data = map.as_slice();
    let start = Instant::now();
    let prefetch = map.prefetch(crate::store::PREFETCH_THREADS, crate::store::PREFETCH_CHUNK);
    let etl = Etl::parse(data).map_err(|e| e.to_string())?;
    let (trace, stats) = etw::import(&etl).map_err(|e| e.to_string())?;
    let import = start.elapsed();
    drop(prefetch);

    let start = Instant::now();
    let saved = index::write(&trace, index::Source::of(data));
    let index_write = start.elapsed();
    let start = Instant::now();
    let reread = index::read(&saved, None).map_err(|e| format!("reading its index: {e}"))?;
    let index_read = start.elapsed();
    drop(reread);

    let pdbs = PdbSymbolizer::new(SymbolPath::from_env());
    let symbolizer: &dyn Symbolizer = if symbols { &pdbs } else { &NoSymbols };
    let resolver = Resolver::new(&trace);
    let frames = if symbols {
        FrameMode::Function
    } else {
        FrameMode::Module
    };
    let start = Instant::now();
    let mut by_process = TreeView::build(
        &trace,
        &resolver,
        symbolizer,
        None,
        TreeSpec {
            source: Source::Samples,
            groups: vec![GroupBy::Process],
            frames,
            invert: false,
            time: None,
        },
    );
    let top = by_process.children(&trace, symbolizer, NodeId::ROOT);
    let tree = start.elapsed();
    let start = Instant::now();
    if let Some(first) = top.first() {
        by_process.hot_path(&trace, symbolizer, NodeId(first.id), 0.01);
    }
    let mut inverted = TreeView::build(
        &trace,
        &resolver,
        symbolizer,
        None,
        TreeSpec {
            invert: true,
            groups: vec![],
            frames,
            ..TreeSpec::default()
        },
    );
    inverted.children(&trace, symbolizer, NodeId::ROOT);
    let expand = start.elapsed();
    let start = Instant::now();
    let mut waits = TreeView::build(
        &trace,
        &resolver,
        symbolizer,
        None,
        TreeSpec {
            source: Source::Waits,
            groups: vec![GroupBy::Process],
            frames,
            ..TreeSpec::default()
        },
    );
    waits.children(&trace, symbolizer, NodeId::ROOT);
    let waits = start.elapsed();
    let names = if symbols {
        Some(save_names(&trace, index::Source::of(data), &pdbs)?)
    } else {
        None
    };

    Ok(Measured {
        size: data.len() as u64,
        duration_ns: span_ns(&trace),
        events: stats.events,
        samples: trace.samples.len(),
        switches: trace.switches.len(),
        import,
        index_size: saved.len(),
        index_write,
        index_read,
        tree,
        expand,
        waits,
        stacks_unmatched: stats.stacks_unmatched,
        saved: names,
    })
}

/// Saves `trace`'s function names from `pdbs` (into the temporary
/// directory, removed after), and builds its first tree from them.
fn save_names(
    trace: &Trace,
    source: index::Source,
    pdbs: &PdbSymbolizer,
) -> Result<SavedNames, String> {
    let path =
        std::env::temp_dir().join(format!("stackrabbit-bench-{}.hxsyms", std::process::id()));
    let start = Instant::now();
    let frames = crate::symbols::frames(trace);
    let tables: Vec<crate::symbols::Table> = pdbs
        .found()
        .into_iter()
        .map(|(guid, age, t)| ((guid, age), t))
        .collect();
    crate::symbols::save(&path, source, &frames, &tables).map_err(|e| e.to_string())?;
    let save = start.elapsed();
    let bytes = std::fs::metadata(&path).map_or(0, |m| m.len());
    let start = Instant::now();
    let seeded = PdbSymbolizer::new(SymbolPath::default());
    seeded.set_waiting(false);
    for ((guid, age), t) in crate::symbols::load_saved(&path, source) {
        seeded.seed(&guid, age, t);
    }
    let resolver = Resolver::new(trace);
    let mut view = TreeView::build(
        trace,
        &resolver,
        &seeded,
        None,
        TreeSpec {
            source: Source::Samples,
            groups: vec![GroupBy::Process],
            frames: FrameMode::Function,
            invert: false,
            time: None,
        },
    );
    view.children(trace, &seeded, NodeId::ROOT);
    let tree = start.elapsed();
    let _ = std::fs::remove_file(&path);
    Ok(SavedNames {
        pdbs: tables.len(),
        bytes,
        save,
        tree,
    })
}

/// The time from the first sample, switch or ready event to the last.
fn span_ns(trace: &Trace) -> i64 {
    let times = trace
        .samples
        .time
        .iter()
        .chain(&trace.switches.time)
        .chain(&trace.readies.time);
    let (first, last) = times.fold((i64::MAX, i64::MIN), |(a, b), &t| (a.min(t), b.max(t)));
    if first <= last {
        trace.clock.nanos(last) - trace.clock.nanos(first)
    } else {
        0
    }
}

/// Prints the import's phases for each trace: reading the events in time
/// order, reading and decoding them, and the whole import.
fn phase_table(traces: &[PathBuf]) -> ExitCode {
    println!(
        "{:<28} {:>9} {:>9} {:>8} {:>8} {:>8} {:>8}",
        "trace", "MB", "Mevents", "read", "decode", "import", "ns/evt"
    );
    for path in traces {
        let result = (|| -> Result<String, String> {
            let map = Mmap::open(path).map_err(|e| e.to_string())?;
            let data = map.as_slice();
            let etl = Etl::parse(data).map_err(|e| e.to_string())?;
            let start = Instant::now();
            let mut events = 0u64;
            let mut cursor = etl.events().map_err(|e| e.to_string())?;
            while let Some(e) = cursor.next() {
                if e.is_ok() {
                    events += 1;
                }
            }
            let read = start.elapsed();
            let start = Instant::now();
            let mut decoded = 0u64;
            let mut cursor = etl.events().map_err(|e| e.to_string())?;
            while let Some(e) = cursor.next() {
                if let Ok(e) = e
                    && hexcavator_etw::decode(&e).is_some()
                {
                    decoded += 1;
                }
            }
            let decode = start.elapsed();
            std::hint::black_box(decoded);
            let start = Instant::now();
            let (trace, _) = etw::import(&etl).map_err(|e| e.to_string())?;
            let import = start.elapsed();
            std::hint::black_box(&trace);
            #[allow(clippy::cast_precision_loss)]
            let per = import.as_nanos() as f64 / events.max(1) as f64;
            Ok(format!(
                "{:<28} {:>9.1} {:>9.2} {:>8.3} {:>8.3} {:>8.3} {:>8.0}",
                path.file_name()
                    .map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
                mb(data.len() as u64),
                mb(events),
                read.as_secs_f64(),
                decode.as_secs_f64(),
                import.as_secs_f64(),
                per
            ))
        })();
        match result {
            Ok(line) => println!("{line}"),
            Err(e) => {
                eprintln!("stackrabbit bench: {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}

/// Prints, for each file, how fast it reads from the disk: by page faults
/// through a mapping, and by reads of several sizes on several threads.
fn read_table(traces: &[PathBuf]) -> ExitCode {
    let configs: Vec<(usize, usize)> = [1usize, 2, 4, 8]
        .iter()
        .flat_map(|&t| [1usize, 4, 16].map(|mb| (t, mb << 20)))
        .collect();
    print!("{:<28} {:>9} {:>9}", "trace", "MB", "faults");
    for (t, c) in &configs {
        print!(" {:>7}", format!("{t}x{}M", c >> 20));
    }
    println!("  (GB/s)");
    for path in traces {
        let result = (|| -> Result<String, String> {
            let evicted = hexcavator_mmap::evict_from_cache(path).map_err(|e| e.to_string())?;
            let map = Mmap::open(path).map_err(|e| e.to_string())?;
            let len = map.len();
            let gbs = |d: Duration| {
                #[allow(clippy::cast_precision_loss)]
                let g = len as f64 / 1e9 / d.as_secs_f64().max(1e-9);
                g
            };
            // Page faults: touching each page in order.
            let start = Instant::now();
            let mut sum = 0u64;
            for page in map.chunks(4096) {
                sum = sum.wrapping_add(u64::from(page[0]));
            }
            std::hint::black_box(sum);
            let faults = gbs(start.elapsed());
            drop(map);
            let mut line = format!(
                "{:<28} {:>9.1} {:>9.2}",
                path.file_name()
                    .map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
                mb(len as u64),
                faults
            );
            for &(threads, chunk) in &configs {
                hexcavator_mmap::evict_from_cache(path).map_err(|e| e.to_string())?;
                let map = Mmap::open(path).map_err(|e| e.to_string())?;
                let start = Instant::now();
                map.prefetch(threads, chunk)
                    .and_then(hexcavator_mmap::Prefetch::wait)
                    .map_err(|e| e.to_string())?;
                line += &format!(" {:>7.2}", gbs(start.elapsed()));
            }
            if !evicted {
                line += "  (not evicted: cached reads)";
            }
            Ok(line)
        })();
        match result {
            Ok(line) => println!("{line}"),
            Err(e) => {
                eprintln!("stackrabbit bench: {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}

/// Prints, for each trace, its events by provider and opcode.
fn events_table(traces: &[PathBuf]) -> ExitCode {
    let mut failed = false;
    for path in traces {
        let r: Result<(), String> = (|| {
            let map = Mmap::open(path).map_err(|e| e.to_string())?;
            let etl = Etl::parse(map.as_slice()).map_err(|e| e.to_string())?;
            let max = usize::try_from(etl.header().buffer_size)
                .unwrap_or(1 << 20)
                .max(1 << 16);
            // (provider, opcode) -> (count, smallest, largest payload).
            let mut counts: std::collections::BTreeMap<(String, u8), (u64, usize, usize)> =
                std::collections::BTreeMap::new();
            let mut scratch = Vec::new();
            // Each sample's (timestamp, thread), and each stack's.
            let mut samples: Vec<(i64, u32)> = Vec::new();
            let mut stacks: std::collections::HashSet<(i64, u32)> =
                std::collections::HashSet::new();
            for buffer in etl.buffers() {
                let Ok(buffer) = buffer else { continue };
                let _ = hexcavator_etl::merge::for_each_event(&buffer, max, &mut scratch, |e| {
                    let ptr = if e.is_64bit { 8 } else { 4 };
                    let u = e.user_data;
                    if e.provider == hexcavator_etw::guids::PERF_INFO
                        && e.descriptor.opcode == 46
                        && u.len() >= ptr + 4
                    {
                        let tid = u32::from_le_bytes(u[ptr..ptr + 4].try_into().unwrap());
                        samples.push((e.timestamp, tid));
                    }
                    if e.provider == hexcavator_etw::guids::STACK_WALK
                        && e.descriptor.opcode == 32
                        && u.len() >= 16
                    {
                        let ts = i64::from_le_bytes(u[0..8].try_into().unwrap());
                        let tid = u32::from_le_bytes(u[12..16].try_into().unwrap());
                        stacks.insert((ts, tid));
                    }
                    let c = counts
                        .entry((e.provider.to_string(), e.descriptor.opcode))
                        .or_insert((0, usize::MAX, 0));
                    c.0 += 1;
                    c.1 = c.1.min(e.user_data.len());
                    c.2 = c.2.max(e.user_data.len());
                });
            }
            let stack_walk = hexcavator_etw::guids::STACK_WALK.to_string();
            let mut rows: Vec<_> = counts.into_iter().collect();
            rows.sort_by(|a, b| b.1.0.cmp(&a.1.0).then_with(|| a.0.cmp(&b.0)));
            println!("{}", path.display());
            let named = samples.iter().filter(|k| stacks.contains(k)).count();
            let named_any = {
                let times: std::collections::HashSet<i64> = stacks.iter().map(|k| k.0).collect();
                samples.iter().filter(|k| times.contains(&k.0)).count()
            };
            let idle = samples.iter().filter(|k| k.1 == 0).count();
            println!(
                "  samples {}: a stack names {} (timestamp and thread), {} (timestamp only); {} on thread 0",
                samples.len(),
                named,
                named_any,
                idle
            );
            println!(
                "  {:<40} {:>6} {:>12} {:>8} {:>8}",
                "provider", "opcode", "events", "min", "max"
            );
            for (i, ((provider, opcode), (n, lo, hi))) in rows.iter().enumerate() {
                if i < 40 || *provider == stack_walk {
                    let name = if *provider == stack_walk {
                        "StackWalk".to_string()
                    } else {
                        provider.clone()
                    };
                    println!("  {name:<40} {opcode:>6} {n:>12} {lo:>8} {hi:>8}");
                }
            }
            Ok(())
        })();
        if let Err(e) = r {
            failed = true;
            eprintln!("stackrabbit bench: {}: {e}", path.display());
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Prints, for each trace, its samples by what their stacks hold.
fn stacks_table(traces: &[PathBuf]) -> ExitCode {
    println!(
        "{:<28} {:>10} {:>9} {:>9} {:>9} {:>9} {:>11} {:>9} {:>11} {:>8}",
        "trace",
        "samples",
        "joined %",
        "kernel %",
        "user %",
        "none %",
        "none,busy %",
        "ip=leaf %",
        "lost events",
        "lost buf"
    );
    let mut failed = false;
    for path in traces {
        let options = crate::store::Options {
            use_index: false,
            cache_dir: None,
        };
        let loaded = match crate::store::open(path, &options) {
            Ok(l) => l,
            Err(e) => {
                failed = true;
                eprintln!("stackrabbit bench: {}: {e}", path.display());
                continue;
            }
        };
        let t = &loaded.trace;
        if let crate::store::Opened::Imported { stats, .. } = &loaded.opened {
            let with = |stacks: &[hexcavator_trace::StackId]| {
                let n = stacks.iter().filter(|s| !s.is_empty()).count();
                format!("{n} of {}", stacks.len())
            };
            eprintln!(
                "  stacks: {} paired, {} continuations, {} unmatched; switches with stacks {}, readies {}",
                stats.stacks,
                stats.stack_continuations,
                stats.stacks_unmatched,
                with(&t.switches.stack),
                with(&t.readies.stack)
            );
        }
        // Kernel addresses: the top half of the address space (a 32-bit
        // trace's images are all below 4 GB).
        let narrow = t.images.iter().all(|i| i.base < 1 << 32);
        let kernel = |a: u64| {
            if narrow {
                a >= 0x8000_0000
            } else {
                a >= 0xffff_8000_0000_0000
            }
        };
        let s = &t.samples;
        let (mut joined, mut kernel_only, mut user_only, mut none, mut ip_leaf) =
            (0u64, 0u64, 0u64, 0u64, 0u64);
        // (Samples without stacks outside the idle process.)
        let mut none_busy = 0u64;
        for i in 0..s.len() {
            let stack = s.stack[i];
            if stack.is_empty() {
                none += 1;
                let thread = s.thread[i];
                let p = t.thread_process(thread);
                let idle = (p.is_some() && t.processes[p.index()].pid == 0)
                    || (thread.is_some() && t.threads[thread.index()].tid == 0);
                if !idle {
                    none_busy += 1;
                }
                continue;
            }
            let (mut k, mut u) = (false, false);
            for f in t.stacks.frames(stack) {
                if kernel(f) {
                    k = true;
                } else {
                    u = true;
                }
            }
            match (k, u) {
                (true, true) => joined += 1,
                (true, false) => kernel_only += 1,
                _ => user_only += 1,
            }
            if t.stacks.frame(stack) == s.ip[i] {
                ip_leaf += 1;
            }
        }
        let n = s.len().max(1) as f64;
        let pct = |x: u64| 100.0 * x as f64 / n;
        let name = path
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        println!(
            "{:<28} {:>10} {:>9.1} {:>9.1} {:>9.1} {:>9.1} {:>11.1} {:>9.1} {:>11} {:>8}",
            name,
            s.len(),
            pct(joined),
            pct(kernel_only),
            pct(user_only),
            pct(none),
            pct(none_busy),
            pct(ip_leaf),
            loaded.lost.events,
            loaded.lost.buffers
        );
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Prints, for each trace, a digest of its import (see `-digest`).
fn digest_table(traces: &[PathBuf]) -> ExitCode {
    for path in traces {
        let result = (|| -> Result<String, String> {
            let map = Mmap::open(path).map_err(|e| e.to_string())?;
            let etl = Etl::parse(map.as_slice()).map_err(|e| e.to_string())?;
            let start = Instant::now();
            let (trace, stats) = etw::import(&etl).map_err(|e| e.to_string())?;
            let secs = start.elapsed().as_secs_f64();
            Ok(format!(
                "{:<28} {:016x} samples {} switches {} readies {} stacks {}+{} unmatched {} errors {}/{} ({secs:.3} s)",
                path.file_name()
                    .map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
                digest(&trace),
                trace.samples.len(),
                trace.switches.len(),
                trace.readies.len(),
                stats.stacks,
                stats.stack_continuations,
                stats.stacks_unmatched,
                stats.read_errors,
                stats.decode_errors,
            ))
        })();
        match result {
            Ok(line) => println!("{line}"),
            Err(e) => {
                eprintln!("stackrabbit bench: {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}

/// A hash of what `trace` holds, independent of how its stacks are
/// numbered.
fn digest(trace: &Trace) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = rustc_hash::FxHasher::default();
    let tid = |t: hexcavator_trace::ThreadIx| {
        if t.is_some() {
            trace.threads[t.index()].tid
        } else {
            u32::MAX
        }
    };
    let frames = |s: hexcavator_trace::StackId| trace.stacks.frames(s).collect::<Vec<u64>>();
    let s = &trace.samples;
    for i in 0..s.len() {
        (s.time[i], s.cpu[i], tid(s.thread[i]), s.ip[i], s.weight[i]).hash(&mut h);
        frames(s.stack[i]).hash(&mut h);
    }
    let w = &trace.switches;
    for i in 0..w.len() {
        (
            w.time[i],
            w.cpu[i],
            tid(w.new_thread[i]),
            tid(w.old_thread[i]),
        )
            .hash(&mut h);
        (w.wait_reason[i], w.old_state[i], w.ready[i].0).hash(&mut h);
        frames(w.stack[i]).hash(&mut h);
    }
    let r = &trace.readies;
    for i in 0..r.len() {
        (r.time[i], r.cpu[i], tid(r.thread[i]), tid(r.readier[i])).hash(&mut h);
        frames(r.stack[i]).hash(&mut h);
    }
    for p in &trace.processes {
        (
            p.pid,
            &p.name,
            &p.command_line,
            p.start,
            p.end,
            p.exit_status,
        )
            .hash(&mut h);
    }
    for t in &trace.threads {
        (t.tid, t.process.0, &t.name, t.start, t.end).hash(&mut h);
    }
    for im in &trace.images {
        (im.process.0, im.base, im.size, &im.path, im.load, im.unload).hash(&mut h);
        im.debug_id
            .as_ref()
            .map(|d| (d.guid, d.age, &d.pdb_path))
            .hash(&mut h);
    }
    (trace.clock.origin, trace.sample_interval).hash(&mut h);
    h.finish()
}
