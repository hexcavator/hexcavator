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
  -symbols   Name functions with the PDBs _NT_SYMBOL_PATH finds (default: by module).
  -json      One JSON object per trace instead of a table.
  -phases    Instead, time the import's phases: reading the events in time order
             (buffers merged, decompressed), then decoding them too, then the import.
  -digest    Instead, print a digest of each trace's import: a hash of what it holds (rows,
             their stacks' frames, processes, threads, images), not of how it is stored;
             two imports that agree have the same digest.
  -read      Instead, time reading each file from the disk (evicted from the cache
             first, where the host allows): page faults through a mapping, one thread;
             then reads of 1, 4 and 16 MB on 1, 2, 4 and 8 threads.";

/// Runs `stackrabbit bench`.
pub fn run(args: &[String]) -> ExitCode {
    let mut a = Args::new(args);
    let mut paths = Vec::new();
    let mut symbols = false;
    let mut as_json = false;
    let mut phases = false;
    let mut read = false;
    let mut digest = false;
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

    let pdbs;
    let symbolizer: &dyn Symbolizer = if symbols {
        pdbs = PdbSymbolizer::new(SymbolPath::from_env());
        &pdbs
    } else {
        &NoSymbols
    };
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
        TreeSpec {
            source: Source::Waits,
            groups: vec![GroupBy::Process],
            frames,
            ..TreeSpec::default()
        },
    );
    waits.children(&trace, symbolizer, NodeId::ROOT);
    let waits = start.elapsed();

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
