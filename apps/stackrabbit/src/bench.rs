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

Times, for each trace (a directory's *.etl files, by name): importing it; writing and reading
its index; and building the first stack trees (CPU samples by process, inverted, and waits),
expanding the top level and the hot path. Prints timings and counts only.

Options:
  -symbols   Name functions with the PDBs _NT_SYMBOL_PATH finds (default: by module).
  -json      One JSON object per trace instead of a table.";

/// Runs `stackrabbit bench`.
pub fn run(args: &[String]) -> ExitCode {
    let mut a = Args::new(args);
    let mut paths = Vec::new();
    let mut symbols = false;
    let mut as_json = false;
    while let Some(arg) = a.next() {
        match arg {
            "-h" | "-help" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "-symbols" => symbols = true,
            "-json" => as_json = true,
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
    let map = Mmap::open(path).map_err(|e| e.to_string())?;
    let data = map.as_slice();
    let start = Instant::now();
    let etl = Etl::parse(data).map_err(|e| e.to_string())?;
    let (trace, stats) = etw::import(&etl).map_err(|e| e.to_string())?;
    let import = start.elapsed();

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
