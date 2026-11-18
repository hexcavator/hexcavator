//! `stackrabbit tree`: prints a trace's stack tree.

use std::fmt::Write as _;
use std::path::Path;
use std::process::ExitCode;

use hexcavator_symbolize::SymbolPath;
use hexcavator_trace_analysis::{NodeId, PdbSymbolizer, Resolver};

use crate::Args;
use crate::store;
use crate::views::{self, Source, TreeSpec, TreeView};

const USAGE: &str = "\
usage: stackrabbit tree <trace> [options]

Prints a trace's stack tree: grouping columns above call stacks, each node with its share of
the whole, its weight and its own (exclusive) weight.

Options:
  -source <samples|running|waits>  What to weigh (samples).
  -group <columns>                 Grouping columns, comma-separated: process, thread, cpu
                                   (process); '' for none.
  -frames <function|module|address> How frames are told apart (function).
  -invert                          Callers: innermost frames first.
  -depth <n>                       Levels to print (6).
  -top <n>                         Children to print under each node (5).
  -hot                             Print the hot path under the heaviest child instead.
  -no-index                        Import the trace, without reading or writing an index.";

/// Runs `stackrabbit tree`.
pub fn run(args: &[String]) -> ExitCode {
    match parse(args) {
        Ok(Some(o)) => match print(&o) {
            Ok(text) => {
                print!("{text}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("stackrabbit tree: {e}");
                ExitCode::FAILURE
            }
        },
        Ok(None) => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("stackrabbit tree: {e}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

struct Options {
    path: String,
    spec: TreeSpec,
    depth: u32,
    top: usize,
    hot: bool,
    use_index: bool,
}

fn parse(args: &[String]) -> Result<Option<Options>, String> {
    let mut a = Args::new(args);
    let mut o = Options {
        path: String::new(),
        spec: TreeSpec::default(),
        depth: 6,
        top: 5,
        hot: false,
        use_index: true,
    };
    while let Some(arg) = a.next() {
        match arg {
            "-h" | "-help" | "--help" => return Ok(None),
            "-source" => {
                let v = a.value(arg)?;
                o.spec.source =
                    Source::parse(v).ok_or_else(|| format!("-source: unknown '{v}'"))?;
            }
            "-group" => {
                let v = a.value(arg)?;
                o.spec.groups = v
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|g| views::parse_group(g).ok_or_else(|| format!("-group: unknown '{g}'")))
                    .collect::<Result<_, _>>()?;
            }
            "-frames" => {
                let v = a.value(arg)?;
                o.spec.frames =
                    views::parse_frames(v).ok_or_else(|| format!("-frames: unknown '{v}'"))?;
            }
            "-invert" => o.spec.invert = true,
            "-depth" => o.depth = a.number(arg)?,
            "-top" => o.top = a.number(arg)?,
            "-hot" => o.hot = true,
            "-no-index" => o.use_index = false,
            x if x.starts_with('-') => return Err(format!("unknown option '{x}'")),
            p if o.path.is_empty() => o.path = p.to_string(),
            extra => return Err(format!("unexpected '{extra}'")),
        }
    }
    if o.path.is_empty() {
        return Err("expected a trace".into());
    }
    Ok(Some(o))
}

/// The tree's text.
fn print(o: &Options) -> Result<String, String> {
    let options = store::Options {
        use_index: o.use_index,
        ..store::Options::default()
    };
    let loaded = store::open(Path::new(&o.path), &options)?;
    let trace = &loaded.trace;
    let resolver = Resolver::new(trace);
    let symbols = PdbSymbolizer::new(SymbolPath::from_env());
    let mut view = TreeView::build(trace, &resolver, &symbols, o.spec.clone());
    let total = view.tree.inclusive(NodeId::ROOT).max(1);
    let mut out = String::new();
    let mut line = |out: &mut String, row: &views::Row| {
        #[allow(clippy::cast_precision_loss)]
        let pct = 100.0 * row.inclusive as f64 / total as f64;
        let indent = 2 * (row.depth.saturating_sub(1) as usize);
        let _ = writeln!(
            out,
            "{:indent$}{:<60} {pct:6.2}% {:>12} {:>12}",
            "", row.label, row.inclusive, row.exclusive
        );
    };
    let _ = writeln!(
        out,
        "{:<60} {:>7} {:>12} {:>12}",
        "", "share", "weight", "exclusive"
    );
    if o.hot {
        let first = view.children(trace, &symbols, NodeId::ROOT);
        if let Some(top) = first.first() {
            line(&mut out, top);
            for row in view.hot_path(trace, &symbols, NodeId(top.id), 0.1) {
                line(&mut out, &row);
            }
        }
        return Ok(out);
    }
    print_rows(
        &mut view,
        trace,
        &symbols,
        NodeId::ROOT,
        o,
        &mut out,
        &mut line,
    );
    Ok(out)
}

/// Prints `node`'s heaviest children, each followed by its own, depth
/// first.
fn print_rows(
    view: &mut TreeView,
    trace: &hexcavator_trace::Trace,
    symbols: &PdbSymbolizer,
    node: NodeId,
    o: &Options,
    out: &mut String,
    line: &mut impl FnMut(&mut String, &views::Row),
) {
    if view.tree.depth(node) >= o.depth {
        return;
    }
    for row in view.children(trace, symbols, node).into_iter().take(o.top) {
        line(out, &row);
        print_rows(view, trace, symbols, NodeId(row.id), o, out, line);
    }
}
