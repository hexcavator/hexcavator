//! Stackrabbit's engine: it opens performance traces and answers queries
//! over them, for the Stackrabbit editor extension (`serve`) or from the
//! command line.
//!
//! - [`protocol`]: the session protocol's framing;
//! - [`store`]: opening a trace, from its saved index when there is one;
//! - [`views`]: queries (stack trees) and the rows they show;
//! - [`serve`]: the session an editor drives;
//! - [`symbols`]: which PDBs a trace needs, and downloading them;
//! - [`bench`], [`synth`], [`tree`]: the command-line tools.

use std::process::ExitCode;

pub mod bench;
pub mod disk;
pub mod fileio;
pub mod generic;
pub mod protocol;
pub mod regions;
pub mod serve;
pub mod store;
pub mod symbols;
pub mod synth;
pub mod tree;
pub mod views;

const USAGE: &str = "\
usage: stackrabbit <command> [options]

Commands:
  serve                     Answer an editor's requests on standard input and output
                            (the Stackrabbit extension starts this).
  tree <trace> [options]    Print a trace's stack tree.
  bench <trace or dir>...   Time opening and querying traces: import, index, trees.
                            Prints timings and counts only, never what the traces hold.
  symbols <trace> [options] Download the PDBs a trace's stacks need, many at once.
  synth <out.etl> [options] Write a synthetic trace (and, with -truth, its answers).
  help                      Show this.
  version                   Show the version.

Run a command with -h for its options.";

/// Runs the command line `args` (without the program name).
pub fn run(args: &[String]) -> ExitCode {
    let Some((command, rest)) = args.split_first() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    match command.as_str() {
        "serve" => serve::run(rest),
        "tree" => tree::run(rest),
        "bench" => bench::run(rest),
        "synth" => synth::run(rest),
        "symbols" => symbols::run(rest),
        "help" | "-h" | "--help" | "-help" => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        "version" | "-V" | "--version" | "-version" => {
            println!("stackrabbit {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("stackrabbit: unknown command '{other}'\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// A command line's options, read one by one.
pub(crate) struct Args<'a> {
    args: &'a [String],
    pos: usize,
}

impl<'a> Args<'a> {
    pub(crate) fn new(args: &'a [String]) -> Self {
        Self { args, pos: 0 }
    }

    /// The next argument.
    pub(crate) fn next(&mut self) -> Option<&'a str> {
        let a = self.args.get(self.pos)?;
        self.pos += 1;
        Some(a)
    }

    /// The value after option `name`.
    pub(crate) fn value(&mut self, name: &str) -> Result<&'a str, String> {
        self.next()
            .ok_or_else(|| format!("{name}: expected a value"))
    }

    /// The number after option `name`.
    pub(crate) fn number<T: std::str::FromStr>(&mut self, name: &str) -> Result<T, String> {
        let v = self.value(name)?;
        v.parse()
            .map_err(|_| format!("{name}: '{v}' isn't a number in range"))
    }
}
