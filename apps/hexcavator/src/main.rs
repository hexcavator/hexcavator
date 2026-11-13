//! The `hexc` command-line driver (see the library for the commands).

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    hexcavator::run(&args)
}
