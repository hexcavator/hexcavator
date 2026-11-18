//! `stackrabbit synth`: writes a synthetic trace, for tests, demos and
//! benchmarks with nothing private in them.

use std::process::ExitCode;

use hexcavator_trace_synth::{Config, Truth, generate};
use serde_json::{Value, json};

use crate::Args;

const USAGE: &str = "\
usage: stackrabbit synth <out.etl> [options]

Writes a synthetic trace: processes and threads running a call graph through their own code,
the system DLLs and the kernel, sampled with stacks and switching between processors.

Options:
  -seed <n>             The random seed (1). The same options give the same trace.
  -processors <n>       Processors (4).
  -duration-ms <n>      How long the trace runs (2000).
  -interval-us <n>      The sampling interval (1000: 1 kHz).
  -processes <n>        Processes (6), with
  -threads <n>          threads each (4), and
  -dlls <n>             DLLs of their own each (3).
  -functions <n>        Functions per module (40).
  -depth <n>            The deepest stack (24).
  -switch-per-mille <n> The chance of a context switch before each sample (150).
  -pointer-size <4|8>   The traced machine's pointer size (8).
  -compress             Compress the trace's buffers.
  -truth <out.json>     Also write what the trace holds: samples by process, thread and
                        function, and the function table.";

/// Runs `stackrabbit synth`.
pub fn run(args: &[String]) -> ExitCode {
    match parse(args) {
        Ok(Some((out, config, truth))) => write(&out, &config, truth.as_deref()),
        Ok(None) => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("stackrabbit synth: {e}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

type Parsed = (String, Config, Option<String>);

fn parse(args: &[String]) -> Result<Option<Parsed>, String> {
    let mut a = Args::new(args);
    let mut out = None;
    let mut truth = None;
    let mut c = Config::default();
    while let Some(arg) = a.next() {
        match arg {
            "-h" | "-help" | "--help" => return Ok(None),
            "-seed" => c.seed = a.number(arg)?,
            "-processors" => c.processors = a.number(arg)?,
            "-duration-ms" => c.duration_ms = a.number(arg)?,
            "-interval-us" => c.sample_interval_us = a.number(arg)?,
            "-processes" => c.processes = a.number(arg)?,
            "-threads" => c.threads_per_process = a.number(arg)?,
            "-dlls" => c.dlls_per_process = a.number(arg)?,
            "-functions" => c.functions_per_module = a.number(arg)?,
            "-depth" => c.max_depth = a.number(arg)?,
            "-switch-per-mille" => c.switch_per_mille = a.number(arg)?,
            "-pointer-size" => c.pointer_size = a.number(arg)?,
            "-compress" => c.compress = true,
            "-truth" => truth = Some(a.value(arg)?.to_string()),
            o if o.starts_with('-') => return Err(format!("unknown option '{o}'")),
            path if out.is_none() => out = Some(path.to_string()),
            extra => return Err(format!("unexpected '{extra}'")),
        }
    }
    let out = out.ok_or("expected an output path")?;
    if c.processors == 0 || !(c.pointer_size == 4 || c.pointer_size == 8) {
        return Err("expected processors > 0 and a pointer size of 4 or 8".into());
    }
    if c.processes == 0 || c.threads_per_process == 0 || c.processes > 2048 {
        return Err("expected 1 to 2048 processes and at least one thread each".into());
    }
    if c.dlls_per_process > 64 || c.functions_per_module > 2000 {
        return Err("expected at most 64 DLLs per process and 2000 functions per module".into());
    }
    if c.duration_ms == 0 || c.sample_interval_us == 0 {
        return Err("expected a duration and an interval above 0".into());
    }
    Ok(Some((out, c, truth)))
}

fn write(out: &str, config: &Config, truth_path: Option<&str>) -> ExitCode {
    let s = generate(config);
    if let Err(e) = std::fs::write(out, &s.etl) {
        eprintln!("stackrabbit synth: {out}: {e}");
        return ExitCode::FAILURE;
    }
    if let Some(p) = truth_path {
        let text = serde_json::to_string_pretty(&truth_json(&s.truth)).expect("JSON");
        if let Err(e) = std::fs::write(p, text) {
            eprintln!("stackrabbit synth: {p}: {e}");
            return ExitCode::FAILURE;
        }
    }
    println!(
        "{out}: {} bytes; {} samples, {} switches, {} readies",
        s.etl.len(),
        s.truth.samples,
        s.truth.switches,
        s.truth.readies
    );
    ExitCode::SUCCESS
}

/// A truth as JSON.
pub fn truth_json(t: &Truth) -> Value {
    json!({
        "samples": t.samples,
        "idleSamples": t.idle_samples,
        "switches": t.switches,
        "readies": t.readies,
        "stacks": t.stacks,
        "processes": t.processes.iter().map(|p| json!({
            "pid": p.pid, "name": p.name, "samples": p.samples,
        })).collect::<Vec<_>>(),
        "threads": t.threads.iter().map(|th| json!({
            "tid": th.tid, "pid": th.pid, "name": th.name,
            "samples": th.samples, "switchIns": th.switch_ins,
        })).collect::<Vec<_>>(),
        "modules": t.modules.iter().map(|m| json!({
            "name": m.name, "path": m.path, "base": m.base, "size": m.size,
            "pdb": m.pdb.2, "kernel": m.kernel,
        })).collect::<Vec<_>>(),
        "functions": t.functions.iter().enumerate().map(|(i, f)| json!({
            "module": t.modules[f.module].name, "name": f.name, "rva": f.rva, "size": f.size,
            "inclusive": t.inclusive[i], "exclusive": t.exclusive[i],
        })).collect::<Vec<_>>(),
    })
}
