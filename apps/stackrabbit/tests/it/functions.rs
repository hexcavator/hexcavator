//! The hot functions and modules: each function's and module's exclusive
//! and inclusive samples are the simulation's.

use rustc_hash::FxHashMap;
use serde_json::{Value, json};

use hexcavator_trace::{ImageIx, Trace};
use hexcavator_trace_analysis::{Resolver, Symbolizer};
use hexcavator_trace_synth::Truth;
use stackrabbit::store;
use stackrabbit::views::{TreeSpec, functions};

use crate::common::{scratch, small, write_trace};

/// Finds functions in the truth's function table, as a PDB would.
struct TruthSymbols<'a>(&'a Truth);

impl Symbolizer for TruthSymbols<'_> {
    fn function(&self, trace: &Trace, image: ImageIx, offset: u64) -> Option<(u64, String)> {
        let img = &trace.images[image.index()];
        let pid = if img.process.is_some() {
            trace.processes[img.process.index()].pid
        } else {
            0
        };
        let module = self.0.module_named(pid, img.file_name())?;
        let f = self.0.function_at(module, offset)?;
        Some((u64::from(f.rva), f.name.clone()))
    }

    /// A line for each 16 bytes of a function, in a file named for its
    /// module.
    fn line(&self, trace: &Trace, image: ImageIx, offset: u64) -> Option<(String, u32)> {
        self.function(trace, image, offset)?;
        let name = trace.images[image.index()].file_name();
        Some((format!("{name}.cpp"), u32::try_from(offset / 16).ok()?))
    }
}

fn by_label(rows: &Value) -> FxHashMap<String, (u64, u64)> {
    rows.as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["label"].as_str().unwrap().to_string(),
                (
                    r["exclusive"].as_u64().unwrap(),
                    r["inclusive"].as_u64().unwrap(),
                ),
            )
        })
        .collect()
}

#[test]
fn hot_functions_and_modules_are_the_truths() {
    let dir = scratch("functions");
    let (path, s) = write_trace(&dir, "t.etl", &small());
    let truth = &s.truth;
    let loaded = store::open(
        &path,
        &store::Options {
            use_index: false,
            cache_dir: None,
        },
    )
    .unwrap();
    let trace = &loaded.trace;
    let resolver = Resolver::new(trace);
    let symbols = TruthSymbols(truth);
    let f = functions(trace, &resolver, &symbols, &TreeSpec::default(), usize::MAX);
    assert_eq!(f["unit"], "samples");
    assert_eq!(f["total"], truth.samples);

    // Every function the truth sampled, by "module!name" (a shared DLL's
    // function is one row, its processes' samples added up). The idle
    // thread's samples are in KiIdleLoop (the truth counts them apart).
    let mut want: FxHashMap<String, (u64, u64)> = FxHashMap::default();
    for (i, func) in truth.functions.iter().enumerate() {
        let mut e = truth.exclusive[i];
        let mut n = truth.inclusive[i];
        if func.name == "KiIdleLoop" {
            e += truth.idle_samples;
            n += truth.idle_samples;
        }
        if n > 0 {
            let label = format!("{}!{}", truth.modules[func.module].name, func.name);
            let w = want.entry(label).or_default();
            w.0 += e;
            w.1 += n;
        }
    }
    let got = by_label(&f["functions"]);
    assert_eq!(got, want);
    assert_eq!(f["functionCount"], want.len());
    // Heaviest exclusive first.
    let rows = f["functions"].as_array().unwrap();
    let ex: Vec<u64> = rows
        .iter()
        .map(|r| r["exclusive"].as_u64().unwrap())
        .collect();
    assert!(ex.windows(2).all(|w| w[0] >= w[1]));
    assert!(rows.iter().all(|r| {
        r["label"]
            .as_str()
            .unwrap()
            .starts_with(r["module"].as_str().unwrap())
    }));

    // Modules: their functions' exclusive samples added up; inclusive at
    // least that, at least any one function's, and at most every sample.
    let mut module_ex: FxHashMap<String, u64> = FxHashMap::default();
    for (label, (e, _)) in &want {
        *module_ex
            .entry(label.split('!').next().unwrap().to_string())
            .or_default() += e;
    }
    let modules = by_label(&f["modules"]);
    for (m, (e, n)) in &modules {
        assert_eq!(*e, module_ex.get(m).copied().unwrap_or(0), "{m}");
        assert!(*n >= *e && *n <= truth.samples, "{m}");
        for (label, (_, fi)) in &want {
            if label.starts_with(&format!("{m}!")) {
                assert!(*n >= *fi, "{m} under {label}");
            }
        }
    }
    let ex_sum: u64 = modules.values().map(|v| v.0).sum();
    assert_eq!(
        ex_sum, truth.samples,
        "every sample's innermost frame is in a module"
    );

    // A limit keeps the heaviest by each measure; a time range only its
    // samples.
    let few = functions(trace, &resolver, &symbols, &TreeSpec::default(), 3);
    let n = few["functions"].as_array().unwrap().len();
    assert!((3..=6).contains(&n), "{n} rows");
    let first = TreeSpec::from_json(&json!({"time": [0, 100_000_000]})).unwrap();
    let part = functions(trace, &resolver, &symbols, &first, usize::MAX);
    let part_total = part["total"].as_u64().unwrap();
    assert!(part_total > 0 && part_total < truth.samples);
    let ex_part: u64 = by_label(&part["modules"]).values().map(|v| v.0).sum();
    assert_eq!(ex_part, part_total);
}

#[test]
fn a_highlighted_function_is_its_inclusive_cpu_over_time() {
    use stackrabbit::views::{Highlight, Source, cpu_graph};
    let dir = scratch("functions-highlight");
    let (path, s) = write_trace(&dir, "t.etl", &small());
    let truth = &s.truth;
    let loaded = store::open(
        &path,
        &store::Options {
            use_index: false,
            cache_dir: None,
        },
    )
    .unwrap();
    let trace = &loaded.trace;
    let resolver = Resolver::new(trace);
    let symbols = TruthSymbols(truth);
    let f = functions(trace, &resolver, &symbols, &TreeSpec::default(), usize::MAX);
    // The truth's inclusive samples by "module!name" (the idle thread's
    // aren't in it, nor in the graph).
    let mut want: FxHashMap<String, u64> = FxHashMap::default();
    for (i, func) in truth.functions.iter().enumerate() {
        *want
            .entry(format!("{}!{}", truth.modules[func.module].name, func.name))
            .or_default() += truth.inclusive[i];
    }
    let mut checked = 0;
    for row in f["functions"].as_array().unwrap() {
        let id = row["fn"].as_str().unwrap();
        let h = Highlight::new(trace, &resolver, &symbols, id).unwrap();
        let g = cpu_graph(trace, Source::Samples, 50, None, 8, Some(&h));
        let lit = &g["highlight"];
        assert_eq!(lit["label"], id);
        assert_eq!(
            lit["samples"],
            want[row["label"].as_str().unwrap()],
            "{}",
            row["label"]
        );
        assert_eq!(
            lit["values"].as_array().unwrap().len() as u64,
            g["buckets"].as_u64().unwrap()
        );
        checked += 1;
    }
    assert!(checked > 20, "{checked} functions");

    // Precise: an executable's function (never on the idle thread) runs
    // as long as the precise functions table says.
    let running = TreeSpec::from_json(&json!({"source": "running"})).unwrap();
    let f = functions(trace, &resolver, &symbols, &running, usize::MAX);
    let mut checked = 0;
    for row in f["functions"].as_array().unwrap() {
        if !row["module"].as_str().unwrap().ends_with(".exe") || row["module"] == "ntoskrnl.exe" {
            continue;
        }
        let h = Highlight::new(trace, &resolver, &symbols, row["fn"].as_str().unwrap()).unwrap();
        let g = cpu_graph(trace, Source::Running, 300, None, 8, Some(&h));
        assert_eq!(
            g["highlight"]["ns"].as_u64().unwrap(),
            row["inclusive"].as_u64().unwrap() * 100,
            "{}",
            row["label"]
        );
        checked += 1;
    }
    assert!(checked > 5, "{checked} functions");

    // A module: at least any of its functions; every sample's module, at
    // most. And bad IDs are errors.
    let ntdll = Highlight::new(trace, &resolver, &symbols, "ntdll.dll|m").unwrap();
    let g = cpu_graph(trace, Source::Samples, 50, None, 8, Some(&ntdll));
    let lit = g["highlight"]["samples"].as_u64().unwrap();
    assert!(lit > 0 && lit <= truth.samples - truth.idle_samples);
    for bad in ["", "ntdll.dll", "ntdll.dll|zz", "ntdll.dll|ix"] {
        assert!(
            Highlight::new(trace, &resolver, &symbols, bad).is_err(),
            "{bad}"
        );
    }
    // A module the trace doesn't have: nothing lit.
    let none = Highlight::new(trace, &resolver, &symbols, "nothere.dll|10").unwrap();
    let g = cpu_graph(trace, Source::Samples, 50, None, 8, Some(&none));
    assert_eq!(g["highlight"]["samples"], 0);
}

#[test]
fn time_by_source_line_is_every_samples_lines() {
    use stackrabbit::views::{line_totals, lines};
    let dir = scratch("functions-lines");
    let (path, s) = write_trace(&dir, "t.etl", &small());
    let truth = &s.truth;
    let loaded = store::open(
        &path,
        &store::Options {
            use_index: false,
            cache_dir: None,
        },
    )
    .unwrap();
    let trace = &loaded.trace;
    let resolver = Resolver::new(trace);
    let symbols = TruthSymbols(truth);
    // The reference: each sample's frames' lines, one at a time (callers'
    // return addresses a byte back), each line once a sample.
    let line_of = |process, address: u64| {
        let image = resolver.image(process, address)?;
        symbols.line(trace, image, address - trace.images[image.index()].base)
    };
    let mut want: FxHashMap<(String, u32), (u64, u64)> = FxHashMap::default();
    let samples = &trace.samples;
    for i in 0..samples.len() {
        let process = trace.thread_process(samples.thread[i]);
        let frames: Vec<u64> = if samples.stack[i].is_empty() {
            vec![samples.ip[i]]
        } else {
            trace.stacks.frames(samples.stack[i]).collect()
        };
        let mut seen = std::collections::HashSet::new();
        for (j, &f) in frames.iter().enumerate() {
            let Some(at) = line_of(process, if j == 0 { f } else { f - 1 }) else {
                continue;
            };
            let w = want.entry(at.clone()).or_default();
            if j == 0 {
                w.0 += u64::from(samples.weight[i]);
            }
            if seen.insert(at) {
                w.1 += u64::from(samples.weight[i]);
            }
        }
    }
    assert!(want.len() > 50, "{} lines", want.len());

    let (totals, unit, total) = line_totals(trace, &resolver, &symbols, &TreeSpec::default());
    assert_eq!(total, truth.samples);
    let files = lines(&totals, unit, total, 10_000_000, None, usize::MAX);
    assert_eq!(files["unit"], "samples");
    let mut got: FxHashMap<(String, u32), (u64, u64)> = FxHashMap::default();
    let rows = files["files"].as_array().unwrap();
    assert_eq!(files["fileCount"], rows.len());
    assert!(
        rows.windows(2)
            .all(|w| w[0]["inclusive"].as_u64() >= w[1]["inclusive"].as_u64())
    );
    for f in rows {
        let name = f["path"].as_str().unwrap();
        let r = lines(&totals, unit, total, 10_000_000, Some(name), 0);
        let ls = r["lines"].as_array().unwrap();
        assert!(
            ls.windows(2)
                .all(|w| w[0]["line"].as_u64() < w[1]["line"].as_u64()),
            "in order"
        );
        let ex: u64 = ls.iter().map(|l| l["exclusive"].as_u64().unwrap()).sum();
        assert_eq!(
            ex,
            f["exclusive"].as_u64().unwrap(),
            "{name}: its lines' self time"
        );
        let most = ls
            .iter()
            .map(|l| l["inclusive"].as_u64().unwrap())
            .max()
            .unwrap();
        assert!(
            f["inclusive"].as_u64().unwrap() >= most,
            "{name}: at least its heaviest line"
        );
        for l in ls {
            got.insert(
                (
                    name.to_string(),
                    u32::try_from(l["line"].as_u64().unwrap()).unwrap(),
                ),
                (
                    l["exclusive"].as_u64().unwrap(),
                    l["inclusive"].as_u64().unwrap(),
                ),
            );
        }
    }
    assert_eq!(got, want);
    // A limit; a file that isn't there.
    assert_eq!(
        lines(&totals, unit, total, 1, None, 2)["files"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        lines(&totals, unit, total, 1, Some("nothere.cpp"), 0)["lines"],
        json!([])
    );
    // Precise: in ticks.
    let running = TreeSpec::from_json(&json!({"source": "running"})).unwrap();
    let (_, unit, total) = line_totals(trace, &resolver, &symbols, &running);
    assert!(total > 0);
    assert_eq!(lines(&totals, unit, total, 1, None, 1)["unit"], "ticks");
}
