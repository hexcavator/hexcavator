//! Generated traces import exactly as their truth says: every event read
//! and decoded, every stack matched, and the counts and trees of the
//! import equal to the simulation's.

use rustc_hash::FxHashMap;

use hexcavator_etl::Etl;
use hexcavator_trace::{ImageIx, Trace, etw};
use hexcavator_trace_analysis::{
    Filter, FrameMode, Framer, GroupBy, Key, Keys, NodeId, Resolver, Symbolizer, Tree, sources,
};
use hexcavator_trace_synth::{Config, Synthetic, Truth, generate};

/// Finds functions in the truth's function table, as a PDB would.
struct TruthSymbols<'a>(&'a Truth);

impl TruthSymbols<'_> {
    fn module(&self, trace: &Trace, image: ImageIx) -> Option<usize> {
        let img = &trace.images[image.index()];
        let pid = if img.process.is_some() {
            trace.processes[img.process.index()].pid
        } else {
            0
        };
        self.0.module_named(pid, img.file_name())
    }
}

impl Symbolizer for TruthSymbols<'_> {
    fn function(&self, trace: &Trace, image: ImageIx, offset: u64) -> Option<(u64, String)> {
        let f = self.0.function_at(self.module(trace, image)?, offset)?;
        Some((u64::from(f.rva), f.name.clone()))
    }
}

fn import(s: &Synthetic) -> Trace {
    let etl = Etl::parse(&s.etl).unwrap();
    let (trace, stats) = etw::import(&etl).unwrap();
    assert_eq!(stats.read_errors, 0, "every buffer and record reads");
    assert_eq!(stats.decode_errors, 0, "every payload decodes");
    assert_eq!(stats.stacks_unmatched, 0, "every stack finds its event");
    assert_eq!(stats.stacks, s.truth.stacks, "every stack is kept");
    trace
}

/// Checks an import against the truth: counts, threads, processes, and
/// the trees by process and by innermost function.
fn check(s: &Synthetic) {
    let truth = &s.truth;
    let trace = import(s);
    assert_eq!(trace.samples.len() as u64, truth.samples);
    assert_eq!(trace.switches.len() as u64, truth.switches);
    assert_eq!(trace.readies.len() as u64, truth.readies);
    // Every ready event knows its readier, even before its processor's
    // first switch (from its stack).
    assert!(trace.readies.readier.iter().all(|r| r.is_some()));

    // Samples by thread.
    let mut by_tid: FxHashMap<u32, u64> = FxHashMap::default();
    for &t in &trace.samples.thread {
        let tid = if t.is_some() {
            trace.threads[t.index()].tid
        } else {
            u32::MAX
        };
        *by_tid.entry(tid).or_default() += 1;
    }
    assert_eq!(by_tid.get(&0).copied().unwrap_or(0), truth.idle_samples);
    for t in &truth.threads {
        assert_eq!(
            by_tid.get(&t.tid).copied().unwrap_or(0),
            t.samples,
            "samples of thread {}",
            t.tid
        );
        let thread = trace
            .threads
            .iter()
            .find(|th| th.tid == t.tid)
            .expect("the thread is in the trace");
        assert_eq!(thread.name, t.name, "thread {}'s name", t.tid);
    }

    // The tree by process: each process's samples.
    let symbols = TruthSymbols(truth);
    let resolver = Resolver::new(&trace);
    let mut framer = Framer::new(&trace, &resolver, &symbols, FrameMode::Function);
    let mut keys = Keys::default();
    let instances = sources::samples(
        &trace,
        &mut framer,
        &mut keys,
        &[GroupBy::Process],
        &Filter::default(),
    );
    let mut tree = Tree::new(instances.without_frames());
    let mut by_pid: FxHashMap<u32, u64> = FxHashMap::default();
    for &c in &tree.children(NodeId::ROOT).to_vec() {
        if let Key::Process(p) = keys.get(tree.key(c).unwrap())
            && p.is_some()
        {
            *by_pid.entry(trace.processes[p.index()].pid).or_default() += tree.inclusive(c);
        }
    }
    // The idle thread's samples are the Idle process's (process 0).
    assert_eq!(by_pid.get(&0).copied().unwrap_or(0), truth.idle_samples);
    for p in &truth.processes {
        assert_eq!(
            by_pid.get(&p.pid).copied().unwrap_or(0),
            p.samples,
            "samples of {}",
            p.name
        );
    }

    // The inverted tree without grouping: its first level is each sample's
    // innermost function, the functions' exclusive samples. (A shared
    // DLL's function is a key per process; they add up.)
    let instances = sources::samples(&trace, &mut framer, &mut keys, &[], &Filter::default());
    let mut tree = Tree::new(instances.inverted());
    let mut exclusive: FxHashMap<(String, u32), u64> = FxHashMap::default();
    for &c in &tree.children(NodeId::ROOT).to_vec() {
        let Key::Frame { image, offset } = keys.get(tree.key(c).unwrap()) else {
            panic!("an innermost frame we can't place");
        };
        let module = symbols
            .module(&trace, image)
            .expect("a module of the truth");
        let rva = u32::try_from(offset).unwrap();
        *exclusive
            .entry((truth.modules[module].name.clone(), rva))
            .or_default() += tree.inclusive(c);
    }
    let mut expected: FxHashMap<(String, u32), u64> = FxHashMap::default();
    for (i, f) in truth.functions.iter().enumerate() {
        if truth.exclusive[i] > 0 {
            *expected
                .entry((truth.modules[f.module].name.clone(), f.rva))
                .or_default() += truth.exclusive[i];
        }
    }
    // The idle thread's samples are in KiIdleLoop (the truth counts them
    // apart from the functions').
    let idle = truth
        .functions
        .iter()
        .find(|f| f.name == "KiIdleLoop")
        .unwrap();
    if truth.idle_samples > 0 {
        *expected
            .entry((truth.modules[idle.module].name.clone(), idle.rva))
            .or_default() += truth.idle_samples;
    }
    assert_eq!(exclusive, expected);
}

fn small() -> Config {
    Config {
        duration_ms: 300,
        processes: 4,
        threads_per_process: 3,
        ..Config::default()
    }
}

#[test]
fn a_64_bit_trace_imports_exactly() {
    check(&generate(&small()));
}

#[test]
fn a_32_bit_trace_imports_exactly() {
    check(&generate(&Config {
        pointer_size: 4,
        ..small()
    }));
}

#[test]
fn a_compressed_trace_imports_exactly() {
    check(&generate(&Config {
        compress: true,
        ..small()
    }));
}

#[test]
fn a_busy_many_processor_trace_imports_exactly() {
    check(&generate(&Config {
        processors: 16,
        processes: 12,
        threads_per_process: 6,
        duration_ms: 500,
        sample_interval_us: 125,
        switch_per_mille: 400,
        ..Config::default()
    }));
}

#[test]
fn the_same_configuration_gives_the_same_trace() {
    let a = generate(&small());
    let b = generate(&small());
    assert_eq!(a.etl, b.etl);
    assert_eq!(a.truth, b.truth);
    let c = generate(&Config { seed: 2, ..small() });
    assert_ne!(a.etl, c.etl);
}

#[test]
fn processes_start_and_end_during_the_trace() {
    let s = generate(&small());
    let trace = import(&s);
    let last = s.truth.processes.last().unwrap();
    let started = trace.processes.iter().find(|p| p.pid == last.pid).unwrap();
    assert!(
        started.start.is_some(),
        "the last process starts in the trace"
    );
    let second = &s.truth.processes[1];
    let ended = trace
        .processes
        .iter()
        .find(|p| p.pid == second.pid)
        .unwrap();
    assert!(ended.end.is_some(), "the second process ends in the trace");
    // Nothing runs in a process before it starts or after it ends.
    for (i, &t) in trace.samples.thread.iter().enumerate() {
        let p = &trace.processes[trace.thread_process(t).index()];
        let at = trace.samples.time[i];
        assert!(p.start.is_none_or(|s| s <= at) && p.end.is_none_or(|e| at < e));
    }
}

#[test]
fn every_image_has_its_pdb_identity() {
    let s = generate(&small());
    let trace = import(&s);
    for img in &trace.images {
        let id = img.debug_id.as_ref().expect("a debug identity");
        assert!(id.pdb_path.ends_with(".pdb"));
    }
}

#[test]
fn function_lookup_finds_what_the_table_holds() {
    let s = generate(&small());
    let t = &s.truth;
    for f in &t.functions {
        for off in [0, u64::from(f.size) - 1] {
            assert_eq!(
                t.function_at(f.module, u64::from(f.rva) + off),
                Some(f),
                "{}",
                f.name
            );
        }
    }
    assert_eq!(t.function_at(0, 0), None, "before the first function");
}

#[test]
fn the_import_is_the_same_on_any_number_of_threads() {
    use hexcavator_trace::index;
    for config in [
        small(),
        Config {
            processors: 16,
            processes: 12,
            threads_per_process: 6,
            duration_ms: 200,
            sample_interval_us: 125,
            switch_per_mille: 400,
            ..Config::default()
        },
    ] {
        let s = generate(&config);
        let etl = Etl::parse(&s.etl).unwrap();
        let source = index::Source::of(&s.etl);
        let saved: Vec<Vec<u8>> = [1, 2, 8, 33]
            .into_iter()
            .map(|threads| {
                let (trace, _) = etw::import_with(&etl, threads).unwrap();
                index::write(&trace, source)
            })
            .collect();
        assert!(saved.windows(2).all(|w| w[0] == w[1]));
    }
}

#[test]
fn the_import_is_the_same_in_any_number_of_parts() {
    use hexcavator_trace::index;
    for config in [
        small(),
        Config {
            processors: 16,
            processes: 12,
            threads_per_process: 6,
            duration_ms: 300,
            sample_interval_us: 125,
            switch_per_mille: 400,
            ..Config::default()
        },
        Config {
            pointer_size: 4,
            compress: true,
            ..small()
        },
    ] {
        let s = generate(&config);
        let etl = Etl::parse(&s.etl).unwrap();
        let source = index::Source::of(&s.etl);
        let (one, stats) = etw::import_parts(&etl, 1, Some(1)).unwrap();
        let expected = index::write(&one, source);
        for parts in [2, 3, 7, 50, 1000] {
            let (trace, st) = etw::import_parts(&etl, 4, Some(parts)).unwrap();
            assert_eq!(st, stats, "{parts} parts");
            assert!(index::write(&trace, source) == expected, "{parts} parts");
        }
    }
}
