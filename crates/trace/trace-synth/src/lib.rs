//! Synthetic ETW traces of any size, with the exact answers each analysis
//! should give.
//!
//! [`generate`] simulates a machine from a [`Config`] and a seed: processes
//! with threads, an executable and DLLs each, the shared system DLLs and the
//! kernel, and a call graph through all of them (a thread starts in
//! `ntdll!RtlUserThreadStart`, runs its executable's code, and calls down
//! through the DLLs into the kernel). Each processor runs one thread at a
//! time, switching between them; every sampling interval it logs a CPU
//! sample with its stack. Switches log a ready-thread event (with the
//! readying thread's stack) and a context switch (with the new thread's
//! wait stack). One process starts during the trace and one ends, and the
//! trace has the rundowns and image identities a WPR trace has.
//!
//! The result is an ETL file, as WPR would write it, and its [`Truth`]:
//! samples by process, thread and function (self and inclusive), switches
//! and readies, and the function table, so tests can check an import or a
//! query against exact numbers, and benchmarks can run on traces of any
//! size with nothing private in them.
//!
//! Each processor's events are generated on a thread of their own, from a
//! seed of their own, so a large trace is generated on every core, and the
//! same configuration always gives the same bytes.

use std::collections::BTreeSet;

use hexcavator_etl::Guid;
use hexcavator_etl::write::{Writer, WriterOptions};
use hexcavator_etw::encode::{Context, encode, record};
use hexcavator_etw::kernel::{
    ContextSwitch, DbgId, Frames, ImageEvent, ImageId, KernelEvent, Lifetime, ProcessEvent,
    ReadyThread, Sample, StackWalk, ThreadEvent, ThreadName, Utf16,
};

/// What to simulate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// The random seed: the same configuration always gives the same trace.
    pub seed: u64,
    /// Processors.
    pub processors: u16,
    /// The traced machine's pointer size: 4 or 8.
    pub pointer_size: u8,
    /// How long the trace runs, in milliseconds.
    pub duration_ms: u64,
    /// The CPU sampling interval, in microseconds (1000: 1 kHz).
    pub sample_interval_us: u64,
    /// Processes (besides Idle).
    pub processes: u32,
    /// Threads in each process.
    pub threads_per_process: u32,
    /// DLLs of its own in each process (besides the system's).
    pub dlls_per_process: u32,
    /// Functions in each module.
    pub functions_per_module: u32,
    /// The deepest call stack, in frames.
    pub max_depth: u32,
    /// The chance of a context switch before each sample, in thousandths.
    pub switch_per_mille: u32,
    /// The chance that a switch goes to the idle thread, in thousandths.
    pub idle_per_mille: u32,
    /// The trace's buffer size, in bytes.
    pub buffer_size: u32,
    /// Whether the buffers are compressed.
    pub compress: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            seed: 1,
            processors: 4,
            pointer_size: 8,
            duration_ms: 2000,
            sample_interval_us: 1000,
            processes: 6,
            threads_per_process: 4,
            dlls_per_process: 3,
            functions_per_module: 40,
            max_depth: 24,
            switch_per_mille: 150,
            idle_per_mille: 200,
            buffer_size: 0x10000,
            compress: false,
        }
    }
}

/// A function of the simulated machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Function {
    /// Its module's index in [`Truth::modules`].
    pub module: usize,
    /// Its name.
    pub name: String,
    /// Its offset in its module.
    pub rva: u32,
    /// Its size in bytes.
    pub size: u32,
}

/// A module (image) of the simulated machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Module {
    /// Its file name (`app.exe`).
    pub name: String,
    /// Its path, as the kernel logs it.
    pub path: String,
    /// Where it is loaded.
    pub base: u64,
    /// Its size in memory.
    pub size: u64,
    /// Its PDB's GUID and age, and the PDB's path.
    pub pdb: ([u8; 16], u32, String),
    /// The process it is loaded in (an index in [`Truth::processes`]), or
    /// `None` for the kernel's and the system DLLs (loaded everywhere).
    pub process: Option<usize>,
    /// Whether it is a kernel image.
    pub kernel: bool,
}

/// A process, and what was sampled in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessTruth {
    /// The process ID.
    pub pid: u32,
    /// The image name.
    pub name: String,
    /// Its CPU samples.
    pub samples: u64,
}

/// A thread, and what was sampled in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreadTruth {
    /// The thread ID.
    pub tid: u32,
    /// Its process ID.
    pub pid: u32,
    /// Its name, if it has one.
    pub name: Option<String>,
    /// Its CPU samples.
    pub samples: u64,
    /// How many times it was switched in.
    pub switch_ins: u64,
}

/// The exact answers for a generated trace.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Truth {
    /// The modules.
    pub modules: Vec<Module>,
    /// The functions.
    pub functions: Vec<Function>,
    /// The processes (not Idle), in the order of their process IDs.
    pub processes: Vec<ProcessTruth>,
    /// The threads (not the idle thread).
    pub threads: Vec<ThreadTruth>,
    /// CPU samples in all.
    pub samples: u64,
    /// CPU samples of the idle thread.
    pub idle_samples: u64,
    /// Each function's samples with it on the stack (an index of
    /// [`Truth::functions`]).
    pub inclusive: Vec<u64>,
    /// Each function's samples with it as the innermost frame.
    pub exclusive: Vec<u64>,
    /// Context switches.
    pub switches: u64,
    /// Ready-thread events.
    pub readies: u64,
    /// Stack events (one per sample, switch and ready).
    pub stacks: u64,
}

impl Truth {
    /// The function at `rva` in module `module` (an index of
    /// [`Truth::modules`]), as a symbolizer would find it.
    pub fn function_at(&self, module: usize, rva: u64) -> Option<&Function> {
        // Functions are in module order, by RVA within each.
        let i = self
            .functions
            .partition_point(|f| (f.module, u64::from(f.rva)) <= (module, rva));
        let f = self.functions.get(i.checked_sub(1)?)?;
        (f.module == module && rva < u64::from(f.rva) + u64::from(f.size)).then_some(f)
    }

    /// The module (an index of [`Truth::modules`]) named `name` that is
    /// loaded in process `pid` (or everywhere).
    pub fn module_named(&self, pid: u32, name: &str) -> Option<usize> {
        let process = self.processes.iter().position(|p| p.pid == pid);
        self.modules.iter().position(|m| {
            m.name.eq_ignore_ascii_case(name) && (m.process.is_none() || m.process == process)
        })
    }
}

/// A generated trace: the ETL file's bytes, and its answers.
#[derive(Clone, Debug)]
pub struct Synthetic {
    /// The ETL file.
    pub etl: Vec<u8>,
    /// What the trace holds.
    pub truth: Truth,
}

/// Generates a trace.
///
/// # Panics
///
/// If the configuration is out of range: no processors, a pointer size
/// other than 4 or 8, no processes or threads, or no time.
pub fn generate(config: &Config) -> Synthetic {
    assert!(config.processors > 0, "at least one processor");
    assert!(
        config.pointer_size == 4 || config.pointer_size == 8,
        "pointers are 4 or 8 bytes"
    );
    assert!(
        config.processes > 0 && config.threads_per_process > 0,
        "at least one thread"
    );
    assert!(
        config.duration_ms > 0 && config.sample_interval_us > 0,
        "some time to sample"
    );
    // (So that a process's modules never overlap: its DLLs are 1 MB apart,
    // below the system's, and the executables below them.)
    assert!(
        config.processes <= 2048 && config.dlls_per_process <= 64,
        "at most 2048 processes with 64 DLLs each"
    );
    assert!(config.functions_per_module <= 2000, "modules fit in 1 MB");
    let machine = Machine::new(config);
    let streams: Vec<(Stream, Partial)> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..config.processors)
            .map(|cpu| {
                let machine = &machine;
                s.spawn(move || machine.simulate(cpu))
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("the simulation doesn't panic"))
            .collect()
    });

    let mut writer = Writer::new(WriterOptions {
        buffer_size: config.buffer_size,
        pointer_size: u32::from(config.pointer_size),
        processors: u32::from(config.processors),
        compress: config.compress,
        ..WriterOptions::default()
    });
    let mut truth = machine.truth_skeleton();
    for (cpu, (stream, partial)) in streams.iter().enumerate() {
        let cpu = u16::try_from(cpu).expect("processors fit in u16");
        let mut pos = 0;
        for &len in &stream.lens {
            let end = pos + len as usize;
            writer.record(cpu, &stream.data[pos..end]);
            pos = end;
        }
        partial.add_to(&mut truth, &machine);
    }
    Synthetic {
        etl: writer.finish(),
        truth,
    }
}

/// A small, fast, seedable generator (SplitMix64).
#[derive(Clone, Debug)]
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A number in `0..n` (`n` > 0).
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    /// Whether an event with a chance of `per_mille` thousandths happens.
    fn chance(&mut self, per_mille: u32) -> bool {
        self.below(1000) < u64::from(per_mille)
    }

    /// An index in `0..n`.
    fn index(&mut self, n: usize) -> usize {
        usize::try_from(self.below(n as u64)).expect("an index fits in usize")
    }
}

const VERBS: &[&str] = &[
    "Parse", "Render", "Update", "Compute", "Load", "Save", "Draw", "Encode", "Decode", "Hash",
    "Sort", "Merge", "Flush", "Read", "Write", "Resolve", "Build", "Scan", "Map", "Visit", "Emit",
    "Lookup", "Insert", "Remove", "Validate", "Process", "Dispatch", "Schedule", "Compress",
    "Format",
];
const NOUNS: &[&str] = &[
    "Header", "Frame", "Buffer", "Token", "Node", "Tree", "Table", "Cache", "Index", "Block",
    "Record", "Page", "Image", "Texture", "Mesh", "Packet", "Stream", "Symbol", "Range", "Entry",
    "Batch", "Request", "Response", "Layout", "Glyph", "Path", "Query", "Row", "Column", "Chunk",
];
const CLASSES: &[&str] = &[
    "Engine",
    "Renderer",
    "Parser",
    "Scheduler",
    "Allocator",
    "Codec",
    "Session",
    "Document",
    "Window",
    "Socket",
    "Store",
    "Compiler",
    "Indexer",
    "Mixer",
    "World",
];
const DLLS: &[&str] = &[
    "render", "physics", "audio", "net", "storage", "script", "ui", "codec", "parser", "engine",
    "crypto", "search", "layout", "fonts", "media", "db",
];
const EXES: &[&str] = &[
    "app", "editor", "server", "worker", "indexer", "compiler", "browser", "game", "player",
    "builder",
];
const THREAD_NAMES: &[&str] = &["main", "render", "io", "worker", "timer", "net", "audio"];

/// How deep a module sits in the call graph: code calls only into its own
/// layer's later functions or into deeper layers.
const LAYER_EXE: u8 = 0;
const LAYER_APP: u8 = 1;
const LAYER_KERNEL32: u8 = 2;
const LAYER_KERNELBASE: u8 = 3;
const LAYER_NTDLL: u8 = 4;
const LAYER_KERNEL: u8 = 5;

/// The functions every machine has, by name, at the start of their
/// modules: (module, name).
const SPECIAL: &[(usize, &str)] = &[
    (NTOSKRNL, "KiIdleLoop"),
    (NTOSKRNL, "KeWaitForSingleObject"),
    (NTDLL, "RtlUserThreadStart"),
    (NTDLL, "NtWaitForSingleObject"),
    (KERNEL32, "BaseThreadInitThunk"),
    (KERNELBASE, "WaitForSingleObjectEx"),
];
// The shared modules' indexes, in the order they are made.
const NTOSKRNL: usize = 0;
const NTDLL: usize = 1;
const KERNELBASE: usize = 2;
const KERNEL32: usize = 3;
const SHARED: usize = 4;

/// The specials' function indexes, once made.
#[derive(Clone, Copy, Debug)]
struct Specials {
    idle: usize,
    kernel_wait: usize,
    thread_start: usize,
    nt_wait: usize,
    thread_thunk: usize,
    wait: usize,
}

const FUNCTION_SIZE: u32 = 0x200;
const FIRST_RVA: u32 = 0x1000;

#[derive(Clone, Debug)]
struct Func {
    callees: Vec<(usize, u64)>,
    self_weight: u64,
}

#[derive(Clone, Debug)]
struct Proc {
    pid: u32,
    name: String,
    /// When it starts (`None`: it was running when the trace started) and
    /// ends (`None`: still running when it stopped), in ticks.
    start: Option<i64>,
    end: Option<i64>,
    unique_key: u64,
    /// Its modules: the executable first.
    modules: Vec<usize>,
}

#[derive(Clone, Debug)]
struct Thr {
    tid: u32,
    process: usize,
    name: Option<String>,
    /// The functions it runs: its executable's entry points.
    roots: Vec<usize>,
}

/// The simulated machine: its modules, functions, processes and threads.
struct Machine {
    config: Config,
    modules: Vec<Module>,
    layers: Vec<u8>,
    functions: Vec<Function>,
    funcs: Vec<Func>,
    specials: Specials,
    processes: Vec<Proc>,
    threads: Vec<Thr>,
    /// The first tick of sampling, and the tick after the last.
    t0: i64,
    t1: i64,
    interval: i64,
    /// Rundown records: before `t0`, on processor 0.
    rundown_start: i64,
}

/// One processor's records: their bytes, end to end, and their lengths.
#[derive(Default)]
struct Stream {
    data: Vec<u8>,
    lens: Vec<u32>,
}

/// One processor's counts.
#[derive(Default)]
struct Partial {
    samples: u64,
    idle_samples: u64,
    thread_samples: Vec<u64>,
    thread_switch_ins: Vec<u64>,
    inclusive: Vec<u64>,
    exclusive: Vec<u64>,
    switches: u64,
    readies: u64,
    stacks: u64,
}

impl Partial {
    fn add_to(&self, truth: &mut Truth, machine: &Machine) {
        truth.samples += self.samples;
        truth.idle_samples += self.idle_samples;
        truth.switches += self.switches;
        truth.readies += self.readies;
        truth.stacks += self.stacks;
        for (i, n) in self.inclusive.iter().enumerate() {
            truth.inclusive[i] += n;
        }
        for (i, n) in self.exclusive.iter().enumerate() {
            truth.exclusive[i] += n;
        }
        for (i, t) in machine.threads.iter().enumerate() {
            truth.threads[i].samples += self.thread_samples[i];
            truth.threads[i].switch_ins += self.thread_switch_ins[i];
            truth.processes[t.process].samples += self.thread_samples[i];
        }
    }
}

/// Clock ticks per second: 100 ns ticks, as QPC usually runs.
const TICKS_PER_SECOND: i64 = 10_000_000;

impl Machine {
    #[allow(clippy::too_many_lines)]
    fn new(config: &Config) -> Self {
        let mut rng = Rng::new(config.seed);
        let bits64 = config.pointer_size == 8;
        let mut m = Self {
            config: config.clone(),
            modules: Vec::new(),
            layers: Vec::new(),
            functions: Vec::new(),
            funcs: Vec::new(),
            specials: Specials {
                idle: 0,
                kernel_wait: 0,
                thread_start: 0,
                nt_wait: 0,
                thread_thunk: 0,
                wait: 0,
            },
            processes: Vec::new(),
            threads: Vec::new(),
            t0: 0,
            t1: 0,
            interval: 0,
            rundown_start: 0,
        };

        // The shared modules: the kernel and the system DLLs.
        let (kernel_base, shared_base) = if bits64 {
            (0xffff_f800_0000_0000_u64, 0x7ffc_0000_0000_u64)
        } else {
            (0x8040_0000, 0x7700_0000)
        };
        let shared: [(&str, &str, u8, bool, u64); SHARED] = [
            (
                "ntoskrnl.exe",
                r"\SystemRoot\system32\ntoskrnl.exe",
                LAYER_KERNEL,
                true,
                kernel_base,
            ),
            (
                "ntdll.dll",
                r"\Device\HarddiskVolume3\Windows\System32\ntdll.dll",
                LAYER_NTDLL,
                false,
                shared_base,
            ),
            (
                "KernelBase.dll",
                r"\Device\HarddiskVolume3\Windows\System32\KernelBase.dll",
                LAYER_KERNELBASE,
                false,
                shared_base + 0x100_0000,
            ),
            (
                "kernel32.dll",
                r"\Device\HarddiskVolume3\Windows\System32\kernel32.dll",
                LAYER_KERNEL32,
                false,
                shared_base + 0x200_0000,
            ),
        ];
        for (name, path, layer, kernel, base) in shared {
            m.add_module(&mut rng, name, path, base, None, kernel, layer);
        }

        // The processes: an executable and DLLs of their own each.
        let (exe_base, dll_base) = if bits64 {
            (0x7ff6_0000_0000_u64, 0x7ffa_0000_0000_u64)
        } else {
            (0x0040_0000, 0x1000_0000)
        };
        let mut used_exe = BTreeSet::new();
        for p in 0..config.processes as usize {
            let stem = unique(&mut used_exe, EXES[p % EXES.len()]);
            let name = format!("{stem}.exe");
            let pid = 1000 + 4 * u32::try_from(p).expect("processes fit in u32") * 17;
            m.processes.push(Proc {
                pid,
                name: name.clone(),
                start: None,
                end: None,
                unique_key: if bits64 {
                    0xffff_c000_1000_0000 + 0x1000 * p as u64
                } else {
                    0x8800_0000 + 0x1000 * p as u64
                },
                modules: Vec::new(),
            });
            let exe = m.add_module(
                &mut rng,
                &name,
                &format!(r"\Device\HarddiskVolume3\Program Files\{stem}\{name}"),
                // (32-bit executables load at the same base in every
                // process; 64-bit ones apart.)
                if bits64 {
                    exe_base + 0x10_0000 * p as u64
                } else {
                    exe_base
                },
                Some(p),
                false,
                LAYER_EXE,
            );
            m.processes[p].modules.push(exe);
            let mut used_dll = BTreeSet::new();
            for d in 0..config.dlls_per_process as usize {
                let dll_stem = unique(&mut used_dll, DLLS[(p * 3 + d) % DLLS.len()]);
                let dll = format!("{dll_stem}.dll");
                let i = m.add_module(
                    &mut rng,
                    &dll,
                    &format!(r"\Device\HarddiskVolume3\Program Files\{stem}\{dll}"),
                    dll_base + 0x10_0000 * d as u64,
                    Some(p),
                    false,
                    LAYER_APP,
                );
                m.processes[p].modules.push(i);
            }
        }

        m.make_call_graph(&mut rng);

        // Time: rundown, then sampling.
        m.interval = i64::try_from(config.sample_interval_us).expect("an interval") * 10;
        m.rundown_start = 1;
        m.t0 = TICKS_PER_SECOND / 1000; // 1 ms in.
        m.t1 = m.t0 + i64::try_from(config.duration_ms).expect("a duration") * 10_000;
        // With three or more processes, the last starts a third of the way
        // in and the second ends two thirds of the way in.
        let span = m.t1 - m.t0;
        if m.processes.len() >= 3 {
            let last = m.processes.len() - 1;
            m.processes[last].start = Some(m.align(m.t0 + span / 3));
            m.processes[1].end = Some(m.align(m.t0 + 2 * span / 3));
        }

        // Threads, each with one to three entry points in its executable.
        for p in 0..m.processes.len() {
            for t in 0..config.threads_per_process as usize {
                let exe = m.processes[p].modules[0];
                let candidates: Vec<usize> = (0..m.functions.len())
                    .filter(|&f| m.functions[f].module == exe)
                    .collect();
                let roots = (0..1 + rng.index(3))
                    .map(|_| candidates[rng.index(candidates.len())])
                    .collect();
                let index = m.threads.len();
                m.threads.push(Thr {
                    tid: 2000 + 4 * u32::try_from(index).expect("threads fit in u32") * 3,
                    process: p,
                    name: THREAD_NAMES
                        .get(t)
                        .filter(|_| rng.chance(700))
                        .map(|n| (*n).to_string()),
                    roots,
                });
            }
        }
        m
    }

    /// `t` moved back to just before a sample tick, so that lifetime events
    /// fall between samples.
    fn align(&self, t: i64) -> i64 {
        self.t0 + (t - self.t0) / self.interval * self.interval - self.interval / 2
    }

    #[allow(clippy::too_many_arguments)]
    fn add_module(
        &mut self,
        rng: &mut Rng,
        name: &str,
        path: &str,
        base: u64,
        process: Option<usize>,
        kernel: bool,
        layer: u8,
    ) -> usize {
        let index = self.modules.len();
        let n = self.config.functions_per_module.max(8);
        let mut guid = [0u8; 16];
        for chunk in guid.as_chunks_mut::<8>().0 {
            *chunk = rng.next().to_le_bytes();
        }
        let stem = name.rsplit_once('.').map_or(name, |(s, _)| s);
        self.modules.push(Module {
            name: name.to_string(),
            path: path.to_string(),
            base,
            size: u64::from(FIRST_RVA + n * FUNCTION_SIZE),
            pdb: (guid, 1, format!(r"c:\build\{stem}\{stem}.pdb")),
            process,
            kernel,
        });
        self.layers.push(layer);
        // The specials of this module, then named functions.
        let mut used = BTreeSet::new();
        let mut i = 0u32;
        for &(_, special) in SPECIAL.iter().filter(|(mi, _)| *mi == index) {
            used.insert(special.to_string());
            self.push_function(index, special.to_string(), i);
            i += 1;
        }
        let class = CLASSES[rng.index(CLASSES.len())];
        while i < n {
            let base_name = format!(
                "{class}::{}{}",
                VERBS[rng.index(VERBS.len())],
                NOUNS[rng.index(NOUNS.len())]
            );
            let name = unique(&mut used, &base_name);
            self.push_function(index, name, i);
            i += 1;
        }
        index
    }

    fn push_function(&mut self, module: usize, name: String, i: u32) {
        self.functions.push(Function {
            module,
            name,
            rva: FIRST_RVA + i * FUNCTION_SIZE,
            size: FUNCTION_SIZE,
        });
        self.funcs.push(Func {
            callees: Vec::new(),
            self_weight: 1,
        });
    }

    fn find_special(&self, module: usize, name: &str) -> usize {
        self.functions
            .iter()
            .position(|f| f.module == module && f.name == name)
            .expect("the special function exists")
    }

    fn make_call_graph(&mut self, rng: &mut Rng) {
        self.specials = Specials {
            idle: self.find_special(NTOSKRNL, "KiIdleLoop"),
            kernel_wait: self.find_special(NTOSKRNL, "KeWaitForSingleObject"),
            thread_start: self.find_special(NTDLL, "RtlUserThreadStart"),
            nt_wait: self.find_special(NTDLL, "NtWaitForSingleObject"),
            thread_thunk: self.find_special(KERNEL32, "BaseThreadInitThunk"),
            wait: self.find_special(KERNELBASE, "WaitForSingleObjectEx"),
        };
        let special: BTreeSet<usize> = [
            self.specials.idle,
            self.specials.kernel_wait,
            self.specials.thread_start,
            self.specials.nt_wait,
            self.specials.thread_thunk,
            self.specials.wait,
        ]
        .into();
        // Which modules each module's code may call: its own, and deeper
        // layers in the same process (or shared).
        for f in 0..self.functions.len() {
            if special.contains(&f) {
                continue;
            }
            let module = self.functions[f].module;
            let layer = self.layers[module];
            let process = self.modules[module].process;
            let candidates: Vec<usize> = (0..self.functions.len())
                .filter(|&g| {
                    if special.contains(&g) {
                        return false;
                    }
                    let gm = self.functions[g].module;
                    if gm == module {
                        return g > f;
                    }
                    let gl = self.layers[gm];
                    let reachable =
                        self.modules[gm].process.is_none() || self.modules[gm].process == process;
                    // User code reaches the kernel only through ntdll.
                    let kernel_ok = gl != LAYER_KERNEL || layer >= LAYER_NTDLL;
                    reachable && gl > layer && kernel_ok
                })
                .collect();
            if candidates.is_empty() {
                self.funcs[f].self_weight = 1;
                continue;
            }
            let count = rng.index(4).min(candidates.len());
            let mut callees: Vec<(usize, u64)> = Vec::new();
            for rank in 0..count {
                let g = candidates[rng.index(candidates.len())];
                if callees.iter().all(|&(c, _)| c != g) {
                    // Skewed: the first callee is the hot one.
                    callees.push((g, 24 / (rank as u64 + 1)));
                }
            }
            self.funcs[f].callees = callees;
            self.funcs[f].self_weight = 1 + rng.below(8);
        }
    }

    /// An empty truth with the machine's tables.
    fn truth_skeleton(&self) -> Truth {
        Truth {
            modules: self.modules.clone(),
            functions: self.functions.clone(),
            processes: self
                .processes
                .iter()
                .map(|p| ProcessTruth {
                    pid: p.pid,
                    name: p.name.clone(),
                    samples: 0,
                })
                .collect(),
            threads: self
                .threads
                .iter()
                .map(|t| ThreadTruth {
                    tid: t.tid,
                    pid: self.processes[t.process].pid,
                    name: t.name.clone(),
                    samples: 0,
                    switch_ins: 0,
                })
                .collect(),
            inclusive: vec![0; self.functions.len()],
            exclusive: vec![0; self.functions.len()],
            ..Truth::default()
        }
    }

    fn alive(&self, thread: usize, t: i64) -> bool {
        let p = &self.processes[self.threads[thread].process];
        p.start.is_none_or(|s| s <= t) && p.end.is_none_or(|e| t < e)
    }

    /// The address of function `f` plus `offset`.
    fn address(&self, f: usize, offset: u64) -> u64 {
        let func = &self.functions[f];
        self.modules[func.module].base + u64::from(func.rva) + offset
    }

    /// A call path for a sample of `thread`: from the thread's start down
    /// to the function it is in, outermost first.
    fn walk(&self, rng: &mut Rng, thread: usize, path: &mut Vec<usize>) {
        path.clear();
        let thr = &self.threads[thread];
        path.push(self.specials.thread_start);
        path.push(self.specials.thread_thunk);
        let mut f = thr.roots[rng.index(thr.roots.len())];
        path.push(f);
        while path.len() < self.config.max_depth as usize {
            let func = &self.funcs[f];
            let total = func.self_weight + func.callees.iter().map(|c| c.1).sum::<u64>();
            let mut pick = rng.below(total);
            if pick < func.self_weight {
                break;
            }
            pick -= func.self_weight;
            let mut next = None;
            for &(g, w) in &func.callees {
                if pick < w {
                    next = Some(g);
                    break;
                }
                pick -= w;
            }
            let Some(g) = next else { break };
            path.push(g);
            f = g;
        }
    }

    /// A thread's stack while it waits: its start, an entry point, then
    /// the wait down into the kernel.
    fn wait_path(&self, rng: &mut Rng, thread: usize, path: &mut Vec<usize>) {
        let thr = &self.threads[thread];
        path.clear();
        path.extend([
            self.specials.thread_start,
            self.specials.thread_thunk,
            thr.roots[rng.index(thr.roots.len())],
            self.specials.wait,
            self.specials.nt_wait,
            self.specials.kernel_wait,
        ]);
    }

    /// The frames of `path` (outermost first), innermost first: the
    /// innermost an instruction in its function, the others return
    /// addresses in their functions.
    fn frames(&self, rng: &mut Rng, path: &[usize], out: &mut Vec<u64>) {
        out.clear();
        for (i, &f) in path.iter().enumerate().rev() {
            let offset = if i + 1 == path.len() {
                rng.below(u64::from(FUNCTION_SIZE))
            } else {
                // The return address of its call to the next frame: a call
                // site of its own for each callee.
                let callee = path[i + 1];
                0x10 + (callee as u64 * 0x18) % u64::from(FUNCTION_SIZE - 0x20)
            };
            out.push(self.address(f, offset));
        }
    }

    /// The events of processor `cpu`, and its counts.
    #[allow(clippy::too_many_lines)]
    fn simulate(&self, cpu: u16) -> (Stream, Partial) {
        let mut rng = Rng::new(
            self.config
                .seed
                .wrapping_mul(0x2545_f491_4f6c_dd1d)
                .wrapping_add(u64::from(cpu) + 1),
        );
        let mut out = Emitter {
            stream: Stream::default(),
            ptr: usize::from(self.config.pointer_size),
        };
        let mut part = Partial {
            thread_samples: vec![0; self.threads.len()],
            thread_switch_ins: vec![0; self.threads.len()],
            inclusive: vec![0; self.functions.len()],
            exclusive: vec![0; self.functions.len()],
            ..Partial::default()
        };
        // This processor's threads.
        let mine: Vec<usize> = (0..self.threads.len())
            .filter(|&t| t % usize::from(self.config.processors) == usize::from(cpu))
            .collect();

        // Processor 0 logs the rundown, and the lifetimes during the trace.
        let mut lifetimes: Vec<(i64, usize, bool)> = Vec::new();
        if cpu == 0 {
            let mut t = self.rundown_start;
            self.rundown(&mut out, &mut t, Lifetime::RundownStart);
            for (i, p) in self.processes.iter().enumerate() {
                if let Some(s) = p.start {
                    lifetimes.push((s, i, true));
                }
                if let Some(e) = p.end {
                    lifetimes.push((e, i, false));
                }
            }
            lifetimes.sort_unstable();
        }
        let mut lifetimes = lifetimes.into_iter().peekable();

        let mut current: Option<usize> = None; // None: the idle thread.
        let mut path = Vec::new();
        let mut frames = Vec::new();
        // Processors don't take their timer interrupts in lockstep: each
        // samples at a phase of its own.
        let mut t = self.t0 + (i64::from(cpu) * 37) % (self.interval / 4).max(1);
        while t < self.t1 {
            while let Some(&(at, p, start)) = lifetimes.peek() {
                if at > t {
                    break;
                }
                self.lifetime(&mut out, at, p, start);
                lifetimes.next();
            }
            // A switch: by chance, or because the thread's process ended.
            let must = current.is_some_and(|c| !self.alive(c, t));
            if must || rng.chance(self.config.switch_per_mille) {
                let alive: Vec<usize> =
                    mine.iter().copied().filter(|&c| self.alive(c, t)).collect();
                let next = if alive.is_empty() || rng.chance(self.config.idle_per_mille) {
                    None
                } else {
                    Some(alive[rng.index(alive.len())])
                };
                if next != current {
                    self.switch(
                        &mut out,
                        &mut rng,
                        &mut part,
                        t,
                        current,
                        next,
                        &mut path,
                        &mut frames,
                    );
                    current = next;
                }
            }
            // The sample.
            part.samples += 1;
            part.stacks += 1;
            let (tid, pid) = match current {
                None => {
                    part.idle_samples += 1;
                    path.clear();
                    path.push(self.specials.idle);
                    (0, 0)
                }
                Some(c) => {
                    part.thread_samples[c] += 1;
                    self.walk(&mut rng, c, &mut path);
                    let mut seen = BTreeSet::new();
                    for &f in &path {
                        if seen.insert(f) {
                            part.inclusive[f] += 1;
                        }
                    }
                    part.exclusive[*path.last().expect("a frame")] += 1;
                    (
                        self.threads[c].tid,
                        self.processes[self.threads[c].process].pid,
                    )
                }
            };
            self.frames(&mut rng, &path, &mut frames);
            let at = Context {
                timestamp: t,
                thread_id: tid,
                process_id: pid,
            };
            out.emit(
                &KernelEvent::Sample(Sample {
                    instruction_pointer: frames[0],
                    thread_id: tid,
                    count: 1,
                }),
                at,
            );
            out.stack(t, pid, tid, &frames, at);
            t += self.interval;
        }
        for (at, p, start) in lifetimes {
            self.lifetime(&mut out, at, p, start);
        }
        if cpu == 0 {
            let mut t = self.t1 + 1;
            self.rundown(&mut out, &mut t, Lifetime::RundownEnd);
        }
        (out.stream, part)
    }

    /// A switch from `old` to `new` (`None`: the idle thread) just before
    /// the sample at `t`: the new thread is readied by the old one, then
    /// switched in, each with its stack.
    #[allow(clippy::too_many_arguments)]
    fn switch(
        &self,
        out: &mut Emitter,
        rng: &mut Rng,
        part: &mut Partial,
        t: i64,
        old: Option<usize>,
        new: Option<usize>,
        path: &mut Vec<usize>,
        frames: &mut Vec<u64>,
    ) {
        let ids = |thread: Option<usize>| {
            thread.map_or((0, 0), |c| {
                (
                    self.threads[c].tid,
                    self.processes[self.threads[c].process].pid,
                )
            })
        };
        let (old_tid, old_pid) = ids(old);
        let (new_tid, new_pid) = ids(new);
        if let Some(n) = new {
            // The old thread readies the new one (from its own code, or
            // from the idle loop).
            let ready_at = t - 3;
            // (Like the kernel's, the header names no thread: the stack
            // says who readied.)
            let at = Context {
                timestamp: ready_at,
                thread_id: u32::MAX,
                process_id: u32::MAX,
            };
            out.emit(
                &KernelEvent::ReadyThread(ReadyThread {
                    thread_id: self.threads[n].tid,
                    adjust_reason: 1,
                    adjust_increment: 1,
                    flag: 0,
                }),
                at,
            );
            match old {
                Some(o) => self.walk(rng, o, path),
                None => {
                    path.clear();
                    path.push(self.specials.idle);
                }
            }
            self.frames(rng, path, frames);
            out.stack(ready_at, old_pid, old_tid, frames, at);
            part.readies += 1;
            part.stacks += 1;
            part.thread_switch_ins[n] += 1;
        }
        let switch_at = t - 2;
        let at = Context {
            timestamp: switch_at,
            thread_id: u32::MAX,
            process_id: u32::MAX,
        };
        out.emit(
            &KernelEvent::ContextSwitch(ContextSwitch {
                new_thread_id: new_tid,
                old_thread_id: old_tid,
                new_thread_priority: if new.is_some() { 8 } else { 0 },
                old_thread_priority: if old.is_some() { 8 } else { 0 },
                previous_c_state: u8::from(old.is_none()),
                old_thread_wait_reason: 6, // UserRequest
                old_thread_wait_mode: 1,
                old_thread_state: 5, // Waiting
                old_thread_wait_ideal_processor: 0,
                new_thread_wait_time: u32::try_from(rng.below(5000)).expect("small"),
            }),
            at,
        );
        // The new thread's stack: where it waited.
        match new {
            Some(n) => self.wait_path(rng, n, path),
            None => {
                path.clear();
                path.push(self.specials.idle);
            }
        }
        self.frames(rng, path, frames);
        out.stack(switch_at, new_pid, new_tid, frames, at);
        part.switches += 1;
        part.stacks += 1;
    }

    /// The rundown of every process, thread and image alive at `t`, from
    /// tick `*t` on (one tick each).
    fn rundown(&self, out: &mut Emitter, t: &mut i64, lifetime: Lifetime) {
        let at_start = lifetime == Lifetime::RundownStart;
        let sample_at = if at_start { self.t0 } else { self.t1 };
        // The Idle process (whose threads, one per processor, all have ID
        // 0) and the System process.
        for (pid, name) in [(0u32, "Idle"), (4, "System")] {
            let empty: &[u8] = &[];
            out.emit(
                &KernelEvent::Process(ProcessEvent {
                    lifetime,
                    unique_key: if self.config.pointer_size == 8 {
                        0xffff_c000_0000_0000 + u64::from(pid)
                    } else {
                        0x8000_0000 + u64::from(pid)
                    },
                    process_id: pid,
                    parent_id: 0,
                    session_id: u32::MAX,
                    exit_status: 259,
                    directory_table_base: 0x1000,
                    flags: 0,
                    user_sid: empty,
                    image_file_name: name.as_bytes(),
                    command_line: Utf16(empty),
                    package_full_name: Utf16(empty),
                    application_id: Utf16(empty),
                    exit_time: None,
                }),
                Context {
                    timestamp: *t,
                    thread_id: u32::MAX,
                    process_id: u32::MAX,
                },
            );
            *t += 1;
        }
        // The kernel's images (in no process: process ID 0).
        let kernel: Vec<usize> = (0..self.modules.len())
            .filter(|&i| self.modules[i].kernel)
            .collect();
        for &i in &kernel {
            self.image(out, *t, i, 0, lifetime);
            *t += 1;
        }
        for (p, proc_) in self.processes.iter().enumerate() {
            let alive = proc_.start.is_none_or(|s| s <= sample_at)
                && proc_.end.is_none_or(|e| sample_at < e);
            if !alive {
                continue;
            }
            self.process_events(out, t, p, lifetime);
        }
    }

    /// A process's events: the process, its threads, then its images.
    fn process_events(&self, out: &mut Emitter, t: &mut i64, p: usize, lifetime: Lifetime) {
        let proc_ = &self.processes[p];
        let cmd = utf16(&format!("\"{}\" --synthetic", proc_.name));
        let at = Context {
            timestamp: *t,
            thread_id: u32::MAX,
            process_id: u32::MAX,
        };
        out.emit(
            &KernelEvent::Process(ProcessEvent {
                lifetime,
                unique_key: proc_.unique_key,
                process_id: proc_.pid,
                parent_id: 4,
                session_id: 1,
                exit_status: if lifetime == Lifetime::End { 0 } else { 259 },
                directory_table_base: 0x1000,
                flags: 0,
                user_sid: &[],
                image_file_name: proc_.name.as_bytes(),
                command_line: Utf16(&cmd),
                package_full_name: Utf16(&[]),
                application_id: Utf16(&[]),
                exit_time: None,
            }),
            at,
        );
        *t += 1;
        for thr in self.threads.iter().filter(|th| th.process == p) {
            let at = Context {
                timestamp: *t,
                ..at
            };
            out.emit(
                &KernelEvent::Thread(ThreadEvent {
                    lifetime,
                    process_id: proc_.pid,
                    thread_id: thr.tid,
                    stack_base: 0,
                    stack_limit: 0,
                    user_stack_base: 0,
                    user_stack_limit: 0,
                    win32_start_address: self.address(thr.roots[0], 0),
                    teb: 0,
                    sub_process_tag: 0,
                    base_priority: 8,
                }),
                at,
            );
            *t += 1;
            if let Some(name) = &thr.name
                && lifetime != Lifetime::End
                && lifetime != Lifetime::RundownEnd
            {
                let units = utf16(name);
                out.emit(
                    &KernelEvent::ThreadName(ThreadName {
                        process_id: proc_.pid,
                        thread_id: thr.tid,
                        name: Utf16(&units),
                    }),
                    Context {
                        timestamp: *t,
                        ..at
                    },
                );
                *t += 1;
            }
        }
        let shared = (0..SHARED).filter(|&i| !self.modules[i].kernel);
        for i in proc_.modules.iter().copied().chain(shared) {
            self.image(out, *t, i, proc_.pid, lifetime);
            *t += 1;
        }
    }

    /// An image event, and (when it starts or is in the start rundown) its
    /// identity and PDB, as a merge adds them.
    fn image(&self, out: &mut Emitter, t: i64, i: usize, pid: u32, lifetime: Lifetime) {
        let m = &self.modules[i];
        let path = utf16(&m.path);
        let at = Context {
            timestamp: t,
            thread_id: u32::MAX,
            process_id: u32::MAX,
        };
        out.emit(
            &KernelEvent::Image(ImageEvent {
                lifetime,
                base: m.base,
                size: m.size,
                process_id: pid,
                checksum: 0,
                time_date_stamp: 0x6000_0000,
                default_base: m.base,
                file_name: Utf16(&path),
            }),
            at,
        );
        if matches!(lifetime, Lifetime::Start | Lifetime::RundownStart) {
            let name = utf16(&m.name);
            out.emit(
                &KernelEvent::ImageId(ImageId {
                    base: m.base,
                    size: m.size,
                    process_id: pid,
                    time_date_stamp: 0x6000_0000,
                    original_file_name: Utf16(&name),
                }),
                at,
            );
            out.emit(
                &KernelEvent::DbgId(DbgId {
                    base: m.base,
                    process_id: pid,
                    guid: Guid::from_bytes(&m.pdb.0),
                    age: m.pdb.1,
                    pdb_file_name: m.pdb.2.as_bytes(),
                    il: false,
                }),
                at,
            );
        }
    }

    /// A process starting or ending during the trace.
    fn lifetime(&self, out: &mut Emitter, at: i64, p: usize, start: bool) {
        let mut t = at;
        if start {
            self.process_events(out, &mut t, p, Lifetime::Start);
        } else {
            self.process_events(out, &mut t, p, Lifetime::End);
        }
    }
}

/// Encodes events into a processor's stream.
struct Emitter {
    stream: Stream,
    ptr: usize,
}

impl Emitter {
    fn emit(&mut self, event: &KernelEvent<'_>, at: Context) {
        let enc = encode(event, self.ptr).expect("the simulation logs only real events");
        let rec = record(&enc, at, self.ptr == 8);
        self.stream
            .lens
            .push(u32::try_from(rec.len()).expect("a record fits in 64 KB"));
        self.stream.data.extend_from_slice(&rec);
    }

    fn stack(&mut self, event_timestamp: i64, pid: u32, tid: u32, frames: &[u64], at: Context) {
        let mut bytes = Vec::with_capacity(frames.len() * self.ptr);
        for &f in frames {
            if self.ptr == 8 {
                bytes.extend_from_slice(&f.to_le_bytes());
            } else {
                bytes.extend_from_slice(
                    &u32::try_from(f)
                        .expect("32-bit addresses on a 32-bit trace")
                        .to_le_bytes(),
                );
            }
        }
        self.emit(
            &KernelEvent::Stack(StackWalk {
                event_timestamp,
                process_id: pid,
                thread_id: tid,
                frames: Frames::new(&bytes, self.ptr),
            }),
            Context {
                timestamp: event_timestamp + 1,
                ..at
            },
        );
    }
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// `base`, or `base` with a number after it if it is taken; records it.
fn unique(used: &mut BTreeSet<String>, base: &str) -> String {
    let mut name = base.to_string();
    let mut n = 2;
    while !used.insert(name.clone()) {
        name = format!("{base}{n}");
        n += 1;
    }
    name
}
