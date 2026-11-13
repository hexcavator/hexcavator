//! Importing synthetic ETL traces (built with `hexcavator_etl::write`).

use hexcavator_etl::write::{self, Classic, Kernel, Writer, WriterOptions};
use hexcavator_etl::{Etl, Guid, classic};
use hexcavator_etw::guids;
use hexcavator_trace::{ProcessIx, ReadyIx, ThreadIx, etw};

#[derive(Default)]
struct P(Vec<u8>);

impl P {
    fn u8(mut self, v: u8) -> Self {
        self.0.push(v);
        self
    }
    fn u16(mut self, v: u16) -> Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn u32(mut self, v: u32) -> Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn u64(mut self, v: u64) -> Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    fn bytes(mut self, v: &[u8]) -> Self {
        self.0.extend_from_slice(v);
        self
    }
    fn utf16z(mut self, s: &str) -> Self {
        for u in s.encode_utf16().chain([0]) {
            self.0.extend_from_slice(&u.to_le_bytes());
        }
        self
    }
    fn ansiz(mut self, s: &str) -> Self {
        self.0.extend_from_slice(s.as_bytes());
        self.0.push(0);
        self
    }
}

fn process(key: u64, pid: u32, name: &str) -> Vec<u8> {
    P::default()
        .u64(key)
        .u32(pid)
        .u32(4)
        .u32(1)
        .u32(0)
        .u64(0)
        .u32(0)
        .u32(0) // no SID
        .ansiz(name)
        .utf16z(&format!("{name} --flag"))
        .utf16z("")
        .utf16z("")
        .0
}

fn thread(pid: u32, tid: u32) -> Vec<u8> {
    let mut p = P::default().u32(pid).u32(tid);
    for v in [0u64, 0, 0, 0, 0, 0x1234, 0] {
        p = p.u64(v);
    }
    p.u32(0).u8(8).u8(5).u8(2).u8(0).0
}

fn image(pid: u32, base: u64, name: &str) -> Vec<u8> {
    P::default()
        .u64(base)
        .u64(0x1_0000)
        .u32(pid)
        .u32(0)
        .u32(0x5000)
        .u32(0)
        .u64(base)
        .bytes(&[0; 16])
        .utf16z(name)
        .0
}

fn sample(ip: u64, tid: u32) -> Vec<u8> {
    P::default().u64(ip).u32(tid).u16(1).u16(0).0
}

fn cswitch(new: u32, old: u32) -> Vec<u8> {
    P::default()
        .u32(new)
        .u32(old)
        .bytes(&[9, 8, 0, 0, 6, 1, 5, 0])
        .u32(0)
        .u32(0)
        .0
}

fn ready(tid: u32) -> Vec<u8> {
    P::default().u32(tid).u32(0).0
}

fn stack(ts: i64, tid: u32, frames: &[u64]) -> Vec<u8> {
    let mut p = P::default().u64(ts as u64).u32(0).u32(tid);
    for &f in frames {
        p = p.u64(f);
    }
    p.0
}

struct T(Writer);

impl T {
    fn new() -> Self {
        Self(Writer::new(WriterOptions {
            buffer_size: 0x10000,
            processors: 2,
            ..WriterOptions::default()
        }))
    }

    fn kernel(
        &mut self,
        cpu: u16,
        provider: Guid,
        op: u8,
        version: u16,
        ts: i64,
        payload: Vec<u8>,
    ) {
        let hook = classic::guid_group(&provider).unwrap() << 8 | u16::from(op);
        let k = Kernel {
            hook,
            version,
            thread_id: u32::MAX,
            process_id: u32::MAX,
            timestamp: ts,
            ..Kernel::default()
        };
        self.0.record(cpu, &write::system(&k, true, &payload));
    }

    fn control(&mut self, ts: i64, op: u8, payload: Vec<u8>) {
        let c = Classic {
            provider: guids::KERNEL_TRACE_CONTROL,
            opcode: op,
            version: 2,
            timestamp: ts,
            ..Classic::default()
        };
        self.0.record(0, &write::classic(&c, true, &payload));
    }
}

const K: u64 = 0xffff_f800_0000_1000;
const U: u64 = 0x7ff0_0000_1000;

#[test]
fn imports_a_trace() {
    let mut t = T::new();
    // Rundown: process 100 with thread 200 and app.exe, and a driver.
    t.kernel(0, guids::PROCESS, 3, 4, 1, process(0xaaaa, 100, "app.exe"));
    t.kernel(0, guids::THREAD, 3, 3, 2, thread(100, 200));
    t.kernel(
        0,
        guids::IMAGE,
        3,
        3,
        3,
        image(100, 0x7ff0_0000_0000, r"\Device\X\app.exe"),
    );
    t.kernel(
        0,
        guids::IMAGE,
        3,
        3,
        4,
        image(0, 0xffff_f800_0000_0000, r"\SystemRoot\drv.sys"),
    );
    // Thread 200 is switched in on cpu 0; its stack comes in two parts.
    t.kernel(0, guids::THREAD, 36, 2, 10, cswitch(200, 0));
    t.kernel(0, guids::STACK_WALK, 32, 2, 11, stack(10, 200, &[K, K + 1]));
    // Thread 200 readies thread 300, which we haven't seen yet.
    t.kernel(0, guids::THREAD, 50, 2, 20, ready(300));
    t.kernel(0, guids::STACK_WALK, 32, 2, 21, stack(20, 200, &[K + 2]));
    // A sample of thread 200, with a kernel and a user part.
    t.kernel(0, guids::PERF_INFO, 46, 2, 25, sample(U, 200));
    t.kernel(0, guids::STACK_WALK, 32, 2, 26, stack(25, 200, &[K + 3]));
    t.kernel(1, guids::STACK_WALK, 32, 2, 27, stack(25, 200, &[U, U + 1]));
    // The user part of the switch's stack, on cpu 1.
    t.kernel(1, guids::STACK_WALK, 32, 2, 28, stack(10, 200, &[U + 2]));
    // Thread 300 is switched in on cpu 1: it was readied at 20.
    t.kernel(1, guids::THREAD, 36, 2, 30, cswitch(300, 0));
    // Process 100 ends; a new process gets ID 100, and its thread ID 200.
    t.kernel(0, guids::PROCESS, 2, 4, 40, process(0xaaaa, 100, "app.exe"));
    t.kernel(
        0,
        guids::PROCESS,
        1,
        4,
        50,
        process(0xbbbb, 100, "other.exe"),
    );
    t.kernel(0, guids::THREAD, 1, 3, 51, thread(100, 200));
    t.kernel(0, guids::PERF_INFO, 46, 2, 52, sample(U, 200));
    // The merge's image identities, for app.exe.
    t.control(
        60,
        36,
        P::default()
            .u64(0x7ff0_0000_0000)
            .u32(100)
            .bytes(&[7; 16])
            .u32(2)
            .ansiz(r"c:\src\app.pdb")
            .0,
    );
    let data = t.0.finish();
    let etl = Etl::parse(&data).unwrap();
    let (trace, stats) = etw::import(&etl).unwrap();

    assert_eq!(stats.decode_errors, 0);
    assert_eq!(
        (
            stats.stacks,
            stats.stack_continuations,
            stats.stacks_unmatched
        ),
        (3, 2, 0)
    );

    // Processes: the first and the one that reused its ID.
    assert_eq!(trace.processes.len(), 2);
    let (a, b) = (&trace.processes[0], &trace.processes[1]);
    assert_eq!(
        (a.pid, a.name.as_str(), a.start, a.end),
        (100, "app.exe", None, Some(40))
    );
    assert_eq!(a.command_line, "app.exe --flag");
    assert_eq!(
        (b.pid, b.name.as_str(), b.start),
        (100, "other.exe", Some(50))
    );

    // Threads: 200, 0 (the idle thread), 300, and the second 200.
    let tid = |ix: ThreadIx| trace.threads[ix.index()].tid;
    let s = &trace.samples;
    assert_eq!(s.len(), 2);
    assert_eq!(tid(s.thread[0]), 200);
    assert_eq!(trace.thread_process(s.thread[0]), ProcessIx(0));
    assert_eq!(
        trace.thread_process(s.thread[1]),
        ProcessIx(1),
        "the reused thread ID"
    );

    // The sample's stack: kernel part, then the user part's callers.
    let frames: Vec<u64> = trace.stacks.frames(s.stack[0]).collect();
    assert_eq!(frames, [K + 3, U, U + 1]);
    assert!(s.stack[1].is_empty());

    // Switches: the first's stack joined across processors; the second
    // was readied by thread 200.
    let sw = &trace.switches;
    assert_eq!(sw.len(), 2);
    assert_eq!(
        trace.stacks.frames(sw.stack[0]).collect::<Vec<_>>(),
        [K, K + 1, U + 2]
    );
    assert_eq!(sw.ready[0], ReadyIx::NONE);
    let r = sw.ready[1];
    assert_eq!(r, ReadyIx(0));
    let rd = &trace.readies;
    assert_eq!(tid(rd.thread[0]), 300);
    assert_eq!(tid(rd.readier[0]), 200);
    assert_eq!(
        trace.stacks.frames(rd.stack[0]).collect::<Vec<_>>(),
        [K + 2]
    );
    assert_eq!(
        (sw.wait_reason[0], sw.old_state[0], sw.new_priority[0]),
        (6, 5, 9)
    );

    // Images: app.exe in process 100 with its PDB; the driver in the kernel.
    assert_eq!(trace.images.len(), 2);
    let app = &trace.images[0];
    assert_eq!(
        (app.process, app.file_name(), app.time_date_stamp),
        (ProcessIx(0), "app.exe", 0x5000)
    );
    let id = app.debug_id.as_ref().unwrap();
    assert_eq!(
        (id.guid, id.age, id.pdb_path.as_str()),
        ([7; 16], 2, r"c:\src\app.pdb")
    );
    assert!(app.contains(0x7ff0_0000_ffff) && !app.contains(0x7ff0_0001_0000));
    assert_eq!(trace.images[1].process, ProcessIx::NONE);

    // Times are relative to the first event (the header).
    assert_eq!(
        trace.clock.nanos(trace.clock.origin + 10_000_000),
        1_000_000_000
    );
}

#[test]
fn imports_hostile_traces_without_panicking() {
    // The fuzz seeds, cut at every length and corrupted at every byte.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../testdata/etl");
    for name in ["sample.etl", "sample-compressed.etl"] {
        let data = std::fs::read(dir.join(name)).unwrap();
        for len in 0..data.len() {
            if let Ok(etl) = Etl::parse(&data[..len]) {
                let _ = etw::import(&etl);
            }
        }
        let mut copy = data.clone();
        for i in 0..data.len() {
            copy[i] ^= 0x5a;
            if let Ok(etl) = Etl::parse(&copy) {
                let _ = etw::import(&etl);
            }
            copy[i] = data[i];
        }
    }
}

/// A trace with something in every table.
fn rich() -> Vec<u8> {
    let mut t = T::new();
    t.kernel(0, guids::PROCESS, 3, 4, 1, process(0xaaaa, 100, "app.exe"));
    t.kernel(0, guids::THREAD, 3, 3, 2, thread(100, 200));
    t.kernel(
        0,
        guids::IMAGE,
        3,
        3,
        3,
        image(100, 0x7ff0_0000_0000, r"\Device\X\app.exe"),
    );
    t.kernel(0, guids::THREAD, 36, 2, 10, cswitch(200, 0));
    t.kernel(0, guids::STACK_WALK, 32, 2, 11, stack(10, 200, &[K, K + 1]));
    t.kernel(0, guids::THREAD, 50, 2, 20, ready(300));
    t.kernel(0, guids::STACK_WALK, 32, 2, 21, stack(20, 200, &[K + 2]));
    t.kernel(0, guids::PERF_INFO, 46, 2, 25, sample(U, 200));
    t.kernel(0, guids::STACK_WALK, 32, 2, 26, stack(25, 200, &[K + 3]));
    t.kernel(1, guids::THREAD, 36, 2, 30, cswitch(300, 0));
    t.kernel(0, guids::PROCESS, 2, 4, 40, process(0xaaaa, 100, "app.exe"));
    t.control(
        60,
        36,
        P::default()
            .u64(0x7ff0_0000_0000)
            .u32(100)
            .bytes(&[7; 16])
            .u32(2)
            .ansiz("a.pdb")
            .0,
    );
    t.0.finish()
}

#[test]
fn index_round_trips() {
    use hexcavator_trace::index;
    let data = rich();
    let etl = Etl::parse(&data).unwrap();
    let (trace, _) = etw::import(&etl).unwrap();
    let source = index::Source::of(&data);
    let saved = index::write(&trace, source);
    let back = index::read(&saved, Some(source)).unwrap();
    assert_eq!(back.clock, trace.clock);
    assert_eq!(back.processors, trace.processors);
    assert_eq!(back.processes, trace.processes);
    assert_eq!(back.threads, trace.threads);
    assert_eq!(back.images, trace.images);
    assert_eq!(back.samples.time, trace.samples.time);
    assert_eq!(back.samples.stack, trace.samples.stack);
    assert_eq!(back.switches.stack, trace.switches.stack);
    assert_eq!(back.switches.ready, trace.switches.ready);
    assert_eq!(back.readies.readier, trace.readies.readier);
    assert_eq!(back.stacks.len(), trace.stacks.len());
    for s in &trace.samples.stack {
        assert_eq!(
            back.stacks.frames(*s).collect::<Vec<_>>(),
            trace.stacks.frames(*s).collect::<Vec<_>>()
        );
    }
    // Saving again gives the same bytes.
    assert_eq!(index::write(&back, source), saved);

    // An index of another trace is refused; so is no index at all.
    let other = index::Source { size: 1, hash: 2 };
    assert!(index::read(&saved, Some(other)).is_err());
    assert!(index::read(b"HXTRACE\0", None).is_err());
    assert!(index::read(&[], None).is_err());
}

#[test]
fn hostile_indexes_are_errors() {
    use hexcavator_trace::index;
    let data = rich();
    let etl = Etl::parse(&data).unwrap();
    let (trace, _) = etw::import(&etl).unwrap();
    let saved = index::write(&trace, index::Source::of(&data));
    for len in 0..saved.len() {
        assert!(
            index::read(&saved[..len], None).is_err(),
            "truncated to {len}"
        );
    }
    let mut copy = saved.clone();
    for i in 0..saved.len() {
        for v in [0x00, 0xff, 0x80, saved[i].wrapping_add(1)] {
            copy[i] = v;
            // Either a consistent trace or an error; never a panic. A trace
            // that reads must be safe to query.
            if let Ok(t) = index::read(&copy, None) {
                for s in t.samples.stack.iter().chain(&t.switches.stack) {
                    let _ = t.stacks.frames(*s).count();
                }
                for th in &t.samples.thread {
                    let _ = t.thread_process(*th);
                }
            }
        }
        copy[i] = saved[i];
    }
}

/// `testdata/etl/rich.hxtrace`, which seeds the fuzzer's index target, is
/// the index of `rich()`. `HEXC_BLESS=1` rewrites it.
#[test]
fn testdata_index_is_current() {
    use hexcavator_trace::index;
    let data = rich();
    let etl = Etl::parse(&data).unwrap();
    let (trace, _) = etw::import(&etl).unwrap();
    let saved = index::write(&trace, index::Source::of(&data));
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../testdata/etl/rich.hxtrace");
    if std::env::var_os("HEXC_BLESS").is_some() {
        std::fs::write(&path, &saved).unwrap();
    }
    let committed =
        std::fs::read(&path).expect("testdata/etl/rich.hxtrace (HEXC_BLESS=1 writes it)");
    assert!(
        committed == saved,
        "rich.hxtrace is stale; HEXC_BLESS=1 rewrites it"
    );
}
