//! Building a [`Trace`] from a Windows ETL file.

use rustc_hash::FxHashMap;

use hexcavator_core::Result;
use hexcavator_etl::{Etl, Event};
use hexcavator_etw::kernel::{KernelEvent, Lifetime, decode};
use hexcavator_etw::stacks::StackMatcher;

use crate::model::{
    Clock, DebugId, Image, ImageIx, Process, ProcessIx, ReadyIx, Thread, ThreadIx, Trace,
};
use crate::stacks::{PathCache, StackId};

/// What an import did, in counts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImportStats {
    /// Events read.
    pub events: u64,
    /// Events or buffers the reader reported as malformed.
    pub read_errors: u64,
    /// Kernel events whose payloads were malformed.
    pub decode_errors: u64,
    /// Stacks paired with an event we keep.
    pub stacks: u64,
    /// Second (user-mode) parts of split stacks joined to their first.
    pub stack_continuations: u64,
    /// Stacks whose event we didn't keep or couldn't find.
    pub stacks_unmatched: u64,
}

// Tags in the stack matcher's IDs: which table the row is in.
const SAMPLE: u64 = 1 << 56;
const SWITCH: u64 = 2 << 56;
const READY: u64 = 3 << 56;
const ROW: u64 = (1 << 56) - 1;

/// Reads `etl` into a [`Trace`].
pub fn import(etl: &Etl<'_>) -> Result<(Trace, ImportStats)> {
    let header = etl.header();
    let ticks = header.ticks_per_second().unwrap_or(10_000_000);
    let mut builder = Builder {
        trace: Trace::new(
            Clock {
                ticks_per_second: ticks,
                origin: 0,
            },
            header.number_of_processors,
        ),
        stats: ImportStats::default(),
        live_processes: FxHashMap::default(),
        live_threads: FxHashMap::default(),
        live_images: FxHashMap::default(),
        running: Vec::new(),
        last_ready: FxHashMap::default(),
        // Wait up to five seconds for the user part of a split stack.
        matcher: StackMatcher::new(i64::try_from(ticks.saturating_mul(5)).unwrap_or(i64::MAX)),
        caches: FxHashMap::default(),
        scratch: Vec::new(),
        scratch2: Vec::new(),
    };
    let mut cursor = etl.events()?;
    let mut first = true;
    while let Some(event) = cursor.next() {
        let Ok(event) = event else {
            builder.stats.read_errors += 1;
            continue;
        };
        builder.stats.events += 1;
        if first {
            builder.trace.clock.origin = event.timestamp;
            first = false;
        }
        builder.event(&event);
    }
    Ok((builder.trace, builder.stats))
}

struct Builder {
    trace: Trace,
    stats: ImportStats,
    live_processes: FxHashMap<u32, ProcessIx>,
    live_threads: FxHashMap<u32, ThreadIx>,
    live_images: FxHashMap<(u32, u64), ImageIx>,
    /// The thread running on each processor.
    running: Vec<ThreadIx>,
    /// Each thread's latest ready event not yet followed by its switch-in.
    last_ready: FxHashMap<ThreadIx, ReadyIx>,
    matcher: StackMatcher,
    /// Each thread's recent stack paths: first parts, and whole stacks.
    caches: FxHashMap<u32, (PathCache, PathCache)>,
    scratch: Vec<u64>,
    scratch2: Vec<u64>,
}

fn row(n: usize) -> u32 {
    u32::try_from(n).expect("fewer than 4G rows")
}

impl Builder {
    fn event(&mut self, e: &Event<'_>) {
        // The sampling interval: PerfInfo's CollectionStart for the profile
        // source (0), in 100 ns units.
        if e.provider == hexcavator_etw::guids::PERF_INFO && e.descriptor.opcode == 73 {
            if let Some(Ok(p)) = hexcavator_etw::Properties::of(e) {
                let field = |n: &str| {
                    p.get(n)
                        .and_then(|f| f.data.get(..4))
                        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                };
                if field("Source") == Some(0)
                    && let Some(interval) = field("NewInterval")
                {
                    self.trace.sample_interval = Some(u64::from(interval) * 100);
                }
            }
            return;
        }
        let decoded = match decode(e) {
            None => return,
            Some(Ok(d)) => d,
            Some(Err(_)) => {
                self.stats.decode_errors += 1;
                return;
            }
        };
        let t = e.timestamp;
        let cpu = e.context.processor;
        match &decoded {
            KernelEvent::Stack(s) => {
                let Some(m) = self.matcher.stack(cpu, t, s) else {
                    self.stats.stacks_unmatched += 1;
                    return;
                };
                let r = (m.id & ROW) as usize;
                let current = match m.id & !ROW {
                    SAMPLE => self.trace.samples.stack[r],
                    SWITCH => self.trace.switches.stack[r],
                    READY => self.trace.readies.stack[r],
                    _ => unreachable!("only tagged rows are registered"),
                };
                // The frames, outermost first. A continuation is the user
                // part: the callers of the kernel part we have.
                let frames = &mut self.scratch;
                frames.clear();
                frames.extend(s.frames.iter());
                frames.reverse();
                let caches = self.caches.entry(s.thread_id).or_default();
                let stack = if m.continuation {
                    let inner = &mut self.scratch2;
                    self.trace.stacks.frames_outermost_first(current, inner);
                    frames.extend_from_slice(inner);
                    self.stats.stack_continuations += 1;
                    self.trace
                        .stacks
                        .intern_outermost_first(frames, &mut caches.1)
                } else {
                    self.stats.stacks += 1;
                    self.trace
                        .stacks
                        .intern_outermost_first(frames, &mut caches.0)
                };
                match m.id & !ROW {
                    SAMPLE => self.trace.samples.stack[r] = stack,
                    SWITCH => self.trace.switches.stack[r] = stack,
                    _ => self.trace.readies.stack[r] = stack,
                }
            }
            KernelEvent::Sample(s) => {
                let thread = self.thread(s.thread_id);
                let samples = &mut self.trace.samples;
                let r = samples.len();
                samples.time.push(t);
                samples.cpu.push(cpu);
                samples.thread.push(thread);
                samples.ip.push(s.instruction_pointer);
                samples.stack.push(StackId::EMPTY);
                samples.weight.push(s.count.max(1));
                self.matcher.event(SAMPLE | r as u64, e, Some(&decoded));
            }
            KernelEvent::ContextSwitch(c) => {
                let new = self.thread(c.new_thread_id);
                let old = self.thread(c.old_thread_id);
                let ready = self.last_ready.remove(&new).unwrap_or(ReadyIx::NONE);
                let sw = &mut self.trace.switches;
                let r = sw.len();
                sw.time.push(t);
                sw.cpu.push(cpu);
                sw.new_thread.push(new);
                sw.old_thread.push(old);
                sw.new_priority.push(c.new_thread_priority);
                sw.old_priority.push(c.old_thread_priority);
                sw.wait_reason.push(c.old_thread_wait_reason);
                sw.old_state.push(c.old_thread_state);
                sw.stack.push(StackId::EMPTY);
                sw.ready.push(ready);
                self.matcher.event(SWITCH | r as u64, e, Some(&decoded));
                let i = usize::from(cpu);
                if i >= self.running.len() {
                    self.running.resize(i + 1, ThreadIx::NONE);
                }
                self.running[i] = new;
            }
            KernelEvent::ReadyThread(rt) => {
                let thread = self.thread(rt.thread_id);
                let readier = self
                    .running
                    .get(usize::from(cpu))
                    .copied()
                    .unwrap_or(ThreadIx::NONE);
                let rd = &mut self.trace.readies;
                let r = rd.len();
                rd.time.push(t);
                rd.cpu.push(cpu);
                rd.thread.push(thread);
                rd.readier.push(readier);
                rd.stack.push(StackId::EMPTY);
                self.last_ready.insert(thread, ReadyIx(row(r)));
                self.matcher.event(READY | r as u64, e, Some(&decoded));
            }
            KernelEvent::Process(p) => self.process(t, p),
            KernelEvent::Thread(th) => self.thread_event(t, th),
            KernelEvent::ThreadName(n) => {
                let thread = self.thread(n.thread_id);
                self.trace.threads[thread.index()].name = Some(n.name.to_string_lossy());
            }
            KernelEvent::Image(im) => self.image(t, im),
            KernelEvent::ImageId(id) => {
                if let Some(&ix) = self.live_images.get(&(id.process_id, id.base)) {
                    let image = &mut self.trace.images[ix.index()];
                    if image.time_date_stamp == 0 {
                        image.time_date_stamp = id.time_date_stamp;
                    }
                }
            }
            KernelEvent::DbgId(d) => {
                if d.il {
                    return;
                }
                if let Some(&ix) = self.live_images.get(&(d.process_id, d.base)) {
                    self.trace.images[ix.index()].debug_id = Some(DebugId {
                        guid: d.guid.to_bytes(),
                        age: d.age,
                        pdb_path: String::from_utf8_lossy(d.pdb_file_name).into_owned(),
                    });
                }
            }
            _ => {}
        }
    }

    /// The live thread with `tid`, or a new one of unknown process.
    fn thread(&mut self, tid: u32) -> ThreadIx {
        if let Some(&t) = self.live_threads.get(&tid) {
            return t;
        }
        let process = if tid == 0 {
            // The idle threads belong to the idle process.
            self.live_processes
                .get(&0)
                .copied()
                .unwrap_or(ProcessIx::NONE)
        } else {
            ProcessIx::NONE
        };
        let ix = ThreadIx(row(self.trace.threads.len()));
        self.trace.threads.push(Thread {
            tid,
            process,
            name: None,
            start_address: 0,
            start: None,
            end: None,
        });
        self.live_threads.insert(tid, ix);
        ix
    }

    fn process(&mut self, t: i64, p: &hexcavator_etw::kernel::ProcessEvent<'_>) {
        let existing = self.live_processes.get(&p.process_id).copied();
        let same = existing.filter(|ix| {
            let q = &self.trace.processes[ix.index()];
            q.unique_key == p.unique_key || q.unique_key == 0
        });
        match p.lifetime {
            Lifetime::Start | Lifetime::RundownStart => {
                if p.lifetime == Lifetime::RundownStart && same.is_some() {
                    return;
                }
                let ix = ProcessIx(row(self.trace.processes.len()));
                self.trace.processes.push(Process {
                    pid: p.process_id,
                    parent_pid: p.parent_id,
                    unique_key: p.unique_key,
                    name: String::from_utf8_lossy(p.image_file_name).into_owned(),
                    command_line: p.command_line.to_string_lossy(),
                    start: (p.lifetime == Lifetime::Start).then_some(t),
                    end: None,
                    exit_status: None,
                });
                self.live_processes.insert(p.process_id, ix);
            }
            Lifetime::End => {
                if let Some(ix) = same {
                    let q = &mut self.trace.processes[ix.index()];
                    q.end = Some(t);
                    q.exit_status = Some(p.exit_status);
                }
            }
            Lifetime::RundownEnd => {
                if same.is_none() {
                    let ix = ProcessIx(row(self.trace.processes.len()));
                    self.trace.processes.push(Process {
                        pid: p.process_id,
                        parent_pid: p.parent_id,
                        unique_key: p.unique_key,
                        name: String::from_utf8_lossy(p.image_file_name).into_owned(),
                        command_line: p.command_line.to_string_lossy(),
                        ..Process::default()
                    });
                    self.live_processes.insert(p.process_id, ix);
                }
            }
            Lifetime::Defunct => {}
        }
    }

    fn thread_event(&mut self, t: i64, th: &hexcavator_etw::kernel::ThreadEvent) {
        let process = self
            .live_processes
            .get(&th.process_id)
            .copied()
            .unwrap_or(ProcessIx::NONE);
        match th.lifetime {
            Lifetime::Start | Lifetime::RundownStart => {
                if let Some(&ix) = self.live_threads.get(&th.thread_id) {
                    let existing = &mut self.trace.threads[ix.index()];
                    // A rundown for a thread we only knew by its ID fills it in.
                    if th.lifetime == Lifetime::RundownStart
                        || (existing.process == ProcessIx::NONE && existing.start.is_none())
                    {
                        if existing.process == ProcessIx::NONE {
                            existing.process = process;
                            existing.start_address = th.win32_start_address;
                        }
                        if th.lifetime == Lifetime::RundownStart {
                            return;
                        }
                        existing.start = Some(t);
                        return;
                    }
                }
                let ix = ThreadIx(row(self.trace.threads.len()));
                self.trace.threads.push(Thread {
                    tid: th.thread_id,
                    process,
                    name: None,
                    start_address: th.win32_start_address,
                    start: (th.lifetime == Lifetime::Start).then_some(t),
                    end: None,
                });
                self.live_threads.insert(th.thread_id, ix);
            }
            Lifetime::End => {
                let ix = self.thread(th.thread_id);
                let thread = &mut self.trace.threads[ix.index()];
                thread.end = Some(t);
                if thread.process == ProcessIx::NONE {
                    thread.process = process;
                }
            }
            Lifetime::RundownEnd => {
                let ix = self.thread(th.thread_id);
                let thread = &mut self.trace.threads[ix.index()];
                if thread.process == ProcessIx::NONE {
                    thread.process = process;
                    thread.start_address = th.win32_start_address;
                }
            }
            Lifetime::Defunct => {}
        }
    }

    fn image(&mut self, t: i64, im: &hexcavator_etw::kernel::ImageEvent<'_>) {
        let key = (im.process_id, im.base);
        let process = if im.process_id == 0 {
            ProcessIx::NONE
        } else {
            self.live_processes
                .get(&im.process_id)
                .copied()
                .unwrap_or(ProcessIx::NONE)
        };
        match im.lifetime {
            Lifetime::End => {
                if let Some(ix) = self.live_images.remove(&key) {
                    self.trace.images[ix.index()].unload = Some(t);
                }
            }
            Lifetime::RundownEnd if self.live_images.contains_key(&key) => {}
            Lifetime::RundownStart if self.live_images.contains_key(&key) => {}
            _ => {
                let ix = ImageIx(row(self.trace.images.len()));
                self.trace.images.push(Image {
                    process,
                    base: im.base,
                    size: im.size,
                    path: im.file_name.to_string_lossy(),
                    time_date_stamp: im.time_date_stamp,
                    checksum: im.checksum,
                    debug_id: None,
                    load: (im.lifetime == Lifetime::Start).then_some(t),
                    unload: None,
                });
                self.live_images.insert(key, ix);
            }
        }
    }
}
