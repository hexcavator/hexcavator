//! The index file: a [`Trace`] saved so that reopening it skips the import.
//!
//! The file is little-endian, in sections. A header names the format and
//! version and the source it was built from ([`Source`]: the trace's size
//! and a hash of its start and end), so a stale index is never used. Then
//! come the tables: processes, threads and images as length-prefixed
//! records, the event columns and the stack trie as raw arrays.
//!
//! Reading treats the file as hostile (it may be stale, truncated or
//! tampered with): every count, index and stack reference is checked, and
//! a bad file is an error, never a panic.

use hexcavator_core::{Error, ErrorKind, Result};

use crate::model::{
    Clock, ContextSwitches, DebugId, Image, Process, ProcessIx, ReadyIx, ReadyThreads, Samples,
    Thread, ThreadIx, Trace,
};
use crate::stacks::{StackId, StackStore};

/// The file's magic.
pub const MAGIC: &[u8; 8] = b"HXTRACE\0";
/// The format's version; any change to the layout bumps it.
pub const VERSION: u32 = 2;

/// What an index was built from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Source {
    /// The trace file's size.
    pub size: u64,
    /// A hash of its first and last megabyte.
    pub hash: u64,
}

impl Source {
    /// The identity of a trace file's contents.
    pub fn of(data: &[u8]) -> Self {
        const SPAN: usize = 1 << 20;
        let head = &data[..data.len().min(SPAN)];
        let tail = &data[data.len().saturating_sub(SPAN)..];
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        for &b in head.iter().chain(tail) {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x100_0000_01b3);
        }
        Self {
            size: data.len() as u64,
            hash: h,
        }
    }
}

struct Writer {
    out: Vec<u8>,
}

impl Writer {
    fn u8(&mut self, v: u8) {
        self.out.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }
    fn i64(&mut self, v: i64) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }
    fn len(&mut self, n: usize) {
        self.u64(n as u64);
    }
    fn str(&mut self, s: &str) {
        self.len(s.len());
        self.out.extend_from_slice(s.as_bytes());
    }
    fn opt_i64(&mut self, v: Option<i64>) {
        match v {
            Some(v) => {
                self.u8(1);
                self.i64(v);
            }
            None => self.u8(0),
        }
    }
    fn column<T: Copy>(&mut self, v: &[T], put: impl Fn(&mut Self, T)) {
        self.len(v.len());
        for &x in v {
            put(self, x);
        }
    }
}

/// Saves `trace`, built from `source`.
pub fn write(trace: &Trace, source: Source) -> Vec<u8> {
    let mut w = Writer { out: Vec::new() };
    w.out.extend_from_slice(MAGIC);
    w.u32(VERSION);
    w.u64(source.size);
    w.u64(source.hash);
    w.u64(trace.clock.ticks_per_second);
    w.i64(trace.clock.origin);
    w.u32(trace.processors);
    w.u64(trace.sample_interval.unwrap_or(0));

    w.len(trace.processes.len());
    for p in &trace.processes {
        w.u32(p.pid);
        w.u32(p.parent_pid);
        w.u64(p.unique_key);
        w.str(&p.name);
        w.str(&p.command_line);
        w.opt_i64(p.start);
        w.opt_i64(p.end);
        w.opt_i64(p.exit_status.map(i64::from));
    }
    w.len(trace.threads.len());
    for t in &trace.threads {
        w.u32(t.tid);
        w.u32(t.process.0);
        match &t.name {
            Some(n) => {
                w.u8(1);
                w.str(n);
            }
            None => w.u8(0),
        }
        w.u64(t.start_address);
        w.opt_i64(t.start);
        w.opt_i64(t.end);
    }
    w.len(trace.images.len());
    for i in &trace.images {
        w.u32(i.process.0);
        w.u64(i.base);
        w.u64(i.size);
        w.str(&i.path);
        w.u32(i.time_date_stamp);
        w.u32(i.checksum);
        match &i.debug_id {
            Some(d) => {
                w.u8(1);
                w.out.extend_from_slice(&d.guid);
                w.u32(d.age);
                w.str(&d.pdb_path);
            }
            None => w.u8(0),
        }
        w.opt_i64(i.load);
        w.opt_i64(i.unload);
    }

    let s = &trace.samples;
    w.column(&s.time, Writer::i64);
    w.column(&s.cpu, Writer::u16);
    w.column(&s.thread, |w, t| w.u32(t.0));
    w.column(&s.ip, Writer::u64);
    w.column(&s.stack, |w, t| w.u32(t.0));
    w.column(&s.weight, Writer::u16);

    let sw = &trace.switches;
    w.column(&sw.time, Writer::i64);
    w.column(&sw.cpu, Writer::u16);
    w.column(&sw.new_thread, |w, t| w.u32(t.0));
    w.column(&sw.old_thread, |w, t| w.u32(t.0));
    w.column(&sw.new_priority, |w, v| w.u8(v.to_le_bytes()[0]));
    w.column(&sw.old_priority, |w, v| w.u8(v.to_le_bytes()[0]));
    w.column(&sw.wait_reason, |w, v| w.u8(v.to_le_bytes()[0]));
    w.column(&sw.old_state, |w, v| w.u8(v.to_le_bytes()[0]));
    w.column(&sw.stack, |w, t| w.u32(t.0));
    w.column(&sw.ready, |w, t| w.u32(t.0));

    let rd = &trace.readies;
    w.column(&rd.time, Writer::i64);
    w.column(&rd.cpu, Writer::u16);
    w.column(&rd.thread, |w, t| w.u32(t.0));
    w.column(&rd.readier, |w, t| w.u32(t.0));
    w.column(&rd.stack, |w, t| w.u32(t.0));

    // The trie, without its root: each node's parent and frame.
    let n = trace.stacks.len();
    w.len(n - 1);
    for i in 1..n {
        let id = StackId(u32::try_from(i).expect("fewer than 4G nodes"));
        w.u32(trace.stacks.parent(id).0);
        w.u64(trace.stacks.frame(id));
    }
    w.out
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn err(&self, kind: ErrorKind, what: &'static str) -> Error {
        Error::new(kind, self.pos as u64, what)
    }
    fn bytes(&mut self, n: usize, what: &'static str) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.data.len())
            .ok_or(self.err(ErrorKind::Truncated, what))?;
        let b = &self.data[self.pos..end];
        self.pos = end;
        Ok(b)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1, "u8")?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        let b = self.bytes(2, "u16")?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32> {
        let b = self.bytes(4, "u32")?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Result<u64> {
        let b = self.bytes(8, "u64")?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }
    fn i64(&mut self) -> Result<i64> {
        let b = self.bytes(8, "i64")?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(i64::from_le_bytes(a))
    }
    fn i8(&mut self) -> Result<i8> {
        Ok(i8::from_le_bytes([self.u8()?]))
    }
    /// A count of items at least `item` bytes each, which must fit in what
    /// is left (so a hostile count can't make us allocate).
    fn count(&mut self, item: usize, what: &'static str) -> Result<usize> {
        let n = self.u64()?;
        let n = usize::try_from(n).map_err(|_| self.err(ErrorKind::Overflow, what))?;
        if n.checked_mul(item.max(1))
            .is_none_or(|b| b > self.data.len() - self.pos)
        {
            return Err(self.err(ErrorKind::Malformed, what));
        }
        Ok(n)
    }
    fn str(&mut self) -> Result<String> {
        let n = self.count(1, "string")?;
        let b = self.bytes(n, "string")?;
        String::from_utf8(b.to_vec()).map_err(|_| self.err(ErrorKind::Malformed, "string"))
    }
    fn flag(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(self.err(ErrorKind::Malformed, "flag")),
        }
    }
    fn opt_i64(&mut self) -> Result<Option<i64>> {
        Ok(if self.flag()? {
            Some(self.i64()?)
        } else {
            None
        })
    }
    fn column<T>(
        &mut self,
        item: usize,
        mut get: impl FnMut(&mut Self) -> Result<T>,
    ) -> Result<Vec<T>> {
        let n = self.count(item, "column")?;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(get(self)?);
        }
        Ok(v)
    }
}

/// Reads an index, checking it was built from `source` (if given) and that
/// it is consistent.
pub fn read(data: &[u8], source: Option<Source>) -> Result<Trace> {
    let mut r = Reader { data, pos: 0 };
    if r.bytes(8, "magic")? != MAGIC {
        return Err(Error::new(ErrorKind::BadMagic, 0, "index magic"));
    }
    if r.u32()? != VERSION {
        return Err(Error::new(ErrorKind::Unsupported, 8, "index version"));
    }
    let built_from = Source {
        size: r.u64()?,
        hash: r.u64()?,
    };
    if source.is_some_and(|s| s != built_from) {
        return Err(Error::new(
            ErrorKind::Malformed,
            12,
            "index of another trace",
        ));
    }
    let clock = Clock {
        ticks_per_second: r.u64()?,
        origin: r.i64()?,
    };
    let mut trace = Trace::new(clock, r.u32()?);
    trace.sample_interval = Some(r.u64()?).filter(|&i| i != 0);

    let n = r.count(8, "processes")?;
    for _ in 0..n {
        let pid = r.u32()?;
        let parent_pid = r.u32()?;
        let unique_key = r.u64()?;
        let name = r.str()?;
        let command_line = r.str()?;
        let start = r.opt_i64()?;
        let end = r.opt_i64()?;
        let exit_status = r
            .opt_i64()?
            .map(|v| i32::try_from(v).map_err(|_| r.err(ErrorKind::Malformed, "exit status")))
            .transpose()?;
        trace.processes.push(Process {
            pid,
            parent_pid,
            unique_key,
            name,
            command_line,
            start,
            end,
            exit_status,
        });
    }
    let processes = trace.processes.len();
    let process_ix = |r: &mut Reader<'_>| -> Result<ProcessIx> {
        let p = ProcessIx(r.u32()?);
        if p.is_some() && p.index() >= processes {
            return Err(r.err(ErrorKind::Malformed, "process index"));
        }
        Ok(p)
    };
    let n = r.count(8, "threads")?;
    for _ in 0..n {
        let tid = r.u32()?;
        let process = process_ix(&mut r)?;
        let name = if r.flag()? { Some(r.str()?) } else { None };
        trace.threads.push(Thread {
            tid,
            process,
            name,
            start_address: r.u64()?,
            start: r.opt_i64()?,
            end: r.opt_i64()?,
        });
    }
    let n = r.count(8, "images")?;
    for _ in 0..n {
        let process = process_ix(&mut r)?;
        let base = r.u64()?;
        let size = r.u64()?;
        let path = r.str()?;
        let time_date_stamp = r.u32()?;
        let checksum = r.u32()?;
        let debug_id = if r.flag()? {
            let mut guid = [0u8; 16];
            guid.copy_from_slice(r.bytes(16, "guid")?);
            Some(DebugId {
                guid,
                age: r.u32()?,
                pdb_path: r.str()?,
            })
        } else {
            None
        };
        trace.images.push(Image {
            process,
            base,
            size,
            path,
            time_date_stamp,
            checksum,
            debug_id,
            load: r.opt_i64()?,
            unload: r.opt_i64()?,
        });
    }

    let thread = |r: &mut Reader<'_>| Ok(ThreadIx(r.u32()?));
    let stack = |r: &mut Reader<'_>| Ok(StackId(r.u32()?));
    trace.samples = Samples {
        time: r.column(8, Reader::i64)?,
        cpu: r.column(2, Reader::u16)?,
        thread: r.column(4, thread)?,
        ip: r.column(8, Reader::u64)?,
        stack: r.column(4, stack)?,
        weight: r.column(2, Reader::u16)?,
    };
    trace.switches = ContextSwitches {
        time: r.column(8, Reader::i64)?,
        cpu: r.column(2, Reader::u16)?,
        new_thread: r.column(4, thread)?,
        old_thread: r.column(4, thread)?,
        new_priority: r.column(1, Reader::i8)?,
        old_priority: r.column(1, Reader::i8)?,
        wait_reason: r.column(1, Reader::i8)?,
        old_state: r.column(1, Reader::i8)?,
        stack: r.column(4, stack)?,
        ready: r.column(4, |r| Ok(ReadyIx(r.u32()?)))?,
    };
    trace.readies = ReadyThreads {
        time: r.column(8, Reader::i64)?,
        cpu: r.column(2, Reader::u16)?,
        thread: r.column(4, thread)?,
        readier: r.column(4, thread)?,
        stack: r.column(4, stack)?,
    };

    let n = r.count(12, "stack nodes")?;
    let mut stacks = StackStore::new();
    for i in 0..n {
        let parent = StackId(r.u32()?);
        let frame = r.u64()?;
        // Parents come before children, so a trie read in order is the
        // trie that was written.
        if parent.0 as usize > i {
            return Err(r.err(ErrorKind::Malformed, "stack parent"));
        }
        let id = stacks.push(parent, frame);
        if id.0 as usize != i + 1 {
            return Err(r.err(ErrorKind::Malformed, "duplicate stack node"));
        }
    }
    if r.pos != data.len() {
        return Err(r.err(ErrorKind::Malformed, "trailing data"));
    }
    trace.stacks = stacks;
    check(&trace).map_err(|what| Error::new(ErrorKind::Malformed, 0, what))?;
    Ok(trace)
}

/// Checks that the columns agree in length and every reference is in
/// range.
fn check(t: &Trace) -> core::result::Result<(), &'static str> {
    let threads = t.threads.len();
    let nodes = t.stacks.len();
    let thread_ok = |x: &ThreadIx| !x.is_some() || x.index() < threads;
    let stack_ok = |x: &StackId| (x.0 as usize) < nodes;
    let s = &t.samples;
    let n = s.time.len();
    if [
        s.cpu.len(),
        s.thread.len(),
        s.ip.len(),
        s.stack.len(),
        s.weight.len(),
    ]
    .iter()
    .any(|&l| l != n)
    {
        return Err("sample columns");
    }
    if !s.thread.iter().all(thread_ok) || !s.stack.iter().all(stack_ok) {
        return Err("sample references");
    }
    let sw = &t.switches;
    let n = sw.time.len();
    if [
        sw.cpu.len(),
        sw.new_thread.len(),
        sw.old_thread.len(),
        sw.new_priority.len(),
        sw.old_priority.len(),
        sw.wait_reason.len(),
        sw.old_state.len(),
        sw.stack.len(),
        sw.ready.len(),
    ]
    .iter()
    .any(|&l| l != n)
    {
        return Err("switch columns");
    }
    let readies = t.readies.len();
    if !sw.new_thread.iter().all(thread_ok)
        || !sw.old_thread.iter().all(thread_ok)
        || !sw.stack.iter().all(stack_ok)
        || !sw.ready.iter().all(|r| !r.is_some() || r.index() < readies)
    {
        return Err("switch references");
    }
    let rd = &t.readies;
    let n = rd.time.len();
    if [
        rd.cpu.len(),
        rd.thread.len(),
        rd.readier.len(),
        rd.stack.len(),
    ]
    .iter()
    .any(|&l| l != n)
    {
        return Err("ready columns");
    }
    if !rd.thread.iter().all(thread_ok)
        || !rd.readier.iter().all(thread_ok)
        || !rd.stack.iter().all(stack_ok)
    {
        return Err("ready references");
    }
    Ok(())
}
