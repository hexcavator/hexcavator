//! Writing ETL files.
//!
//! [`Writer`] builds a trace in memory: a header buffer with the logfile
//! header, then each processor's buffers, filled with records in the order
//! they're added. It writes every record kind [`crate::Records`] reads, and
//! can compress buffers. Tests use it to build exact traces, and the record
//! encoders ([`system`], [`event`], ...) to build malformed ones.

use crate::buffer::BUFFER_HEADER_SIZE;
use crate::guid::Guid;

/// How to write a trace.
#[derive(Clone, Debug)]
pub struct WriterOptions {
    /// Bytes per buffer.
    pub buffer_size: u32,
    /// The logging machine's pointer size: 4 or 8.
    pub pointer_size: u32,
    /// Processors.
    pub processors: u32,
    /// The clock (`ReservedFlags`): 1 for QPC, 2 for system time, 3 for
    /// CPU cycles.
    pub clock_type: u32,
    /// The QPC frequency.
    pub perf_freq: i64,
    /// The OS build number.
    pub provider_version: u32,
    /// Whether to compress the event buffers.
    pub compress: bool,
}

impl Default for WriterOptions {
    fn default() -> Self {
        Self {
            buffer_size: 0x1000,
            pointer_size: 8,
            processors: 2,
            clock_type: 1,
            perf_freq: 10_000_000,
            provider_version: 26100,
            compress: false,
        }
    }
}

/// The fields of a kernel (system, compact or PerfInfo) record.
#[derive(Clone, Copy, Debug, Default)]
pub struct Kernel {
    /// The hook ID: group in the high byte, opcode in the low byte.
    pub hook: u16,
    /// The event's version.
    pub version: u16,
    /// The thread (not in PerfInfo records).
    pub thread_id: u32,
    /// The process (not in PerfInfo records).
    pub process_id: u32,
    /// The timestamp.
    pub timestamp: i64,
    /// Kernel time (system records only).
    pub kernel_time: u32,
    /// User time (system records only).
    pub user_time: u32,
}

/// The fields of an `EVENT_HEADER` record.
#[derive(Clone, Copy, Debug, Default)]
pub struct EventFields {
    /// `EVENT_HEADER_FLAG_*`; the extended-info flag is set for you when
    /// there are items.
    pub flags: u16,
    /// `EVENT_HEADER_PROPERTY_*`.
    pub event_property: u16,
    /// The thread.
    pub thread_id: u32,
    /// The process.
    pub process_id: u32,
    /// The timestamp.
    pub timestamp: i64,
    /// The provider.
    pub provider: Guid,
    /// The event ID.
    pub id: u16,
    /// The version.
    pub version: u8,
    /// The channel.
    pub channel: u8,
    /// The level.
    pub level: u8,
    /// The opcode.
    pub opcode: u8,
    /// The task.
    pub task: u16,
    /// The keywords.
    pub keyword: u64,
    /// Kernel and user time, or processor time.
    pub processor_time: u64,
    /// The activity ID.
    pub activity_id: Guid,
}

/// The fields of a classic `EVENT_TRACE_HEADER` record.
#[derive(Clone, Copy, Debug, Default)]
pub struct Classic {
    /// The provider.
    pub provider: Guid,
    /// The opcode (`Class.Type`).
    pub opcode: u8,
    /// The level.
    pub level: u8,
    /// The version.
    pub version: u16,
    /// The thread.
    pub thread_id: u32,
    /// The process.
    pub process_id: u32,
    /// The timestamp.
    pub timestamp: i64,
    /// Kernel and user time.
    pub processor_time: u64,
}

fn marker(version: u16, header_type: u8) -> [u8; 4] {
    let v = version.to_le_bytes();
    [v[0], v[1], header_type, 0xc0]
}

fn size16(n: usize) -> [u8; 2] {
    u16::try_from(n)
        .expect("record fits in 64 KB")
        .to_le_bytes()
}

/// A system record (`SYSTEM_TRACE_HEADER`); `bits64` picks the 64-bit
/// header type.
pub fn system(k: &Kernel, bits64: bool, payload: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(0x20 + payload.len());
    r.extend_from_slice(&marker(k.version, if bits64 { 0x02 } else { 0x01 }));
    r.extend_from_slice(&size16(0x20 + payload.len()));
    r.extend_from_slice(&k.hook.to_le_bytes());
    r.extend_from_slice(&k.thread_id.to_le_bytes());
    r.extend_from_slice(&k.process_id.to_le_bytes());
    r.extend_from_slice(&k.timestamp.to_le_bytes());
    r.extend_from_slice(&k.kernel_time.to_le_bytes());
    r.extend_from_slice(&k.user_time.to_le_bytes());
    r.extend_from_slice(payload);
    r
}

/// A compact record (a system header without CPU times).
pub fn compact(k: &Kernel, bits64: bool, payload: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(0x18 + payload.len());
    r.extend_from_slice(&marker(k.version, if bits64 { 0x04 } else { 0x03 }));
    r.extend_from_slice(&size16(0x18 + payload.len()));
    r.extend_from_slice(&k.hook.to_le_bytes());
    r.extend_from_slice(&k.thread_id.to_le_bytes());
    r.extend_from_slice(&k.process_id.to_le_bytes());
    r.extend_from_slice(&k.timestamp.to_le_bytes());
    r.extend_from_slice(payload);
    r
}

/// A PerfInfo record: hook and timestamp only.
pub fn perfinfo(k: &Kernel, bits64: bool, payload: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(0x10 + payload.len());
    r.extend_from_slice(&marker(k.version, if bits64 { 0x11 } else { 0x10 }));
    r.extend_from_slice(&size16(0x10 + payload.len()));
    r.extend_from_slice(&k.hook.to_le_bytes());
    r.extend_from_slice(&k.timestamp.to_le_bytes());
    r.extend_from_slice(payload);
    r
}

/// An `EVENT_HEADER` record with extended data items `(type, data)`.
pub fn event(e: &EventFields, bits64: bool, extended: &[(u16, &[u8])], payload: &[u8]) -> Vec<u8> {
    let mut ext = Vec::new();
    for (i, (ty, data)) in extended.iter().enumerate() {
        let size = (8 + data.len() + 7) & !7;
        ext.extend_from_slice(&size16(size));
        ext.extend_from_slice(&ty.to_le_bytes());
        let linkage: u16 = if i + 1 < extended.len() { 1 } else { 0 };
        ext.extend_from_slice(&linkage.to_le_bytes());
        ext.extend_from_slice(&size16(data.len()));
        ext.extend_from_slice(data);
        ext.resize(ext.len() + (size - 8 - data.len()), 0);
    }
    let mut flags = e.flags;
    if !extended.is_empty() {
        flags |= crate::event::flags::EXTENDED_INFO;
    }
    let mut r = Vec::with_capacity(0x50 + ext.len() + payload.len());
    r.extend_from_slice(&size16(0x50 + ext.len() + payload.len()));
    r.push(if bits64 { 0x13 } else { 0x12 });
    r.push(0xc0);
    r.extend_from_slice(&flags.to_le_bytes());
    r.extend_from_slice(&e.event_property.to_le_bytes());
    r.extend_from_slice(&e.thread_id.to_le_bytes());
    r.extend_from_slice(&e.process_id.to_le_bytes());
    r.extend_from_slice(&e.timestamp.to_le_bytes());
    r.extend_from_slice(&e.provider.to_bytes());
    r.extend_from_slice(&e.id.to_le_bytes());
    r.extend_from_slice(&[e.version, e.channel, e.level, e.opcode]);
    r.extend_from_slice(&e.task.to_le_bytes());
    r.extend_from_slice(&e.keyword.to_le_bytes());
    r.extend_from_slice(&e.processor_time.to_le_bytes());
    r.extend_from_slice(&e.activity_id.to_bytes());
    r.extend_from_slice(&ext);
    r.extend_from_slice(payload);
    r
}

/// A classic `EVENT_TRACE_HEADER` record.
pub fn classic(c: &Classic, bits64: bool, payload: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(0x30 + payload.len());
    r.extend_from_slice(&size16(0x30 + payload.len()));
    r.push(if bits64 { 0x14 } else { 0x0a });
    r.push(0xc0);
    r.extend_from_slice(&[c.opcode, c.level]);
    r.extend_from_slice(&c.version.to_le_bytes());
    r.extend_from_slice(&c.thread_id.to_le_bytes());
    r.extend_from_slice(&c.process_id.to_le_bytes());
    r.extend_from_slice(&c.timestamp.to_le_bytes());
    r.extend_from_slice(&c.provider.to_bytes());
    r.extend_from_slice(&c.processor_time.to_le_bytes());
    r.extend_from_slice(payload);
    r
}

/// Compresses `data` as "Plain LZ77" using literals only: valid input for
/// any decoder, if not small.
pub fn lz77_literals(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 8 + 4);
    for chunk in data.chunks(32) {
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(chunk);
    }
    out
}

/// Builds an ETL file in memory.
#[derive(Debug)]
pub struct Writer {
    options: WriterOptions,
    /// Finished event buffers, in the order they filled.
    out: Vec<u8>,
    /// Each processor's buffer in progress: its records so far.
    current: Vec<Vec<u8>>,
    buffers: u32,
}

impl Writer {
    /// A writer with `options`.
    pub fn new(options: WriterOptions) -> Self {
        let processors = options.processors.max(1) as usize;
        Self {
            options,
            out: Vec::new(),
            current: vec![Vec::new(); processors],
            buffers: 0,
        }
    }

    /// Appends a record (from one of this module's encoders) to
    /// `processor`'s buffer, starting a new buffer when it doesn't fit.
    pub fn record(&mut self, processor: u16, record: &[u8]) {
        let cpu = usize::from(processor);
        assert!(cpu < self.current.len(), "processor out of range");
        let aligned = (record.len() + 7) & !7;
        let capacity = self.options.buffer_size as usize - BUFFER_HEADER_SIZE;
        assert!(aligned <= capacity, "record larger than a buffer");
        if self.current[cpu].len() + aligned > capacity {
            self.flush(processor);
        }
        let buf = &mut self.current[cpu];
        buf.extend_from_slice(record);
        buf.resize(buf.len() + (aligned - record.len()), 0);
    }

    /// Ends `processor`'s buffer in progress, if it has records.
    pub fn flush(&mut self, processor: u16) {
        let records = std::mem::take(&mut self.current[usize::from(processor)]);
        if records.is_empty() {
            return;
        }
        let used = BUFFER_HEADER_SIZE + records.len();
        let (body, size, flags) = if self.options.compress {
            let body = lz77_literals(&records);
            let size = BUFFER_HEADER_SIZE + body.len();
            (body, size, crate::BufferHeader::FLAG_COMPRESSED)
        } else {
            let mut body = records;
            body.resize(self.options.buffer_size as usize - BUFFER_HEADER_SIZE, 0);
            (body, self.options.buffer_size as usize, 0)
        };
        self.buffers += 1;
        let header = buffer_header(size, used, i64::from(self.buffers), processor, 0, flags, 0);
        self.out.extend_from_slice(&header);
        self.out.extend_from_slice(&body);
    }

    /// The finished file: the header buffer, then the event buffers.
    pub fn finish(mut self) -> Vec<u8> {
        for cpu in 0..self.current.len() {
            self.flush(u16::try_from(cpu).expect("processor fits in u16"));
        }
        let o = &self.options;
        let header = system(
            &Kernel {
                hook: 0,
                version: 2,
                ..Kernel::default()
            },
            o.pointer_size == 8,
            &logfile_header(o, self.buffers + 1),
        );
        let aligned = (header.len() + 7) & !7;
        let used = BUFFER_HEADER_SIZE + aligned;
        let size = used.max(o.buffer_size as usize);
        let mut file = buffer_header(
            size,
            used,
            0,
            0,
            0,
            crate::BufferHeader::FLAG_FLUSH_MARKER,
            4,
        )
        .to_vec();
        file.extend_from_slice(&header);
        file.resize(size, 0);
        file.extend_from_slice(&self.out);
        file
    }
}

/// A `WMI_BUFFER_HEADER`.
fn buffer_header(
    size: usize,
    used: usize,
    sequence: i64,
    processor: u16,
    logger: u16,
    flags: u16,
    buffer_type: u16,
) -> [u8; BUFFER_HEADER_SIZE] {
    let mut h = [0u8; BUFFER_HEADER_SIZE];
    let size = u32::try_from(size).expect("buffer fits in 4 GB");
    let used = u32::try_from(used).expect("buffer fits in 4 GB");
    h[0x00..0x04].copy_from_slice(&size.to_le_bytes());
    h[0x04..0x08].copy_from_slice(&used.to_le_bytes());
    h[0x18..0x20].copy_from_slice(&sequence.to_le_bytes());
    h[0x28..0x2a].copy_from_slice(&processor.to_le_bytes());
    h[0x2a..0x2c].copy_from_slice(&logger.to_le_bytes());
    h[0x30..0x34].copy_from_slice(&used.to_le_bytes());
    h[0x34..0x36].copy_from_slice(&flags.to_le_bytes());
    h[0x36..0x38].copy_from_slice(&buffer_type.to_le_bytes());
    h
}

/// A `TRACE_LOGFILE_HEADER` and the two names after it.
fn logfile_header(o: &WriterOptions, buffers: u32) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(&o.buffer_size.to_le_bytes());
    h.extend_from_slice(&0x0501_000au32.to_le_bytes());
    h.extend_from_slice(&o.provider_version.to_le_bytes());
    h.extend_from_slice(&o.processors.to_le_bytes());
    h.extend_from_slice(&134_000_000_000_000_000i64.to_le_bytes()); // end time
    h.extend_from_slice(&156_250u32.to_le_bytes()); // timer resolution
    h.extend_from_slice(&0u32.to_le_bytes()); // maximum file size
    h.extend_from_slice(&0x0001_0001u32.to_le_bytes()); // log file mode
    h.extend_from_slice(&buffers.to_le_bytes());
    h.extend_from_slice(&1u32.to_le_bytes()); // start buffers
    h.extend_from_slice(&o.pointer_size.to_le_bytes());
    h.extend_from_slice(&0u32.to_le_bytes()); // events lost
    h.extend_from_slice(&3000u32.to_le_bytes()); // CPU MHz
    h.resize(h.len() + 2 * o.pointer_size as usize, 0); // name pointers
    h.resize(h.len() + 176, 0); // time zone
    h.extend_from_slice(&133_999_000_000_000_000i64.to_le_bytes()); // boot time
    h.extend_from_slice(&o.perf_freq.to_le_bytes());
    h.extend_from_slice(&133_999_999_000_000_000i64.to_le_bytes()); // start time
    h.extend_from_slice(&o.clock_type.to_le_bytes());
    h.extend_from_slice(&0u32.to_le_bytes()); // buffers lost
    for name in ["Test Session", "test.etl"] {
        for u in name.encode_utf16().chain([0]) {
            h.extend_from_slice(&u.to_le_bytes());
        }
    }
    h
}
