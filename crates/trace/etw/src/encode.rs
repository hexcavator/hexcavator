//! Encoders for the kernel events [`crate::kernel`] decodes: the inverse
//! of [`crate::kernel::decode`].
//!
//! [`encode`] turns a [`KernelEvent`] into its provider, opcode, version
//! and payload, laid out as the kernel logs them (with the fields the
//! decoder skips filled with what Windows writes: zeros, or the usual
//! priorities); [`record`] wraps one in the record header the kernel
//! uses for it, ready for [`hexcavator_etl::write::Writer`]. Tests and
//! the synthetic trace generator build traces with them, and every event
//! round-trips: decoding what is encoded gives back the same event.

use hexcavator_etl::write::{self, Classic, Kernel};
use hexcavator_etl::{Guid, classic};

use crate::guids;
use crate::kernel::{
    ContextSwitch, DbgId, ImageEvent, ImageId, KernelEvent, Lifetime, ProcessEvent, ReadyThread,
    Sample, StackWalk, ThreadEvent, ThreadName,
};

/// An encoded event: what identifies it, and its payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Encoded {
    /// The event class.
    pub provider: Guid,
    /// The opcode.
    pub opcode: u8,
    /// The version.
    pub version: u16,
    /// The payload.
    pub payload: Vec<u8>,
}

/// The kernel's hook group of image loads: the process group (an image
/// load is opcode 10 of it), not the image group.
const PROCESS_GROUP: u16 = 0x03;

/// Encodes `event` for a trace whose pointers are `pointer_size` bytes (4
/// or 8). Returns `None` for an event the kernel never logs: an image
/// event with [`Lifetime::Defunct`].
pub fn encode(event: &KernelEvent<'_>, pointer_size: usize) -> Option<Encoded> {
    assert!(
        pointer_size == 4 || pointer_size == 8,
        "pointers are 4 or 8 bytes"
    );
    let mut p = Payload {
        out: Vec::new(),
        ptr: pointer_size,
    };
    let (provider, opcode, version) = match event {
        KernelEvent::Process(e) => {
            process(&mut p, e);
            // (Defunct processes are version 5: version 4 and the exit
            // time.)
            let version = if e.lifetime == Lifetime::Defunct {
                5
            } else {
                4
            };
            (guids::PROCESS, lifetime_opcode(e.lifetime), version)
        }
        KernelEvent::Thread(e) => {
            if e.lifetime == Lifetime::Defunct {
                return None;
            }
            thread(&mut p, e);
            (guids::THREAD, lifetime_opcode(e.lifetime), 3)
        }
        KernelEvent::ThreadName(e) => {
            thread_name(&mut p, e);
            (guids::THREAD, 72, 2)
        }
        KernelEvent::Image(e) => {
            let opcode = match e.lifetime {
                Lifetime::Start => 10,
                Lifetime::End => 2,
                Lifetime::RundownStart => 3,
                Lifetime::RundownEnd => 4,
                Lifetime::Defunct => return None,
            };
            image(&mut p, e);
            (guids::IMAGE, opcode, 3)
        }
        KernelEvent::Sample(e) => {
            sample(&mut p, e);
            (guids::PERF_INFO, 46, 2)
        }
        KernelEvent::ContextSwitch(e) => {
            context_switch(&mut p, e);
            (guids::THREAD, 36, 2)
        }
        KernelEvent::ReadyThread(e) => {
            ready_thread(&mut p, e);
            (guids::THREAD, 50, 2)
        }
        KernelEvent::Stack(e) => {
            stack(&mut p, e);
            (guids::STACK_WALK, 32, 2)
        }
        KernelEvent::ImageId(e) => {
            image_id(&mut p, e);
            (guids::KERNEL_TRACE_CONTROL, 0, 2)
        }
        KernelEvent::DbgId(e) => {
            dbg_id(&mut p, e);
            (guids::KERNEL_TRACE_CONTROL, if e.il { 37 } else { 36 }, 2)
        }
    };
    Some(Encoded {
        provider,
        opcode,
        version,
        payload: p.out,
    })
}

/// Where an event happened, for its record header.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Context {
    /// The timestamp, in the trace's clock.
    pub timestamp: i64,
    /// The thread that logged it (`u32::MAX` when none is meaningful).
    pub thread_id: u32,
    /// The process that logged it (`u32::MAX` when none is meaningful).
    pub process_id: u32,
}

/// The record of `event`, with the header the kernel gives that event: a
/// PerfInfo header for CPU samples, a system header for other kernel
/// events, and a classic header for the trace-control events a merge adds.
/// `bits64` picks the 64-bit header types (and must agree with the
/// pointer size the event was encoded with).
pub fn record(event: &Encoded, at: Context, bits64: bool) -> Vec<u8> {
    if event.provider == guids::KERNEL_TRACE_CONTROL {
        let c = Classic {
            provider: event.provider,
            opcode: event.opcode,
            version: event.version,
            thread_id: at.thread_id,
            process_id: at.process_id,
            timestamp: at.timestamp,
            ..Classic::default()
        };
        return write::classic(&c, bits64, &event.payload);
    }
    let group = if event.provider == guids::IMAGE && event.opcode == 10 {
        PROCESS_GROUP
    } else {
        classic::guid_group(&event.provider).expect("a kernel event class")
    };
    let k = Kernel {
        hook: group << 8 | u16::from(event.opcode),
        version: event.version,
        thread_id: at.thread_id,
        process_id: at.process_id,
        timestamp: at.timestamp,
        ..Kernel::default()
    };
    if event.provider == guids::PERF_INFO {
        write::perfinfo(&k, bits64, &event.payload)
    } else {
        write::system(&k, bits64, &event.payload)
    }
}

fn lifetime_opcode(l: Lifetime) -> u8 {
    match l {
        Lifetime::Start => 1,
        Lifetime::End => 2,
        Lifetime::RundownStart => 3,
        Lifetime::RundownEnd => 4,
        Lifetime::Defunct => 39,
    }
}

struct Payload {
    out: Vec<u8>,
    ptr: usize,
}

impl Payload {
    fn u8(&mut self, v: u8) {
        self.out.push(v);
    }
    fn i8(&mut self, v: i8) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }
    fn u16(&mut self, v: u16) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }
    fn i32(&mut self, v: i32) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }
    fn i64(&mut self, v: i64) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }
    /// A pointer-sized value; on a 32-bit trace, its low half.
    #[allow(clippy::cast_possible_truncation)]
    fn ptr(&mut self, v: u64) {
        if self.ptr == 8 {
            self.u64(v);
        } else {
            self.u32(v as u32);
        }
    }
    fn bytes(&mut self, v: &[u8]) {
        self.out.extend_from_slice(v);
    }
    /// UTF-16 code units (as bytes) and a NUL.
    fn utf16z(&mut self, units: &[u8]) {
        self.out.extend_from_slice(&units[..units.len() & !1]);
        self.u16(0);
    }
    fn ansiz(&mut self, s: &[u8]) {
        self.out.extend_from_slice(s);
        self.u8(0);
    }
    /// A `TOKEN_USER` (a pointer to the SID and its attributes) and the
    /// SID; or, for none, a zero.
    fn sid(&mut self, sid: &[u8]) {
        if sid.is_empty() {
            self.u32(0);
            return;
        }
        // The pointer: anything not zero in its first four bytes.
        self.ptr(1);
        self.ptr(0);
        self.bytes(sid);
    }
}

fn process(p: &mut Payload, e: &ProcessEvent<'_>) {
    p.ptr(e.unique_key);
    p.u32(e.process_id);
    p.u32(e.parent_id);
    p.u32(e.session_id);
    p.i32(e.exit_status);
    p.ptr(e.directory_table_base);
    p.u32(e.flags);
    p.sid(e.user_sid);
    p.ansiz(e.image_file_name);
    p.utf16z(e.command_line.0);
    p.utf16z(e.package_full_name.0);
    p.utf16z(e.application_id.0);
    if e.lifetime == Lifetime::Defunct {
        p.u64(e.exit_time.unwrap_or(0));
    }
}

fn thread(p: &mut Payload, e: &ThreadEvent) {
    p.u32(e.process_id);
    p.u32(e.thread_id);
    p.ptr(e.stack_base);
    p.ptr(e.stack_limit);
    p.ptr(e.user_stack_base);
    p.ptr(e.user_stack_limit);
    p.ptr(0); // Affinity
    p.ptr(e.win32_start_address);
    p.ptr(e.teb);
    p.u32(e.sub_process_tag);
    p.u8(e.base_priority);
    p.u8(5); // PagePriority
    p.u8(2); // IoPriority
    p.u8(0); // ThreadFlags
}

fn thread_name(p: &mut Payload, e: &ThreadName<'_>) {
    p.u32(e.process_id);
    p.u32(e.thread_id);
    p.utf16z(e.name.0);
}

fn image(p: &mut Payload, e: &ImageEvent<'_>) {
    p.ptr(e.base);
    p.ptr(e.size);
    p.u32(e.process_id);
    p.u32(e.checksum);
    p.u32(e.time_date_stamp);
    p.u32(0); // SignatureLevel, SignatureType, Reserved0
    p.ptr(e.default_base);
    p.bytes(&[0; 16]); // Reserved1 to Reserved4
    p.utf16z(e.file_name.0);
}

fn sample(p: &mut Payload, e: &Sample) {
    p.ptr(e.instruction_pointer);
    p.u32(e.thread_id);
    p.u16(e.count);
    p.u16(0); // Reserved
}

fn context_switch(p: &mut Payload, e: &ContextSwitch) {
    p.u32(e.new_thread_id);
    p.u32(e.old_thread_id);
    p.i8(e.new_thread_priority);
    p.i8(e.old_thread_priority);
    p.u8(e.previous_c_state);
    p.u8(0); // SpareByte
    p.i8(e.old_thread_wait_reason);
    p.i8(e.old_thread_wait_mode);
    p.i8(e.old_thread_state);
    p.i8(e.old_thread_wait_ideal_processor);
    p.u32(e.new_thread_wait_time);
    p.u32(0); // Reserved
}

fn ready_thread(p: &mut Payload, e: &ReadyThread) {
    p.u32(e.thread_id);
    p.i8(e.adjust_reason);
    p.i8(e.adjust_increment);
    p.i8(e.flag);
    p.u8(0); // Reserved
}

fn stack(p: &mut Payload, e: &StackWalk<'_>) {
    p.i64(e.event_timestamp);
    p.u32(e.process_id);
    p.u32(e.thread_id);
    for f in e.frames.iter() {
        p.ptr(f);
    }
}

fn image_id(p: &mut Payload, e: &ImageId<'_>) {
    p.ptr(e.base);
    p.ptr(e.size);
    p.u32(e.process_id);
    p.u32(e.time_date_stamp);
    p.utf16z(e.original_file_name.0);
}

fn dbg_id(p: &mut Payload, e: &DbgId<'_>) {
    p.ptr(e.base);
    p.u32(e.process_id);
    p.bytes(&e.guid.to_bytes());
    p.u32(e.age);
    p.ansiz(e.pdb_file_name);
}
