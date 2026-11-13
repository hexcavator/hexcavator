//! Typed decoders for the kernel events a trace analyzer reads most:
//! processes, threads, images, CPU samples, context switches, ready
//! threads and stacks, and the image identities a merged trace carries.
//!
//! They read fixed offsets for speed (a trace has tens of millions of
//! samples, switches and stacks) and agree with the layouts in
//! [`crate::schema`], which are tested against TDH.

use hexcavator_core::{Error, ErrorKind, Result};
use hexcavator_etl::{Event, Guid};

use crate::{guids, schema::pointer_size};

/// A kernel event we decode.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum KernelEvent<'a> {
    /// A process started, ended, or was running when the trace started
    /// or stopped (rundown).
    Process(ProcessEvent<'a>),
    /// A thread started, ended, or was running (rundown).
    Thread(ThreadEvent),
    /// A thread got a name.
    ThreadName(ThreadName<'a>),
    /// An image was loaded, unloaded, or was loaded (rundown).
    Image(ImageEvent<'a>),
    /// A CPU sample.
    Sample(Sample),
    /// A context switch.
    ContextSwitch(ContextSwitch),
    /// A thread was made ready to run.
    ReadyThread(ReadyThread),
    /// A stack, for an earlier event.
    Stack(StackWalk<'a>),
    /// An image's identity: its size, timestamp and original name.
    ImageId(ImageId<'a>),
    /// An image's PDB: GUID, age and path.
    DbgId(DbgId<'a>),
}

/// Whether a process or thread event is a start, an end or a rundown.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Lifetime {
    /// It started (opcode 1).
    Start,
    /// It ended (opcode 2).
    End,
    /// It was running when the trace started (opcode 3).
    RundownStart,
    /// It was running when the trace stopped (opcode 4).
    RundownEnd,
    /// A process that had exited but not been freed (opcode 39).
    Defunct,
}

impl Lifetime {
    fn from_opcode(op: u8) -> Option<Self> {
        Some(match op {
            1 => Self::Start,
            2 => Self::End,
            3 => Self::RundownStart,
            4 => Self::RundownEnd,
            39 => Self::Defunct,
            _ => return None,
        })
    }
}

/// A NUL-terminated UTF-16 string in a payload, without the NUL.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Utf16<'a>(pub &'a [u8]);

impl Utf16<'_> {
    /// The code units.
    pub fn units(&self) -> impl Iterator<Item = u16> + '_ {
        self.0
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
    }

    /// The string, with ill-formed UTF-16 replaced.
    pub fn to_string_lossy(&self) -> String {
        char::decode_utf16(self.units())
            .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect()
    }

    /// Whether it's empty.
    pub fn is_empty(&self) -> bool {
        self.0.len() < 2
    }
}

impl core::fmt::Debug for Utf16<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self.to_string_lossy())
    }
}

/// A process event.
#[derive(Clone, Debug)]
pub struct ProcessEvent<'a> {
    /// What happened.
    pub lifetime: Lifetime,
    /// The kernel's address of the process object, which identifies it
    /// even when its ID is reused.
    pub unique_key: u64,
    /// The process ID.
    pub process_id: u32,
    /// The parent's process ID.
    pub parent_id: u32,
    /// The session.
    pub session_id: u32,
    /// The exit status (for ends).
    pub exit_status: i32,
    /// The page directory base.
    pub directory_table_base: u64,
    /// Process flags.
    pub flags: u32,
    /// The user's SID, or empty.
    pub user_sid: &'a [u8],
    /// The image file name (8-bit; at most 15 characters, by the kernel).
    pub image_file_name: &'a [u8],
    /// The command line.
    pub command_line: Utf16<'a>,
    /// The package's full name, for packaged apps.
    pub package_full_name: Utf16<'a>,
    /// The application ID, for packaged apps.
    pub application_id: Utf16<'a>,
    /// When a defunct process exited.
    pub exit_time: Option<u64>,
}

/// A thread event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadEvent {
    /// What happened.
    pub lifetime: Lifetime,
    /// The process.
    pub process_id: u32,
    /// The thread.
    pub thread_id: u32,
    /// The kernel stack's base.
    pub stack_base: u64,
    /// The kernel stack's limit.
    pub stack_limit: u64,
    /// The user stack's base.
    pub user_stack_base: u64,
    /// The user stack's limit.
    pub user_stack_limit: u64,
    /// The thread's start address.
    pub win32_start_address: u64,
    /// The thread environment block.
    pub teb: u64,
    /// The service tag.
    pub sub_process_tag: u32,
    /// The base priority.
    pub base_priority: u8,
}

/// A thread's name.
#[derive(Clone, Copy, Debug)]
pub struct ThreadName<'a> {
    /// The process.
    pub process_id: u32,
    /// The thread.
    pub thread_id: u32,
    /// The name.
    pub name: Utf16<'a>,
}

/// An image event.
#[derive(Clone, Copy, Debug)]
pub struct ImageEvent<'a> {
    /// What happened.
    pub lifetime: Lifetime,
    /// Where it's loaded.
    pub base: u64,
    /// Its size in memory.
    pub size: u64,
    /// The process (0 for the kernel and drivers).
    pub process_id: u32,
    /// The PE checksum.
    pub checksum: u32,
    /// The PE timestamp.
    pub time_date_stamp: u32,
    /// The preferred base.
    pub default_base: u64,
    /// The path, in the kernel's form (`\Device\HarddiskVolume3\...`).
    pub file_name: Utf16<'a>,
}

/// A CPU sample (`SampledProfile`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample {
    /// The instruction pointer.
    pub instruction_pointer: u64,
    /// The thread that was running.
    pub thread_id: u32,
    /// How many samples this stands for.
    pub count: u16,
}

/// A context switch (`CSwitch`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextSwitch {
    /// The thread switched in.
    pub new_thread_id: u32,
    /// The thread switched out.
    pub old_thread_id: u32,
    /// The new thread's priority.
    pub new_thread_priority: i8,
    /// The old thread's priority.
    pub old_thread_priority: i8,
    /// The idle state the processor left, for switches out of idle.
    pub previous_c_state: u8,
    /// Why the old thread is waiting (`KWAIT_REASON`).
    pub old_thread_wait_reason: i8,
    /// Whether the old thread waits in user or kernel mode.
    pub old_thread_wait_mode: i8,
    /// The old thread's state (`KTHREAD_STATE`).
    pub old_thread_state: i8,
    /// The old thread's ideal processor.
    pub old_thread_wait_ideal_processor: i8,
    /// How long the new thread waited, in clock ticks.
    pub new_thread_wait_time: u32,
}

/// A thread was made ready (`ReadyThread`). The event's own thread is
/// the one that readied it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadyThread {
    /// The thread made ready.
    pub thread_id: u32,
    /// Why its priority changed.
    pub adjust_reason: i8,
    /// By how much.
    pub adjust_increment: i8,
    /// Flags: whether its kernel stack was swapped out, its process
    /// swapped out, ...
    pub flag: i8,
}

/// A stack (`StackWalk`): the return addresses for the event with the same
/// timestamp and thread.
#[derive(Clone, Copy, Debug)]
pub struct StackWalk<'a> {
    /// The timestamp of the event the stack belongs to.
    pub event_timestamp: i64,
    /// The process.
    pub process_id: u32,
    /// The thread.
    pub thread_id: u32,
    /// The frames, innermost first.
    pub frames: Frames<'a>,
}

/// A stack's frames: pointers of 4 or 8 bytes.
#[derive(Clone, Copy, Debug)]
pub struct Frames<'a> {
    data: &'a [u8],
    pointer_size: usize,
}

impl<'a> Frames<'a> {
    /// Frames of `pointer_size` bytes in `data`.
    pub fn new(data: &'a [u8], pointer_size: usize) -> Self {
        Self { data, pointer_size }
    }

    /// The number of frames.
    pub fn len(&self) -> usize {
        self.data.len() / self.pointer_size
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The frames, innermost first.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = u64> + 'a {
        let ptr = self.pointer_size;
        self.data.chunks_exact(ptr).map(move |c| {
            if ptr == 8 {
                u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]])
            } else {
                u64::from(u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            }
        })
    }
}

/// An image's identity (`ImageId`), from a merged trace.
#[derive(Clone, Copy, Debug)]
pub struct ImageId<'a> {
    /// Where it's loaded.
    pub base: u64,
    /// Its size.
    pub size: u64,
    /// The process.
    pub process_id: u32,
    /// The PE timestamp.
    pub time_date_stamp: u32,
    /// The file name from its version resource.
    pub original_file_name: Utf16<'a>,
}

/// An image's CodeView record (`DbgID_RSDS`), from a merged trace: what
/// finds its PDB.
#[derive(Clone, Copy, Debug)]
pub struct DbgId<'a> {
    /// Where the image is loaded.
    pub base: u64,
    /// The process.
    pub process_id: u32,
    /// The PDB's GUID.
    pub guid: Guid,
    /// The PDB's age.
    pub age: u32,
    /// The PDB's path when the image was built.
    pub pdb_file_name: &'a [u8],
    /// Whether this is the IL PDB of a precompiled managed image.
    pub il: bool,
}

/// A cursor over a payload.
struct Payload<'a> {
    data: &'a [u8],
    pos: usize,
    ptr: usize,
    offset: u64,
}

impl<'a> Payload<'a> {
    fn new(event: &Event<'a>) -> Self {
        Self {
            data: event.user_data,
            pos: 0,
            ptr: pointer_size(event),
            offset: event.file_offset,
        }
    }

    fn bytes(&mut self, n: usize, what: &'static str) -> Result<&'a [u8]> {
        let b = self
            .data
            .get(self.pos..self.pos.saturating_add(n))
            .ok_or(Error::new(ErrorKind::Truncated, self.offset, what))?;
        self.pos += n;
        Ok(b)
    }

    fn u8(&mut self, what: &'static str) -> Result<u8> {
        Ok(self.bytes(1, what)?[0])
    }

    fn i8(&mut self, what: &'static str) -> Result<i8> {
        Ok(i8::from_le_bytes([self.u8(what)?]))
    }

    fn u16(&mut self, what: &'static str) -> Result<u16> {
        let b = self.bytes(2, what)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self, what: &'static str) -> Result<u32> {
        let b = self.bytes(4, what)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self, what: &'static str) -> Result<u64> {
        let b = self.bytes(8, what)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn i32(&mut self, what: &'static str) -> Result<i32> {
        let b = self.bytes(4, what)?;
        Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn i64(&mut self, what: &'static str) -> Result<i64> {
        let b = self.bytes(8, what)?;
        Ok(i64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn ptr(&mut self, what: &'static str) -> Result<u64> {
        if self.ptr == 8 {
            self.u64(what)
        } else {
            self.u32(what).map(u64::from)
        }
    }

    fn guid(&mut self, what: &'static str) -> Result<Guid> {
        let b = self.bytes(16, what)?;
        let mut a = [0u8; 16];
        a.copy_from_slice(b);
        Ok(Guid::from_bytes(&a))
    }

    /// A NUL-terminated UTF-16 string; an unterminated one runs to the end.
    fn utf16z(&mut self) -> Utf16<'a> {
        let rest = &self.data[self.pos..];
        let mut i = 0;
        while i + 2 <= rest.len() {
            if rest[i] == 0 && rest[i + 1] == 0 {
                self.pos += i + 2;
                return Utf16(&rest[..i]);
            }
            i += 2;
        }
        self.pos += rest.len();
        Utf16(&rest[..rest.len() & !1])
    }

    /// A NUL-terminated 8-bit string; an unterminated one runs to the end.
    fn ansiz(&mut self) -> &'a [u8] {
        let rest = &self.data[self.pos..];
        let len = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        self.pos += (len + 1).min(rest.len());
        &rest[..len]
    }

    /// A `TOKEN_USER` and its SID; returns the SID.
    fn sid(&mut self) -> Result<&'a [u8]> {
        let first = self.bytes(4, "UserSID")?;
        if first == [0, 0, 0, 0] {
            return Ok(&[]);
        }
        self.pos -= 4;
        self.bytes(2 * self.ptr, "UserSID")?;
        let header = self.bytes(8, "UserSID")?;
        let count = usize::from(header[1]);
        self.pos -= 8;
        self.bytes(8 + 4 * count, "UserSID")
    }

    fn rest(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }
}

/// Decodes `event` if it is one of the kinds in [`KernelEvent`]. Newer
/// versions than we know are decoded by the fields they share with the
/// known ones.
pub fn decode<'a>(event: &Event<'a>) -> Option<Result<KernelEvent<'a>>> {
    let op = event.descriptor.opcode;
    let p = &event.provider;
    let result = if *p == guids::PERF_INFO && op == 46 {
        sample(event).map(KernelEvent::Sample)
    } else if *p == guids::STACK_WALK && op == 32 {
        stack(event).map(KernelEvent::Stack)
    } else if *p == guids::THREAD {
        match op {
            36 => context_switch(event).map(KernelEvent::ContextSwitch),
            50 => ready_thread(event).map(KernelEvent::ReadyThread),
            1..=4 => thread(event, op).map(KernelEvent::Thread),
            72 => thread_name(event).map(KernelEvent::ThreadName),
            _ => return None,
        }
    } else if *p == guids::PROCESS {
        match op {
            1..=4 | 39 => process(event, op).map(KernelEvent::Process),
            _ => return None,
        }
    } else if *p == guids::IMAGE {
        match op {
            2..=4 | 10 => image(event, op).map(KernelEvent::Image),
            _ => return None,
        }
    } else if *p == guids::KERNEL_TRACE_CONTROL {
        match op {
            0 => image_id(event).map(KernelEvent::ImageId),
            36 | 37 => dbg_id(event, op == 37).map(KernelEvent::DbgId),
            _ => return None,
        }
    } else {
        return None;
    };
    Some(result)
}

fn sample(event: &Event<'_>) -> Result<Sample> {
    let mut p = Payload::new(event);
    Ok(Sample {
        instruction_pointer: p.ptr("InstructionPointer")?,
        thread_id: p.u32("ThreadId")?,
        count: p.u16("Count")?,
    })
}

fn stack<'a>(event: &Event<'a>) -> Result<StackWalk<'a>> {
    let mut p = Payload::new(event);
    let event_timestamp = p.i64("EventTimeStamp")?;
    let process_id = p.u32("StackProcess")?;
    let thread_id = p.u32("StackThread")?;
    let rest = p.rest();
    let len = rest.len() - rest.len() % p.ptr;
    Ok(StackWalk {
        event_timestamp,
        process_id,
        thread_id,
        frames: Frames::new(&rest[..len], p.ptr),
    })
}

fn context_switch(event: &Event<'_>) -> Result<ContextSwitch> {
    let mut p = Payload::new(event);
    let new_thread_id = p.u32("NewThreadId")?;
    let old_thread_id = p.u32("OldThreadId")?;
    let new_thread_priority = p.i8("NewThreadPriority")?;
    let old_thread_priority = p.i8("OldThreadPriority")?;
    let previous_c_state = p.u8("PreviousCState")?;
    p.u8("SpareByte")?;
    Ok(ContextSwitch {
        new_thread_id,
        old_thread_id,
        new_thread_priority,
        old_thread_priority,
        previous_c_state,
        old_thread_wait_reason: p.i8("OldThreadWaitReason")?,
        old_thread_wait_mode: p.i8("OldThreadWaitMode")?,
        old_thread_state: p.i8("OldThreadState")?,
        old_thread_wait_ideal_processor: p.i8("OldThreadWaitIdealProcessor")?,
        new_thread_wait_time: p.u32("NewThreadWaitTime")?,
    })
}

fn ready_thread(event: &Event<'_>) -> Result<ReadyThread> {
    let mut p = Payload::new(event);
    Ok(ReadyThread {
        thread_id: p.u32("TThreadId")?,
        adjust_reason: p.i8("AdjustReason")?,
        adjust_increment: p.i8("AdjustIncrement")?,
        flag: p.i8("Flag")?,
    })
}

fn thread(event: &Event<'_>, op: u8) -> Result<ThreadEvent> {
    let mut p = Payload::new(event);
    let process_id = p.u32("ProcessId")?;
    let thread_id = p.u32("TThreadId")?;
    let stack_base = p.ptr("StackBase")?;
    let stack_limit = p.ptr("StackLimit")?;
    let user_stack_base = p.ptr("UserStackBase")?;
    let user_stack_limit = p.ptr("UserStackLimit")?;
    p.ptr("Affinity")?;
    let win32_start_address = p.ptr("Win32StartAddr")?;
    let teb = p.ptr("TebBase")?;
    let sub_process_tag = p.u32("SubProcessTag")?;
    let base_priority = p.u8("BasePriority")?;
    Ok(ThreadEvent {
        lifetime: Lifetime::from_opcode(op).expect("a thread lifetime opcode"),
        process_id,
        thread_id,
        stack_base,
        stack_limit,
        user_stack_base,
        user_stack_limit,
        win32_start_address,
        teb,
        sub_process_tag,
        base_priority,
    })
}

fn thread_name<'a>(event: &Event<'a>) -> Result<ThreadName<'a>> {
    let mut p = Payload::new(event);
    Ok(ThreadName {
        process_id: p.u32("ProcessId")?,
        thread_id: p.u32("ThreadId")?,
        name: p.utf16z(),
    })
}

fn process<'a>(event: &Event<'a>, op: u8) -> Result<ProcessEvent<'a>> {
    let mut p = Payload::new(event);
    let unique_key = p.ptr("UniqueProcessKey")?;
    let process_id = p.u32("ProcessId")?;
    let parent_id = p.u32("ParentId")?;
    let session_id = p.u32("SessionId")?;
    let exit_status = p.i32("ExitStatus")?;
    let directory_table_base = p.ptr("DirectoryTableBase")?;
    let flags = p.u32("Flags")?;
    let user_sid = p.sid()?;
    let image_file_name = p.ansiz();
    let command_line = p.utf16z();
    let package_full_name = p.utf16z();
    let application_id = p.utf16z();
    let exit_time = if op == 39 {
        Some(p.u64("ExitTime")?)
    } else {
        None
    };
    Ok(ProcessEvent {
        lifetime: Lifetime::from_opcode(op).expect("a process lifetime opcode"),
        unique_key,
        process_id,
        parent_id,
        session_id,
        exit_status,
        directory_table_base,
        flags,
        user_sid,
        image_file_name,
        command_line,
        package_full_name,
        application_id,
        exit_time,
    })
}

fn image<'a>(event: &Event<'a>, op: u8) -> Result<ImageEvent<'a>> {
    let mut p = Payload::new(event);
    let base = p.ptr("ImageBase")?;
    let size = p.ptr("ImageSize")?;
    let process_id = p.u32("ProcessId")?;
    let checksum = p.u32("ImageChecksum")?;
    let time_date_stamp = p.u32("TimeDateStamp")?;
    p.u32("SignatureLevel")?;
    let default_base = p.ptr("DefaultBase")?;
    p.bytes(16, "Reserved")?;
    let lifetime = match op {
        10 => Lifetime::Start,
        2 => Lifetime::End,
        3 => Lifetime::RundownStart,
        _ => Lifetime::RundownEnd,
    };
    Ok(ImageEvent {
        lifetime,
        base,
        size,
        process_id,
        checksum,
        time_date_stamp,
        default_base,
        file_name: p.utf16z(),
    })
}

fn image_id<'a>(event: &Event<'a>) -> Result<ImageId<'a>> {
    let mut p = Payload::new(event);
    Ok(ImageId {
        base: p.ptr("ImageBase")?,
        size: p.ptr("ImageSize")?,
        process_id: p.u32("ProcessId")?,
        time_date_stamp: p.u32("TimeDateStamp")?,
        original_file_name: p.utf16z(),
    })
}

fn dbg_id<'a>(event: &Event<'a>, il: bool) -> Result<DbgId<'a>> {
    let mut p = Payload::new(event);
    Ok(DbgId {
        base: p.ptr("ImageBase")?,
        process_id: p.u32("ProcessId")?,
        guid: p.guid("GuidSig")?,
        age: p.u32("Age")?,
        pdb_file_name: p.ansiz(),
        il,
    })
}
