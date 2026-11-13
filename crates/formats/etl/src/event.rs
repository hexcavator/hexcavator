//! Event records within a buffer.
//!
//! A buffer holds a sequence of records, each aligned to 8 bytes. A record
//! starts with a marker whose third byte says which kind of header it has:
//!
//! | Kind | Header | Size | Fields |
//! |---|---|---|---|
//! | system | `SYSTEM_TRACE_HEADER` | 0x20 | hook, thread, process, time, kernel/user time |
//! | compact | (system without CPU times) | 0x18 | hook, thread, process, time |
//! | perfinfo | `PERFINFO_TRACE_HEADER` | 0x10 | hook, time |
//! | event | `EVENT_HEADER` | 0x50 | the manifest/TraceLogging header |
//! | full | `EVENT_TRACE_HEADER` | 0x30 | classic events with a GUID |
//! | instance | `EVENT_INSTANCE_HEADER` | 0x38 | classic events with instance IDs |
//!
//! The kernel's classic events (system, compact, perfinfo) carry a 16-bit
//! hook ID: a group in the high byte, which names the event class (the
//! provider GUID), and the opcode in the low byte.
//!
//! [`Event`] presents every kind the way `ProcessTrace` does in an
//! `EVENT_RECORD`, so that consumers handle one shape.

use hexcavator_core::{Error, ErrorKind, Result};

use crate::buffer::BufferContext;
use crate::bytes::{align8, guid_at, i64_at, u16_at, u32_at, u64_at};
use crate::classic;
use crate::guid::Guid;

/// Header-type values (the marker's third byte).
mod header_type {
    pub const SYSTEM32: u8 = 0x01;
    pub const SYSTEM64: u8 = 0x02;
    pub const COMPACT32: u8 = 0x03;
    pub const COMPACT64: u8 = 0x04;
    pub const FULL_HEADER32: u8 = 0x0a;
    pub const INSTANCE32: u8 = 0x0b;
    pub const PERFINFO32: u8 = 0x10;
    pub const PERFINFO64: u8 = 0x11;
    pub const EVENT_HEADER32: u8 = 0x12;
    pub const EVENT_HEADER64: u8 = 0x13;
    pub const FULL_HEADER64: u8 = 0x14;
    pub const INSTANCE64: u8 = 0x15;
}

/// `EVENT_HEADER_FLAG_*` values, as in [`Event::flags`].
pub mod flags {
    /// The event has extended data items.
    pub const EXTENDED_INFO: u16 = 0x0001;
    /// The event was logged by a private session.
    pub const PRIVATE_SESSION: u16 = 0x0002;
    /// The payload is a NUL-terminated UTF-16 string.
    pub const STRING_ONLY: u16 = 0x0004;
    /// The event is a WPP trace message.
    pub const TRACE_MESSAGE: u16 = 0x0008;
    /// The event has no kernel/user CPU times.
    pub const NO_CPUTIME: u16 = 0x0010;
    /// The event was logged by a 32-bit provider.
    pub const BIT32_HEADER: u16 = 0x0020;
    /// The event was logged by a 64-bit provider.
    pub const BIT64_HEADER: u16 = 0x0040;
    /// The event's provider GUID is a decode GUID.
    pub const DECODE_GUID: u16 = 0x0080;
    /// The event has a classic (MOF) header.
    pub const CLASSIC_HEADER: u16 = 0x0100;
    /// The buffer context holds a processor index.
    pub const PROCESSOR_INDEX: u16 = 0x0200;
}

/// What kind of header a record had in the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HeaderKind {
    /// A kernel system header: hook, thread, process, time and CPU times.
    System,
    /// A kernel system header without CPU times.
    Compact,
    /// A kernel PerfInfo header: hook and time only.
    PerfInfo,
    /// A manifest-based or TraceLogging `EVENT_HEADER`.
    Event,
    /// A classic `EVENT_TRACE_HEADER` with a provider GUID.
    Full,
    /// A classic `EVENT_INSTANCE_HEADER`.
    Instance,
}

/// One event, presented as `ProcessTrace` presents it in an `EVENT_RECORD`.
#[derive(Clone, Copy, Debug)]
pub struct Event<'a> {
    /// The record's position in the file.
    pub file_offset: u64,
    /// What kind of header the record had.
    pub kind: HeaderKind,
    /// Whether the header was the 64-bit variant of its kind.
    pub is_64bit: bool,
    /// The timestamp, in the trace's clock (see `ClockType`).
    pub timestamp: i64,
    /// The provider (for kernel events, the event class the hook's group
    /// names).
    pub provider: Guid,
    /// For kernel events, the hook ID: group in the high byte, opcode in the
    /// low byte.
    pub hook: Option<u16>,
    /// The event descriptor.
    pub descriptor: EventDescriptor,
    /// `EVENT_HEADER_FLAG_*` (see [`flags`]).
    pub flags: u16,
    /// `EVENT_HEADER_PROPERTY_*`.
    pub event_property: u16,
    /// The process, or `u32::MAX` when the record has none.
    pub process_id: u32,
    /// The thread, or `u32::MAX` when the record has none.
    pub thread_id: u32,
    /// Kernel time in the low half and user time in the high half, or the
    /// processor time for private sessions.
    pub processor_time: u64,
    /// The activity ID.
    pub activity_id: Guid,
    /// The processor and session of the buffer the event was in.
    pub context: BufferContext,
    /// The raw extended data items (see [`Event::extended_data`]).
    pub extended: &'a [u8],
    /// The payload.
    pub user_data: &'a [u8],
}

/// An event's descriptor (`EVENT_DESCRIPTOR`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct EventDescriptor {
    /// The event ID (zero for classic events).
    pub id: u16,
    /// The event's version.
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
}

impl<'a> Event<'a> {
    /// The event's extended data items.
    pub fn extended_data(&self) -> ExtendedItems<'a> {
        ExtendedItems {
            data: self.extended,
            offset: self.file_offset,
        }
    }
}

/// An iterator over the records of one buffer, in the order they were
/// written.
#[derive(Clone, Debug)]
pub struct Records<'a> {
    data: &'a [u8],
    pos: usize,
    base: u64,
    context: BufferContext,
    done: bool,
}

impl<'a> Records<'a> {
    /// Records in `data[start..]`. `base` is the file offset of `data[0]`,
    /// used in errors.
    pub(crate) fn new(data: &'a [u8], start: usize, base: u64, context: BufferContext) -> Self {
        Self {
            data,
            pos: start,
            base,
            context,
            done: false,
        }
    }

    /// The position of the next record, relative to the start of the data.
    pub fn position(&self) -> usize {
        self.pos
    }

    fn error(&self, kind: ErrorKind, what: &'static str) -> Error {
        Error::new(kind, self.base + self.pos as u64, what)
    }

    fn next_record(&mut self) -> Result<Option<Event<'a>>> {
        let rest = &self.data[self.pos..];
        if rest.len() < 8 {
            return Ok(None);
        }
        let marker = u32_at(rest, 0);
        // The end of the events is marked by padding: all ones or all zeros.
        if marker == u32::MAX || marker == 0 {
            return Ok(None);
        }
        let header_type = rest[2];
        let marker_flags = rest[3];
        // Every record we know sets the "trace header" flag.
        if marker_flags & 0x80 == 0 {
            return Err(self.error(ErrorKind::Malformed, "event marker"));
        }
        let file_offset = self.base + self.pos as u64;
        let (size, event) = match header_type {
            header_type::SYSTEM32
            | header_type::SYSTEM64
            | header_type::COMPACT32
            | header_type::COMPACT64
            | header_type::PERFINFO32
            | header_type::PERFINFO64 => self.kernel(rest, header_type, file_offset)?,
            header_type::EVENT_HEADER32 | header_type::EVENT_HEADER64 => {
                self.event_header(rest, header_type, file_offset)?
            }
            header_type::FULL_HEADER32 | header_type::FULL_HEADER64 => {
                self.full(rest, header_type, file_offset)?
            }
            header_type::INSTANCE32 | header_type::INSTANCE64 => {
                self.instance(rest, header_type, file_offset)?
            }
            _ => return Err(self.error(ErrorKind::Unsupported, "event header type")),
        };
        let next = align8(size)
            .and_then(|n| self.pos.checked_add(n))
            .ok_or(self.error(ErrorKind::Overflow, "event size"))?;
        self.pos = next.min(self.data.len());
        Ok(Some(event))
    }

    /// The kernel's system, compact and PerfInfo headers.
    fn kernel(&self, rest: &'a [u8], ty: u8, file_offset: u64) -> Result<(usize, Event<'a>)> {
        use header_type::*;
        let header_size = match ty {
            SYSTEM32 | SYSTEM64 => 0x20,
            COMPACT32 | COMPACT64 => 0x18,
            _ => 0x10,
        };
        let size = usize::from(u16_at(rest, 4));
        if size < header_size || size > rest.len() {
            return Err(self.error(ErrorKind::Malformed, "kernel event size"));
        }
        let version = u16_at(rest, 0);
        let hook = u16_at(rest, 6);
        let is_64bit = matches!(ty, SYSTEM64 | COMPACT64 | PERFINFO64);
        let (thread_id, process_id, timestamp) = if header_size >= 0x18 {
            (u32_at(rest, 8), u32_at(rest, 12), i64_at(rest, 16))
        } else {
            (u32::MAX, u32::MAX, i64_at(rest, 8))
        };
        let processor_time = if header_size == 0x20 {
            u64_at(rest, 24)
        } else {
            0
        };
        let mut f = flags::CLASSIC_HEADER | flags::PROCESSOR_INDEX;
        f |= if is_64bit {
            flags::BIT64_HEADER
        } else {
            flags::BIT32_HEADER
        };
        if header_size != 0x20 {
            f |= flags::NO_CPUTIME;
        }
        let event = Event {
            file_offset,
            kind: match header_size {
                0x20 => HeaderKind::System,
                0x18 => HeaderKind::Compact,
                _ => HeaderKind::PerfInfo,
            },
            is_64bit,
            timestamp,
            provider: classic::hook_guid(hook).unwrap_or(Guid::ZERO),
            hook: Some(hook),
            descriptor: EventDescriptor {
                // EVENT_RECORD has a byte for the version; ProcessTrace keeps
                // the low byte.
                version: version.to_le_bytes()[0],
                opcode: hook.to_le_bytes()[0],
                ..EventDescriptor::default()
            },
            flags: f,
            event_property: 0,
            process_id,
            thread_id,
            processor_time,
            activity_id: Guid::ZERO,
            context: self.context,
            extended: &[],
            user_data: &rest[header_size..size],
        };
        Ok((size, event))
    }

    /// `EVENT_HEADER`: manifest-based and TraceLogging events.
    fn event_header(&self, rest: &'a [u8], ty: u8, file_offset: u64) -> Result<(usize, Event<'a>)> {
        const HEADER: usize = 0x50;
        let size = usize::from(u16_at(rest, 0));
        if size < HEADER || size > rest.len() {
            return Err(self.error(ErrorKind::Malformed, "event size"));
        }
        let record = &rest[..size];
        let file_flags = u16_at(record, 4);
        let mut payload = HEADER;
        let mut extended: &'a [u8] = &[];
        if file_flags & flags::EXTENDED_INFO != 0 {
            let len = extended_len(&record[HEADER..])
                .ok_or(self.error(ErrorKind::Malformed, "extended data"))?;
            extended = &record[HEADER..HEADER + len];
            payload += len;
        }
        let is_64bit = ty == header_type::EVENT_HEADER64;
        let mut f = file_flags | flags::PROCESSOR_INDEX;
        if f & (flags::BIT32_HEADER | flags::BIT64_HEADER) == 0 {
            f |= if is_64bit {
                flags::BIT64_HEADER
            } else {
                flags::BIT32_HEADER
            };
        }
        let event = Event {
            file_offset,
            kind: HeaderKind::Event,
            is_64bit,
            timestamp: i64_at(record, 0x10),
            provider: guid_at(record, 0x18),
            hook: None,
            descriptor: EventDescriptor {
                id: u16_at(record, 0x28),
                version: record[0x2a],
                channel: record[0x2b],
                level: record[0x2c],
                opcode: record[0x2d],
                task: u16_at(record, 0x2e),
                keyword: u64_at(record, 0x30),
            },
            flags: f,
            event_property: u16_at(record, 6),
            thread_id: u32_at(record, 8),
            process_id: u32_at(record, 12),
            processor_time: u64_at(record, 0x38),
            activity_id: guid_at(record, 0x40),
            context: self.context,
            extended,
            user_data: &record[payload..],
        };
        Ok((size, event))
    }

    /// `EVENT_TRACE_HEADER`: classic events with a provider GUID.
    fn full(&self, rest: &'a [u8], ty: u8, file_offset: u64) -> Result<(usize, Event<'a>)> {
        const HEADER: usize = 0x30;
        let size = usize::from(u16_at(rest, 0));
        if size < HEADER || size > rest.len() {
            return Err(self.error(ErrorKind::Malformed, "classic event size"));
        }
        let is_64bit = ty == header_type::FULL_HEADER64;
        let event = Event {
            file_offset,
            kind: HeaderKind::Full,
            is_64bit,
            timestamp: i64_at(rest, 0x10),
            provider: guid_at(rest, 0x18),
            hook: None,
            descriptor: EventDescriptor {
                opcode: rest[4],
                level: rest[5],
                version: u16_at(rest, 6).to_le_bytes()[0],
                ..EventDescriptor::default()
            },
            flags: flags::CLASSIC_HEADER
                | flags::PROCESSOR_INDEX
                | if is_64bit {
                    flags::BIT64_HEADER
                } else {
                    flags::BIT32_HEADER
                },
            event_property: 0,
            thread_id: u32_at(rest, 8),
            process_id: u32_at(rest, 12),
            processor_time: u64_at(rest, 0x28),
            activity_id: Guid::ZERO,
            context: self.context,
            extended: &[],
            user_data: &rest[HEADER..size],
        };
        Ok((size, event))
    }

    /// `EVENT_INSTANCE_HEADER`: classic events with instance IDs. The
    /// provider is named by a registration handle we can't resolve from the
    /// file, so it is reported as the zero GUID.
    fn instance(&self, rest: &'a [u8], ty: u8, file_offset: u64) -> Result<(usize, Event<'a>)> {
        const HEADER: usize = 0x38;
        let size = usize::from(u16_at(rest, 0));
        if size < HEADER || size > rest.len() {
            return Err(self.error(ErrorKind::Malformed, "instance event size"));
        }
        let is_64bit = ty == header_type::INSTANCE64;
        let event = Event {
            file_offset,
            kind: HeaderKind::Instance,
            is_64bit,
            timestamp: i64_at(rest, 0x10),
            provider: Guid::ZERO,
            hook: None,
            descriptor: EventDescriptor {
                opcode: rest[4],
                level: rest[5],
                version: u16_at(rest, 6).to_le_bytes()[0],
                ..EventDescriptor::default()
            },
            flags: flags::CLASSIC_HEADER
                | flags::PROCESSOR_INDEX
                | if is_64bit {
                    flags::BIT64_HEADER
                } else {
                    flags::BIT32_HEADER
                },
            event_property: 0,
            thread_id: u32_at(rest, 8),
            process_id: u32_at(rest, 12),
            processor_time: u64_at(rest, 0x28),
            activity_id: Guid::ZERO,
            context: self.context,
            extended: &[],
            user_data: &rest[HEADER..size],
        };
        Ok((size, event))
    }
}

impl<'a> Iterator for Records<'a> {
    type Item = Result<Event<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.next_record() {
            Ok(Some(event)) => Some(Ok(event)),
            Ok(None) => {
                self.done = true;
                None
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

impl core::iter::FusedIterator for Records<'_> {}

/// The length of the extended data items at the start of `data`: items
/// follow one another while the "linkage" bit is set.
///
/// In a file each item is an `EVENT_HEADER_EXTENDED_DATA_ITEM` without its
/// data pointer: its total size (header and padding included), its type,
/// the linkage word and the data's size; the data follows. Items are 8-byte
/// aligned.
fn extended_len(data: &[u8]) -> Option<usize> {
    let mut pos = 0usize;
    loop {
        let (size, linked) = extended_item_at(data, pos)?;
        pos = align8(pos.checked_add(size)?)?;
        if pos > data.len() {
            return None;
        }
        if !linked {
            return Some(pos);
        }
    }
}

/// The total size of the extended item at `pos` and whether another
/// follows it, if it is well formed.
fn extended_item_at(data: &[u8], pos: usize) -> Option<(usize, bool)> {
    let header = data.get(pos..pos.checked_add(EXTENDED_ITEM_HEADER)?)?;
    let size = usize::from(u16_at(header, 0));
    let data_size = usize::from(u16_at(header, 6));
    if size < EXTENDED_ITEM_HEADER + data_size || pos.checked_add(size)? > data.len() {
        return None;
    }
    Some((size, u16_at(header, 4) & 1 != 0))
}

/// The size of an extended item's header in a file.
const EXTENDED_ITEM_HEADER: usize = 8;

/// An extended data item (`EVENT_HEADER_EXTENDED_DATA_ITEM`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtendedItem<'a> {
    /// The item's type (`EVENT_HEADER_EXT_TYPE_*`).
    pub ext_type: u16,
    /// The item's data.
    pub data: &'a [u8],
}

/// `EVENT_HEADER_EXT_TYPE_*` values.
pub mod ext_type {
    /// A related activity ID.
    pub const RELATED_ACTIVITYID: u16 = 1;
    /// The security identifier of the logging user.
    pub const SID: u16 = 2;
    /// The terminal session.
    pub const TS_ID: u16 = 3;
    /// Instance information.
    pub const INSTANCE_INFO: u16 = 4;
    /// A 32-bit stack.
    pub const STACK_TRACE32: u16 = 5;
    /// A 64-bit stack.
    pub const STACK_TRACE64: u16 = 6;
    /// A PEBS index.
    pub const PEBS_INDEX: u16 = 7;
    /// Performance counter values.
    pub const PMC_COUNTERS: u16 = 8;
    /// A process-state-manager key.
    pub const PSM_KEY: u16 = 9;
    /// An event key.
    pub const EVENT_KEY: u16 = 10;
    /// A TraceLogging event schema.
    pub const EVENT_SCHEMA_TL: u16 = 11;
    /// Provider traits.
    pub const PROV_TRAITS: u16 = 12;
    /// The process start key.
    pub const PROCESS_START_KEY: u16 = 13;
    /// The control GUID.
    pub const CONTROL_GUID: u16 = 14;
    /// A QPC delta.
    pub const QPC_DELTA: u16 = 15;
    /// The container ID.
    pub const CONTAINER_ID: u16 = 16;
    /// A 32-bit stack key.
    pub const STACK_KEY32: u16 = 17;
    /// A 64-bit stack key.
    pub const STACK_KEY64: u16 = 18;
}

/// An iterator over an event's extended data items.
#[derive(Clone, Debug)]
pub struct ExtendedItems<'a> {
    data: &'a [u8],
    offset: u64,
}

impl<'a> Iterator for ExtendedItems<'a> {
    type Item = Result<ExtendedItem<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }
        let Some((size, linked)) = extended_item_at(self.data, 0) else {
            let err = Error::new(ErrorKind::Malformed, self.offset, "extended data item");
            self.data = &[];
            return Some(Err(err));
        };
        let data_size = usize::from(u16_at(self.data, 6));
        let item = ExtendedItem {
            ext_type: u16_at(self.data, 2),
            data: &self.data[EXTENDED_ITEM_HEADER..EXTENDED_ITEM_HEADER + data_size],
        };
        let next = align8(size).unwrap_or(usize::MAX).min(self.data.len());
        self.data = if linked { &self.data[next..] } else { &[] };
        Some(Ok(item))
    }
}
