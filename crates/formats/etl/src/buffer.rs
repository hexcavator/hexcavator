//! ETL buffers: the fixed-size blocks a trace file is made of.

use hexcavator_core::{Error, ErrorKind, Result};

use crate::bytes::{i64_at, u16_at, u32_at, u64_at};
use crate::event::Records;

/// The size of a buffer's header (`WMI_BUFFER_HEADER`).
pub const BUFFER_HEADER_SIZE: usize = 0x48;

/// What a buffer holds (`BufferType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BufferType {
    /// Ordinary events.
    Generic,
    /// Rundown events.
    Rundown,
    /// Context-switch events (a context-swap buffer).
    ContextSwap,
    /// A reference-time buffer.
    RefTime,
    /// The file's first buffer, which holds the logfile header.
    Header,
    /// Batched events.
    Batched,
    /// A marker that holds no events.
    EmptyMarker,
    /// Debug information.
    DebugInfo,
    /// A value we don't know.
    Other(u16),
}

impl BufferType {
    fn from_raw(v: u16) -> Self {
        match v {
            0 => Self::Generic,
            1 => Self::Rundown,
            2 => Self::ContextSwap,
            3 => Self::RefTime,
            4 => Self::Header,
            5 => Self::Batched,
            6 => Self::EmptyMarker,
            7 => Self::DebugInfo,
            v => Self::Other(v),
        }
    }
}

/// A buffer's header (`WMI_BUFFER_HEADER`), as stored in a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferHeader {
    /// The buffer's size in bytes, including this header.
    pub buffer_size: u32,
    /// The offset of the end of the events when the buffer was saved.
    pub saved_offset: u32,
    /// The logger's write position when the buffer was flushed.
    pub current_offset: u32,
    /// When the buffer was flushed, as a FILETIME.
    pub timestamp: i64,
    /// The buffer's sequence number in its session.
    pub sequence_number: i64,
    /// The clock type and frequency field (an in-memory link for some
    /// buffers; meaningful only in some files).
    pub clock: u64,
    /// The processor whose events the buffer holds.
    pub processor: u16,
    /// The session (logger) that wrote the buffer.
    pub logger_id: u16,
    /// The buffer's state when it was written.
    pub state: u32,
    /// The offset of the end of the events: the buffer's used size.
    pub offset: u32,
    /// `BufferFlag`: flush markers, lost events, compression.
    pub flags: u16,
    /// What the buffer holds.
    pub buffer_type: BufferType,
}

impl BufferHeader {
    /// Buffer flag: the buffer was written by a flush.
    pub const FLAG_FLUSH_MARKER: u16 = 0x0001;
    /// Buffer flag: events were lost before this buffer.
    pub const FLAG_EVENTS_LOST: u16 = 0x0002;
    /// Buffer flag: buffers were lost before this buffer.
    pub const FLAG_BUFFER_LOST: u16 = 0x0004;
    /// Buffer flag: the buffer's events are compressed.
    pub const FLAG_COMPRESSED: u16 = 0x0040;

    /// Reads a buffer header from the start of `data`.
    pub fn parse(data: &[u8], file_offset: u64) -> Result<Self> {
        if data.len() < BUFFER_HEADER_SIZE {
            return Err(Error::new(
                ErrorKind::Truncated,
                file_offset,
                "buffer header",
            ));
        }
        Ok(Self {
            buffer_size: u32_at(data, 0x00),
            saved_offset: u32_at(data, 0x04),
            current_offset: u32_at(data, 0x08),
            timestamp: i64_at(data, 0x10),
            sequence_number: i64_at(data, 0x18),
            clock: u64_at(data, 0x20),
            processor: u16_at(data, 0x28),
            logger_id: u16_at(data, 0x2a),
            state: u32_at(data, 0x2c),
            offset: u32_at(data, 0x30),
            flags: u16_at(data, 0x34),
            buffer_type: BufferType::from_raw(u16_at(data, 0x36)),
        })
    }

    /// Whether the buffer's events are compressed.
    pub fn is_compressed(&self) -> bool {
        self.flags & Self::FLAG_COMPRESSED != 0
    }
}

/// One buffer of a trace file.
#[derive(Clone, Copy, Debug)]
pub struct Buffer<'a> {
    /// The buffer's position in the file.
    pub file_offset: u64,
    /// Its index among the file's buffers.
    pub index: u32,
    /// Its header.
    pub header: BufferHeader,
    /// The whole buffer, header included.
    pub data: &'a [u8],
}

impl<'a> Buffer<'a> {
    /// The events' bytes: from after the header to the buffer's used size.
    pub fn payload(&self) -> Result<&'a [u8]> {
        let end = self.header.offset as usize;
        if end < BUFFER_HEADER_SIZE || end > self.data.len() {
            return Err(Error::new(
                ErrorKind::Malformed,
                self.file_offset + 0x30,
                "buffer used size",
            ));
        }
        Ok(&self.data[..end])
    }

    /// The buffer's events, in the order they were written.
    ///
    /// Compressed buffers must be decompressed first (see
    /// [`crate::Etl::decompress`]); for them this returns an error.
    pub fn records(&self) -> Result<Records<'a>> {
        if self.header.is_compressed() {
            return Err(Error::new(
                ErrorKind::Unsupported,
                self.file_offset + 0x34,
                "compressed buffer",
            ));
        }
        let data = self.payload()?;
        Ok(Records::new(
            data,
            BUFFER_HEADER_SIZE,
            self.file_offset,
            self.context(),
        ))
    }

    /// The processor and session every event in the buffer shares.
    pub fn context(&self) -> BufferContext {
        BufferContext {
            processor: self.header.processor,
            logger_id: self.header.logger_id,
        }
    }
}

/// The processor and session of a buffer, which apply to all its events
/// (`ETW_BUFFER_CONTEXT`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct BufferContext {
    /// The processor index.
    pub processor: u16,
    /// The session (logger) ID.
    pub logger_id: u16,
}
