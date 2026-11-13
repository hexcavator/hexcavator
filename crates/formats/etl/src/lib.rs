//! A reader for Windows event trace log (ETL) files.
//!
//! An ETL file is a sequence of buffers ([`Buffer`]). Each starts with a
//! `WMI_BUFFER_HEADER` that says how big it is, which processor's events it
//! holds and how many bytes of it are used; the events follow, each aligned
//! to 8 bytes ([`Records`]). The first buffer's first event carries the
//! [`LogfileHeader`]: the clock, the pointer size, the processor count.
//!
//! [`Etl::events`] reads every event in timestamp order, merging the
//! processors' streams the way `ProcessTrace` does, and decompresses
//! compressed buffers on the way.
//!
//! The format is not documented as a whole. This reader follows the SDK's
//! structure definitions (`evntrace.h`, `evntcons.h`) and is tested against
//! what Windows' own `ProcessTrace` reports for the same files (see
//! `tools/etwdump`).

pub mod buffer;
mod bytes;
pub mod classic;
pub mod event;
mod guid;
pub mod logfile;
pub mod lz77;
mod merge;
pub mod write;

use hexcavator_core::{Error, ErrorKind, Result};

pub use buffer::{Buffer, BufferContext, BufferHeader, BufferType};
pub use event::{Event, EventDescriptor, ExtendedItem, ExtendedItems, HeaderKind, Records};
pub use guid::Guid;
pub use logfile::{ClockType, LogfileHeader};
pub use merge::EventCursor;

use buffer::BUFFER_HEADER_SIZE;
use bytes::u32_at;

/// An ETL file.
#[derive(Clone, Debug)]
pub struct Etl<'a> {
    data: &'a [u8],
    header: LogfileHeader,
}

impl<'a> Etl<'a> {
    /// Reads the file's logfile header.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let first = Buffers::new(data).next().ok_or(Error::new(
            ErrorKind::Truncated,
            0,
            "first buffer",
        ))??;
        let event = first.records()?.next().ok_or(Error::new(
            ErrorKind::Malformed,
            0,
            "logfile header event",
        ))??;
        if event.hook != Some(0) {
            return Err(Error::new(
                ErrorKind::BadMagic,
                event.file_offset,
                "logfile header event",
            ));
        }
        let header = LogfileHeader::parse(event.user_data, event.file_offset)?;
        Ok(Self { data, header })
    }

    /// The logfile header.
    pub fn header(&self) -> &LogfileHeader {
        &self.header
    }

    /// The file's bytes.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// The buffers, in file order.
    pub fn buffers(&self) -> Buffers<'a> {
        Buffers::new(self.data)
    }

    /// Every event, in timestamp order, as `ProcessTrace` delivers them.
    pub fn events(&self) -> Result<EventCursor<'a>> {
        EventCursor::new(self)
    }
}

/// An iterator over a file's buffers.
#[derive(Clone, Debug)]
pub struct Buffers<'a> {
    data: &'a [u8],
    pos: usize,
    index: u32,
}

impl<'a> Buffers<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            index: 0,
        }
    }

    fn next_buffer(&mut self) -> Result<Option<Buffer<'a>>> {
        let rest = &self.data[self.pos..];
        if rest.is_empty() {
            return Ok(None);
        }
        let offset = self.pos as u64;
        if rest.len() < BUFFER_HEADER_SIZE {
            return Err(Error::new(ErrorKind::Truncated, offset, "buffer header"));
        }
        let size = u32_at(rest, 0) as usize;
        if size < BUFFER_HEADER_SIZE {
            return Err(Error::new(ErrorKind::Malformed, offset, "buffer size"));
        }
        if size > rest.len() {
            return Err(Error::new(ErrorKind::Truncated, offset, "buffer"));
        }
        let data = &rest[..size];
        let header = BufferHeader::parse(data, offset)?;
        let buffer = Buffer {
            file_offset: offset,
            index: self.index,
            header,
            data,
        };
        self.pos += size;
        self.index += 1;
        Ok(Some(buffer))
    }
}

impl<'a> Iterator for Buffers<'a> {
    type Item = Result<Buffer<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_buffer() {
            Ok(b) => b.map(Ok),
            Err(e) => {
                self.pos = self.data.len();
                Some(Err(e))
            }
        }
    }
}

impl core::iter::FusedIterator for Buffers<'_> {}
