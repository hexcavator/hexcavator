//! Reading a file's events in timestamp order.
//!
//! Each processor's buffers form a stream whose events are in time order;
//! the file interleaves the streams' buffers in the order they were flushed.
//! [`EventCursor`] merges the streams by timestamp, as `ProcessTrace` does.
//!
//! # Ties
//!
//! Events of different processors can have the same timestamp. When one of
//! them is from the stream that gave the previous event, `ProcessTrace`
//! always delivers that one first, and so do we. Otherwise its order isn't
//! one we could derive (neither processor number, file position nor
//! recency explains it), and we deliver the stream queued most recently
//! first. This is a classified divergence: events with equal timestamps on
//! different processors are concurrent, and nothing should depend on their
//! order. The oracle test compares each run of equal timestamps as a set.

use std::cell::Cell;
use std::cmp::Reverse;
use std::collections::BinaryHeap;

use hexcavator_core::{Error, ErrorKind, Result};

use crate::buffer::{BUFFER_HEADER_SIZE, Buffer, BufferContext, BufferType};
use crate::event::{Event, Records};
use crate::{Etl, lz77};

/// One processor's buffers.
struct Stream<'a> {
    buffers: Vec<Buffer<'a>>,
    /// The index in `buffers` of the current buffer.
    next: usize,
    current: Current<'a>,
}

/// The buffer a stream is reading.
enum Current<'a> {
    None,
    /// An uncompressed buffer, read in place.
    Borrowed {
        data: &'a [u8],
        base: u64,
        context: BufferContext,
        pos: Cell<usize>,
    },
    /// A decompressed buffer.
    Owned {
        data: Vec<u8>,
        base: u64,
        context: BufferContext,
        pos: Cell<usize>,
    },
}

/// A cursor over a file's events in timestamp order.
///
/// It is a lending iterator: each event borrows the cursor (decompressed
/// buffers live in it), so use it with `while let`.
pub struct EventCursor<'a> {
    streams: Vec<Stream<'a>>,
    /// The next event of each stream: smallest timestamp first, and on a
    /// tie the stream queued most recently. That is how `ProcessTrace`
    /// orders ties: a stream keeps going while its events tie with others'.
    heap: BinaryHeap<Reverse<(i64, Reverse<u64>, usize)>>,
    /// Counts pushes onto the heap, to order ties.
    pushes: u64,
    /// A stored error, reported once in place of the next event.
    error: Option<Error>,
    /// Reused for decompression.
    spare: Vec<u8>,
    /// The stream whose event was returned last, to advance on the next call.
    pending: Option<usize>,
    /// The session's buffer size: no buffer decompresses to more.
    max_buffer: usize,
}

impl<'a> EventCursor<'a> {
    pub(crate) fn new(etl: &Etl<'a>) -> Result<Self> {
        let mut streams: Vec<Stream<'a>> = Vec::new();
        let mut index_of = std::collections::HashMap::new();
        for buffer in etl.buffers() {
            let buffer = buffer?;
            // The header buffer is a stream of its own: it claims processor
            // 0, but its events aren't in that processor's time order.
            let key = if buffer.header.buffer_type == BufferType::Header {
                None
            } else {
                Some(buffer.header.processor)
            };
            let i = *index_of.entry(key).or_insert_with(|| {
                streams.push(Stream {
                    buffers: Vec::new(),
                    next: 0,
                    current: Current::None,
                });
                streams.len() - 1
            });
            streams[i].buffers.push(buffer);
        }
        let mut cursor = Self {
            streams,
            heap: BinaryHeap::new(),
            pushes: 0,
            error: None,
            spare: Vec::new(),
            pending: None,
            max_buffer: etl.header().buffer_size as usize,
        };
        // Queued last to first, so that on ties at the start the file's
        // first stream goes first.
        for i in (0..cursor.streams.len()).rev() {
            cursor.refill(i);
        }
        Ok(cursor)
    }

    /// Finds stream `i`'s next event, loading buffers as needed, and queues
    /// it by timestamp. Errors are stored and reported by `next`.
    fn refill(&mut self, i: usize) {
        if let Some(timestamp) = self.head(i) {
            self.pushes += 1;
            self.heap
                .push(Reverse((timestamp, Reverse(self.pushes), i)));
        }
    }

    /// The timestamp of stream `i`'s next event, loading buffers as needed;
    /// `None` at the stream's end. Errors are stored and reported by `next`.
    fn head(&mut self, i: usize) -> Option<i64> {
        loop {
            match self.peek(i) {
                Ok(Some(timestamp)) => return Some(timestamp),
                Ok(None) => {}
                Err(e) => {
                    self.error.get_or_insert(e);
                    // Skip the rest of a malformed buffer.
                }
            }
            if !self.load_next_buffer(i) {
                return None;
            }
        }
    }

    /// The timestamp of stream `i`'s next event in its current buffer.
    fn peek(&self, i: usize) -> Result<Option<i64>> {
        let current = &self.streams[i].current;
        if matches!(current, Current::None) {
            return Ok(None);
        }
        let (data, base, context, pos) = current.parts();
        Ok(Records::new(data, pos.get(), base, context)
            .next()
            .transpose()?
            .map(|e| e.timestamp))
    }

    /// Makes stream `i`'s next buffer current; false at the end.
    fn load_next_buffer(&mut self, i: usize) -> bool {
        let stream = &mut self.streams[i];
        // Recycle the previous decompression buffer.
        if let Current::Owned { data, .. } = std::mem::replace(&mut stream.current, Current::None) {
            self.spare = data;
        }
        let Some(buffer) = stream.buffers.get(stream.next).copied() else {
            return false;
        };
        stream.next += 1;
        let context = buffer.context();
        if buffer.header.is_compressed() {
            let mut data = std::mem::take(&mut self.spare);
            match decompress(&buffer, self.max_buffer, &mut data) {
                Ok(()) => {
                    self.streams[i].current = Current::Owned {
                        data,
                        base: buffer.file_offset,
                        context,
                        pos: Cell::new(BUFFER_HEADER_SIZE),
                    };
                }
                Err(e) => {
                    self.error.get_or_insert(e);
                    self.spare = data;
                }
            }
        } else {
            match buffer.payload() {
                Ok(data) => {
                    stream.current = Current::Borrowed {
                        data,
                        base: buffer.file_offset,
                        context,
                        pos: Cell::new(BUFFER_HEADER_SIZE),
                    }
                }
                Err(e) => {
                    self.error.get_or_insert(e);
                }
            }
        }
        true
    }

    /// The next event, or `None` at the end. After an error the cursor skips
    /// the rest of the malformed buffer and continues.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<Result<Event<'_>>> {
        // The previous event borrowed its stream's buffer, so the stream moves
        // on only now.
        if let Some(i) = self.pending.take() {
            self.refill(i);
        }
        if let Some(e) = self.error.take() {
            return Some(Err(e));
        }
        let Reverse((_, _, i)) = self.heap.pop()?;
        self.pending = Some(i);
        let (data, base, context, pos) = self.streams[i].current.parts();
        let mut records = Records::new(data, pos.get(), base, context);
        let event = records.next()?;
        pos.set(records.position());
        Some(event)
    }
}

impl<'a> Current<'a> {
    fn parts(&self) -> (&[u8], u64, BufferContext, &Cell<usize>) {
        match self {
            Current::None => unreachable!("no buffer"),
            Current::Borrowed {
                data,
                base,
                context,
                pos,
            } => (data, *base, *context, pos),
            Current::Owned {
                data,
                base,
                context,
                pos,
            } => (data.as_slice(), *base, *context, pos),
        }
    }
}

/// The largest decompressed buffer we accept. ETW's buffers are at most a
/// few MB; this bounds what a hostile size can make us allocate.
const MAX_DECOMPRESSED: usize = 64 << 20;

/// Decompresses `buffer` into `out`: its header, then its events.
///
/// A buffer can't hold more than the session's buffer size (`max`), and
/// never more than [`MAX_DECOMPRESSED`].
pub(crate) fn decompress(buffer: &Buffer<'_>, max: usize, out: &mut Vec<u8>) -> Result<()> {
    let used = buffer.header.offset as usize;
    if used < BUFFER_HEADER_SIZE || used > max.min(MAX_DECOMPRESSED) {
        return Err(Error::new(
            ErrorKind::Malformed,
            buffer.file_offset + 0x30,
            "buffer used size",
        ));
    }
    out.clear();
    out.extend_from_slice(&buffer.data[..BUFFER_HEADER_SIZE]);
    lz77::decompress(
        &buffer.data[BUFFER_HEADER_SIZE..],
        used - BUFFER_HEADER_SIZE,
        out,
    )
    .map_err(|e| Error {
        offset: buffer.file_offset + BUFFER_HEADER_SIZE as u64 + e.offset,
        ..e
    })
}
