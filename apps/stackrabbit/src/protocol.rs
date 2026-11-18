//! The session protocol's framing.
//!
//! A message is a frame: an 8-byte prefix, then a header, then a payload.
//! The prefix is two little-endian 32-bit lengths: the header's, then the
//! payload's. The header is a JSON object (UTF-8); the payload is bytes
//! (empty for most messages; bulk data, such as a graph's series, rides
//! there rather than in JSON).
//!
//! The editor sends requests, `{"id": 1, "method": "open", "params":
//! {...}}`, and the engine answers each with `{"id": 1, "result": ...}` or
//! `{"id": 1, "error": "..."}`, in any order. The engine also sends
//! notifications, which have a `method` and no `id`.
//!
//! Frames are read as hostile: lengths are bounded, and a frame that
//! doesn't parse is an error, never a panic.

use std::io::{self, Read, Write};

use serde_json::Value;

/// The largest header a frame may have.
pub const MAX_HEADER: u32 = 16 << 20;
/// The largest payload a frame may have.
pub const MAX_PAYLOAD: u32 = 1 << 30;

/// A message.
#[derive(Clone, Debug, PartialEq)]
pub struct Frame {
    /// The header.
    pub header: Value,
    /// The payload.
    pub payload: Vec<u8>,
}

impl Frame {
    /// A frame of `header` with no payload.
    pub fn new(header: Value) -> Self {
        Self {
            header,
            payload: Vec::new(),
        }
    }
}

/// Reads the next frame, or `None` at the end of the input (before a
/// frame starts).
pub fn read_frame(r: &mut impl Read) -> io::Result<Option<Frame>> {
    let mut prefix = [0u8; 8];
    // The end of input is only clean between frames.
    let mut got = 0;
    while got < prefix.len() {
        match r.read(&mut prefix[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(invalid("the input ends in a frame's prefix")),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let header_len = u32::from_le_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]);
    let payload_len = u32::from_le_bytes([prefix[4], prefix[5], prefix[6], prefix[7]]);
    if header_len > MAX_HEADER {
        return Err(invalid("a frame's header is too large"));
    }
    if payload_len > MAX_PAYLOAD {
        return Err(invalid("a frame's payload is too large"));
    }
    let header = read_len(r, header_len, "the input ends in a frame's header")?;
    let payload = read_len(r, payload_len, "the input ends in a frame's payload")?;
    let header: Value = serde_json::from_slice(&header)
        .map_err(|e| invalid(&format!("a frame's header isn't JSON: {e}")))?;
    if !header.is_object() {
        return Err(invalid("a frame's header isn't a JSON object"));
    }
    Ok(Some(Frame { header, payload }))
}

/// Writes `frame` (and flushes).
pub fn write_frame(w: &mut (impl Write + ?Sized), frame: &Frame) -> io::Result<()> {
    let header = serde_json::to_vec(&frame.header).map_err(io::Error::other)?;
    let header_len = u32::try_from(header.len())
        .ok()
        .filter(|&n| n <= MAX_HEADER)
        .ok_or_else(|| invalid("a frame's header is too large"))?;
    let payload_len = u32::try_from(frame.payload.len())
        .ok()
        .filter(|&n| n <= MAX_PAYLOAD)
        .ok_or_else(|| invalid("a frame's payload is too large"))?;
    let mut prefix = [0u8; 8];
    prefix[..4].copy_from_slice(&header_len.to_le_bytes());
    prefix[4..].copy_from_slice(&payload_len.to_le_bytes());
    w.write_all(&prefix)?;
    w.write_all(&header)?;
    w.write_all(&frame.payload)?;
    w.flush()
}

/// Reads `len` bytes. (The buffer grows as bytes arrive, so a frame that
/// claims to be huge and isn't costs nothing.)
fn read_len(r: &mut impl Read, len: u32, what: &str) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity((len as usize).min(1 << 20));
    r.take(u64::from(len)).read_to_end(&mut buf)?;
    if buf.len() == len as usize {
        Ok(buf)
    } else {
        Err(invalid(what))
    }
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.to_string())
}
