//! Bounds-checked access to byte slices using target-derived offsets.

use crate::{Error, ErrorKind, Pod, Result, U16Le, U32Le, U64Le, from_bytes, slice_from_bytes};

/// Converts a target-derived `u64` to a host `usize`, or fails with
/// [`ErrorKind::Overflow`] if it does not fit on this host.
#[inline]
pub fn to_usize(value: u64, offset: u64, what: &'static str) -> Result<usize> {
    usize::try_from(value).map_err(|_| Error::new(ErrorKind::Overflow, offset, what))
}

/// Returns `data[offset..offset + len]`.
#[inline]
pub fn bytes_at(data: &[u8], offset: u64, len: u64) -> Result<&[u8]> {
    let what = "bytes";
    let start = to_usize(offset, offset, what)?;
    let len = to_usize(len, offset, what)?;
    let end = start
        .checked_add(len)
        .ok_or(Error::new(ErrorKind::Overflow, offset, what))?;
    data.get(start..end)
        .ok_or(Error::new(ErrorKind::Truncated, offset, what))
}

/// Overlays a `T` at `offset`.
#[inline]
pub fn read_at<T: Pod>(data: &[u8], offset: u64) -> Result<&T> {
    let what = core::any::type_name::<T>();
    let start = to_usize(offset, offset, what)?;
    data.get(start..)
        .and_then(from_bytes)
        .ok_or(Error::new(ErrorKind::Truncated, offset, what))
}

/// Overlays `count` consecutive `T`s at `offset`.
#[inline]
pub fn read_slice_at<T: Pod>(data: &[u8], offset: u64, count: u64) -> Result<&[T]> {
    let what = core::any::type_name::<T>();
    let start = to_usize(offset, offset, what)?;
    let count = to_usize(count, offset, what)?;
    let tail = data
        .get(start..)
        .ok_or(Error::new(ErrorKind::Truncated, offset, what))?;
    slice_from_bytes(tail, count).ok_or_else(|| {
        let kind = if core::mem::size_of::<T>().checked_mul(count).is_none() {
            ErrorKind::Overflow
        } else {
            ErrorKind::Truncated
        };
        Error::new(kind, offset, what)
    })
}

/// Returns the NUL-terminated byte string at `offset`, without the NUL.
#[inline]
pub fn cstr_at(data: &[u8], offset: u64) -> Result<&[u8]> {
    let what = "string";
    let start = to_usize(offset, offset, what)?;
    let tail = data
        .get(start..)
        .ok_or(Error::new(ErrorKind::Truncated, offset, what))?;
    let len =
        tail.iter()
            .position(|&b| b == 0)
            .ok_or(Error::new(ErrorKind::Truncated, offset, what))?;
    Ok(&tail[..len])
}

/// A forward-only cursor over a byte slice.
///
/// `base` is the position of `data[0]` within the enclosing file or stream; it
/// only affects the offsets reported in errors.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    base: u64,
}

impl<'a> Reader<'a> {
    /// A reader of `data`, from its start.
    #[inline]
    pub const fn new(data: &'a [u8]) -> Self {
        Self::with_base(data, 0)
    }

    /// A reader of `data`, which starts at offset `base` of the file or
    /// stream that holds it (errors give offsets in that).
    #[inline]
    pub const fn with_base(data: &'a [u8], base: u64) -> Self {
        Self { data, pos: 0, base }
    }

    /// The current position, relative to the start of the slice.
    #[inline]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// The current position, relative to the enclosing file or stream.
    #[inline]
    pub const fn offset(&self) -> u64 {
        self.base.saturating_add(self.pos as u64)
    }

    /// The bytes not yet read.
    #[inline]
    pub fn remaining(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    /// Whether every byte has been read.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.pos == self.data.len()
    }

    #[inline]
    fn error(&self, kind: ErrorKind, what: &'static str) -> Error {
        Error::new(kind, self.offset(), what)
    }

    /// Consumes and returns the next `len` bytes.
    #[inline]
    pub fn bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let rest = self.remaining();
        if rest.len() < len {
            return Err(self.error(ErrorKind::Truncated, "bytes"));
        }
        self.pos += len;
        Ok(&rest[..len])
    }

    /// Skips `len` bytes.
    #[inline]
    pub fn skip(&mut self, len: usize) -> Result<()> {
        self.bytes(len).map(|_| ())
    }

    /// Advances to the next multiple of `align` (relative to the start of the
    /// slice), which must be a power of two.
    #[inline]
    pub fn align_to(&mut self, align: usize) -> Result<()> {
        debug_assert!(align.is_power_of_two());
        let padding = self.pos.wrapping_neg() & (align - 1);
        self.skip(padding)
    }

    /// Consumes and overlays a `T`.
    #[inline]
    pub fn read<T: Pod>(&mut self) -> Result<&'a T> {
        let size = core::mem::size_of::<T>();
        let bytes = self.bytes(size).map_err(|e| Error {
            what: core::any::type_name::<T>(),
            ..e
        })?;
        Ok(from_bytes(bytes).expect("length checked"))
    }

    /// Consumes and overlays `count` consecutive `T`s.
    #[inline]
    pub fn read_slice<T: Pod>(&mut self, count: usize) -> Result<&'a [T]> {
        let what = core::any::type_name::<T>();
        let len = core::mem::size_of::<T>()
            .checked_mul(count)
            .ok_or(self.error(ErrorKind::Overflow, what))?;
        let bytes = self.bytes(len).map_err(|e| Error { what, ..e })?;
        Ok(slice_from_bytes(bytes, count).expect("length checked"))
    }

    /// Consumes a NUL-terminated string and returns it without the NUL.
    #[inline]
    pub fn cstr(&mut self) -> Result<&'a [u8]> {
        let rest = self.remaining();
        let len = rest
            .iter()
            .position(|&b| b == 0)
            .ok_or(self.error(ErrorKind::Truncated, "string"))?;
        self.pos += len + 1;
        Ok(&rest[..len])
    }

    /// Reads a byte.
    #[inline]
    pub fn u8(&mut self) -> Result<u8> {
        self.read::<u8>().copied()
    }

    /// Reads a little-endian `u16`.
    #[inline]
    pub fn u16_le(&mut self) -> Result<u16> {
        self.read::<U16Le>().map(|v| v.get())
    }

    /// Reads a little-endian `u32`.
    #[inline]
    pub fn u32_le(&mut self) -> Result<u32> {
        self.read::<U32Le>().map(|v| v.get())
    }

    /// Reads a little-endian `u64`.
    #[inline]
    pub fn u64_le(&mut self) -> Result<u64> {
        self.read::<U64Le>().map(|v| v.get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_functions_check_bounds() {
        let data = [1, 0, 2, 0, b'h', b'i', 0, 9];
        assert_eq!(read_at::<U16Le>(&data, 2).unwrap().get(), 2);
        assert_eq!(
            read_at::<U16Le>(&data, 7).unwrap_err().kind,
            ErrorKind::Truncated
        );
        assert_eq!(read_at::<U16Le>(&data, u64::MAX).unwrap_err().kind, {
            if usize::BITS < 64 {
                ErrorKind::Overflow
            } else {
                ErrorKind::Truncated
            }
        });
        assert_eq!(read_slice_at::<U16Le>(&data, 0, 2).unwrap().len(), 2);
        assert_eq!(
            read_slice_at::<U16Le>(&data, 0, 5).unwrap_err().kind,
            ErrorKind::Truncated
        );
        assert_eq!(
            read_slice_at::<U16Le>(&data, 0, u64::MAX).unwrap_err().kind,
            ErrorKind::Overflow
        );
        assert_eq!(cstr_at(&data, 4).unwrap(), b"hi");
        assert_eq!(cstr_at(&data, 7).unwrap_err().kind, ErrorKind::Truncated);
        assert_eq!(bytes_at(&data, 6, 2).unwrap(), &[0, 9]);
        assert_eq!(
            bytes_at(&data, 7, 2).unwrap_err().kind,
            ErrorKind::Truncated
        );
        assert_eq!(
            bytes_at(&data, 1, u64::MAX).unwrap_err().kind,
            ErrorKind::Overflow
        );
    }

    #[test]
    fn reader_sequence() {
        let data = [0xAA, 0, 0, 0, 0x34, 0x12, b'o', b'k', 0, 0xFF];
        let mut r = Reader::with_base(&data, 0x100);
        assert_eq!(r.u8().unwrap(), 0xAA);
        r.align_to(4).unwrap();
        assert_eq!(r.position(), 4);
        assert_eq!(r.u16_le().unwrap(), 0x1234);
        assert_eq!(r.cstr().unwrap(), b"ok");
        assert_eq!(r.offset(), 0x109);
        let err = r.u32_le().unwrap_err();
        assert_eq!((err.kind, err.offset), (ErrorKind::Truncated, 0x109));
        // A failed read does not advance.
        assert_eq!(r.u8().unwrap(), 0xFF);
        assert!(r.is_empty());
    }
}
