//! The TLS directory (`IMAGE_TLS_DIRECTORY32/64`).

use hexcavator_core::{Rva, Va};

use crate::PeFile;
use crate::consts::directory;

/// The TLS directory. Addresses are VAs, as stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsDirectory {
    pub start_of_raw_data: Va,
    pub end_of_raw_data: Va,
    pub address_of_index: Va,
    pub address_of_callbacks: Va,
    pub size_of_zero_fill: u32,
    /// Bits 20–23 are the alignment, as in section characteristics.
    pub characteristics: u32,
}

impl<'data> PeFile<'data> {
    /// The TLS directory.
    pub fn tls(&self) -> Option<TlsDirectory> {
        let dir = self.data_directory(directory::TLS)?;
        let is_64 = self.optional_header()?.is_64();
        let w = if is_64 { 8 } else { 4 };
        let b = self
            .bytes_at_rva(Rva(dir.virtual_address.get()), 4 * w + 8)
            .ok()?;
        let ptr = |i: usize| -> u64 {
            let s = &b[i * w as usize..(i + 1) * w as usize];
            let mut v = [0u8; 8];
            v[..s.len()].copy_from_slice(s);
            u64::from_le_bytes(v)
        };
        let tail = 4 * w as usize;
        Some(TlsDirectory {
            start_of_raw_data: Va(ptr(0)),
            end_of_raw_data: Va(ptr(1)),
            address_of_index: Va(ptr(2)),
            address_of_callbacks: Va(ptr(3)),
            size_of_zero_fill: u32::from_le_bytes(b[tail..tail + 4].try_into().ok()?),
            characteristics: u32::from_le_bytes(b[tail + 4..tail + 8].try_into().ok()?),
        })
    }

    /// The TLS callbacks (VAs), up to the terminating zero.
    pub fn tls_callbacks(&self) -> impl Iterator<Item = Va> + 'data {
        let file = *self;
        let start = self
            .tls()
            .map(|t| t.address_of_callbacks)
            .filter(|v| v.get() != 0);
        let w: u64 = if self
            .optional_header()
            .is_some_and(super::file::OptionalHeader::is_64)
        {
            8
        } else {
            4
        };
        (0u64..).map_while(move |i| {
            let va = Va(start?.get().checked_add(i * w)?);
            let v = file.thunk(file.va_to_rva(va)?)?;
            (v != 0).then_some(Va(v))
        })
    }
}
