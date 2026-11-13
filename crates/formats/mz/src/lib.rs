//! MS-DOS "MZ" executables.
//!
//! Every DOS, 16-bit Windows (NE), OS/2 and VxD (LE/LX), and PE executable
//! starts with an MZ header. Later formats extend it with a pointer at offset
//! 0x3C (`e_lfanew`) to a "new" header, identified by its signature. This
//! crate parses the MZ header itself and tells you which new header, if any,
//! follows; the PE, NE, and LE/LX readers take it from there.

#![no_std]
#![warn(missing_docs)]

use hexcavator_core::{Error, ErrorKind, Result, U16Le, U32Le, pod, read_at, read_slice_at};

pod! {
    /// The original DOS 2.0 header: the first 28 bytes of every MZ file.
    #[derive(Debug)]
    pub struct DosHeader {
        /// `MZ` (or, rarely, `ZM`).
        pub magic: [u8; 2],
        /// Bytes used in the last 512-byte page; 0 means the whole page.
        pub bytes_on_last_page: U16Le,
        /// File size in 512-byte pages, including the partial last page.
        pub pages: U16Le,
        /// Entries in the relocation table.
        pub relocation_count: U16Le,
        /// Header size, including the relocation table, in 16-byte paragraphs.
        pub header_paragraphs: U16Le,
        /// Memory needed beyond the load module, in paragraphs, at least.
        pub min_extra_paragraphs: U16Le,
        /// ... and at most.
        pub max_extra_paragraphs: U16Le,
        /// The initial stack segment, relative to the load module.
        pub initial_ss: U16Le,
        /// The initial stack pointer.
        pub initial_sp: U16Le,
        /// The checksum (rarely set).
        pub checksum: U16Le,
        /// The entry point's offset.
        pub initial_ip: U16Le,
        /// The entry point's segment, relative to the load module.
        pub initial_cs: U16Le,
        /// File offset of the relocation table.
        pub relocation_table: U16Le,
        /// The overlay number (0: the main program).
        pub overlay: U16Le,
    }

    /// Fields that follow the DOS header in "new" executables (offsets
    /// 0x1C..0x40). Present when the file is at least 64 bytes long.
    #[derive(Debug)]
    pub struct ExtendedDosHeader {
        /// Reserved.
        pub reserved1: [U16Le; 4],
        /// The OEM's identifier, for `oem_info`.
        pub oem_id: U16Le,
        /// OEM-specific information.
        pub oem_info: U16Le,
        /// Reserved.
        pub reserved2: [U16Le; 10],
        /// File offset of the new header (`e_lfanew`).
        pub new_header: U32Le,
    }

    /// One entry of the DOS relocation table: a far pointer, relative to the
    /// start of the load module, to a segment word that needs fixing up.
    #[derive(Debug)]
    pub struct Relocation {
        /// The word's offset in its segment.
        pub offset: U16Le,
        /// Its segment, relative to the load module.
        pub segment: U16Le,
    }
}

/// The kind of header that `e_lfanew` points to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NewHeaderKind {
    /// `PE\0\0`: Windows NT and later.
    Pe,
    /// `NE`: 16-bit Windows and OS/2 1.x.
    Ne,
    /// `LE`: Windows VxDs and 386 DOS extenders.
    Le,
    /// `LX`: 32-bit OS/2.
    Lx,
}

impl NewHeaderKind {
    /// Its signature, as text (`PE`, `NE`, `LE`, `LX`).
    pub const fn name(self) -> &'static str {
        match self {
            NewHeaderKind::Pe => "PE",
            NewHeaderKind::Ne => "NE",
            NewHeaderKind::Le => "LE",
            NewHeaderKind::Lx => "LX",
        }
    }
}

/// A new header found via `e_lfanew`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NewHeader {
    /// Which header it is.
    pub kind: NewHeaderKind,
    /// File offset of the signature.
    pub offset: u64,
}

/// A parsed MZ executable.
#[derive(Clone, Copy, Debug)]
pub struct MzFile<'data> {
    data: &'data [u8],
    header: &'data DosHeader,
    extended: Option<&'data ExtendedDosHeader>,
}

impl<'data> MzFile<'data> {
    /// Parses the DOS header of `data` (and the extended header, if the
    /// file is long enough).
    pub fn parse(data: &'data [u8]) -> Result<Self> {
        let header: &DosHeader = read_at(data, 0)?;
        if &header.magic != b"MZ" && &header.magic != b"ZM" {
            return Err(Error::new(ErrorKind::BadMagic, 0, "DOS header"));
        }
        let extended = read_at(data, size_of::<DosHeader>() as u64).ok();
        Ok(Self {
            data,
            header,
            extended,
        })
    }

    /// The file's bytes.
    #[inline]
    pub fn data(&self) -> &'data [u8] {
        self.data
    }

    /// The DOS header.
    #[inline]
    pub fn header(&self) -> &'data DosHeader {
        self.header
    }

    /// The extended header, if the file has one.
    #[inline]
    pub fn extended_header(&self) -> Option<&'data ExtendedDosHeader> {
        self.extended
    }

    /// The size of the header, in bytes, as declared.
    #[inline]
    pub fn header_size(&self) -> u64 {
        u64::from(self.header.header_paragraphs.get()) * 16
    }

    /// The size of the DOS image (header plus load module), in bytes, as
    /// declared by the page counts. It may exceed the file size if the file
    /// is truncated, or be less if the file has an overlay or a new header.
    pub fn image_size(&self) -> u64 {
        let pages = u64::from(self.header.pages.get());
        let last = u64::from(self.header.bytes_on_last_page.get());
        if last == 0 || pages == 0 {
            pages * 512
        } else {
            (pages - 1) * 512 + last
        }
    }

    /// The file range of the load module (the code and data DOS loads),
    /// clamped to the file.
    pub fn load_module(&self) -> core::ops::Range<u64> {
        let len = self.data.len() as u64;
        let end = self.image_size().min(len);
        let start = self.header_size().min(end);
        start..end
    }

    /// The DOS relocation table.
    pub fn relocations(&self) -> Result<&'data [Relocation]> {
        read_slice_at(
            self.data,
            u64::from(self.header.relocation_table.get()),
            u64::from(self.header.relocation_count.get()),
        )
    }

    /// The new header that `e_lfanew` points to, if it has a recognized
    /// signature. A plain DOS program has none; its `e_lfanew` bytes are
    /// usually part of its code or relocation table.
    pub fn new_header(&self) -> Option<NewHeader> {
        let offset = u64::from(self.extended?.new_header.get());
        if offset == 0 {
            return None;
        }
        let signature: &[u8; 4] = read_at(self.data, offset).ok()?;
        let kind = match signature {
            b"PE\0\0" => NewHeaderKind::Pe,
            [b'N', b'E', ..] => NewHeaderKind::Ne,
            [b'L', b'E', ..] => NewHeaderKind::Le,
            [b'L', b'X', ..] => NewHeaderKind::Lx,
            _ => return None,
        };
        Some(NewHeader { kind, offset })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate alloc;
    use alloc::vec::Vec;

    fn dos_exe() -> Vec<u8> {
        let mut v = Vec::new();
        for w in [
            0x5A4Du16, 0x50, 1, 1, 2, 0x10, 0xFFFF, 0, 0xB8, 0, 0, 0, 0x1C, 0,
        ] {
            v.extend_from_slice(&w.to_le_bytes());
        }
        v.extend_from_slice(&[0x10, 0, 0, 0]); // one relocation: 0000:0010
        v.resize(0x20, 0);
        v.extend_from_slice(&[0xB4, 0x4C, 0xCD, 0x21]); // mov ah,4Ch / int 21h
        v.resize(0x50, 0x90);
        v
    }

    #[test]
    fn plain_dos_program() {
        let data = dos_exe();
        let mz = MzFile::parse(&data).unwrap();
        assert_eq!(mz.header_size(), 0x20);
        assert_eq!(mz.image_size(), 0x50);
        assert_eq!(mz.load_module(), 0x20..0x50);
        let relocs = mz.relocations().unwrap();
        assert_eq!(relocs.len(), 1);
        assert_eq!((relocs[0].segment.get(), relocs[0].offset.get()), (0, 0x10));
        // The bytes at 0x3C are code, not a pointer to a new header.
        assert_eq!(mz.new_header(), None);
    }

    #[test]
    fn new_headers() {
        for (sig, kind) in [
            (&b"PE\0\0"[..], NewHeaderKind::Pe),
            (b"NE\x05\x0a", NewHeaderKind::Ne),
            (b"LE\0\0", NewHeaderKind::Le),
            (b"LX\0\0", NewHeaderKind::Lx),
        ] {
            let mut data = dos_exe();
            data.resize(0x80, 0);
            data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
            data.extend_from_slice(sig);
            let mz = MzFile::parse(&data).unwrap();
            assert_eq!(mz.new_header(), Some(NewHeader { kind, offset: 0x80 }));
        }
    }

    #[test]
    fn malformed() {
        assert_eq!(MzFile::parse(b"MZ").unwrap_err().kind, ErrorKind::Truncated);
        assert_eq!(
            MzFile::parse(&[0; 64]).unwrap_err().kind,
            ErrorKind::BadMagic
        );
        // A short but valid DOS header has no extended header.
        let data = dos_exe();
        let mz = MzFile::parse(&data[..0x30]).unwrap();
        assert!(mz.extended_header().is_none());
        assert_eq!(mz.load_module(), 0x20..0x30);
        // A new-header pointer past the end of the file is ignored.
        let mut data = dos_exe();
        data[0x3C..0x40].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
        assert_eq!(MzFile::parse(&data).unwrap().new_header(), None);
    }
}
