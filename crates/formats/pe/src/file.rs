use hexcavator_core::{Error, ErrorKind, Result, Rva, Va, bytes_at, read_at, read_slice_at};
use hexcavator_mz::{MzFile, NewHeaderKind};

use crate::consts::{debug_type, directory, file_characteristics, magic};
use crate::raw::{
    DataDirectory, DebugDirectory, FileHeader, OptionalHeader32, OptionalHeader64, SectionHeader,
};
use crate::symbols::{StringTable, SymbolTable};

/// Whether a file is a linked image or an object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FileKind {
    /// A linked image: an MZ stub, `PE\0\0`, and an optional header.
    Image,
    /// A COFF object: the file header comes first.
    Object,
}

/// The optional header of an image, in either of its two widths.
#[derive(Clone, Copy, Debug)]
pub enum OptionalHeader<'data> {
    Pe32(&'data OptionalHeader32),
    Pe64(&'data OptionalHeader64),
}

macro_rules! common_fields {
    ($($name:ident: $ty:ty),* $(,)?) => {$(
        #[inline]
        pub fn $name(&self) -> $ty {
            match self {
                OptionalHeader::Pe32(h) => h.$name.into(),
                OptionalHeader::Pe64(h) => h.$name.into(),
            }
        }
    )*};
}

impl OptionalHeader<'_> {
    #[inline]
    pub fn is_64(&self) -> bool {
        matches!(self, OptionalHeader::Pe64(_))
    }

    common_fields! {
        magic: u16,
        major_linker_version: u8,
        minor_linker_version: u8,
        size_of_code: u32,
        size_of_initialized_data: u32,
        size_of_uninitialized_data: u32,
        address_of_entry_point: u32,
        base_of_code: u32,
        section_alignment: u32,
        file_alignment: u32,
        major_operating_system_version: u16,
        minor_operating_system_version: u16,
        major_image_version: u16,
        minor_image_version: u16,
        major_subsystem_version: u16,
        minor_subsystem_version: u16,
        win32_version_value: u32,
        size_of_image: u32,
        size_of_headers: u32,
        check_sum: u32,
        subsystem: u16,
        dll_characteristics: u16,
        loader_flags: u32,
        number_of_rva_and_sizes: u32,
    }

    /// `BaseOfData`, which only PE32 has.
    #[inline]
    pub fn base_of_data(&self) -> Option<u32> {
        match self {
            OptionalHeader::Pe32(h) => Some(h.base_of_data.get()),
            OptionalHeader::Pe64(_) => None,
        }
    }

    #[inline]
    pub fn image_base(&self) -> Va {
        Va(match self {
            OptionalHeader::Pe32(h) => u64::from(h.image_base.get()),
            OptionalHeader::Pe64(h) => h.image_base.get(),
        })
    }

    #[inline]
    pub fn size_of_stack_reserve(&self) -> u64 {
        match self {
            OptionalHeader::Pe32(h) => h.size_of_stack_reserve.get().into(),
            OptionalHeader::Pe64(h) => h.size_of_stack_reserve.get(),
        }
    }

    #[inline]
    pub fn size_of_stack_commit(&self) -> u64 {
        match self {
            OptionalHeader::Pe32(h) => h.size_of_stack_commit.get().into(),
            OptionalHeader::Pe64(h) => h.size_of_stack_commit.get(),
        }
    }

    #[inline]
    pub fn size_of_heap_reserve(&self) -> u64 {
        match self {
            OptionalHeader::Pe32(h) => h.size_of_heap_reserve.get().into(),
            OptionalHeader::Pe64(h) => h.size_of_heap_reserve.get(),
        }
    }

    #[inline]
    pub fn size_of_heap_commit(&self) -> u64 {
        match self {
            OptionalHeader::Pe32(h) => h.size_of_heap_commit.get().into(),
            OptionalHeader::Pe64(h) => h.size_of_heap_commit.get(),
        }
    }

    /// The size of the fixed part, before the data directories.
    #[inline]
    fn fixed_size(&self) -> u64 {
        match self {
            OptionalHeader::Pe32(_) => size_of::<OptionalHeader32>() as u64,
            OptionalHeader::Pe64(_) => size_of::<OptionalHeader64>() as u64,
        }
    }
}

/// A PE image or COFF object.
#[derive(Clone, Copy, Debug)]
pub struct PeFile<'data> {
    data: &'data [u8],
    kind: FileKind,
    mz: Option<MzFile<'data>>,
    file_header_offset: u64,
    /// The COFF file header (for `/bigobj`, the equivalent fields of its
    /// header; the section count is `sections.len()`).
    file_header: FileHeader,
    /// A `/bigobj` object: 20-byte symbol records.
    big: bool,
    optional: Option<OptionalHeader<'data>>,
    directories: &'data [DataDirectory],
    sections: &'data [SectionHeader],
    strings: StringTable<'data>,
}

impl<'data> PeFile<'data> {
    /// Parses an image (if `data` starts with `MZ`) or an object.
    pub fn parse(data: &'data [u8]) -> Result<Self> {
        if data.starts_with(b"MZ") {
            Self::parse_image(data)
        } else {
            Self::parse_object(data)
        }
    }

    /// Parses a PE image.
    pub fn parse_image(data: &'data [u8]) -> Result<Self> {
        let mz = MzFile::parse(data)?;
        let new_header = mz
            .new_header()
            .filter(|h| h.kind == NewHeaderKind::Pe)
            .ok_or(Error::new(ErrorKind::BadMagic, 0x3C, "PE signature"))?;
        let file_header_offset = new_header.offset + 4;
        let file_header: &FileHeader = read_at(data, file_header_offset)?;
        let optional_offset = file_header_offset + size_of::<FileHeader>() as u64;
        let optional_size = u64::from(file_header.size_of_optional_header.get());

        let magic: u16 = read_at::<hexcavator_core::U16Le>(data, optional_offset)?.get();
        let optional = match magic {
            magic::PE32 => OptionalHeader::Pe32(read_at(data, optional_offset)?),
            magic::PE32_PLUS => OptionalHeader::Pe64(read_at(data, optional_offset)?),
            _ => {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    optional_offset,
                    "optional header magic",
                ));
            }
        };

        // The directory count is bounded both by the header's own count and
        // by the declared size of the optional header.
        let room =
            optional_size.saturating_sub(optional.fixed_size()) / size_of::<DataDirectory>() as u64;
        let count = u64::from(optional.number_of_rva_and_sizes()).min(room);
        let directories = read_slice_at(data, optional_offset + optional.fixed_size(), count)?;

        let mut file = Self::finish(
            data,
            FileKind::Image,
            file_header_offset,
            *file_header,
            optional_offset + optional_size,
            u64::from(file_header.number_of_sections.get()),
            false,
        )?;
        file.mz = Some(mz);
        file.optional = Some(optional);
        file.directories = directories;
        Ok(file)
    }

    /// Parses a COFF object.
    pub fn parse_object(data: &'data [u8]) -> Result<Self> {
        let file_header: &FileHeader = read_at(data, 0)?;
        // `ANON_OBJECT_HEADER` (import objects, bigobj) has machine 0 and
        // 0xFFFF in the section count's position.
        if file_header.machine.get() == 0 && file_header.number_of_sections.get() == 0xFFFF {
            return Self::parse_anonymous(data);
        }
        let sections_offset =
            size_of::<FileHeader>() as u64 + u64::from(file_header.size_of_optional_header.get());
        let count = u64::from(file_header.number_of_sections.get());
        Self::finish(
            data,
            FileKind::Object,
            0,
            *file_header,
            sections_offset,
            count,
            false,
        )
    }

    /// A `/bigobj` object (`ANON_OBJECT_HEADER_BIGOBJ`, version 2 or later
    /// with the bigobj class ID). Other anonymous objects (import objects,
    /// LTCG intermediate objects) are not COFF objects.
    fn parse_anonymous(data: &'data [u8]) -> Result<Self> {
        /// `{D1BAA1C7-BAEE-4BA9-AF20-FAF66AA4DCB8}`, as stored.
        const BIGOBJ_CLASS: [u8; 16] = [
            0xC7, 0xA1, 0xBA, 0xD1, 0xEE, 0xBA, 0xA9, 0x4B, 0xAF, 0x20, 0xFA, 0xF6, 0x6A, 0xA4,
            0xDC, 0xB8,
        ];
        let header = hexcavator_core::bytes_at(data, 0, 56)?;
        let u16_at = |o: usize| u16::from_le_bytes([header[o], header[o + 1]]);
        let u32_at =
            |o: usize| u32::from_le_bytes([header[o], header[o + 1], header[o + 2], header[o + 3]]);
        if u16_at(4) < 2 || header[12..28] != BIGOBJ_CLASS {
            return Err(Error::new(
                ErrorKind::Unsupported,
                0,
                "anonymous object header (an import object or an LTCG object)",
            ));
        }
        let count = u32_at(44);
        let mut raw = [0u8; 20];
        raw[0..2].copy_from_slice(&header[6..8]); // machine
        raw[2..4].copy_from_slice(&u16::try_from(count).unwrap_or(u16::MAX).to_le_bytes());
        raw[4..8].copy_from_slice(&header[8..12]); // time stamp
        raw[8..12].copy_from_slice(&header[48..52]); // symbol table
        raw[12..16].copy_from_slice(&header[52..56]); // symbol count
        let file_header = *hexcavator_core::from_bytes::<FileHeader>(&raw).expect("20 bytes");
        Self::finish(
            data,
            FileKind::Object,
            0,
            file_header,
            56,
            u64::from(count),
            true,
        )
    }

    fn finish(
        data: &'data [u8],
        kind: FileKind,
        file_header_offset: u64,
        file_header: FileHeader,
        sections_offset: u64,
        section_count: u64,
        big: bool,
    ) -> Result<Self> {
        let sections = read_slice_at(data, sections_offset, section_count)?;
        let record = if big { 20 } else { 18 };
        let strings = match file_header.pointer_to_symbol_table.get() {
            0 => StringTable::default(),
            offset => StringTable::parse(
                data,
                u64::from(offset) + u64::from(file_header.number_of_symbols.get()) * record,
            ),
        };
        Ok(Self {
            data,
            kind,
            mz: None,
            file_header_offset,
            file_header,
            big,
            optional: None,
            directories: &[],
            sections,
            strings,
        })
    }

    #[inline]
    pub fn data(&self) -> &'data [u8] {
        self.data
    }

    #[inline]
    pub fn kind(&self) -> FileKind {
        self.kind
    }

    /// The MZ stub, for images.
    #[inline]
    pub fn mz(&self) -> Option<&MzFile<'data>> {
        self.mz.as_ref()
    }

    #[inline]
    pub fn file_header_offset(&self) -> u64 {
        self.file_header_offset
    }

    /// The COFF file header. For a `/bigobj` object, its header's
    /// equivalent fields (with the section count capped at 0xFFFF:
    /// [`PeFile::sections`] has them all).
    #[inline]
    pub fn file_header(&self) -> &FileHeader {
        &self.file_header
    }

    /// Whether this is a `/bigobj` object (`ANON_OBJECT_HEADER_BIGOBJ`).
    #[inline]
    pub fn is_bigobj(&self) -> bool {
        self.big
    }

    #[inline]
    pub fn machine(&self) -> u16 {
        self.file_header.machine.get()
    }

    #[inline]
    pub fn is_dll(&self) -> bool {
        self.file_header.characteristics.get() & file_characteristics::DLL != 0
    }

    /// The file offsets of the optional header's checksum and of data
    /// directory `index`'s entry (an image's; the entry's only if the
    /// header has room for it): what an Authenticode hash leaves out,
    /// with the certificates themselves.
    pub fn checksum_and_directory_offsets(&self, index: usize) -> Option<(u64, Option<u64>)> {
        let optional = self.optional.as_ref()?;
        let at = self.file_header_offset + size_of::<FileHeader>() as u64;
        let entry = (index < self.directories.len())
            .then(|| at + optional.fixed_size() + (index * size_of::<DataDirectory>()) as u64);
        Some((at + 64, entry))
    }

    /// The optional header, for images.
    #[inline]
    pub fn optional_header(&self) -> Option<&OptionalHeader<'data>> {
        self.optional.as_ref()
    }

    #[inline]
    pub fn data_directories(&self) -> &'data [DataDirectory] {
        self.directories
    }

    /// A data directory, if present and non-empty.
    pub fn data_directory(&self, index: usize) -> Option<&'data DataDirectory> {
        self.directories
            .get(index)
            .filter(|d| d.virtual_address.get() != 0 || d.size.get() != 0)
    }

    #[inline]
    pub fn sections(&self) -> &'data [SectionHeader] {
        self.sections
    }

    /// A section's name, with `/offset` long names resolved through the
    /// string table. Falls back to the raw name if it cannot be resolved.
    pub fn section_name(&self, section: &'data SectionHeader) -> &'data [u8] {
        let raw = section.raw_name();
        let offset = match raw {
            [b'/', b'/', rest @ ..] => decode_base64_offset(rest),
            [b'/', rest @ ..] => decode_decimal_offset(rest),
            _ => None,
        };
        offset.and_then(|o| self.strings.get(o)).unwrap_or(raw)
    }

    /// The COFF symbol table, if the file has one.
    pub fn symbols(&self) -> Result<Option<SymbolTable<'data>>> {
        let offset = self.file_header.pointer_to_symbol_table.get();
        if offset == 0 {
            return Ok(None);
        }
        SymbolTable::parse(
            self.data,
            u64::from(offset),
            u64::from(self.file_header.number_of_symbols.get()),
            self.big,
        )
        .map(Some)
    }

    /// The file offset that holds the byte at `rva`, if any. Bytes in a
    /// section's virtual extent beyond its raw data (zero-fill) have none,
    /// and neither does anything in an object, which has no address space.
    pub fn rva_to_offset(&self, rva: Rva) -> Option<u64> {
        if self.kind == FileKind::Object {
            return None;
        }
        let rva = rva.get();
        for section in self.sections {
            let start = section.virtual_address.get();
            let raw_size = section.size_of_raw_data.get();
            let extent = match section.virtual_size.get() {
                0 => raw_size,
                size => size,
            };
            let delta = rva.wrapping_sub(start);
            if rva >= start && delta < extent {
                return (delta < raw_size)
                    .then(|| u64::from(section.pointer_to_raw_data.get()) + u64::from(delta));
            }
        }
        // The headers are mapped at RVA 0.
        let headers = self.optional.map_or(0, |o| o.size_of_headers());
        (rva < headers).then_some(u64::from(rva))
    }

    /// `size` bytes of file data starting at `rva`. The range must lie within
    /// the raw data of one section (or the headers).
    pub fn bytes_at_rva(&self, rva: Rva, size: u32) -> Result<&'data [u8]> {
        let offset = self.rva_to_offset(rva).ok_or(Error::new(
            ErrorKind::Malformed,
            u64::from(rva.get()),
            "RVA not in file",
        ))?;
        let end = rva.checked_add(size.saturating_sub(1));
        if size > 1 && end.and_then(|e| self.rva_to_offset(e)) != Some(offset + u64::from(size) - 1)
        {
            return Err(Error::new(ErrorKind::Truncated, offset, "RVA range"));
        }
        bytes_at(self.data, offset, u64::from(size))
    }

    /// The RVA of `va`, if it is at or above the image base.
    pub fn va_to_rva(&self, va: Va) -> Option<Rva> {
        let base = self.optional?.image_base().get();
        let rva = va.get().checked_sub(base)?;
        u32::try_from(rva).ok().map(Rva)
    }

    /// `size` bytes of file data starting at `va`.
    pub fn bytes_at_va(&self, va: Va, size: u32) -> Result<&'data [u8]> {
        let rva = self.va_to_rva(va).ok_or(Error::new(
            ErrorKind::Malformed,
            va.get(),
            "VA not in image",
        ))?;
        self.bytes_at_rva(rva, size)
    }

    /// The debug directory entries.
    pub fn debug_directories(&self) -> Result<&'data [DebugDirectory]> {
        let Some(dir) = self.data_directory(directory::DEBUG) else {
            return Ok(&[]);
        };
        let count = u64::from(dir.size.get()) / size_of::<DebugDirectory>() as u64;
        let offset = self
            .rva_to_offset(Rva(dir.virtual_address.get()))
            .ok_or(Error::new(ErrorKind::Malformed, 0, "debug directory RVA"))?;
        read_slice_at(self.data, offset, count)
    }

    /// Whether the image was linked reproducibly (`/Brepro`), in which case
    /// its timestamps are content hashes rather than times.
    pub fn is_reproducible(&self) -> bool {
        self.debug_directories()
            .is_ok_and(|dirs| dirs.iter().any(|d| d.kind.get() == debug_type::REPRO))
    }
}

/// Decodes the decimal offset in a `/nnnnnnn` section name.
fn decode_decimal_offset(digits: &[u8]) -> Option<u32> {
    if digits.is_empty() {
        return None;
    }
    digits.iter().try_fold(0u32, |acc, &d| {
        d.is_ascii_digit()
            .then(|| acc.checked_mul(10)?.checked_add(u32::from(d - b'0')))?
    })
}

/// Decodes the base-64 offset in a `//AAAAAA` section name (used by LLVM for
/// offsets too large for seven decimal digits).
fn decode_base64_offset(digits: &[u8]) -> Option<u32> {
    if digits.is_empty() {
        return None;
    }
    digits.iter().try_fold(0u32, |acc, &d| {
        let value = match d {
            b'A'..=b'Z' => d - b'A',
            b'a'..=b'z' => d - b'a' + 26,
            b'0'..=b'9' => d - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc.checked_mul(64)?.checked_add(u32::from(value))
    })
}

#[cfg(test)]
mod tests;
