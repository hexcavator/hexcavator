extern crate std;
use std::vec::Vec;

use super::*;
use crate::consts::{machine, storage_class};

/// A little-endian byte buffer that grows as fields are written.
#[derive(Default)]
struct Buf(Vec<u8>);

impl Buf {
    fn bytes(&mut self, offset: usize, bytes: &[u8]) -> &mut Self {
        if self.0.len() < offset + bytes.len() {
            self.0.resize(offset + bytes.len(), 0);
        }
        self.0[offset..offset + bytes.len()].copy_from_slice(bytes);
        self
    }
    fn u16(&mut self, offset: usize, v: u16) -> &mut Self {
        self.bytes(offset, &v.to_le_bytes())
    }
    fn u32(&mut self, offset: usize, v: u32) -> &mut Self {
        self.bytes(offset, &v.to_le_bytes())
    }
    fn u64(&mut self, offset: usize, v: u64) -> &mut Self {
        self.bytes(offset, &v.to_le_bytes())
    }
    #[allow(clippy::too_many_arguments)]
    fn section(
        &mut self,
        offset: usize,
        name: &[u8],
        vsize: u32,
        va: u32,
        raw: u32,
        ptr: u32,
        flags: u32,
    ) {
        self.bytes(offset, name)
            .u32(offset + 8, vsize)
            .u32(offset + 12, va)
            .u32(offset + 16, raw)
            .u32(offset + 20, ptr)
            .u32(offset + 36, flags);
    }
}

/// A minimal PE32+ DLL: two sections, with a debug directory in `.rdata`
/// holding a single REPRO entry.
fn image64() -> Vec<u8> {
    let mut b = Buf::default();
    b.bytes(0, b"MZ").u32(0x3C, 0x80).bytes(0x80, b"PE\0\0");
    // File header.
    b.u16(0x84, machine::AMD64)
        .u16(0x86, 2)
        .u32(0x88, 0x1234_5678)
        .u16(0x94, 0xF0)
        .u16(0x96, 0x2022);
    // Optional header.
    let o = 0x98;
    b.u16(o, magic::PE32_PLUS)
        .bytes(o + 2, &[14, 38])
        .u32(o + 16, 0x1010) // entry point
        .u32(o + 20, 0x1000) // base of code
        .u64(o + 24, 0x1_8000_0000)
        .u32(o + 32, 0x1000)
        .u32(o + 36, 0x200)
        .u32(o + 56, 0x3000) // size of image
        .u32(o + 60, 0x200) // size of headers
        .u16(o + 68, 3)
        .u64(o + 72, 0x10_0000)
        .u32(o + 108, 16);
    // Debug directory entry.
    b.u32(o + 112 + 6 * 8, 0x2000).u32(o + 112 + 6 * 8 + 4, 28);
    let s = o + 0xF0;
    b.section(s, b".text", 0x20, 0x1000, 0x200, 0x200, 0x6000_0020);
    b.section(s + 40, b".rdata", 0x40, 0x2000, 0x200, 0x400, 0x4000_0040);
    b.u32(0x400 + 12, debug_type::REPRO);
    b.bytes(0x5FF, &[0]);
    b.0
}

#[test]
fn parses_image() {
    let data = image64();
    let pe = PeFile::parse(&data).unwrap();
    assert_eq!(pe.kind(), FileKind::Image);
    assert_eq!(pe.machine(), machine::AMD64);
    assert!(pe.is_dll());
    let opt = pe.optional_header().unwrap();
    assert!(opt.is_64());
    assert_eq!(opt.image_base(), Va(0x1_8000_0000));
    assert_eq!(opt.address_of_entry_point(), 0x1010);
    assert_eq!(opt.size_of_stack_reserve(), 0x10_0000);
    assert_eq!(opt.base_of_data(), None);
    assert_eq!(
        (opt.major_linker_version(), opt.minor_linker_version()),
        (14, 38)
    );
    assert_eq!(pe.data_directories().len(), 16);
    assert!(pe.data_directory(directory::EXPORT).is_none());
    assert_eq!(pe.sections().len(), 2);
    assert_eq!(pe.section_name(&pe.sections()[1]), b".rdata");
    assert_eq!(pe.debug_directories().unwrap().len(), 1);
    assert!(pe.is_reproducible());
}

#[test]
fn rva_mapping() {
    let data = image64();
    let pe = PeFile::parse(&data).unwrap();
    assert_eq!(pe.rva_to_offset(Rva(0x10)), Some(0x10)); // headers
    assert_eq!(pe.rva_to_offset(Rva(0x1000)), Some(0x200));
    assert_eq!(pe.rva_to_offset(Rva(0x101F)), Some(0x21F));
    assert_eq!(pe.rva_to_offset(Rva(0x1020)), None); // past the virtual size
    assert_eq!(pe.rva_to_offset(Rva(0x2010)), Some(0x410));
    assert_eq!(pe.rva_to_offset(Rva(0x5000)), None);
    assert_eq!(pe.bytes_at_rva(Rva(0x1000), 0x20).unwrap().len(), 0x20);
    assert!(pe.bytes_at_rva(Rva(0x1000), 0x21).is_err());
    assert!(pe.bytes_at_rva(Rva(0x1010), 0).unwrap().is_empty());
}

#[test]
fn directory_count_is_bounded_by_optional_header_size() {
    let mut data = image64();
    // Claim 100 directories; only 16 fit in the declared optional header.
    data[0x98 + 108..0x98 + 112].copy_from_slice(&100u32.to_le_bytes());
    assert_eq!(PeFile::parse(&data).unwrap().data_directories().len(), 16);
    data[0x98 + 108..0x98 + 112].copy_from_slice(&2u32.to_le_bytes());
    let pe = PeFile::parse(&data).unwrap();
    assert_eq!(pe.data_directories().len(), 2);
    assert!(pe.debug_directories().unwrap().is_empty());
}

#[test]
fn malformed_images() {
    let data = image64();
    // Truncated in the section table.
    let err = PeFile::parse(&data[..0x98 + 0xF0 + 50]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Truncated);
    // Bad optional header magic.
    let mut bad = data.clone();
    bad[0x98] = 0x77;
    assert_eq!(
        PeFile::parse(&bad).unwrap_err().kind,
        ErrorKind::Unsupported
    );
    // No PE signature.
    let mut bad = data.clone();
    bad[0x80] = b'X';
    assert_eq!(PeFile::parse(&bad).unwrap_err().kind, ErrorKind::BadMagic);
    // Every truncation is an error, never a panic.
    for len in 0..data.len() {
        let _ =
            PeFile::parse(&data[..len]).map(|pe| (pe.debug_directories(), pe.is_reproducible()));
    }
}

/// A minimal x64 object with a long section name and a COMDAT section.
fn object() -> Vec<u8> {
    let mut b = Buf::default();
    b.u16(0, machine::AMD64).u16(2, 2).u32(8, 0x100).u32(12, 4);
    b.section(20, b"/4", 0, 0, 0, 0, 0x4210_0040);
    b.section(60, b".text$mn", 0, 0, 0x10, 0xC0, 0x6050_1020);
    // Symbols at 0x100: .text$mn section symbol + 1 aux, then the COMDAT
    // symbol (long name), then an unrelated symbol.
    let sym = |b: &mut Buf, i: usize, name: &[u8], value: u32, section: i16, class: u8, aux: u8| {
        let o = 0x100 + i * 18;
        b.bytes(o, name)
            .u32(o + 8, value)
            .u16(o + 12, section as u16)
            .bytes(o + 16, &[class, aux]);
    };
    sym(&mut b, 0, b".text$mn", 0, 2, storage_class::STATIC, 1);
    sym(
        &mut b,
        2,
        &[0, 0, 0, 0, 16, 0, 0, 0],
        0,
        2,
        storage_class::EXTERNAL,
        0,
    );
    sym(&mut b, 3, b"other", 0, 1, storage_class::STATIC, 0);
    // String table.
    let st = 0x100 + 4 * 18;
    // Offsets: ".debug$S" at 4, "verylongcomdatname" at 16.
    let strings = b"\0\0\0\0.debug$S\0\0\0\0verylongcomdatname\0";
    b.bytes(st, strings)
        .u32(st, u32::try_from(strings.len()).unwrap());
    b.0
}

#[test]
fn parses_object() {
    let data = object();
    let pe = PeFile::parse(&data).unwrap();
    assert_eq!(pe.kind(), FileKind::Object);
    assert!(pe.optional_header().is_none());
    assert_eq!(pe.section_name(&pe.sections()[0]), b".debug$S");
    assert_eq!(pe.section_name(&pe.sections()[1]), b".text$mn");
    let symbols = pe.symbols().unwrap().unwrap();
    assert_eq!(symbols.iter().count(), 3);
    let comdat = symbols.comdat_symbol(2).unwrap();
    assert_eq!(symbols.name(&comdat), Some(&b"verylongcomdatname"[..]));
    assert!(symbols.comdat_symbol(1).is_none());
    assert!(pe.rva_to_offset(Rva(0)).is_none());
}

#[test]
fn section_name_offsets() {
    assert_eq!(decode_decimal_offset(b"1234567"), Some(1_234_567));
    assert_eq!(decode_decimal_offset(b""), None);
    assert_eq!(decode_decimal_offset(b"12a"), None);
    assert_eq!(decode_decimal_offset(b"99999999999"), None);
    assert_eq!(decode_base64_offset(b"AAAAAB"), Some(1));
    assert_eq!(decode_base64_offset(b"AAAABA"), Some(64));
    assert_eq!(decode_base64_offset(b"!"), None);
}

/// A `/bigobj` object: one section, and symbols of 20 bytes, including a
/// section definition whose associated section number needs `HighNumber`.
fn bigobj() -> Vec<u8> {
    let mut b = Buf::default();
    b.u16(0, 0)
        .u16(2, 0xFFFF)
        .u16(4, 2)
        .u16(6, machine::AMD64)
        .u32(8, 0x1234);
    b.bytes(
        12,
        &[
            0xC7, 0xA1, 0xBA, 0xD1, 0xEE, 0xBA, 0xA9, 0x4B, 0xAF, 0x20, 0xFA, 0xF6, 0x6A, 0xA4,
            0xDC, 0xB8,
        ],
    );
    b.u32(44, 1).u32(48, 0x100).u32(52, 3);
    b.section(56, b".text$mn", 0, 0, 0x10, 0xC0, 0x6050_1020);
    // Symbols at 0x100 (20 bytes each): the section symbol, its aux
    // record, then a COMDAT symbol.
    b.bytes(0x100, b".text$mn")
        .u32(0x100 + 8, 0)
        .u32(0x100 + 12, 1)
        .bytes(0x100 + 18, &[storage_class::STATIC, 1]);
    let aux = 0x100 + 20;
    b.u32(aux, 0x10)
        .u16(aux + 4, 2)
        .u16(aux + 6, 0)
        .u32(aux + 8, 0xABCD)
        .u16(aux + 12, 0x0002)
        .bytes(aux + 14, &[5])
        .u16(aux + 16, 0x0001);
    let s = 0x100 + 40;
    b.bytes(s, b"comdat\0\0")
        .u32(s + 8, 0)
        .u32(s + 12, 1)
        .bytes(s + 18, &[storage_class::EXTERNAL, 0]);
    // An empty string table.
    b.u32(0x100 + 60, 4);
    b.0
}

#[test]
fn parses_bigobj() {
    let data = bigobj();
    let pe = PeFile::parse(&data).unwrap();
    assert!(pe.is_bigobj());
    assert_eq!(pe.kind(), FileKind::Object);
    assert_eq!(pe.machine(), machine::AMD64);
    assert_eq!(pe.file_header().time_date_stamp.get(), 0x1234);
    assert_eq!(pe.sections().len(), 1);
    assert_eq!(pe.section_name(&pe.sections()[0]), b".text$mn");
    let symbols = pe.symbols().unwrap().unwrap();
    assert_eq!(symbols.record_size(), 20);
    assert_eq!(symbols.len(), 3);
    let all: Vec<_> = symbols.iter().collect();
    assert_eq!(all.len(), 2);
    let def = all[0].section_definition().unwrap();
    assert_eq!(def.length, 0x10);
    assert_eq!(def.relocations, 2);
    assert_eq!(def.checksum, 0xABCD);
    assert_eq!(def.selection, crate::comdat_select::ASSOCIATIVE);
    assert_eq!(def.number, 0x0001_0002);
    let comdat = symbols.comdat_symbol(1).unwrap();
    assert_eq!(symbols.name(&comdat), Some(&b"comdat"[..]));
    assert_eq!(comdat.index, 2);
    assert!(all[1].section_definition().is_none());
    let one_pass = symbols.comdat_symbols(1);
    assert_eq!(one_pass[1].map(|s| s.index), Some(2));
    // Other anonymous objects (version 0: import objects) are not COFF.
    let mut import = data.clone();
    import[4] = 0;
    assert!(PeFile::parse(&import).is_err());
    // A section count beyond the file.
    let mut bad = data.clone();
    bad[44..48].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    assert!(PeFile::parse(&bad).is_err());
    // A symbol count beyond the file: no table.
    let mut bad = data;
    bad[52..56].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let pe = PeFile::parse(&bad).unwrap();
    assert!(pe.symbols().is_err());
}

#[test]
fn symbol_tables_keep_what_fits() {
    let data = object();
    let pe = PeFile::parse(&data).unwrap();
    let symbols = pe.symbols().unwrap().unwrap();
    assert_eq!(symbols.record_size(), 18);
    assert_eq!(symbols.len(), 4);
    assert!(symbols.get(4).is_none());
    // The section symbol's aux count can't reach past the table.
    let s = symbols.get(0).unwrap();
    assert_eq!(s.aux_count(), 1);
    assert_eq!(s.section, 2);
    let def = s.section_definition().unwrap();
    assert_eq!(def.number, 0);
}
