use super::*;
use crate::testimage::{Buf, IMAGE_BASE, SECTION_RVA, image};

const R: u32 = SECTION_RVA;

fn cstr(b: &mut Buf, at: usize, s: &str) {
    b.bytes(at, s.as_bytes()).bytes(at + s.len(), &[0]);
}

/// (offset in the section, size, kind, name).
fn list(data: &[u8]) -> Vec<(u32, u64, SymbolKind, String)> {
    let pe = PeFile::parse(data).unwrap();
    symbols(&pe)
        .into_iter()
        .map(|s| (s.addr as u32 - R, s.size.file, s.kind, s.name))
        .collect()
}

fn own(v: &[(u32, u64, SymbolKind, &str)]) -> Vec<(u32, u64, SymbolKind, String)> {
    v.iter()
        .map(|&(a, s, k, n)| (a, s, k, n.to_string()))
        .collect()
}

#[test]
fn imports_directories_and_guard_tables() {
    use SymbolKind::*;
    let mut b = Buf::default();
    // Imports: KERNEL32.dll (a name and an ordinal), NOINT.dll (no import
    // name table), and the terminator.
    b.u32(0x00, R + 0x100).u32(0x0C, R + 0x200);
    b.u32(0x14 + 0x0C, R + 0x210);
    b.u64(0x100, u64::from(R + 0x300))
        .u64(0x108, (1 << 63) | 7)
        .u64(0x110, 0);
    cstr(&mut b, 0x200, "KERNEL32.dll");
    cstr(&mut b, 0x210, "NOINT.dll");
    b.u16(0x300, 5);
    cstr(&mut b, 0x302, "Foo");
    // Delay imports: DELAY.dll, then the terminator.
    b.u32(0x400, 1)
        .u32(0x404, R + 0x500)
        .u32(0x408, R + 0x600)
        .u32(0x40C, R + 0x700)
        .u32(0x410, R + 0x800);
    cstr(&mut b, 0x500, "DELAY.dll");
    b.u64(0x700, 0xDEAD).u64(0x800, u64::from(R + 0x900));
    b.u16(0x900, 1);
    cstr(&mut b, 0x902, "Bar");
    // Debug directory: CodeView data, an empty entry (not shown), and
    // repro data.
    let entry = |b: &mut Buf, i: usize, kind: u32, rva: u32, size: u32| {
        let e = 0xA00 + 28 * i;
        b.u32(e + 12, kind).u32(e + 16, size).u32(e + 20, rva);
    };
    entry(&mut b, 0, 2, R + 0xB00, 0x20);
    entry(&mut b, 1, 99, R + 0xB40, 0);
    entry(&mut b, 2, 16, R + 0xB50, 4);
    // Load config (x64) with both guard tables, one byte of flags each.
    let lc = 0xD00;
    b.u32(lc, 0x140)
        .u64(lc + 0x80, IMAGE_BASE + u64::from(R + 0xE00))
        .u64(lc + 0x88, 3)
        .u32(lc + 0x90, 1 << 28)
        .u64(lc + 0xA0, IMAGE_BASE + u64::from(R + 0xE20))
        .u64(lc + 0xA8, 2);
    b.bytes(0xF00, &[0]);
    let data = image(
        true,
        &b.0,
        &[
            (directory::EXPORT, R + 0xC40, 0x28),
            (directory::IMPORT, R, 60),
            (directory::BASERELOC, R + 0xC00, 0x0C),
            (directory::DEBUG, R + 0xA00, 84),
            (directory::LOAD_CONFIG, R + 0xD00, 0x140),
            (directory::DELAY_IMPORT, R + 0x400, 64),
        ],
    );
    assert_eq!(
        list(&data),
        own(&[
            (
                0x000,
                20,
                ImportDescriptor,
                "[import descriptor] KERNEL32.dll"
            ),
            (0x014, 20, ImportDescriptor, "[import descriptor] NOINT.dll"),
            (
                0x028,
                20,
                ImportDescriptor,
                "[import descriptor] null terminator"
            ),
            (
                0x100,
                8,
                ImportThunk,
                "[import thunk] KERNEL32.dll Foo, ordinal 5"
            ),
            (
                0x108,
                8,
                ImportThunk,
                "[import thunk] KERNEL32.dll Ordinal 7"
            ),
            (
                0x110,
                8,
                ImportThunk,
                "[import thunk] KERNEL32.dll null terminator, ordinal 0"
            ),
            (0x200, 13, ImportString, "`string': \"KERNEL32.dll\""),
            (0x210, 10, ImportString, "`string': \"NOINT.dll\""),
            (0x300, 6, ImportByName, "`string': \"Foo\""),
            (0x400, 32, ImportDescriptor, "[import descriptor] DELAY.dll"),
            (
                0x420,
                32,
                ImportDescriptor,
                "[import descriptor] null terminator"
            ),
            (0x500, 10, ImportString, "`string': \"DELAY.dll\""),
            (
                0x700,
                8,
                ImportThunk,
                "[import thunk] DELAY.dll Bar, ordinal 1"
            ),
            (
                0x708,
                8,
                ImportThunk,
                "[import thunk] DELAY.dll IAT null terminator, ordinal 0"
            ),
            (
                0x800,
                8,
                ImportThunk,
                "[import thunk] DELAY.dll Bar, ordinal 1"
            ),
            (
                0x808,
                8,
                ImportThunk,
                "[import thunk] DELAY.dll INT null terminator, ordinal 0"
            ),
            (0x900, 6, ImportByName, "`string': \"Bar\""),
            (0xA00, 84, PeDirectory, "[PE Directory] Debug"),
            (
                0xB00,
                0x20,
                PeDirectory,
                "[PE Directory] [Debug Directory] CodeView"
            ),
            (
                0xB50,
                4,
                PeDirectory,
                "[PE Directory] [Debug Directory] Repro"
            ),
            (
                0xC00,
                0x0C,
                PeDirectory,
                "[PE Directory] Base Relocation Table"
            ),
            (0xC40, 0x28, PeDirectory, "[PE Directory] Exports"),
            (0xD00, 0x140, PeDirectory, "[PE Directory] Load Config"),
            (0xE00, 15, LoadConfigTable, "FID Table"),
            (0xE20, 10, LoadConfigTable, "IAT Address-Taken Table"),
        ])
    );
}

/// Visual C++ 6 delay-load descriptors hold addresses, not RVAs; PE32
/// thunks are 4 bytes.
#[test]
fn address_based_delay_imports() {
    use SymbolKind::*;
    let va = |rva: u32| IMAGE_BASE as u32 + R + rva;
    let mut b = Buf::default();
    b.u32(0x04, va(0x100))
        .u32(0x0C, va(0x200))
        .u32(0x10, va(0x300));
    cstr(&mut b, 0x100, "OLD.dll");
    b.u32(0x300, va(0x400))
        .u32(0x304, 0x8000_0002)
        .u32(0x308, 0);
    b.u16(0x400, 3);
    cstr(&mut b, 0x402, "Baz");
    b.bytes(0x500, &[0]);
    let data = image(false, &b.0, &[(directory::DELAY_IMPORT, R, 64)]);
    assert_eq!(
        list(&data),
        own(&[
            (0x000, 32, ImportDescriptor, "[import descriptor] OLD.dll"),
            (
                0x020,
                32,
                ImportDescriptor,
                "[import descriptor] null terminator"
            ),
            (0x100, 8, ImportString, "`string': \"OLD.dll\""),
            (
                0x200,
                4,
                ImportThunk,
                "[import thunk] OLD.dll Baz, ordinal 3"
            ),
            (0x204, 4, ImportThunk, "[import thunk] OLD.dll Ordinal 2"),
            (
                0x208,
                4,
                ImportThunk,
                "[import thunk] OLD.dll IAT null terminator, ordinal 0"
            ),
            (
                0x300,
                4,
                ImportThunk,
                "[import thunk] OLD.dll Baz, ordinal 3"
            ),
            (0x304, 4, ImportThunk, "[import thunk] OLD.dll Ordinal 2"),
            (
                0x308,
                4,
                ImportThunk,
                "[import thunk] OLD.dll INT null terminator, ordinal 0"
            ),
            (0x400, 6, ImportByName, "`string': \"Baz\""),
        ])
    );
}

#[test]
fn tables_end_at_the_image_end() {
    // A name table running off the end of the image, and descriptors
    // claimed past it.
    let mut b = Buf::default();
    b.u32(0x00, R + 0x1F8).u32(0x0C, R + 0x100);
    cstr(&mut b, 0x100, "A.dll");
    b.u64(0x1F8, u64::from(R + 0x100));
    let data = image(true, &b.0, &[(directory::IMPORT, R, 0xFFFF_FFF0)]);
    let pe = PeFile::parse(&data).unwrap();
    let s = symbols(&pe);
    assert!(s.iter().any(|s| s.name == "[import descriptor] A.dll"));
    // Exports with no size, and no directories at all.
    let data = image(true, &b.0, &[(directory::EXPORT, R, 0)]);
    assert!(list(&data).is_empty());
}

#[test]
fn debug_type_names() {
    assert_eq!(debug_type_name(2), "CodeView");
    assert_eq!(debug_type_name(12), "VCFeature");
    assert_eq!(debug_type_name(20), "ExtendedDllCharacteristics");
    assert_eq!(debug_type_name(99), "99");
}
