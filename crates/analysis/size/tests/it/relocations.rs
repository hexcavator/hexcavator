//! An image's relocations (hexcavator_size::relocations): ELF's (RELA and
//! RELR), PE's base relocations, Mach-O's fixups (chained, and opcodes),
//! each with its type, where it is, what it points to, and its share of
//! its table; and the pointer tables they make.

use hexcavator_image::Image;
use hexcavator_size::relocations::{
    containing, image_symbols, merge_symbols, pointer_tables, relocations,
};

fn read(rel: &str) -> Vec<u8> {
    let p = format!("{}/../../../testdata/{rel}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

#[test]
fn elf_rela_and_relr() {
    // The same 9 relative relocations, as RELA (24 bytes each) and packed
    // as RELR (24 bytes in all).
    let data = read("elf/relr-rela.so");
    let r = relocations(&Image::parse(&data).unwrap());
    assert_eq!(r.word, 8);
    assert_eq!(r.tables.len(), 1);
    assert_eq!(
        (
            r.tables[0].name.as_str(),
            r.tables[0].size,
            r.tables[0].entries
        ),
        (".rela.dyn", 216, 9)
    );
    assert!(
        r.list
            .iter()
            .all(|x| x.kind == "R_X86_64_RELATIVE" && x.relative && x.target.is_some())
    );
    assert!(r.list.windows(2).all(|w| w[0].addr <= w[1].addr));
    assert_eq!(r.share(&r.list[0]), 24.0);
    // (Where they are, from the first: the links lay out a little apart.)
    let apart = |r: &hexcavator_size::relocations::Relocations| -> Vec<u64> {
        r.list.iter().map(|x| x.addr - r.list[0].addr).collect()
    };
    let rela = apart(&r);
    let data = read("elf/relr.so");
    let r = relocations(&Image::parse(&data).unwrap());
    assert_eq!((r.tables[0].name.as_str(), r.total()), (".relr.dyn", 24));
    assert!(r.list.iter().all(|x| x.kind == "RELR"));
    // (The same places, each pointing somewhere.)
    assert_eq!(rela, apart(&r));
    assert!(r.list.iter().all(|x| x.target.is_some()));
    assert!((r.cost(0..r.list.len()) - 24.0).abs() < 1e-9);
}

#[test]
fn elf_symbolic() {
    // libexp.so's calls to itself through the PLT: JUMP_SLOTs, each of
    // the symbol it binds.
    let data = read("linkopts/libexp.so");
    let r = relocations(&Image::parse(&data).unwrap());
    assert_eq!(r.list.len(), 11);
    assert!(
        r.list
            .iter()
            .all(|x| x.kind == "R_X86_64_JUMP_SLOT" && !x.relative)
    );
    assert!(
        r.list
            .iter()
            .any(|x| x.symbol.as_deref() == Some("_Z8exp_usedi"))
    );
}

#[test]
fn pe_base_relocations() {
    let data = read("xref/xref-x64.exe");
    let image = Image::parse(&data).unwrap();
    let r = relocations(&image);
    // 62 DIR64 relocations in a 144-byte .reloc (blocks' headers and
    // padding among its bytes); targets as RVAs.
    assert_eq!(r.list.len(), 62);
    assert_eq!(
        (r.tables[0].name.as_str(), r.tables[0].size),
        (".reloc", 144)
    );
    assert!(r.list.iter().all(|x| x.kind == "DIR64"));
    let end = image
        .sections()
        .iter()
        .map(|s| s.addr + s.vm_size)
        .max()
        .unwrap();
    assert!(r.list.iter().all(|x| x.target.is_some_and(|t| t < end)));
}

#[test]
fn macho_fixups() {
    // The same 9 rebases and a bind, chained and as opcodes (llvm-objdump's
    // account: pointers-arm64.dylib.fixups.txt).
    for (name, tables) in [
        ("macho/pointers-arm64.dylib", vec![("chained fixups", 10)]),
        (
            "macho/pointers-arm64-opcodes.dylib",
            vec![("rebase opcodes", 9), ("bind opcodes", 1)],
        ),
    ] {
        let data = read(name);
        let r = relocations(&Image::parse(&data).unwrap());
        let t: Vec<(&str, u64)> = r
            .tables
            .iter()
            .map(|t| (t.name.as_str(), t.entries))
            .collect();
        assert_eq!(t, tables, "{name}");
        let rebases: Vec<(u64, Option<u64>)> = r
            .list
            .iter()
            .filter(|x| x.kind == "rebase")
            .map(|x| (x.addr & 0xFFFF, x.target.map(|t| t & 0xFFFF)))
            .collect();
        assert_eq!(rebases.len(), 9, "{name}");
        assert_eq!(rebases[0], (0x4000, Some(0x62B8)), "{name}");
        let bind = r.list.iter().find(|x| x.kind == "bind").unwrap();
        assert_eq!(
            (bind.addr & 0xFFFF, bind.symbol.as_deref()),
            (0x62B0, Some("_imported"))
        );
    }
}

#[test]
fn pointer_tables_and_symbols() {
    // A PE image's vtables: their pointers, relocated.
    let data = read("xref/xref-x64.exe");
    let image = Image::parse(&data).unwrap();
    let r = relocations(&image);
    // (No symbol table in a PE image: none of its own.)
    assert!(image_symbols(&image).is_empty());
    let symbols = vec![(0u64, 0x10_0000u64, "everything".to_string())];
    let t = pointer_tables(&r, &symbols, 1);
    assert_eq!(t.len(), 1);
    assert_eq!(t[0].pointers, 62);
    assert_eq!(t[0].narrower, 62 * 4);
    assert!((t[0].relocations - 144.0).abs() < 1e-9);
    // Fewer than the minimum: none.
    assert!(pointer_tables(&r, &symbols, 63).is_empty());
    // Merged: the second's unless one of the first's holds it whole.
    let m = merge_symbols(
        vec![(0x10, 0x20, "a".into())],
        vec![
            (0x12, 0x18, "inside".into()),
            (0x10, 0x30, "around".into()),
            (0x40, 0x50, "b".into()),
        ],
    );
    let names: Vec<&str> = m.iter().map(|s| s.2.as_str()).collect();
    assert_eq!(names.len(), 3, "{names:?}");
    assert!(!names.contains(&"inside"));
    // What holds an address: the last to start that reaches past it.
    let at = |a: u64| containing(&m, a).map(|i| m[i].2.as_str());
    assert_eq!(at(0x28), Some("around"));
    assert_eq!(at(0x44), Some("b"));
    assert_eq!(at(0x38), None);
    assert_eq!(at(0x8), None);
    // An ELF image's own symbols: by start, with sizes.
    let data = read("linkopts/libexp.so");
    let s = image_symbols(&Image::parse(&data).unwrap());
    assert!(s.windows(2).all(|w| w[0].0 <= w[1].0));
    assert!(s.iter().any(|x| x.2 == "_Z8exp_usedi" && x.1 > x.0));
}
