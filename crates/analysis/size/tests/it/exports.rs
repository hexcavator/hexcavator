//! What exported symbols cost (hexcavator_size::exports), of
//! testdata/linkopts's libexp*.so (and exp-main, which imports exp_used)
//! and macho-plain (an executable exporting its global symbols).

use hexcavator_image::Image;
use hexcavator_size::exports::{Exporter, Imports, exports, imports_of, recommend};

fn read(name: &str) -> Vec<u8> {
    let p = format!(
        "{}/../../../testdata/linkopts/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

#[test]
fn elf_costs() {
    let data = read("libexp.so");
    let image = Image::parse(&data).unwrap();
    let ex = exports(&image).unwrap();
    assert_eq!(ex.exporter, Exporter::ElfShared);
    assert_eq!(ex.name, Some(&b"libexp.so"[..]));
    assert_eq!(ex.list.len(), 13);
    // _Z8exp_usedi: its .dynsym entry (24), its name (13), and its share
    // of .gnu.hash (112 bytes, 13 defined symbols: 8); no .gnu.version.
    let used = ex.list.iter().find(|e| e.name == b"_Z8exp_usedi").unwrap();
    assert_eq!(used.table, 24 + 13 + 8);
    // Called through the PLT: its share of .plt (192 bytes, 11 slots: 17),
    // its .got.plt slot (8), and its JUMP_SLOT relocation (24).
    assert_eq!(used.plt, 17 + 8 + 24);
    assert!(used.function && !used.vague);
    let unused = ex
        .list
        .iter()
        .find(|e| e.name == b"_Z10exp_unusedi")
        .unwrap();
    assert_eq!(unused.plt, 0);
    // Box<T>'s members: weak, so of vague linkage.
    let vague: Vec<&[u8]> = ex.list.iter().filter(|e| e.vague).map(|e| e.name).collect();
    assert_eq!(vague.len(), 8);
    assert!(vague.iter().all(|n| n.starts_with(b"_ZNK3Box")));
}

#[test]
fn importers() {
    // exp-main loads libexp.so (DT_NEEDED) and imports exp_used.
    let main = read("exp-main");
    let names = imports_of(&main, Some(b"libexp.so")).unwrap();
    assert!(names.contains(&b"_Z8exp_usedi".to_vec()), "{names:?}");
    // By file name too; and not an importer of another library.
    assert!(imports_of(&main, Some(b"/opt/lib/libexp.so")).is_some());
    assert!(imports_of(&main, Some(b"libother.so")).is_none());
    // Without a name: whatever it imports.
    assert!(imports_of(&main, None).is_some());
    // Not an image.
    assert!(imports_of(b"not an image", None).is_none());
    // What hiding the rest would save: the four not imported.
    let data = read("libexp.so");
    let image = Image::parse(&data).unwrap();
    let ex = exports(&image).unwrap();
    let imports = Imports {
        importers: 1,
        names: names.into_iter().collect(),
    };
    let name = |n: &[u8]| String::from_utf8_lossy(n).into_owned();
    let recs = recommend(&ex, Some(&imports), &name);
    let hide = recs.iter().find(|r| r.kind == "visibility").unwrap();
    let mut hidden: Vec<&str> = hide.examples.iter().map(|e| e.0.as_str()).collect();
    hidden.sort_unstable();
    assert_eq!(
        hidden,
        [
            "_Z10exp_helperi",
            "_Z10exp_unusedi",
            "_Z14exp_internal_ai",
            "_Z14exp_internal_bi"
        ]
    );
    assert_eq!(hide.saving, hide.examples.iter().map(|e| e.1).sum::<u64>());
}

#[test]
fn macho_executable() {
    let data = read("macho-plain");
    let image = Image::parse(&data).unwrap();
    let ex = exports(&image).unwrap();
    assert_eq!(ex.exporter, Exporter::MachOExecutable);
    // Its global symbols, less __mh_execute_header, each with its share of
    // the exports trie.
    let mut names: Vec<&[u8]> = ex.list.iter().map(|e| e.name).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            &b"__start"[..],
            b"_add_a",
            b"_add_b",
            b"_add_c",
            b"_sink",
            b"_table2",
            b"_unused1",
            b"_unused2"
        ]
    );
    assert!(
        ex.list
            .iter()
            .all(|e| e.table > 0 && e.plt == 0 && !e.vague)
    );
    let name = |n: &[u8]| String::from_utf8_lossy(n).into_owned();
    let recs = recommend(&ex, None, &name);
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].kind, "visibility");
    assert!(
        recs[0]
            .advice
            .starts_with("link with -Wl,-no_exported_symbols")
    );
}

#[test]
fn not_exporters() {
    // An object, and a PE image: none.
    let data = read("macho-funcs.o");
    assert!(exports(&Image::parse(&data).unwrap()).is_none());
    let pe = std::fs::read(format!(
        "{}/../../../testdata/xref/xref-x64.exe",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    assert!(exports(&Image::parse(&pe).unwrap()).is_none());
}
