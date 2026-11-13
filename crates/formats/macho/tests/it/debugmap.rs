//! The debug map of testdata/macho/oso's images (see
//! tools/macho/build.cmd): each object, and its functions' and variables'
//! addresses and sizes as llvm-nm -ap shows the STABS entries.

use hexcavator_macho::MachO;

fn testdata(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata/macho/oso")
        .join(name)
}

#[test]
fn objects_functions_and_variables() {
    let data = std::fs::read(testdata("oso-arm64")).unwrap();
    let m = MachO::parse(&data).unwrap();
    let map = m.debug_map();
    let paths: Vec<&[u8]> = map.iter().map(|o| o.path).collect();
    assert_eq!(
        paths,
        [
            &b"program-arm64.o"[..],
            b"libsecond-arm64.a(second-arm64.o)"
        ]
    );
    let sym = |o: usize, name: &str| {
        *map[o]
            .symbols
            .iter()
            .find(|s| s.name == name.as_bytes())
            .unwrap_or_else(|| panic!("{name}"))
    };
    // Functions: address, then size (the nameless N_FUN).
    let f = sym(0, "_compute");
    assert_eq!((f.addr, f.size), (0x1_0000_04bc, Some(0x70)));
    let f = sym(1, "_second_sum");
    assert_eq!((f.addr, f.size), (0x1_0000_057c, Some(0x40)));
    // Statics (N_STSYM) and globals (N_GSYM).
    let d = sym(0, "_hidden_state");
    assert_eq!((d.addr, d.size), (0x1_0000_50a4, None));
    assert_eq!(sym(0, "_counter").addr, 0x1_0000_4000);
    assert_eq!(sym(1, "_second_table").addr, 0x1_0000_4004);
    // The objects' modification times: lld writes none (0), for builds
    // that reproduce.
    assert!(map.iter().all(|o| o.mtime == 0));
}

#[test]
fn images_without_a_debug_map() {
    // A dSYM-less image of no STABS (a dylib linked without -g objects).
    let data = std::fs::read(testdata("../pointers-arm64.dylib")).unwrap();
    assert!(MachO::parse(&data).unwrap().debug_map().is_empty());
    // (The other image's, for comparison.)
    let data = std::fs::read(testdata("oso-x86_64")).unwrap();
    let m = MachO::parse(&data).unwrap();
    assert_eq!(m.debug_map().len(), 2);
}
