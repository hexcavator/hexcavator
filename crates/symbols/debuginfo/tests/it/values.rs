//! The format-independent value reader over DWARF: the same source's
//! globals read as the source sets them. (PDB values, and these, are
//! checked against golden trees in tests/values_golden.rs; the reader
//! matched the PDB crate's own, which it replaced, value for value.)

use hexcavator_debuginfo::value::{self, Limits};
use hexcavator_debuginfo::{DebugInfo, TypeRef};
use hexcavator_image::Image;

fn testdata(p: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata")
        .join(p)
}

/// The DWARF build of tools/types/types.cpp: its globals, read, as the
/// MSVC build's are (where the ABIs lay them out alike).
#[test]
fn dwarf_values() {
    let data = std::fs::read(testdata("types/types-x86_64-linux-gnu")).unwrap();
    let image = Image::parse(&data).unwrap();
    let debug = DebugInfo::parse(&data).unwrap();
    let g = debug
        .symbols()
        .unwrap()
        .into_iter()
        .find(|s| s.name == "g_sample")
        .unwrap();
    let bytes = image.bytes_at(g.addr, g.size.unwrap()).unwrap();
    let v = value::read(&debug, TypeRef(g.type_index), bytes, Limits::default());
    let find = |path: &[&str]| -> String {
        let mut at = &v;
        for p in path {
            at = at
                .children
                .iter()
                .find(|c| c.name == *p)
                .unwrap_or_else(|| panic!("{p} in {path:?}"));
        }
        at.text.clone()
    };
    assert_eq!(find(&["padded", "a"]), "97 'a'");
    assert_eq!(find(&["padded", "b"]), "42");
    assert_eq!(find(&["bits", "a"]), "5");
    assert_eq!(find(&["bits", "b"]), "17");
    assert_eq!(find(&["bits", "c"]), "-3");
    assert_eq!(find(&["color"]), "Green (2)");
    assert_eq!(find(&["ratio"]), "1.5");
    assert_eq!(find(&["name"]), "\"abc\"");
    assert_eq!(find(&["numbers", "[1]"]), "-2");
    assert_eq!(find(&["flag"]), "true");
    assert_eq!(find(&["either", "c"]), "101 'e'");
    // The pointer to the string: an address in the image.
    let text = v.children.iter().find(|c| c.name == "text").unwrap();
    assert!(
        text.pointer
            .is_some_and(|p| image.bytes_at(p, 6) == Some(b"hello\0"))
    );
}

#[test]
fn hostile_bytes_and_limits() {
    let data = std::fs::read(testdata("types/types-x86_64-linux-gnu")).unwrap();
    let debug = DebugInfo::parse(&data).unwrap();
    for s in debug.symbols().unwrap() {
        if s.type_index == 0 {
            continue;
        }
        let ty = TypeRef(s.type_index);
        // Too few bytes, none, and tight limits: answers, not panics.
        for bytes in [&[][..], &[0xFF; 3][..], &[0xA5; 256][..]] {
            let _ = value::read(&debug, ty, bytes, Limits::default());
            let tight = Limits {
                elements: 1,
                nodes: 2,
                depth: 1,
            };
            let _ = value::read(&debug, ty, bytes, tight);
        }
    }
}
