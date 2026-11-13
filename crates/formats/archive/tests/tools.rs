//! The test libraries (testdata/coff, from tools/coff/build.cmd) against
//! what Microsoft's tools say of them, saved beside them by the same build:
//! the members, in order (`lib /list`), and the symbol index, each symbol
//! with the member that defines it (`dumpbin /linkermember:2`). Import
//! objects name their DLL.

use std::collections::BTreeSet;
use std::path::PathBuf;

use hexcavator_archive::Archive;

fn coff(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata/coff")
        .join(name)
}

fn text(name: &str) -> String {
    std::fs::read_to_string(coff(name)).unwrap()
}

/// `dumpbin /linkermember:2`'s symbols: each name, with its member's
/// header offset.
fn index(dump: &str) -> BTreeSet<(String, u64)> {
    let mut lines = dump.lines().map(str::trim);
    // "N offsets", then "i offset" lines (1-based, hex).
    lines.by_ref().find(|l| l.ends_with(" offsets")).unwrap();
    let mut offsets = Vec::new();
    for l in lines.by_ref() {
        if l.is_empty() && !offsets.is_empty() {
            break;
        }
        if let Some((i, at)) = l.split_once(char::is_whitespace) {
            assert_eq!(i.parse::<usize>().unwrap(), offsets.len() + 1, "{l}");
            offsets.push(u64::from_str_radix(at.trim(), 16).unwrap());
        }
    }
    // "M public symbols", then "member name" lines.
    let count: usize = lines
        .by_ref()
        .find_map(|l| l.strip_suffix(" public symbols"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let mut out = BTreeSet::new();
    for l in lines {
        if l.is_empty() && !out.is_empty() {
            break;
        }
        if let Some((i, name)) = l.split_once(char::is_whitespace) {
            let i: usize = i.parse().unwrap();
            out.insert((name.trim().to_owned(), offsets[i - 1]));
        }
    }
    assert_eq!(out.len(), count, "dumpbin's count");
    out
}

#[test]
fn libraries_read_as_lib_and_dumpbin_say() {
    for lib in ["objects.lib", "imports.lib"] {
        let data = std::fs::read(coff(lib)).unwrap();
        let ar = Archive::parse(&data).unwrap();
        // `lib /list` lists the members last first.
        let mut want: Vec<String> = text(&format!("{lib}.list.txt"))
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect();
        want.reverse();
        let got: Vec<String> = ar
            .files()
            .map(|m| String::from_utf8_lossy(&m.name).into_owned())
            .collect();
        assert_eq!(got, want, "{lib}: members");

        let want = index(&text(&format!("{lib}.linkermember.txt")));
        let got: BTreeSet<(String, u64)> = ar
            .symbols()
            .iter()
            .map(|s| (String::from_utf8_lossy(s.name).into_owned(), s.member))
            .collect();
        assert_eq!(got, want, "{lib}: symbols");
    }
}

#[test]
fn import_library_members_name_their_dll() {
    use hexcavator_pe::import_object::ImportObject;
    let data = std::fs::read(coff("imports.lib")).unwrap();
    let ar = Archive::parse(&data).unwrap();
    let mut imports = 0;
    for m in ar.files() {
        if ImportObject::is_import_object(m.data) {
            let i = ImportObject::parse(m.data).unwrap();
            assert!(
                i.dll.eq_ignore_ascii_case(b"example.dll"),
                "{:?}",
                String::from_utf8_lossy(i.dll)
            );
            assert!(!i.symbol.is_empty());
            imports += 1;
        } else {
            // (The import descriptor and thunk-data members are objects.)
            hexcavator_pe::PeFile::parse(m.data).unwrap();
        }
    }
    // ByName, ByOrdinal, Renamed, Decorated, Data.
    assert_eq!(imports, 5);
}
