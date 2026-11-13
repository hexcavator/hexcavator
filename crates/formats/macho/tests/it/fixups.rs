//! Fixups and exports of the dylibs tools/macho/build.cmd links from
//! pointers.c (arm64 and x86-64; chained fixups, and the older rebase and
//! bind opcodes), against llvm-objdump's decoding of each
//! (`*.fixups.txt`).

use hexcavator_macho::{FixupKind, MachO};

fn testdata(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata/macho")
        .join(name)
}

fn hex(s: &str) -> u64 {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap()
}

/// A fixup as objdump lists it: address, and its rebase target or bind
/// (symbol, addend).
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Listed {
    Rebase(u64, Option<u64>),
    Bind(u64, String, i64),
}

/// `--dyld-info` (chained fixups): `segment section address pointer type
/// [addend dylib symbol | vm address]`.
fn chained(text: &str) -> Vec<Listed> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        match f.get(4) {
            Some(&"rebase") => out.push(Listed::Rebase(hex(f[2]), Some(hex(f[5])))),
            Some(&"bind") => out.push(Listed::Bind(
                hex(f[2]),
                f[7].to_string(),
                i64::try_from(hex(f[5])).unwrap(),
            )),
            _ => {}
        }
    }
    out
}

/// `--rebase --bind ...` (opcodes): the tables' rows.
fn opcodes(text: &str) -> Vec<Listed> {
    let mut out = Vec::new();
    let mut table = "";
    for line in text.lines() {
        if line.ends_with("table:") {
            table = if line.starts_with("Rebase") {
                "rebase"
            } else {
                "bind"
            };
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 || !f[2].starts_with("0x") {
            continue;
        }
        match table {
            "rebase" => out.push(Listed::Rebase(hex(f[2]), None)),
            _ if f.len() >= 7 => out.push(Listed::Bind(
                hex(f[2]),
                f[6].to_string(),
                f[4].parse().unwrap(),
            )),
            _ => {}
        }
    }
    out
}

fn ours(m: &MachO<'_>, targets: bool) -> Vec<Listed> {
    let mut v: Vec<Listed> = m
        .fixups()
        .into_iter()
        .map(|f| match f.kind {
            FixupKind::Rebase { target } => Listed::Rebase(f.addr, targets.then_some(target)),
            FixupKind::Bind { symbol, addend, .. } => {
                Listed::Bind(f.addr, String::from_utf8_lossy(symbol).into_owned(), addend)
            }
        })
        .collect();
    v.sort();
    v
}

#[test]
fn chained_fixups_and_opcodes_match_llvm_objdump() {
    for arch in ["arm64", "x86_64"] {
        let name = format!("pointers-{arch}.dylib");
        let data = std::fs::read(testdata(&name)).unwrap();
        let text = std::fs::read_to_string(testdata(&format!("{name}.fixups.txt"))).unwrap();
        let m = MachO::parse(&data).unwrap();
        let mut want = chained(&text);
        want.sort();
        assert_eq!(want.len(), 10, "{name}");
        assert_eq!(ours(&m, true), want, "{name}");

        let name = format!("pointers-{arch}-opcodes.dylib");
        let data = std::fs::read(testdata(&name)).unwrap();
        let text = std::fs::read_to_string(testdata(&format!("{name}.fixups.txt"))).unwrap();
        let m = MachO::parse(&data).unwrap();
        let mut want = opcodes(&text);
        want.sort();
        assert_eq!(want.len(), 10, "{name}");
        assert_eq!(ours(&m, false), want, "{name}");
    }
}

#[test]
fn exports_of_the_dylibs() {
    for name in [
        "pointers-arm64.dylib",
        "pointers-x86_64-opcodes.dylib",
        "libsecond-arm64.dylib",
        // An executable exports its external symbols too.
        "program-arm64",
    ] {
        let data = std::fs::read(testdata(name)).unwrap();
        let m = MachO::parse(&data).unwrap();
        let exports = m.exports();
        let names: Vec<String> = exports
            .iter()
            .map(|e| String::from_utf8_lossy(&e.name).into_owned())
            .collect();
        // The exported symbols are the external defined ones.
        let mut want: Vec<String> = m
            .symbols()
            .iter()
            .filter(|s| s.n_type & 0x01 != 0 && s.is_section_defined() && s.n_type & 0x10 == 0)
            .map(|s| String::from_utf8_lossy(s.name).into_owned())
            .collect();
        want.sort();
        assert_eq!(names, want, "{name}");
        assert!(!names.is_empty());
        // Each at its symbol's address.
        for e in &exports {
            let sym = m
                .symbols()
                .into_iter()
                .find(|s| s.name == e.name.as_slice())
                .unwrap();
            assert_eq!(e.address, Some(sym.n_value), "{name}");
        }
    }
}

#[test]
fn damaged_fixups_do_not_panic() {
    for name in [
        "pointers-arm64.dylib",
        "pointers-x86_64-opcodes.dylib",
        "unwind-arm64.dylib",
    ] {
        let clean = std::fs::read(testdata(name)).unwrap();
        let mut d = clean.clone();
        // The link edit data (fixups, opcodes, trie) lies at the end.
        let from = clean.len().saturating_sub(2048);
        for at in (from..clean.len()).step_by(3) {
            let was = d[at];
            for v in [0x00, 0xFF, was ^ 0x80] {
                d[at] = v;
                if let Ok(m) = MachO::parse(&d) {
                    let _ = (m.fixups(), m.exports(), m.function_starts());
                    let _ = (m.unwind_info(), m.code_signature(), m.entry());
                }
            }
            d[at] = was;
        }
    }
}

fn hex_lines(text: &str) -> Vec<u64> {
    text.lines()
        .take_while(|l| !l.starts_with("Contents of"))
        .filter(|l| l.len() == 16 && l.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(hex)
        .collect()
}

/// Function starts and compact unwind against llvm-objdump
/// (`*.unwind.txt`): the programs', and a dylib's of several frame shapes
/// (tools/macho/unwind.c).
#[test]
fn function_starts_and_unwind_info() {
    for name in [
        "program-arm64",
        "program-x86_64",
        "unwind-arm64.dylib",
        "unwind-x86_64.dylib",
    ] {
        let data = std::fs::read(testdata(name)).unwrap();
        let text = std::fs::read_to_string(testdata(&format!("{name}.unwind.txt"))).unwrap();
        let m = MachO::parse(&data).unwrap();
        assert_eq!(m.function_starts(), hex_lines(&text), "{name}");
        // `[i]: function offset=0x..., encoding[k]=0x...` under the
        // second level indices.
        let want: Vec<(u64, u32)> = text
            .lines()
            .skip_while(|l| !l.contains("Second level index"))
            .filter_map(|l| {
                let (_, rest) = l.split_once("function offset=")?;
                let (f, enc) = rest.split_once(", encoding")?;
                let value = enc.rsplit_once('=')?.1;
                Some((hex(f), u32::try_from(hex(value)).unwrap()))
            })
            .collect();
        match m.unwind_info() {
            Some(u) => {
                let base = if name.starts_with("program") {
                    0x1_0000_0000
                } else {
                    0
                };
                let ours: Vec<(u64, u32)> = u
                    .entries
                    .iter()
                    .map(|e| (e.function - base, e.encoding))
                    .collect();
                assert_eq!(ours, want, "{name}");
                assert!(!want.is_empty());
                assert_eq!(u.version, 1);
            }
            None => assert!(want.is_empty(), "{name}"),
        }
    }
}

/// The code signatures ld64.lld writes (ad hoc, for arm64): a code
/// directory for the file up to the signature, page by page.
#[test]
fn ad_hoc_code_signatures() {
    use hexcavator_macho::info::{CS_HASHTYPE_SHA256, CSMAGIC_CODEDIRECTORY};
    // (A dylib is identified by its install name's leaf.)
    for (name, identifier) in [
        ("program-arm64", "program-arm64"),
        ("pointers-arm64.dylib", "libpointers.dylib"),
        ("unwind-arm64.dylib", "libunwind-test.dylib"),
    ] {
        let data = std::fs::read(testdata(name)).unwrap();
        let m = MachO::parse(&data).unwrap();
        let sig = m.code_signature().expect(name);
        assert!(
            sig.blobs.iter().any(|b| b.magic == CSMAGIC_CODEDIRECTORY),
            "{name}"
        );
        let cd = sig.directory.unwrap();
        assert_eq!(cd.identifier, identifier.as_bytes(), "{name}");
        assert_eq!(
            (cd.hash_type, cd.hash_size),
            (CS_HASHTYPE_SHA256, 32),
            "{name}"
        );
        assert!(cd.page_size.is_power_of_two(), "{name}");
        assert_eq!(
            u64::from(cd.code_slots),
            cd.code_limit.div_ceil(cd.page_size),
            "{name}"
        );
        // The pages signed are the file's, up to the signature.
        let lc = m
            .load_commands()
            .into_iter()
            .find(|c| c.cmd == hexcavator_macho::consts::LC_CODE_SIGNATURE)
            .unwrap();
        let (off, _) = m.linkedit_data(&lc).unwrap();
        assert_eq!(cd.code_limit, u64::from(off), "{name}");
    }
    // x86-64's aren't signed.
    let data = std::fs::read(testdata("program-x86_64")).unwrap();
    assert!(MachO::parse(&data).unwrap().code_signature().is_none());
}
