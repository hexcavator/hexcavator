//! The DWARF backend over real files (testdata/elf: DWARF 4 and 5, x86-64
//! and big-endian AArch64, sections plain and compressed), against
//! llvm-dwarfdump's account of each (`*.dwarfdump.txt`, `*.lines.txt`):
//! the compile units, functions and their code, static variables, inline
//! sites, line tables, and parameters in registers.

#![allow(clippy::cast_possible_truncation, reason = "small test files")]

use std::collections::BTreeSet;

use hexcavator_debuginfo::{DebugInfo, Place, SymbolKind, TypeRef, TypeShape};

fn testdata(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata/elf")
        .join(name)
}

/// A DIE as llvm-dwarfdump prints it.
#[derive(Debug, Default)]
struct Die {
    depth: usize,
    tag: String,
    attrs: Vec<(String, String)>,
    /// Its `DW_AT_ranges`, listed on the lines after it: (start, end).
    ranges: Vec<(u64, u64)>,
}

impl Die {
    fn get(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// A name: its own, or its origin's (`(0x2f "helper")`).
    fn name(&self) -> Option<String> {
        if let Some(n) = self.get("DW_AT_name") {
            return Some(n.trim_matches('"').to_string());
        }
        let o = self
            .get("DW_AT_abstract_origin")
            .or_else(|| self.get("DW_AT_specification"))?;
        Some(o.split_once('"')?.1.trim_end_matches('"').to_string())
    }

    fn address(&self, name: &str) -> Option<u64> {
        let v = self.get(name)?;
        u64::from_str_radix(v.strip_prefix("0x")?, 16).ok()
    }
}

fn dies(text: &str) -> Vec<Die> {
    let mut out: Vec<Die> = Vec::new();
    for line in text.lines() {
        if let Some((at, rest)) = line.split_once(": ")
            && at.starts_with("0x")
            && at.len() == 10
        {
            let spaces = rest.len() - rest.trim_start().len();
            out.push(Die {
                depth: spaces.div_ceil(2),
                tag: rest.trim().to_string(),
                attrs: Vec::new(),
                ranges: Vec::new(),
            });
            continue;
        }
        let t = line.trim_start();
        // `[0x0000000000201210, 0x0000000000201280)`, under DW_AT_ranges.
        if let (Some(d), Some(r)) = (out.last_mut(), t.strip_prefix("[0x")) {
            if let Some((a, b)) = r.split_once(", 0x") {
                let b = b.trim_end_matches(')');
                if let (Ok(a), Ok(b)) = (u64::from_str_radix(a, 16), u64::from_str_radix(b, 16)) {
                    d.ranges.push((a, b));
                }
            }
            continue;
        }
        if let (Some(d), Some((name, value))) = (out.last_mut(), t.split_once('\t'))
            && name.starts_with("DW_AT_")
        {
            let value = value.trim();
            let value = value.strip_prefix('(').unwrap_or(value);
            let value = value.strip_suffix(')').unwrap_or(value);
            d.attrs.push((name.to_string(), value.to_string()));
        }
    }
    out
}

/// The line table's rows: (address, line, file, end of sequence).
fn rows(text: &str) -> Vec<Vec<(u64, u64, u64, bool)>> {
    let mut tables = Vec::new();
    for line in text.lines() {
        if line.starts_with("Address ") {
            tables.push(Vec::new());
            continue;
        }
        let Some(hex) = line.strip_prefix("0x") else {
            continue;
        };
        let f: Vec<&str> = hex.split_whitespace().collect();
        if f.len() < 4 {
            continue;
        }
        if let Some(t) = tables.last_mut() {
            t.push((
                u64::from_str_radix(f[0], 16).unwrap(),
                f[1].parse().unwrap(),
                f[3].parse().unwrap(),
                line.contains("end_sequence"),
            ));
        }
    }
    tables
}

const FILES: &[&str] = &[
    "dwarf4-x86_64-linux-gnu",
    "dwarf5-x86_64-linux-gnu",
    "dwarf4-aarch64_be-linux-gnu",
    "dwarf5-aarch64_be-linux-gnu",
];

#[test]
fn matches_llvm_dwarfdump() {
    for name in FILES {
        let data = std::fs::read(testdata(name)).unwrap();
        let text = std::fs::read_to_string(testdata(&format!("{name}.dwarfdump.txt"))).unwrap();
        let theirs = dies(&text);
        let d = DebugInfo::parse(&data).unwrap();
        assert!(d.dwarf().is_some() && d.pdb().is_none());

        // Compile units.
        let cus: Vec<String> = theirs
            .iter()
            .filter(|d| d.tag == "DW_TAG_compile_unit")
            .filter_map(Die::name)
            .collect();
        let ours: Vec<String> = d
            .compilands()
            .unwrap()
            .into_iter()
            .map(|c| c.name)
            .collect();
        assert_eq!(ours, cus, "{name}");

        let symbols = d.symbols().unwrap();
        // Functions: every subprogram with code.
        let mut want = BTreeSet::new();
        for f in theirs.iter().filter(|d| d.tag == "DW_TAG_subprogram") {
            let (Some(low), Some(high)) = (f.address("DW_AT_low_pc"), f.address("DW_AT_high_pc"))
            else {
                continue;
            };
            want.insert((f.name().unwrap(), low, high - low));
        }
        let have: BTreeSet<(String, u64, u64)> = symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Function)
            .map(|s| (s.name.clone(), s.addr, s.size.unwrap()))
            .collect();
        assert_eq!(have, want, "{name}: functions");
        assert!(want.len() >= 5, "{name}");

        // Statics: every variable at a fixed address (or thread-local).
        let mut statics = 0;
        for v in theirs.iter().filter(|d| d.tag == "DW_TAG_variable") {
            let Some(loc) = v.get("DW_AT_location") else {
                continue;
            };
            let tls = loc.contains("tls_address");
            if !(loc.starts_with("DW_OP_addr") || tls) {
                continue;
            }
            let vname = v.name().unwrap();
            let s = symbols
                .iter()
                .find(|s| s.kind == SymbolKind::Data && s.name == vname)
                .unwrap_or_else(|| panic!("{name}: no {vname}"));
            assert_eq!(s.thread_local, tls, "{name} {vname}");
            assert_eq!(
                s.global,
                v.get("DW_AT_external").is_some(),
                "{name} {vname}"
            );
            if let Some(a) = loc.strip_prefix("DW_OP_addr 0x") {
                assert_eq!(
                    s.addr,
                    u64::from_str_radix(a, 16).unwrap(),
                    "{name} {vname}"
                );
            }
            // Its size is its type's.
            assert!(s.size.is_some_and(|n| n > 0), "{name} {vname}");
            statics += 1;
        }
        assert!(statics >= 5, "{name}");

        // Inline sites.
        let inl = d.inline_sites().unwrap();
        let want: BTreeSet<(String, u64, u64)> = theirs
            .iter()
            .filter(|d| d.tag == "DW_TAG_inlined_subroutine")
            .flat_map(|i| {
                let n = i.name().unwrap();
                let mut r = i.ranges.clone();
                if let (Some(low), Some(high)) =
                    (i.address("DW_AT_low_pc"), i.address("DW_AT_high_pc"))
                {
                    r.push((low, high));
                }
                r.into_iter().map(move |(a, b)| (n.clone(), a, b - a))
            })
            .collect();
        let have: BTreeSet<(String, u64, u64)> = inl
            .sites
            .iter()
            .flat_map(|s| {
                let n = inl.inlinees[s.inlinee as usize].clone();
                s.ranges.iter().map(move |&(a, z)| (n.clone(), a, z))
            })
            .collect();
        assert_eq!(have, want, "{name}: inline sites");
        assert!(!want.is_empty());

        // Parameters wholly in a register.
        for (i, f) in theirs.iter().enumerate() {
            if f.tag != "DW_TAG_subprogram" {
                continue;
            }
            let Some(low) = f.address("DW_AT_low_pc") else {
                continue;
            };
            let vars = d.variables(None, low).unwrap().unwrap();
            for p in theirs[i + 1..]
                .iter()
                .take_while(|c| c.depth > f.depth)
                .filter(|c| c.depth == f.depth + 1 && c.tag == "DW_TAG_formal_parameter")
            {
                let Some(loc) = p.get("DW_AT_location") else {
                    continue;
                };
                let Some(reg) = loc
                    .strip_prefix("DW_OP_reg")
                    .and_then(|r| r.split(' ').next())
                else {
                    continue;
                };
                let reg: u16 = reg.parse().unwrap();
                let pname = p.name().unwrap();
                let v = vars
                    .variables
                    .iter()
                    .find(|v| v.name == pname)
                    .unwrap_or_else(|| panic!("{name}: no parameter {pname}"));
                assert!(v.param);
                assert_eq!(v.ranges.len(), 1, "{name} {pname}");
                assert_eq!(v.ranges[0].place, Place::Register(reg));
                assert_eq!(v.ranges[0].start, low);
                // Its type is int's.
                let shape = d.type_shape(TypeRef(v.type_index));
                assert!(
                    matches!(shape, TypeShape::Basic { size: 4, .. }),
                    "{shape:?}"
                );
            }
        }
    }
}

#[test]
fn line_tables_match_llvm_dwarfdump() {
    for name in FILES {
        let data = std::fs::read(testdata(name)).unwrap();
        let text = std::fs::read_to_string(testdata(&format!("{name}.lines.txt"))).unwrap();
        let d = DebugInfo::parse(&data).unwrap();
        let lines = d.source_lines().unwrap();
        // Each row up to the next, but for the ends of sequences.
        let mut want = BTreeSet::new();
        for (unit, table) in rows(&text).iter().enumerate() {
            for w in table.windows(2) {
                let (a, b) = (w[0], w[1]);
                if !a.3 && b.0 > a.0 {
                    want.insert((a.0, b.0 - a.0, a.1, unit));
                }
            }
        }
        let have: BTreeSet<(u64, u64, u64, usize)> = lines
            .spans
            .iter()
            .map(|l| (l.addr, l.size, u64::from(l.line), l.compiland as usize))
            .collect();
        assert_eq!(have, want, "{name}");
        // Each unit's file, in its compilation directory.
        assert_eq!(lines.files, ["./program.c", "./second.c"], "{name}");
        let sorted = lines.spans.windows(2).all(|w| w[0].addr <= w[1].addr);
        assert!(sorted);
    }
}

#[test]
fn compressed_sections_read_the_same() {
    let plain = std::fs::read(testdata("dwarf5-x86_64-linux-gnu")).unwrap();
    let p = DebugInfo::parse(&plain).unwrap();
    for z in ["zlib", "zstd", "zdebug"] {
        let data = std::fs::read(testdata(&format!("dwarf5-x86_64-linux-gnu.{z}"))).unwrap();
        let d = DebugInfo::parse(&data).unwrap();
        assert_eq!(d.symbols().unwrap(), p.symbols().unwrap(), "{z}");
        assert_eq!(d.source_lines().unwrap(), p.source_lines().unwrap(), "{z}");
        assert_eq!(d.inline_sites().unwrap(), p.inline_sites().unwrap(), "{z}");
    }
}

#[test]
fn a_separate_debug_file_matches_its_image() {
    use hexcavator_image::Image;
    let image = std::fs::read(testdata("program-linked")).unwrap();
    let debug = std::fs::read(testdata("program-split.debug")).unwrap();
    let image = Image::parse(&image).unwrap();
    let d = DebugInfo::parse(&debug).unwrap();
    // By build ID, and by the debug link's CRC.
    let ids = image.debug_ids();
    assert!(ids.len() >= 2);
    assert!(ids.iter().all(|id| d.matches(id)), "{ids:?}");
    // Not another file's.
    let other = std::fs::read(testdata("dwarf5-x86_64-linux-gnu")).unwrap();
    let o = DebugInfo::parse(&other).unwrap();
    assert!(!ids.iter().any(|id| o.matches(id)));
}

#[test]
fn files_without_dwarf_are_refused() {
    let stripped = std::fs::read(testdata("program-stripped")).unwrap();
    assert!(DebugInfo::parse(&stripped).is_err());
    assert!(DebugInfo::parse(b"").is_err());
    assert!(DebugInfo::parse(b"\x7FELF").is_err());
}

#[test]
fn damaged_dwarf_does_not_panic() {
    for name in ["dwarf5-x86_64-linux-gnu", "dwarf4-aarch64_be-linux-gnu"] {
        let clean = std::fs::read(testdata(name)).unwrap();
        let exercise = |data: &[u8]| {
            let Ok(d) = DebugInfo::parse(data) else {
                return;
            };
            let _ = (d.compilands(), d.contributions(), d.source_lines());
            let _ = (d.inline_sites(), d.classes());
            if let Ok(symbols) = d.symbols() {
                for s in symbols.iter().take(64) {
                    let _ = d.type_shape(TypeRef(s.type_index));
                    let _ = d.type_size(TypeRef(s.type_index));
                    let _ = d.variables(s.compiland, s.addr);
                }
            }
        };
        // Every byte of the DWARF sections, flipped (a sample: every 3rd).
        let image = hexcavator_image::Image::parse(&clean).unwrap();
        let debug: Vec<(usize, usize)> = image
            .sections()
            .iter()
            .filter(|s| s.name.starts_with(b".debug_"))
            .map(|s| (s.file_offset as usize, s.file_size as usize))
            .collect();
        let mut data = clean.clone();
        for (at, len) in debug {
            for i in (at..at + len).step_by(3) {
                let was = data[i];
                for v in [0x00, 0xFF, was ^ 0x40] {
                    data[i] = v;
                    exercise(&data);
                }
                data[i] = was;
            }
        }
    }
}

fn types_file(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata/types")
        .join(name)
}

/// C++ (tools/types/types.cpp, built by build-dwarf.cmd): classes, their
/// sizes, bases, and virtual methods, against llvm-dwarfdump.
#[test]
fn classes_match_llvm_dwarfdump() {
    let data = std::fs::read(types_file("types-x86_64-linux-gnu")).unwrap();
    let text = std::fs::read_to_string(types_file("types-x86_64-linux-gnu.dwarfdump.txt")).unwrap();
    let theirs = dies(&text);
    let d = DebugInfo::parse(&data).unwrap();
    let classes = d.classes().unwrap();
    let mut checked = 0;
    for (i, t) in theirs.iter().enumerate() {
        if !(t.tag == "DW_TAG_structure_type" || t.tag == "DW_TAG_class_type")
            || t.get("DW_AT_declaration").is_some()
        {
            continue;
        }
        let Some(cname) = t.name() else { continue };
        let ours = classes
            .iter()
            .find(|c| c.name == cname)
            .unwrap_or_else(|| panic!("no class {cname}"));
        let size = u64::from_str_radix(
            t.get("DW_AT_byte_size").unwrap().trim_start_matches("0x"),
            16,
        )
        .unwrap();
        assert_eq!(d.type_size(ours.ty), Some(size), "{cname}");
        assert!(matches!(d.type_shape(ours.ty), TypeShape::Udt { name } if name == cname));
        let children: Vec<&Die> = theirs[i + 1..]
            .iter()
            .take_while(|c| c.depth > t.depth)
            .filter(|c| c.depth == t.depth + 1)
            .collect();
        let bases: Vec<String> = children
            .iter()
            .filter(|c| c.tag == "DW_TAG_inheritance")
            .map(|c| {
                c.get("DW_AT_type")
                    .unwrap()
                    .split_once('"')
                    .unwrap()
                    .1
                    .trim_end_matches('"')
                    .to_string()
            })
            .collect();
        let our_bases: Vec<String> = ours
            .bases
            .iter()
            .map(|&b| match d.type_shape(b) {
                TypeShape::Udt { name } => name,
                s => panic!("{s:?}"),
            })
            .collect();
        assert_eq!(our_bases, bases, "{cname}");
        let virtuals: BTreeSet<String> = children
            .iter()
            .filter(|c| c.tag == "DW_TAG_subprogram" && c.get("DW_AT_virtuality").is_some())
            .filter_map(|c| c.name())
            .collect();
        let ours_virtual: BTreeSet<String> = ours
            .methods
            .iter()
            .filter(|m| m.kind.is_virtual())
            .map(|m| m.name.clone())
            .collect();
        assert_eq!(ours_virtual, virtuals, "{cname}");
        checked += 1;
    }
    assert!(checked >= 9, "{checked}");
    // Member functions' names are qualified by their classes.
    let names: BTreeSet<String> = d
        .symbols()
        .unwrap()
        .into_iter()
        .filter(|s| s.kind == SymbolKind::Function)
        .map(|s| s.name)
        .collect();
    for n in ["use", "main", "Base::~Base", "Derived::~Derived"] {
        assert!(names.contains(n), "{n}: {names:?}");
    }
}

/// The same source's PDB (MSVC) and DWARF (clang) describe the same
/// classes: each DWARF class is in the PDB, with the same bases and the
/// same virtual methods.
#[test]
fn pdb_and_dwarf_agree_on_classes() {
    let dwarf = std::fs::read(types_file("types-x86_64-linux-gnu")).unwrap();
    let pdb = std::fs::read(types_file("types.pdb")).unwrap();
    let (dw, pd) = (
        DebugInfo::parse(&dwarf).unwrap(),
        DebugInfo::parse(&pdb).unwrap(),
    );
    assert!(pd.pdb().is_some() && dw.dwarf().is_some());
    let named = |d: &DebugInfo<'_>, refs: &[TypeRef]| -> Vec<String> {
        refs.iter()
            .map(|&r| match d.type_shape(r) {
                TypeShape::Udt { name } => name,
                s => format!("{s:?}"),
            })
            .collect()
    };
    let pdb_classes = pd.classes().unwrap();
    for c in dw.classes().unwrap() {
        let p = pdb_classes
            .iter()
            .find(|p| p.name == c.name)
            .unwrap_or_else(|| panic!("{} not in the PDB", c.name));
        assert_eq!(named(&dw, &c.bases), named(&pd, &p.bases), "{}", c.name);
        // (MSVC's ABI adds a virtual vector deleting destructor that the
        // Itanium ABI has no counterpart of: the compiler's, not the
        // source's.)
        let virt = |ms: &[hexcavator_debuginfo::Method]| -> BTreeSet<String> {
            ms.iter()
                .filter(|m| m.kind.is_virtual() && m.name != "__vecDelDtor")
                .map(|m| m.name.clone())
                .collect()
        };
        assert_eq!(virt(&c.methods), virt(&p.methods), "{}", c.name);
    }
}

#[test]
fn where_separate_debug_files_are_looked_for() {
    use hexcavator_debuginfo::candidate_paths;
    use hexcavator_image::DebugId;
    use std::path::{Path, PathBuf};
    let image = Path::new("/opt/app/bin/app");
    let link = DebugId::DebugLink {
        path: b"app.debug",
        crc: Some(1),
    };
    assert_eq!(
        candidate_paths(image, &link),
        [
            PathBuf::from("/opt/app/bin/app.debug"),
            PathBuf::from("/opt/app/bin/.debug/app.debug"),
            PathBuf::from("/usr/lib/debug/opt/app/bin/app.debug"),
        ]
    );
    // A link is a name: paths in it aren't followed.
    for bad in [&b"../etc/passwd"[..], br"a\b", b""] {
        let id = DebugId::DebugLink {
            path: bad,
            crc: None,
        };
        assert!(candidate_paths(image, &id).is_empty());
    }
    let id = DebugId::BuildId(&[0xAB, 0xCD, 0xEF, 0x01]);
    assert_eq!(
        candidate_paths(image, &id),
        [
            PathBuf::from("/opt/app/bin/.build-id/ab/cdef01.debug"),
            PathBuf::from("/usr/lib/debug/.build-id/ab/cdef01.debug"),
            PathBuf::from("/opt/app/bin/app.debug"),
            PathBuf::from("/opt/app/bin/app.dbg"),
        ]
    );
    assert!(candidate_paths(image, &DebugId::BuildId(&[1])).is_empty());
    assert_eq!(
        candidate_paths(Path::new("/Users/me/app"), &DebugId::Uuid([0; 16])),
        [
            Path::new("/Users/me/app.dSYM")
                .join("Contents")
                .join("Resources")
                .join("DWARF")
                .join("app"),
            PathBuf::from("/Users/me/app.dwarf"),
        ]
    );
    let alt = DebugId::AltLink {
        path: b"/usr/lib/debug/.dwz/app.debug",
        build_id: &[1, 2],
    };
    assert_eq!(
        candidate_paths(image, &alt),
        [
            PathBuf::from("/usr/lib/debug/.dwz/app.debug"),
            PathBuf::from("/opt/app/bin/app.debug"),
        ]
    );
}

#[test]
fn where_symbol_directories_are_looked_in() {
    use hexcavator_debuginfo::{candidate_paths, candidate_paths_in};
    use hexcavator_image::DebugId;
    use std::path::{Path, PathBuf};
    let image = Path::new("/opt/app/bin/libapp.so");
    let dirs = [PathBuf::from("/syms")];
    let id = DebugId::BuildId(&[0xAB, 0xCD, 0xEF, 0x01]);
    let all = candidate_paths_in(image, &id, &dirs);
    // The image's own places first, then the directory's layouts.
    let own = candidate_paths(image, &id);
    assert_eq!(all[..own.len()], own[..]);
    assert_eq!(
        all[own.len()..],
        [
            Path::new("/syms")
                .join("_.debug")
                .join("elf-buildid-sym-abcdef01")
                .join("_.debug"),
            Path::new("/syms").join("abcdef01").join("debuginfo"),
            Path::new("/syms")
                .join(".build-id")
                .join("ab")
                .join("cdef01.debug"),
            Path::new("/syms").join("ab").join("cdef01.debug"),
        ]
    );
    let uuid = [0x12; 16];
    let mach = candidate_paths_in(Path::new("/x/libapp.dylib"), &DebugId::Uuid(uuid), &dirs);
    assert!(
        mach.contains(
            &Path::new("/syms")
                .join("_.dwarf")
                .join("mach-uuid-sym-12121212121212121212121212121212")
                .join("_.dwarf")
        )
    );
    assert!(
        mach.contains(
            &Path::new("/syms")
                .join("libapp.dylib.dSYM")
                .join("Contents")
                .join("Resources")
                .join("DWARF")
                .join("libapp.dylib")
        )
    );
    // A PDB: the symbol store's layout (as recorded, and in lower case),
    // and the name alone; a recorded path's directories are not followed.
    let pdb = DebugId::Pdb {
        guid: [
            0xFD, 0x0D, 0xB9, 0x1C, 0xB9, 0x4C, 0xA8, 0x4B, 0xBA, 0x9C, 0xAE, 0x62, 0x63, 0x7E,
            0x69, 0x30,
        ],
        age: 1,
        path: br"D:\out\CoreCLR.pdb",
    };
    let p = candidate_paths_in(Path::new("/x/coreclr.dll"), &pdb, &dirs);
    for want in [
        Path::new("/syms")
            .join("CoreCLR.pdb")
            .join("1CB90DFD4CB94BA8BA9CAE62637E69301")
            .join("CoreCLR.pdb"),
        Path::new("/syms")
            .join("coreclr.pdb")
            .join("1CB90DFD4CB94BA8BA9CAE62637E69301")
            .join("coreclr.pdb"),
        Path::new("/syms").join("CoreCLR.pdb"),
    ] {
        assert!(p.contains(&want), "{want:?} in {p:?}");
    }
    let dots = DebugId::Pdb {
        guid: [0; 16],
        age: 1,
        path: b"x/..",
    };
    assert!(
        candidate_paths_in(Path::new("/x/a.dll"), &dots, &dirs)
            .iter()
            .all(|p| !p.starts_with("/syms"))
    );
}

#[test]
fn symbol_directories_from_the_environment() {
    use hexcavator_debuginfo::symbol_dirs_from;
    use std::path::PathBuf;
    let nt = r"srv*C:\symcache*https://msdl.microsoft.com/download/symbols;D:\mine;cache*E:\c;symsrv*symsrv.dll*F:\s*https://x;";
    assert_eq!(
        symbol_dirs_from(
            None,
            Some(nt),
            Some(PathBuf::from("/home/me/.cache/debuginfod_client"))
        ),
        [
            PathBuf::from(r"C:\symcache"),
            PathBuf::from(r"D:\mine"),
            PathBuf::from(r"E:\c"),
            PathBuf::from(r"F:\s"),
            PathBuf::from("/home/me/.cache/debuginfod_client"),
        ]
    );
    assert!(symbol_dirs_from(None, Some("srv**https://x"), None).is_empty());
    let joined = std::env::join_paths(["/a", "/b"]).unwrap();
    assert_eq!(
        symbol_dirs_from(Some(&joined), None, Some(PathBuf::from("/a"))),
        [PathBuf::from("/a"), PathBuf::from("/b")]
    );
}

/// Layouts: the same source's PDB (MSVC) and DWARF (clang, Itanium ABI)
/// lay out the types whose layout the ABIs agree on alike, part for part
/// (names, offsets, sizes, bits, kinds, types' names); and the types
/// they don't, each as its ABI does.
#[test]
fn pdb_and_dwarf_layouts() {
    use hexcavator_debuginfo::layout::PartKind;
    let dwarf = std::fs::read(types_file("types-x86_64-linux-gnu")).unwrap();
    let pdb = std::fs::read(types_file("types.pdb")).unwrap();
    let (dw, pd) = (
        DebugInfo::parse(&dwarf).unwrap(),
        DebugInfo::parse(&pdb).unwrap(),
    );
    let find = |d: &DebugInfo<'_>, name: &str| {
        let l = d
            .layouts()
            .unwrap()
            .into_iter()
            .find(|l| l.name == name)
            .unwrap_or_else(|| panic!("no {name}"));
        // (With its parts' type names.)
        d.layout(l.ty).unwrap()
    };
    /// (offset, size, bits, kind, name, type's name).
    type Parts = Vec<(u64, u64, Option<(u8, u8)>, PartKind, String, String)>;
    let parts = |l: &hexcavator_debuginfo::layout::Layout| -> Parts {
        l.parts
            .iter()
            .map(|p| {
                (
                    p.offset,
                    p.size,
                    p.bits,
                    p.kind,
                    p.name.clone(),
                    p.type_name.clone(),
                )
            })
            .collect()
    };
    for name in [
        "Padded",
        "Bits",
        "Sample",
        "Either",
        "Grows",
        "WithEmpty",
        "Empty",
        "VBase",
        "Base",
    ] {
        let (a, b) = (find(&dw, name), find(&pd, name));
        assert_eq!(parts(&a), parts(&b), "{name}");
        assert_eq!(
            (a.size, a.waste(), a.union),
            (b.size, b.waste(), b.union),
            "{name}"
        );
    }
    // Itanium: Derived's y goes in Base's tail padding; Diamond's virtual
    // base right after it, with no vbptr (its vtable has the offset).
    let derived = find(&dw, "Derived");
    assert_eq!(derived.size, 16);
    assert!(
        derived
            .parts
            .iter()
            .any(|p| p.name == "y" && p.offset == 12)
    );
    let diamond = find(&dw, "Diamond");
    let kinds: Vec<(u64, PartKind)> = diamond.parts.iter().map(|p| (p.offset, p.kind)).collect();
    assert_eq!(
        kinds,
        [
            (0, PartKind::VfPtr),
            (8, PartKind::Member),
            (12, PartKind::VirtualBase)
        ]
    );
    // MSVC: a vbptr, and the virtual base after the rest, pointer-aligned.
    let diamond = find(&pd, "Diamond");
    assert!(diamond.parts.iter().any(|p| p.kind == PartKind::VbPtr));
    assert_eq!(diamond.size, 24);
}

/// Every member of every DWARF layout is where llvm-dwarfdump says.
#[test]
fn dwarf_layouts_match_llvm_dwarfdump() {
    let data = std::fs::read(types_file("types-x86_64-linux-gnu")).unwrap();
    let text = std::fs::read_to_string(types_file("types-x86_64-linux-gnu.dwarfdump.txt")).unwrap();
    let theirs = dies(&text);
    let d = DebugInfo::parse(&data).unwrap();
    let layouts = d.layouts().unwrap();
    let mut checked = 0;
    for (i, t) in theirs.iter().enumerate() {
        if !matches!(
            t.tag.as_str(),
            "DW_TAG_structure_type" | "DW_TAG_class_type" | "DW_TAG_union_type"
        ) || t.get("DW_AT_declaration").is_some()
        {
            continue;
        }
        let Some(name) = t.name() else { continue };
        let l = layouts.iter().find(|l| l.name == name).unwrap();
        let l = d.layout(l.ty).unwrap();
        for m in theirs[i + 1..]
            .iter()
            .take_while(|c| c.depth > t.depth)
            .filter(|c| c.depth == t.depth + 1 && c.tag == "DW_TAG_member")
        {
            let mname = m.name().unwrap();
            if mname.starts_with("_vptr") || m.get("DW_AT_bit_size").is_some() {
                continue;
            }
            let at = m.get("DW_AT_data_member_location").map_or(0, |v| {
                u64::from_str_radix(v.trim_start_matches("0x"), 16).unwrap()
            });
            let p = l
                .parts
                .iter()
                .find(|p| p.name == mname)
                .unwrap_or_else(|| panic!("{name}::{mname}"));
            assert_eq!(p.offset, at, "{name}::{mname}");
            checked += 1;
        }
    }
    assert!(checked >= 20, "{checked}");
}

/// A name index (.debug_names, clang's -gpubnames): every name and its
/// entries' DIEs as llvm-dwarfdump --debug-names has them; hashes the DJB
/// hash; each entry's DIE has its tag.
#[test]
fn name_index_matches_llvm_dwarfdump() {
    use hexcavator_dwarf::names::{name_indexes, names_hash};
    let data = std::fs::read(types_file("types-x86_64-linux-gnu-names")).unwrap();
    let text =
        std::fs::read_to_string(types_file("types-x86_64-linux-gnu-names.names.txt")).unwrap();
    // Theirs: (name, DIE offset) for each entry.
    let mut want = BTreeSet::new();
    let mut name = String::new();
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("String: ") {
            name = rest
                .split_once('"')
                .unwrap()
                .1
                .trim_end_matches('"')
                .to_string();
        } else if let Some(v) = t.strip_prefix("DW_IDX_die_offset: 0x") {
            want.insert((name.clone(), u64::from_str_radix(v, 16).unwrap()));
        }
    }
    assert!(want.len() > 30, "{}", want.len());
    let d = DebugInfo::parse(&data).unwrap();
    let dwarf = d.dwarf().unwrap();
    let indexes = name_indexes(&dwarf.sections());
    assert_eq!(indexes.len(), 1);
    let index = &indexes[0];
    assert_eq!(
        (index.version, index.compile_units.as_slice()),
        (5, &[0u64][..])
    );
    assert_eq!(index.augmentation, b"LLVM0700");
    let mut have = BTreeSet::new();
    for n in &index.names {
        assert_eq!(n.hash, Some(names_hash(n.name)));
        for e in &n.entries {
            let name = String::from_utf8_lossy(n.name).into_owned();
            have.insert((name, e.die_offset.unwrap()));
            // The DIE there has the entry's tag.
            let shape_ok = matches!(
                e.tag,
                hexcavator_dwarf::consts::DW_TAG_SUBPROGRAM
                    | hexcavator_dwarf::consts::DW_TAG_VARIABLE
                    | hexcavator_dwarf::consts::DW_TAG_BASE_TYPE
                    | hexcavator_dwarf::consts::DW_TAG_STRUCTURE_TYPE
                    | hexcavator_dwarf::consts::DW_TAG_UNION_TYPE
                    | hexcavator_dwarf::consts::DW_TAG_ENUMERATION_TYPE
                    | hexcavator_dwarf::consts::DW_TAG_POINTER_TYPE
                    | hexcavator_dwarf::consts::DW_TAG_INLINED_SUBROUTINE
                    | hexcavator_dwarf::consts::DW_TAG_TYPEDEF
                    | hexcavator_dwarf::consts::DW_TAG_NAMESPACE
                    | hexcavator_dwarf::consts::DW_TAG_CLASS_TYPE
            );
            assert!(shape_ok, "{:#x}", e.tag);
        }
    }
    assert_eq!(have, want);
    // Damaged: no panics.
    let image = hexcavator_image::Image::parse(&data).unwrap();
    let names = image
        .sections()
        .into_iter()
        .find(|s| s.name == b".debug_names")
        .unwrap();
    let mut dd = data.clone();
    for at in
        (names.file_offset as usize..(names.file_offset + names.file_size) as usize).step_by(2)
    {
        let was = dd[at];
        for v in [0x00, 0xFF, was ^ 0x40] {
            dd[at] = v;
            if let Ok(d) = DebugInfo::parse(&dd) {
                let _ = name_indexes(&d.dwarf().unwrap().sections());
            }
        }
        dd[at] = was;
    }
}
