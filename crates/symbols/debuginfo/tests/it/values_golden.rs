//! Values of every datum with a type of every image and PDB in testdata
//! (and of the DWARF build of tools/types/types.cpp),
//! against testdata/golden/values (one file per image): the value tree as
//! read when the format-independent reader replaced the PDB crate's own,
//! which it matched value for value (but for qualified character arrays,
//! now strings). `HEXC_BLESS=1` rewrites them.

use std::fmt::Write as _;

use hexcavator_debuginfo::value::{self, Limits, Value};
use hexcavator_debuginfo::{DebugInfo, SymbolKind, TypeRef};
use hexcavator_image::Image;

fn testdata(p: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata")
        .join(p)
}

fn pairs() -> Vec<(std::path::PathBuf, std::path::PathBuf)> {
    let mut out = vec![
        (testdata("types/types.exe"), testdata("types/types.pdb")),
        // DWARF: the same source, built by clang; its DWARF in the image.
        (
            testdata("types/types-x86_64-linux-gnu"),
            testdata("types/types-x86_64-linux-gnu"),
        ),
    ];
    let mut more: Vec<_> = std::fs::read_dir(testdata("sizebench/bin"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            matches!(p.extension().and_then(|e| e.to_str()), Some("dll" | "exe"))
                && p.with_extension("pdb").exists()
        })
        .map(|p| {
            let pdb = p.with_extension("pdb");
            (p, pdb)
        })
        .collect();
    more.sort();
    out.extend(more);
    out
}

fn write(v: &Value, depth: usize, out: &mut String) {
    let _ = write!(
        out,
        "{:indent$}{} {:?} {:?} @{:#x}+{}",
        "",
        v.kind.label(),
        v.name,
        v.type_name,
        v.offset,
        v.size,
        indent = depth * 2
    );
    if let Some((b, n)) = v.bits {
        let _ = write!(out, " bits {b}:{n}");
    }
    if !v.text.is_empty() {
        let _ = write!(out, " = {:?}", v.text);
    }
    if let Some(p) = v.pointer {
        let _ = write!(out, " -> {p:#x}");
    }
    if v.elided > 0 {
        let _ = write!(out, " (+{} elided)", v.elided);
    }
    out.push('\n');
    for c in &v.children {
        write(c, depth + 1, out);
    }
}

fn dump(image_path: &std::path::Path, pdb_path: &std::path::Path) -> String {
    let image_data = std::fs::read(image_path).unwrap();
    let pdb_data = std::fs::read(pdb_path).unwrap();
    let image = Image::parse(&image_data).unwrap();
    let debug = DebugInfo::parse(&pdb_data).unwrap();
    let mut out = String::new();
    for s in debug.symbols().unwrap() {
        if s.kind != SymbolKind::Data || s.type_index == 0 {
            continue;
        }
        let size = s.size.unwrap_or(0).min(4096);
        let bytes = image
            .bytes_at(s.addr, size)
            .map_or_else(|| vec![0; size as usize], <[u8]>::to_vec);
        // (Shorter arrays than the default, for files of a reviewable size.)
        let limits = Limits {
            elements: 16,
            ..Limits::default()
        };
        let v = value::read(&debug, TypeRef(s.type_index), &bytes, limits);
        let _ = writeln!(out, "## {} @{:#x}", s.name, s.addr);
        write(&v, 0, &mut out);
    }
    out
}

#[test]
fn values_match_golden() {
    let bless = std::env::var_os("HEXC_BLESS").is_some();
    let dir = testdata("golden/values");
    if bless {
        std::fs::create_dir_all(&dir).unwrap();
    }
    for (image, pdb) in pairs() {
        let name = format!("{}.txt", image.file_name().unwrap().to_string_lossy());
        let got = dump(&image, &pdb);
        let path = dir.join(&name);
        if bless {
            std::fs::write(&path, &got).unwrap();
            continue;
        }
        let want = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{}: {e} (HEXC_BLESS=1 writes it)", path.display()))
            .replace("\r\n", "\n");
        if got != want {
            let line = got
                .lines()
                .zip(want.lines())
                .position(|(a, b)| a != b)
                .unwrap_or(0);
            panic!(
                "{name}: differs at line {}:\n  got:  {}\n  want: {}",
                line + 1,
                got.lines().nth(line).unwrap_or(""),
                want.lines().nth(line).unwrap_or("")
            );
        }
    }
}
