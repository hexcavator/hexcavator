//! testdata/wasm/module.wasm (assembled by tools/wasm/make.py) against
//! llvm-readobj's sections and llvm-objdump's symbol table: every section's
//! id, name, contents offset and size, and every named function's body.

use std::path::PathBuf;

use hexcavator_wasm::{Module, NAME_DATA_SEGMENT, NAME_FUNCTION};

fn testdata(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata/wasm")
        .join(name)
}

fn leb_len(mut n: u64) -> u64 {
    let mut k = 1;
    while n >= 0x80 {
        n >>= 7;
        k += 1;
    }
    k
}

#[test]
fn sections_match_llvm_readobj() {
    let data = std::fs::read(testdata("module.wasm")).unwrap();
    let m = Module::parse(&data).unwrap();
    assert_eq!(m.version, 1);
    let text = std::fs::read_to_string(testdata("module.wasm.readobj.txt")).unwrap();
    // Top-level `Section {` blocks: Type (id), Size, Offset, Name.
    let mut theirs: Vec<(u8, u64, u64, Option<String>)> = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if line.starts_with("Symbols [") {
            break;
        }
        if line.starts_with("  Section {") {
            theirs.push((0, 0, 0, None));
        } else if line.starts_with("    ") && !line.starts_with("     ") {
            let Some(last) = theirs.last_mut() else {
                continue;
            };
            if let Some(v) = t.strip_prefix("Type: ") {
                let hex = v.rsplit("(0x").next().unwrap().trim_end_matches(')');
                last.0 = u8::from_str_radix(hex, 16).unwrap();
            } else if let Some(v) = t.strip_prefix("Size: ") {
                last.1 = v.parse().unwrap();
            } else if let Some(v) = t.strip_prefix("Offset: ") {
                last.2 = v.parse().unwrap();
            } else if let Some(v) = t.strip_prefix("Name: ") {
                last.3 = Some(v.to_string());
            }
        }
    }
    let ours: Vec<(u8, u64, u64, Option<String>)> = m
        .sections()
        .iter()
        .map(|s| {
            // readobj sizes a custom section's payload after its name (but
            // gives the offset of its contents).
            let size = if s.id == 0 {
                s.contents_size - s.name.len() as u64 - leb_len(s.name.len() as u64)
            } else {
                s.contents_size
            };
            (
                s.id,
                size,
                s.contents_offset,
                (s.id == 0).then(|| String::from_utf8_lossy(s.name).into_owned()),
            )
        })
        .collect();
    assert_eq!(ours, theirs);
    assert_eq!(ours.len(), 14);
    // The sections tile the file after the header.
    let mut at = 8;
    for s in m.sections() {
        assert_eq!(s.offset, at);
        at += s.size;
    }
    assert_eq!(at, data.len() as u64);
}

#[test]
fn functions_match_llvm_objdump() {
    let data = std::fs::read(testdata("module.wasm")).unwrap();
    let m = Module::parse(&data).unwrap();
    let text = std::fs::read_to_string(testdata("module.wasm.syms.txt")).unwrap();
    // `00000074 g     F CODE	00000008 add`: the body's offset and size.
    let mut theirs = Vec::new();
    for line in text.lines() {
        if line.contains(" F CODE") {
            let addr = u64::from_str_radix(&line[..8], 16).unwrap();
            let rest = line.split('\t').nth(1).unwrap();
            let (size, name) = rest.split_once(' ').unwrap();
            theirs.push((
                name.to_string(),
                addr,
                u64::from_str_radix(size, 16).unwrap(),
            ));
        }
    }
    let names = m.names(NAME_FUNCTION);
    let ours: Vec<(String, u64, u64)> = m
        .functions()
        .iter()
        .filter_map(|f| {
            let n = names.iter().find(|n| n.index == f.index)?;
            Some((
                String::from_utf8_lossy(n.name).into_owned(),
                f.offset,
                f.size,
            ))
        })
        .collect();
    assert_eq!(ours, theirs);
    assert_eq!(m.imported_functions(), 1);
    assert_eq!(m.functions().len(), 4);
    let segs = m.data_segments();
    assert_eq!(segs.len(), 3);
    let seg_names: Vec<_> = m
        .names(NAME_DATA_SEGMENT)
        .iter()
        .map(|n| (n.index, String::from_utf8_lossy(n.name).into_owned()))
        .collect();
    assert_eq!(
        seg_names,
        [(0, ".rodata".to_string()), (1, ".data".to_string())]
    );
    assert_eq!(m.source_mapping_url(), Some(&b"module.wasm.map"[..]));
    // The data segments end where the data section does.
    let ds = m
        .sections()
        .iter()
        .find(|s| s.id == hexcavator_wasm::SECTION_DATA)
        .unwrap();
    let last = segs.last().unwrap();
    assert_eq!(last.offset + last.size, ds.offset + ds.size);
}
