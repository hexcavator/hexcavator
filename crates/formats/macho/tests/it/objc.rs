//! Objective-C metadata (testdata/macho/objc-*.dylib, from tools/macho/objc.m
//! by build.cmd) against llvm-objdump's account (`--objc-meta-data`, of
//! the builds with the older opcodes: it reads chained pointers raw); the
//! chained builds read the same.
//!
//! Classified divergence: llvm-objdump reads an instance variable's offset
//! variable (32 bits) as 64 bits, taking the next one's too; its low 32
//! bits are compared.

use std::collections::BTreeSet;

use hexcavator_macho::MachO;
use hexcavator_macho::objc::{Method, Objc};

fn testdata(name: &str) -> Vec<u8> {
    let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../testdata/macho")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn hex(s: &str) -> u64 {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap()
}

/// A field's value: past its hex, and the parenthesized address after
/// that (`0x7bbc (0x8408) init`), if any.
fn value(rest: &str) -> (Option<u64>, &str) {
    let rest = rest.split_once(' ').map_or("", |(_, r)| r);
    if let Some(r) = rest.strip_prefix('(') {
        if let Some((a, r)) = r.split_once(") ") {
            return (Some(hex(a)), r);
        }
        if let Some(a) = r.strip_suffix(')') {
            return (Some(hex(a)), "");
        }
    }
    (None, rest)
}

/// llvm-objdump's facts.
fn theirs(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut section = "";
    let mut meta = false;
    let mut class = String::new();
    let mut ro_done = false;
    let mut name: Option<String> = None;
    let mut types: Option<String> = None;
    let mut ivar_offset: Option<u64> = None;
    let mut ivar: Vec<String> = Vec::new();
    for line in text.lines() {
        if let Some(s) = line.strip_prefix("Contents of (") {
            section = s.split_once(',').unwrap().1.split_once(')').unwrap().0;
            continue;
        }
        if line == "Meta Class" {
            meta = true;
            continue;
        }
        let t = line.trim();
        // A list entry: "0000000000004008 0x8000 _OBJC_CLASS_$_Root".
        if !line.starts_with([' ', '\t']) && t.len() > 17 && t.as_bytes()[16] == b' ' {
            let mut parts = t.split(' ');
            let _ = parts.next();
            let addr = hex(parts.next().unwrap());
            let symbol = parts.next().unwrap_or("");
            meta = false;
            ro_done = false;
            match section {
                "__objc_classlist" => {
                    class = symbol.strip_prefix("_OBJC_CLASS_$_").unwrap().to_string();
                    out.insert(format!("class {class} at {addr:#x}"));
                }
                "__objc_catlist" => {
                    let (c, n) = symbol
                        .strip_prefix("__OBJC_$_CATEGORY_")
                        .unwrap()
                        .split_once("_$_")
                        .unwrap();
                    out.insert(format!("category {n} of {c} at {addr:#x}"));
                    class = String::new();
                }
                "__objc_protolist" => {
                    let p = symbol.strip_prefix("__OBJC_PROTOCOL_$_").unwrap();
                    out.insert(format!("protocol {p} at {addr:#x}"));
                }
                _ => {}
            }
            continue;
        }
        let (key, rest) = t.split_once(' ').unwrap_or((t, ""));
        let rest = rest.trim_start();
        match (section, key) {
            ("__objc_imageinfo", "version") => {
                out.insert(format!("image version {rest}"));
            }
            ("__objc_imageinfo", "flags") => {
                out.insert(format!("image flags {}", rest.split(' ').next().unwrap()));
            }
            (_, "superclass") if !meta && !class.is_empty() => {
                let s = value(rest).1;
                let s = s.strip_prefix("_OBJC_CLASS_$_").unwrap_or("(none)");
                out.insert(format!("class {class} super {s}"));
            }
            (_, "flags") if !meta && !class.is_empty() && !ro_done => {
                out.insert(format!(
                    "class {class} flags {}",
                    rest.split(' ').next().unwrap()
                ));
            }
            (_, "instanceStart") if !meta && !class.is_empty() && !ro_done => {
                out.insert(format!("class {class} start {rest}"));
            }
            (_, "instanceSize") if !meta && !class.is_empty() && !ro_done => {
                out.insert(format!("class {class} size {rest}"));
                ro_done = true;
            }
            (_, "name") => {
                name = Some(value(rest).1.to_string());
                types = None;
            }
            (_, "types") => types = Some(value(rest).1.to_string()),
            (_, "imp") => {
                let (addr, label) = value(rest);
                let n = name.take().unwrap();
                let ty = types.take().unwrap();
                if label.is_empty() {
                    out.insert(format!("protocol method {n} {ty}"));
                } else {
                    // "-[Shape(Grow) grow:]" names the method.
                    assert!(label.ends_with(&format!(" {n}]")), "{label} {n}");
                    out.insert(format!("method {label} {ty} at {:#x}", addr.unwrap()));
                }
            }
            (_, "offset") => {
                // (Its low 32 bits: see the divergence above.)
                let v: u64 = rest.split(' ').nth(1).unwrap().parse().unwrap();
                ivar_offset = Some(v & 0xFFFF_FFFF);
                ivar.clear();
            }
            (_, "type") => ivar.push(value(rest).1.to_string()),
            (_, "alignment") if ivar_offset.is_some() => ivar.push(rest.to_string()),
            (_, "size") if ivar_offset.is_some() => {
                let o = ivar_offset.take().unwrap();
                let n = name.take().unwrap();
                out.insert(format!(
                    "ivar {n} {} offset {o} align {} size {rest}",
                    ivar[0], ivar[1]
                ));
            }
            (_, "attributes") => {
                let n = name.take().unwrap();
                out.insert(format!("property {n} {}", value(rest).1));
            }
            _ => {}
        }
    }
    out
}

/// Ours, as the same facts.
fn ours(o: &Objc) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let methods = |out: &mut BTreeSet<String>, sign: char, of: &str, ms: &[Method]| {
        for m in ms {
            out.insert(format!(
                "method {sign}[{of} {}] {} at {:#x}",
                m.name, m.types, m.imp
            ));
        }
    };
    for c in &o.classes {
        out.insert(format!("class {} at {:#x}", c.name, c.addr));
        out.insert(format!(
            "class {} super {}",
            c.name,
            c.superclass.as_deref().unwrap_or("(none)")
        ));
        out.insert(format!("class {} flags {:#x}", c.name, c.flags));
        out.insert(format!("class {} start {}", c.name, c.instance_start));
        out.insert(format!("class {} size {}", c.name, c.instance_size));
        methods(&mut out, '-', &c.name, &c.methods);
        methods(&mut out, '+', &c.name, &c.class_methods);
        for v in &c.ivars {
            out.insert(format!(
                "ivar {} {} offset {} align {} size {}",
                v.name,
                v.types,
                v.offset.unwrap(),
                v.alignment,
                v.size
            ));
        }
        for p in c.properties.iter().chain(&c.class_properties) {
            out.insert(format!("property {} {}", p.name, p.attributes));
        }
    }
    for c in &o.categories {
        let class = c.class.as_deref().unwrap();
        out.insert(format!("category {} of {class} at {:#x}", c.name, c.addr));
        let of = format!("{class}({})", c.name);
        methods(&mut out, '-', &of, &c.methods);
        methods(&mut out, '+', &of, &c.class_methods);
    }
    for p in &o.protocols {
        out.insert(format!("protocol {} at {:#x}", p.name, p.addr));
        for m in &p.methods {
            out.insert(format!("protocol method {} {}", m.name, m.types));
        }
    }
    if let Some((v, f)) = o.image_info {
        out.insert(format!("image version {v}"));
        out.insert(format!("image flags {f:#x}"));
    }
    out
}

#[test]
fn objc_metadata_matches_llvm_objdump() {
    for arch in ["arm64", "x86_64"] {
        let name = format!("objc-{arch}-opcodes.dylib");
        let text = String::from_utf8(testdata(&format!("{name}.objc.txt"))).unwrap();
        let want = theirs(&text);
        assert!(want.len() > 30, "{want:#?}");
        let data = testdata(&name);
        let o = MachO::parse(&data).unwrap().objc();
        assert!(!o.truncated);
        let got = ours(&o);
        let missing: Vec<_> = want.difference(&got).collect();
        let extra: Vec<_> = got.difference(&want).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "{name}: missing {missing:#?}, extra {extra:#?}"
        );
    }
}

/// What llvm-objdump doesn't show (only their addresses), by the source.
#[test]
fn protocols_categories_and_properties() {
    let data = testdata("objc-arm64.dylib");
    let o = MachO::parse(&data).unwrap().objc();
    fn names(ms: &[Method]) -> Vec<&str> {
        ms.iter().map(|m| m.name.as_str()).collect()
    }
    let [p] = &o.protocols[..] else {
        panic!("{:?}", o.protocols)
    };
    assert_eq!(p.name, "Drawable");
    assert_eq!(names(&p.methods), ["drawAt:y:"]);
    assert_eq!(names(&p.optional_methods), ["layer", "size"]);
    assert_eq!(names(&p.optional_class_methods), ["kind"]);
    assert!(p.class_methods.is_empty());
    assert_eq!(p.properties.len(), 1);
    assert_eq!(p.properties[0].name, "size");
    let shape = o.classes.iter().find(|c| c.name == "Shape").unwrap();
    assert_eq!(shape.protocols, ["Drawable"]);
    assert_eq!(names(&shape.class_methods), ["unit"]);
    assert!(!shape.swift);
    let [c] = &o.categories[..] else {
        panic!("{:?}", o.categories)
    };
    assert_eq!(
        (c.name.as_str(), c.class.as_deref()),
        ("Grow", Some("Shape"))
    );
    assert_eq!(names(&c.methods), ["grow:"]);
}

/// Each method's code, by the symbol table (`-[Shape(Grow) grow:]`).
fn check_imps(m: &MachO<'_>, o: &Objc) {
    let symbols: std::collections::BTreeMap<String, u64> = m
        .symbols()
        .iter()
        .map(|s| (String::from_utf8_lossy(s.name).into_owned(), s.n_value))
        .collect();
    let mut checked = 0;
    let mut check = |sign: char, of: &str, ms: &[Method]| {
        for x in ms {
            let name = format!("{sign}[{of} {}]", x.name);
            assert_eq!(symbols.get(&name), Some(&x.imp), "{name}");
            checked += 1;
        }
    };
    for c in &o.classes {
        check('-', &c.name, &c.methods);
        check('+', &c.name, &c.class_methods);
    }
    for c in &o.categories {
        let of = format!("{}({})", c.class.as_deref().unwrap(), c.name);
        check('-', &of, &c.methods);
        check('+', &of, &c.class_methods);
    }
    assert_eq!(checked, 9);
}

/// Chained fixups and opcodes: the same metadata, at the same addresses
/// but for the code's (whose section starts later in one).
#[test]
fn chained_builds_read_as_opcode_builds() {
    let without_code = |mut o: Objc| {
        for c in &mut o.classes {
            c.methods
                .iter_mut()
                .chain(&mut c.class_methods)
                .for_each(|m| m.imp = 0);
        }
        for c in &mut o.categories {
            c.methods
                .iter_mut()
                .chain(&mut c.class_methods)
                .for_each(|m| m.imp = 0);
        }
        o
    };
    for arch in ["arm64", "x86_64"] {
        let chained = testdata(&format!("objc-{arch}.dylib"));
        let opcodes = testdata(&format!("objc-{arch}-opcodes.dylib"));
        let (ma, mb) = (
            MachO::parse(&chained).unwrap(),
            MachO::parse(&opcodes).unwrap(),
        );
        let (a, b) = (ma.objc(), mb.objc());
        check_imps(&ma, &a);
        check_imps(&mb, &b);
        assert_eq!(without_code(a), without_code(b), "{arch}");
    }
}

#[test]
fn images_without_objc_have_none() {
    for name in ["program-arm64", "program-arm64.o", "unwind-x86_64.dylib"] {
        let data = testdata(name);
        assert_eq!(
            MachO::parse(&data).unwrap().objc(),
            Objc::default(),
            "{name}"
        );
    }
}

#[test]
fn damaged_objc_metadata_does_not_panic() {
    for name in ["objc-arm64.dylib", "objc-x86_64-opcodes.dylib"] {
        let file = testdata(name);
        let m = MachO::parse(&file).unwrap();
        // The metadata's sections (and the fixups and load commands).
        let mut spots: Vec<usize> = (0..4096.min(file.len())).collect();
        for s in m.sections() {
            if s.segname.starts_with(b"__DATA") || s.sectname.starts_with(b"__objc") {
                let at = s.offset as usize;
                let size = usize::try_from(s.size).unwrap();
                spots.extend(at..(at + size).min(file.len()));
            }
        }
        for &at in &spots {
            for x in [0x01, 0x80, 0xFF] {
                let mut bad = file.clone();
                bad[at] ^= x;
                if let Ok(m) = MachO::parse(&bad) {
                    let _ = m.objc();
                }
            }
        }
    }
}

/// A list's count is no license to read past its segment: a method list
/// claiming 2^32 - 1 methods gives those its segment holds.
#[test]
fn huge_counts_end_at_the_data() {
    let file = testdata("objc-x86_64-opcodes.dylib");
    let o = MachO::parse(&file).unwrap().objc();
    let shape = o.classes.iter().find(|c| c.name == "Shape").unwrap();
    assert_eq!(shape.methods.len(), 5);
    // Shape's method list: entsize-and-flags, then its count (5), with the
    // relative flag; find it by its header.
    let header = [12u8, 0, 0, 0x80, 5, 0, 0, 0];
    let at = file.windows(8).position(|w| w == header).unwrap();
    let mut bad = file.clone();
    bad[at + 4..at + 8].copy_from_slice(&u32::MAX.to_le_bytes());
    let start = std::time::Instant::now();
    let o = MachO::parse(&bad).unwrap().objc();
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
    let shape = o.classes.iter().find(|c| c.name == "Shape").unwrap();
    assert!(shape.methods.len() > 5, "{}", shape.methods.len());
    assert!(shape.methods.len() < file.len() / 12);
    assert_eq!(
        shape.methods[..5]
            .iter()
            .map(|m| m.name.as_str())
            .collect::<Vec<_>>(),
        ["drawAt:y:", "size", "sides", "setSides:", "scale"]
    );
}
