//! The fuzzer's targets: each takes an input's bytes and runs everything
//! that reads that kind of input. File formats run every `hexc` command
//! that reads them (in-process, on a scratch file); the rest (demanglers,
//! decoders, text formats) are called directly.
//!
//! A target must return for every input: a panic, a hang, a stack
//! overflow, or a runaway allocation is a finding (see `main.rs`).

#![warn(missing_docs)]

use std::path::{Path, PathBuf};

/// One target: what it reads, where its seeds come from, and how to run
/// an input.
pub struct Target {
    /// Its name (`pe`, `pdb`, `demangle`, ...).
    pub name: &'static str,
    /// What it reads, in a phrase.
    pub about: &'static str,
    /// Which of the corpus's files seed it.
    pub seeds: fn(&Path, &[u8]) -> bool,
    /// Runs an input.
    pub run: fn(&[u8], &Scratch),
}

/// Where file targets write their input.
pub struct Scratch {
    /// The directory.
    pub dir: PathBuf,
}

impl Scratch {
    /// Writes `data` as the scratch file named `name`, and its path.
    fn file(&self, name: &str, data: &[u8]) -> String {
        let path = self.dir.join(name);
        std::fs::write(&path, data).expect("writing the scratch file");
        path.to_string_lossy().into_owned()
    }
}

/// Runs `hexc` with `args`, as the command line would (its output goes
/// to the child's standard output, which the supervisor discards).
fn hexc(args: &[&str]) {
    let args: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let _ = hexcavator::run(&args);
}

fn starts(data: &[u8], magic: &[u8]) -> bool {
    data.starts_with(magic)
}

fn is_pe(_: &Path, d: &[u8]) -> bool {
    starts(d, b"MZ")
}
fn is_coff_object(p: &Path, d: &[u8]) -> bool {
    p.extension().is_some_and(|e| e == "obj") && !starts(d, b"MZ")
}
fn is_archive(_: &Path, d: &[u8]) -> bool {
    starts(d, b"!<arch>\n") || starts(d, b"!<thin>\n")
}
fn is_elf(_: &Path, d: &[u8]) -> bool {
    starts(d, b"\x7fELF")
}
fn is_macho(_: &Path, d: &[u8]) -> bool {
    [
        b"\xcf\xfa\xed\xfe",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xfe\xed\xfa\xce",
        b"\xca\xfe\xba\xbe",
    ]
    .iter()
    .any(|m| starts(d, *m))
}
fn is_wasm(_: &Path, d: &[u8]) -> bool {
    starts(d, b"\0asm")
}
fn is_legacy(_: &Path, d: &[u8]) -> bool {
    hexcavator_mz::MzFile::parse(d)
        .ok()
        .and_then(|m| m.new_header())
        .is_some_and(|h| h.kind != hexcavator_mz::NewHeaderKind::Pe)
}
fn is_split_dwarf(p: &Path, d: &[u8]) -> bool {
    is_elf(p, d) && p.extension().is_some_and(|e| e == "dwo" || e == "dwp")
}
fn is_pdb(_: &Path, d: &[u8]) -> bool {
    starts(d, b"Microsoft C/C++ MSF 7.00")
}
fn is_text(p: &Path, _: &[u8]) -> bool {
    p.extension()
        .is_some_and(|e| e == "txt" || e == "map" || e == "log")
}
fn is_code(_: &Path, d: &[u8]) -> bool {
    // Any binary: its bytes are a stream of instructions as good as any.
    !d.is_empty() && d.len() < (8 << 20)
}
fn is_etl(p: &Path, _: &[u8]) -> bool {
    p.extension().is_some_and(|e| e == "etl")
}
fn is_hxtrace(p: &Path, _: &[u8]) -> bool {
    p.extension().is_some_and(|e| e == "hxtrace")
}
fn is_xml(p: &Path, _: &[u8]) -> bool {
    p.extension().is_some_and(|e| e == "xml")
}
fn is_any(_: &Path, _: &[u8]) -> bool {
    true
}
fn is_der(p: &Path, d: &[u8]) -> bool {
    starts(d, &[0x30, 0x82])
        && p.extension()
            .is_some_and(|e| e == "cer" || e == "der" || e == "p7b")
}

/// DER from a signature: as a certificate, a CMS SignedData (and its
/// signers' checks), and a code requirement.
fn der(data: &[u8], _: &Scratch) {
    use hexcavator_signature::{cms, verify, x509};
    if let Ok(c) = x509::Certificate::from_der(data) {
        let _ = verify::CertInfo::of(&c);
        let _ = (
            c.extended_key_usage(),
            c.key_usage(),
            c.is_ca(),
            c.subject_key_id(),
            c.authority_key_id(),
        );
    }
    if let Ok(sd) = cms::SignedData::from_der(data) {
        let content = sd.content.as_ref().map(|c| c.digested().into_owned());
        for s in &sd.signers {
            let mut signer = verify::signer(&sd, s, content.as_deref());
            let stamps = verify::timestamps(&sd, s);
            let (at, what) = verify::judged_at(&stamps);
            verify::finish(
                &mut signer,
                at,
                what,
                hexcavator_signature::oid::EKU_CODE_SIGNING,
            );
        }
        if let Some(c) = &sd.content {
            let _ = cms::IndirectData::parse(c.tlv);
            let _ = cms::TstInfo::parse(&c.digested());
        }
    }
    let _ = hexcavator_signature::requirement::decode(data);
    let _ = hexcavator_signature::requirement::decode_set(data);
}

const SIZE_SOURCES: &str = "sections,segments,symbols,rawsymbols,fullsymbols,compileunits,armembers,inputfiles,inlines,archs";

/// The format-independent view: everything it reads.
fn image(data: &[u8]) {
    let Ok(image) = hexcavator_image::Image::parse(data) else {
        return;
    };
    let _ = (
        image.arch(),
        image.kind(),
        image.hybrid(),
        image.debug_ids(),
    );
    for s in image.sections() {
        // Its start, its whole extent, and one past it.
        let _ = image.bytes_at(s.addr, s.vm_size.min(1 << 20));
        let _ = image.bytes_at(s.addr.saturating_add(s.vm_size), 1);
    }
}

fn pe(data: &[u8], s: &Scratch) {
    image(data);
    let f = s.file("input-pe.bin", data);
    hexc(&["dump", "/all", "/nopdb", &f]);
    hexc(&["size", "-d", "sections,segments", "-n", "0", &f]);
    hexc(&["info", &f]);
    hexc(&["batch", &f]);
    hexc(&["checksec", "-json", &f]);
    hexc(&["signature", "-json", &f]);
    hexc(&["signature", &f]);
}

fn coff(data: &[u8], s: &Scratch) {
    image(data);
    let f = s.file("input-coff.bin", data);
    hexc(&["dump", "/all", &f]);
    hexc(&["size", "-d", "sections,symbols,armembers", "-n", "0", &f]);
}

fn archive(data: &[u8], s: &Scratch) {
    let f = s.file("input-archive.bin", data);
    hexc(&["dump", "/all", &f]);
    hexc(&["size", "-d", "armembers,sections,symbols", "-n", "0", &f]);
}

fn unix(name: &str, data: &[u8], s: &Scratch) {
    image(data);
    debug_info(data);
    let f = s.file(name, data);
    hexc(&["size", "-d", SIZE_SOURCES, "-n", "0", &f]);
    hexc(&["size", "-d", "symbols", "-n", "0", "-csv", &f]);
    hexc(&["info", &f]);
    hexc(&["info", "-json", &f]);
    hexc(&["checksec", "-audit", &f]);
    hexc(&["dump", "-all", &f]);
    hexc(&["checksec", "-json", &f]);
    hexc(&["signature", "-json", &f]);
    hexc(&["dwarf", "-all", &f]);
    hexc(&["dwarf", "-lookup", "0x1000", &f]);
    hexc(&["dwarf", "-find", "main", &f]);
    // Each function's code, by the names its symbols give.
    for name in ["main", "compute", "jumps", "_main", "add", "square"] {
        hexc(&["size", "-disassemble", name, &f]);
        hexc(&["size", "-disassemble", name, "-json", &f]);
    }
}

fn is_xz(_: &Path, d: &[u8]) -> bool {
    starts(d, b"\xFD7zXZ\0")
}

fn xz(data: &[u8], _: &Scratch) {
    // (A small limit: what matters is that damage is refused cleanly.)
    let _ = hexcavator_debuginfo::decompress::xz(data, 1 << 24);
}

fn elf(data: &[u8], s: &Scratch) {
    unix("input-elf.bin", data, s);
}

fn macho(data: &[u8], s: &Scratch) {
    if let Ok(m) = hexcavator_macho::MachO::parse(data) {
        let _ = (m.objc(), m.fixups(), m.exports());
        let _ = (m.function_starts(), m.unwind_info(), m.code_signature());
        let _ = m.debug_map();
    }
    unix("input-macho.bin", data, s);
}

fn wasm(data: &[u8], s: &Scratch) {
    if let Ok(m) = hexcavator_wasm::Module::parse(data) {
        let _ = (
            m.imports(),
            m.linking_symbols(),
            m.segment_info(),
            m.relocations(),
        );
    }
    unix("input-wasm.bin", data, s);
}

fn pdb(data: &[u8], s: &Scratch) {
    let f = s.file("input-pdb.bin", data);
    hexc(&["pdb", "-all", &f]);
    hexc(&["types", "-n", "0", &f]);
    debug_info(data);
}

/// A 16-bit NE or linear (LE/LX) executable: every table, and hexc info.
fn legacy(data: &[u8], s: &Scratch) {
    if let Ok(ne) = hexcavator_ne::NeFile::parse(data) {
        for seg in ne.segments() {
            let _ = (ne.segment_data(&seg), ne.relocations(&seg));
        }
        for r in ne.resources() {
            let _ = ne.resource_data(&r);
        }
        let _ = (
            ne.resident_names(),
            ne.nonresident_names(),
            ne.modules(),
            ne.entries(),
        );
    }
    if let Ok(lx) = hexcavator_lx::LxFile::parse(data) {
        let _ = (
            lx.objects(),
            lx.resources(),
            lx.entries(),
            lx.import_modules(),
        );
        let _ = (lx.resident_names(), lx.nonresident_names());
        for (i, p) in (0u32..).zip(lx.pages().iter().take(4096)) {
            let _ = (lx.page_data(p), lx.fixups(i));
        }
    }
    let f = s.file("input-legacy.bin", data);
    hexc(&["info", &f]);
    hexc(&["dump", &f]);
}

/// A split DWARF file (a `.dwo`, or a `.dwp`), read with the skeletons of
/// the programs it was split from (tools/elf/split.cmd), DWARF 4 and 5.
fn split_dwarf(data: &[u8], _: &Scratch) {
    static IMAGES: [&[u8]; 2] = [
        include_bytes!("../../../testdata/elf/split-dwarf4"),
        include_bytes!("../../../testdata/elf/split-dwarf5"),
    ];
    for image in IMAGES {
        let Ok(mut debug) = hexcavator_debuginfo::DebugInfo::parse(image) else {
            continue;
        };
        if let Some(d) = debug.dwarf_mut()
            && d.add_split(data).is_ok()
        {
            queries(&debug);
        }
    }
}

/// A Mach-O object file of a debug map, read as each object of the
/// debug maps of testdata/macho/oso's images (its addresses moved to the
/// image's by that object's map), and each query asked.
fn debug_map_object(data: &[u8], _: &Scratch) {
    use hexcavator_debuginfo::dwarf_backend::DwarfInfo;
    static IMAGES: [&[u8]; 2] = [
        include_bytes!("../../../testdata/macho/oso/oso-arm64"),
        include_bytes!("../../../testdata/macho/oso/oso-x86_64"),
    ];
    for image in IMAGES {
        let Ok(m) = hexcavator_macho::MachO::parse(image) else {
            continue;
        };
        for o in m.debug_map() {
            let Ok(mut d) = DwarfInfo::from_debug_map(image) else {
                continue;
            };
            if d.add_object(data, &o.symbols, "").is_ok() {
                queries(&hexcavator_debuginfo::DebugInfo::Dwarf(Box::new(d)));
            }
        }
    }
}

/// The debug information's every query (a PDB's, or DWARF's).
fn debug_info(data: &[u8]) {
    if let Ok(debug) = hexcavator_debuginfo::DebugInfo::parse(data) {
        queries(&debug);
    }
}

fn queries(debug: &hexcavator_debuginfo::DebugInfo<'_>) {
    let _ = debug.compilands();
    let _ = debug.contributions();
    let _ = debug.inline_sites();
    let _ = debug.source_lines();
    let _ = debug.annotations();
    let _ = debug.groups();
    let _ = debug.classes();
    let _ = debug.linker_info();
    if let Ok(symbols) = debug.symbols() {
        for sym in symbols.iter().take(64) {
            let _ = debug.variables(sym.compiland, sym.addr);
            if sym.type_index != 0 {
                let ty = hexcavator_debuginfo::TypeRef(sym.type_index);
                let _ = (
                    debug.type_size(ty),
                    debug.type_shape(ty),
                    debug.type_name(ty),
                );
                let _ = (debug.enumerators(ty), debug.layout(ty));
                let _ = hexcavator_debuginfo::value::read(
                    debug,
                    ty,
                    &[0xA5; 256],
                    hexcavator_debuginfo::value::Limits::default(),
                );
            }
        }
    }
    if let Ok(layouts) = debug.layouts() {
        for l in layouts.iter().take(256) {
            let _ = debug.layout(l.ty);
            let _ = hexcavator_debuginfo::layout::flat_fields(debug, l.ty);
            let _ = hexcavator_debuginfo::value::read(
                debug,
                l.ty,
                &[0xA5; 256],
                hexcavator_debuginfo::value::Limits::default(),
            );
        }
    }
}

fn text(data: &[u8], s: &Scratch) {
    let text = String::from_utf8_lossy(data);
    let _ = hexcavator_linkmap::parse(&text);
    let _ = hexcavator_linkerlog::parse(&text);
    let f = s.file("input-text.bin", data);
    hexc(&["linkerlog", &f]);
}

fn etl(data: &[u8], _: &Scratch) {
    let Ok(etl) = hexcavator_etl::Etl::parse(data) else {
        return;
    };
    for buffer in etl.buffers() {
        let Ok(buffer) = buffer else { break };
        if let Ok(records) = buffer.records() {
            for event in records.flatten() {
                for _ in event.extended_data() {}
            }
        }
    }
    if let Ok(mut cursor) = etl.events() {
        while let Some(event) = cursor.next() {
            if let Ok(event) = event {
                for _ in event.extended_data() {}
            }
        }
    }
}

fn etl_import(data: &[u8], _: &Scratch) {
    if let Ok(etl) = hexcavator_etl::Etl::parse(data) {
        let _ = hexcavator_trace::etw::import(&etl);
    }
}

fn hxtrace(data: &[u8], _: &Scratch) {
    let Ok(trace) = hexcavator_trace::index::read(data, None) else {
        return;
    };
    for s in trace.samples.stack.iter().chain(&trace.switches.stack) {
        let _ = trace.stacks.frames(*s).count();
    }
}

fn manifest(data: &[u8], _: &Scratch) {
    use hexcavator_etw::manifest::{Manifest, decode, wevt_template};
    // The resource of an image, or the input as a resource itself.
    let wevt = wevt_template(data).unwrap_or(data);
    if let Ok(m) = Manifest::parse(wevt) {
        for p in &m.providers {
            for e in &p.events {
                if let Some(t) = p.template(e) {
                    let _ = decode(t, data, 8);
                }
            }
        }
    }
}

fn stacktags(data: &[u8], _: &Scratch) {
    let text = String::from_utf8_lossy(data);
    if let Ok(tags) = hexcavator_trace_analysis::StackTags::from_xml(&text) {
        let _ = tags.frame_tag("ntdll.dll", Some("RtlAllocateHeap"));
    }
    if let Ok(folds) = hexcavator_trace_analysis::Folds::from_text(&text) {
        let _ = folds.frame_rule("ntdll.dll", None);
    }
}

fn demangle(data: &[u8], _: &Scratch) {
    let name = String::from_utf8_lossy(data);
    let _ = hexcavator_demangle::msvc::demangle(&name, 0);
    let _ = hexcavator_demangle::itanium::demangle(&name);
    let mut out = String::new();
    let _ = hexcavator_demangle::rust::demangle_into(&name, &mut out);
    // Swift: as is, and as a Swift name whatever its start (most inputs
    // would stop at the prefix check), in both printings.
    let mut swift = hexcavator_demangle::swift::Demangler::new();
    for name in [name.to_string(), format!("$s{name}"), format!("_T{name}")] {
        out.clear();
        let _ = swift.demangle_into(&name, &mut out);
        let _ = swift.demangle_short_into(&name, &mut out);
    }
    let mut tree = hexcavator_demangle::swift::Tree::default();
    let _ = hexcavator_demangle::swift::demangle_type_as_node(&mut tree, &name);
}

fn x86(data: &[u8], _: &Scratch) {
    for mode in [
        hexcavator_x86::Mode::Bits16,
        hexcavator_x86::Mode::Bits32,
        hexcavator_x86::Mode::Bits64,
    ] {
        let mut at = 0;
        while at < data.len().min(1 << 16) {
            match hexcavator_x86::decode(&data[at..], mode, at as u64) {
                Ok(i) => {
                    let _ = hexcavator_x86::format::to_string(&i);
                    at += i.len().max(1);
                }
                Err(_) => at += 1,
            }
        }
    }
}

fn arm64(data: &[u8], _: &Scratch) {
    for (i, w) in data.as_chunks::<4>().0.iter().take(1 << 14).enumerate() {
        let word = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
        if let Some(inst) = hexcavator_arm64::decode(word, i as u64 * 4) {
            let _ = hexcavator_arm64::format(&inst);
        }
        let _ = hexcavator_arm64::explain(word);
    }
}

/// A32 and T32 (and Thumb functions' IT blocks): decoded and written,
/// with branch targets at the top of the address space.
#[allow(clippy::cast_possible_truncation)]
fn arm32(data: &[u8], _: &Scratch) {
    use hexcavator_arm32::format::{Targets, format, format_in_it};
    for (i, w) in data.as_chunks::<4>().0.iter().take(1 << 14).enumerate() {
        let word = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
        let at = u64::from(u32::MAX).wrapping_sub(i as u64 * 4);
        if let Some(inst) = hexcavator_arm32::decode_a32(word) {
            let _ = format(&inst, at, Targets::Addresses);
        }
        let first = (word >> 16) as u16;
        if let Some(inst) = hexcavator_arm32::decode_t32(first, Some(word as u16)) {
            let mut s = String::new();
            format_in_it(&inst, at, Targets::Offsets, Some(word & 15), &mut s);
            let _ = hexcavator_arm32::format::branch_target(&inst, at);
        }
    }
    let _ = hexcavator_code::sweep(hexcavator_code::Arch::Arm, data, 1);
}

fn query(data: &[u8], _: &Scratch) {
    let text = String::from_utf8_lossy(data);
    let _ = hexcavator_query::parse(&text, &hexcavator_size::table::COLUMNS);
}

fn sourcemap(data: &[u8], _: &Scratch) {
    let _ = hexcavator_size::sourcemap::parse(data);
}

/// The harness's own check (`hexcavator-fuzz selftest`): an input's first
/// byte says what to do wrong: panic, overflow the stack, allocate too
/// much, or never return.
fn selftest(data: &[u8], _: &Scratch) {
    fn deep(n: u64) -> u64 {
        let pad = [n; 64];
        if n == u64::MAX {
            0
        } else {
            std::hint::black_box(deep(n + 1)) + pad[0]
        }
    }
    match data.first() {
        Some(b'P') => panic!("selftest: a panic"),
        Some(b'S') => {
            std::hint::black_box(deep(0));
        }
        Some(b'A') => {
            // (A terabyte on 64-bit hosts: past any cap. Written so that it
            // still compiles for 32-bit targets, which never run it.)
            let v: Vec<u8> = vec![1; 1 << (usize::BITS - 24)];
            std::hint::black_box(v);
        }
        Some(b'L') => loop {
            std::hint::black_box(0);
        },
        _ => {}
    }
}

/// The harness's self-test target (not in [`TARGETS`]).
pub const SELFTEST: Target = Target {
    name: "selftest",
    about: "the harness's own check",
    seeds: is_any,
    run: selftest,
};

/// Every target.
pub const TARGETS: &[Target] = &[
    Target {
        name: "pe",
        about: "PE images: every dump, size by sections, info, batch",
        seeds: is_pe,
        run: pe,
    },
    Target {
        name: "coff",
        about: "COFF objects: dump, size",
        seeds: is_coff_object,
        run: coff,
    },
    Target {
        name: "archive",
        about: "archives (.lib, .a): dump, size by member",
        seeds: is_archive,
        run: archive,
    },
    Target {
        name: "elf",
        about: "ELF files: size by every source, disassembly",
        seeds: is_elf,
        run: elf,
    },
    Target {
        name: "macho",
        about: "Mach-O files: size by every source, disassembly",
        seeds: is_macho,
        run: macho,
    },
    Target {
        name: "wasm",
        about: "WebAssembly modules: size by every source, disassembly",
        seeds: is_wasm,
        run: wasm,
    },
    Target {
        name: "pdb",
        about: "PDBs: the whole dump, types, and every debug-information query",
        seeds: is_pdb,
        run: pdb,
    },
    Target {
        name: "etl",
        about: "event trace logs: buffers, records, decompression, the merge",
        seeds: is_etl,
        run: etl,
    },
    Target {
        name: "etl-import",
        about: "trace import from ETL: kernel event decoding, stack matching, the model",
        seeds: is_etl,
        run: etl_import,
    },
    Target {
        name: "hxtrace",
        about: "trace index files",
        seeds: is_hxtrace,
        run: hxtrace,
    },
    Target {
        name: "manifest",
        about: "instrumentation manifests (WEVT_TEMPLATE) and payloads decoded by them",
        seeds: is_pe,
        run: manifest,
    },
    Target {
        name: "stacktags",
        about: "stack tag XML and folding rules",
        seeds: is_xml,
        run: stacktags,
    },
    Target {
        name: "legacy",
        about: "16-bit NE and linear (LE/LX) executables: every table, info, dump",
        seeds: is_legacy,
        run: legacy,
    },
    Target {
        name: "dwo",
        about: "split DWARF (.dwo files, .dwp packages), with their skeletons",
        seeds: is_split_dwarf,
        run: split_dwarf,
    },
    Target {
        name: "debugmap",
        about: "Mach-O objects of a debug map (no dSYM): their DWARF, addresses moved to the image's",
        seeds: is_macho,
        run: debug_map_object,
    },
    Target {
        name: "text",
        about: "link maps and linker logs",
        seeds: is_text,
        run: text,
    },
    Target {
        name: "demangle",
        about: "the MSVC, Itanium, Rust, and Swift demanglers",
        seeds: is_text,
        run: demangle,
    },
    Target {
        name: "x86",
        about: "the x86 decoder and formatter, in 16-, 32-, and 64-bit modes",
        seeds: is_code,
        run: x86,
    },
    Target {
        name: "arm64",
        about: "the ARM64 decoder, formatter, and explainer",
        seeds: is_code,
        run: arm64,
    },
    Target {
        name: "arm32",
        about: "the AArch32 (A32 and T32) decoder and formatter",
        seeds: is_code,
        run: arm32,
    },
    Target {
        name: "query",
        about: "the query language's parser",
        seeds: is_any,
        run: query,
    },
    Target {
        name: "sourcemap",
        about: "source maps (JSON)",
        seeds: is_any,
        run: sourcemap,
    },
    Target {
        name: "der",
        about: "DER from signatures: certificates, CMS SignedData (checked), code requirements",
        seeds: is_der,
        run: der,
    },
    Target {
        name: "xz",
        about: "xz streams (ELF MiniDebugInfo's container) and their LZMA2 data",
        seeds: is_xz,
        run: xz,
    },
];

/// The target named `name`.
pub fn target(name: &str) -> Option<&'static Target> {
    if name == SELFTEST.name {
        return Some(&SELFTEST);
    }
    TARGETS.iter().find(|t| t.name == name)
}
