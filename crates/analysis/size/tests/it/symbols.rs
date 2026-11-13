//! Symbols from the debug information against SizeBench's `SYMBOL` lines
//! (`testdata/sizebench/oracle`), over SizeBench's own test binaries.
//!
//! Compared: kind, address, file and memory size, and whether folded; and,
//! for code, thunks, strings, exception data, imports, directories, and
//! resources, the name.
//!
//! Every remaining difference must be one of the classified divergences
//! below, which are cases where DIA (and so SizeBench) is arbitrary or
//! wrong.

use std::collections::{BTreeMap, BTreeSet};

use hexcavator_debuginfo::DebugInfo;
use hexcavator_image::Image;
use hexcavator_size::{pe, symbols};

fn root() -> String {
    format!("{}/../../../testdata/sizebench", env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The kinds of symbol compared: those from the debug information, and
/// those from the image's own structures.
const DEBUG_KINDS: &[&str] = &[
    "SimpleFunctionCodeSymbol",
    "PrimaryCodeBlockSymbol",
    "SeparatedCodeBlockSymbol",
    "ThunkSymbol",
    "StaticDataSymbol",
    "PublicSymbol",
    "StringSymbol",
    "PDataSymbol",
    "PackedUnwindDataPDataSymbol",
    "ForwarderPDataSymbol",
    "UnwindInfoSymbol",
    "ChainUnwindInfoSymbol",
    "CppXdataSymbol",
    "StateUnwindMapSymbol",
    "TryMapSymbol",
    "HandlerMapSymbol",
    "IpToStateMapSymbol",
    "SeparatedIpToStateMapSymbol",
    "ImportDescriptorSymbol",
    "ImportThunkSymbol",
    "ImportByNameSymbol",
    "ImportStringSymbol",
    "PEDirectorySymbol",
    "LoadConfigTableSymbol",
    "RsrcDirectorySymbol",
    "RsrcDataEntrySymbol",
    "RsrcStringSymbol",
    "RsrcDataSymbol",
    "RsrcGroupIconDataSymbol",
    "RsrcGroupCursorDataSymbol",
    "RsrcGroupStringTablesDataSymbol",
];

/// Kinds whose names are compared too.
const NAMED_KINDS: &[&str] = &[
    "StaticDataSymbol",
    "SimpleFunctionCodeSymbol",
    "PrimaryCodeBlockSymbol",
    "SeparatedCodeBlockSymbol",
    "ThunkSymbol",
    "StringSymbol",
    "PDataSymbol",
    "PackedUnwindDataPDataSymbol",
    "ForwarderPDataSymbol",
    "UnwindInfoSymbol",
    "ChainUnwindInfoSymbol",
    "CppXdataSymbol",
    "StateUnwindMapSymbol",
    "TryMapSymbol",
    "HandlerMapSymbol",
    "IpToStateMapSymbol",
    "SeparatedIpToStateMapSymbol",
    "ImportDescriptorSymbol",
    "ImportThunkSymbol",
    "ImportByNameSymbol",
    "ImportStringSymbol",
    "PEDirectorySymbol",
    "LoadConfigTableSymbol",
    "RsrcDirectorySymbol",
    "RsrcDataEntrySymbol",
    "RsrcStringSymbol",
    "RsrcDataSymbol",
    "RsrcGroupIconDataSymbol",
    "RsrcGroupCursorDataSymbol",
    "RsrcGroupStringTablesDataSymbol",
];

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Line {
    kind: String,
    addr: u64,
    size: u64,
    vsize: u64,
    folded: bool,
    name: String,
}

impl Line {
    /// What is compared: the name only for named kinds.
    fn key(&self, names: bool) -> (String, u64, u64, u64, bool, String) {
        let name = if names && NAMED_KINDS.contains(&self.kind.as_str()) {
            self.name.clone()
        } else {
            String::new()
        };
        (
            self.kind.clone(),
            self.addr,
            self.size,
            self.vsize,
            self.folded,
            name,
        )
    }
}

fn parse(line: &str) -> Option<Line> {
    let rest = line.strip_prefix("SYMBOL ")?;
    let mut w = rest.splitn(6, ' ');
    let addr = u64::from_str_radix(w.next()?, 16).ok()?;
    let size = w.next()?.strip_prefix("size=")?.parse().ok()?;
    let vsize = w.next()?.strip_prefix("vsize=")?.parse().ok()?;
    let kind = w.next()?.to_string();
    let folded = w.next()? == "1";
    let name = w.next().unwrap_or("").to_string();
    Some(Line {
        kind,
        addr,
        size,
        vsize,
        folded,
        name,
    })
}

/// Why a difference is not ours to fix, if it is a known one.
fn divergence(theirs: Option<&Line>, ours: Option<&Line>) -> Option<&'static str> {
    let any = theirs.or(ours)?;
    // DIA picks arbitrarily among a variable's several records: the CRT's
    // initializer-table markers have an 8-byte definition and an `extern`
    // declaration of size 0, clang's `__security_cookie` has a 64-byte and
    // an 8-byte record. We take the largest that fits before the next
    // symbol.
    if any.kind == "StaticDataSymbol"
        && (any.name.starts_with("__x") || any.name == "__security_cookie")
    {
        return Some("DIA picks one of a variable's records arbitrarily");
    }
    // SizeBench sizes delay-load descriptors as import descriptors (20
    // bytes); an `IMAGE_DELAYLOAD_DESCRIPTOR` is 32.
    if any.kind == "ImportDescriptorSymbol"
        && theirs.is_none_or(|l| l.size == 20)
        && ours.is_none_or(|l| l.size == 32)
    {
        return Some("delay-load descriptors are 32 bytes");
    }
    // DIA gives a public a size of 0 where a contribution does cover it.
    if any.name == "_tls_end" {
        return Some("DIA sizes this public 0");
    }
    // `_guard_dispatch_icall_nop` is both code and data: SizeBench's two
    // names for it sort the data's first. The formatted function name
    // depends on how the PDB records the function's type.
    if any.name.starts_with("_guard_") && any.name.contains("_nop") {
        return Some("code and data at one address");
    }
    // SizeBench guesses whether a string is wide with `IsTextUnicode`; the
    // decorated name says (`??_C@_1` for wide), and we go by it.
    let wide_or_nul = |l: &Line| l.name.starts_with("`string': L\"") || l.name.contains('\0');
    if any.kind == "StringSymbol" && theirs.or(ours).is_some_and(wide_or_nul) {
        return Some("wide or narrow by IsTextUnicode's guess");
    }
    // SizeBench names data for code it can't find a symbol for (DIA
    // returned a zero-size folded name there) `<unnamed code at 0x...>`;
    // we name it for the function holding the code.
    if theirs.is_some_and(|l| l.name.contains("<unnamed code at 0x")) {
        return Some("SizeBench found no symbol for the code");
    }
    // Fortran's own types (dimension arrays with symbolic bounds, complex
    // numbers, OEM types) are named by DIA in ways it alone knows.
    let fortran = |l: &Line| {
        l.name.starts_with("SUBROUTINE")
            || l.name
                .split_once("] ")
                .is_some_and(|(_, n)| n.starts_with("SUBROUTINE"))
    };
    if theirs.or(ours).is_some_and(fortran) {
        return Some("Fortran type names");
    }
    None
}

fn compare(name: &str) -> Vec<String> {
    let dir = format!("{}/bin", root());
    let image_path = ["dll", "exe"]
        .iter()
        .map(|e| format!("{dir}/{name}.{e}"))
        .find(|p| std::path::Path::new(p).exists())
        .unwrap();
    let oracle = format!("{}/oracle/{name}.txt", root());
    compare_files(
        name,
        &image_path,
        &format!("{dir}/{name}.pdb"),
        &oracle,
        true,
    )
}

/// What both sides have at each address, for divergences that show as a
/// pair of differences.
struct Context {
    /// (address, name) of data SizeBench sizes 0, and of data we size.
    their_empty_data: BTreeSet<(u64, String)>,
    our_sized_data: BTreeSet<(u64, String)>,
    /// Addresses of SizeBench's data, and of our functions' statics.
    their_data: BTreeSet<u64>,
    our_statics: BTreeSet<u64>,
}

impl Context {
    fn new(theirs: &[Line], ours: &[Line]) -> Self {
        let data = |l: &&Line| l.kind == "StaticDataSymbol";
        Self {
            their_empty_data: theirs
                .iter()
                .filter(data)
                .filter(|l| l.size == 0 && l.vsize == 0)
                .map(|l| (l.addr, l.name.clone()))
                .collect(),
            our_sized_data: ours
                .iter()
                .filter(data)
                .filter(|l| l.vsize > 0)
                .map(|l| (l.addr, l.name.clone()))
                .collect(),
            their_data: theirs.iter().filter(data).map(|l| l.addr).collect(),
            our_statics: ours
                .iter()
                .filter(data)
                .filter(|l| l.name.contains(" (in "))
                .map(|l| l.addr)
                .collect(),
        }
    }

    fn divergence(&self, theirs: Option<&Line>, ours: Option<&Line>) -> Option<&'static str> {
        let any = theirs.or(ours)?;
        // A variable recorded twice, once with its complete type and once
        // with an incomplete one (`extern const T table[];`): DIA sizes it
        // by the incomplete one, 0; we by the complete one.
        if any.kind == "StaticDataSymbol" {
            let key = (any.addr, any.name.clone());
            if self.their_empty_data.contains(&key) && self.our_sized_data.contains(&key) {
                return Some("DIA picks a variable's incomplete record");
            }
        }
        // DIA leaves some functions' statics out of its symbols by address
        // (one with an incomplete type, or one an inline function's copies
        // share); SizeBench then shows their publics, if they have any.
        if let Some(o) = ours
            && o.kind == "StaticDataSymbol"
            && o.name.contains(" (in ")
            && !self.their_data.contains(&o.addr)
        {
            return Some("DIA omits this function's static");
        }
        if let Some(t) = theirs
            && t.kind == "PublicSymbol"
            && self.our_statics.contains(&t.addr)
        {
            return Some("DIA omits this function's static");
        }
        None
    }
}

/// Compares the symbols of an image (with its PDB) with SizeBench's; with
/// `names`, names too.
fn compare_files(
    name: &str,
    image_path: &str,
    pdb_path: &str,
    oracle: &str,
    names: bool,
) -> Vec<String> {
    let image_data = read(image_path);
    let pdb_data = read(pdb_path);
    let image = Image::parse(&image_data).unwrap();
    let debug = DebugInfo::parse(&pdb_data).unwrap();
    let model = pe::model(&image, &debug).unwrap();
    let ours = symbols::build(&image, &debug, &model).unwrap();

    let text = std::fs::read_to_string(oracle).unwrap();
    let all: Vec<Line> = text.lines().filter_map(parse).collect();
    let theirs: Vec<Line> = all
        .into_iter()
        .filter(|l| DEBUG_KINDS.contains(&l.kind.as_str()))
        .collect();
    let ours: Vec<Line> = ours
        .iter()
        .map(|s| Line {
            kind: s.kind.sizebench_name().to_string(),
            addr: s.addr,
            size: s.size.file,
            vsize: s.size.vm,
            folded: s.folded,
            name: s.name.clone(),
        })
        .collect();

    // Multisets by key.
    let mut counts: BTreeMap<_, (Vec<&Line>, Vec<&Line>)> = BTreeMap::new();
    for l in &theirs {
        counts.entry(l.key(names)).or_default().0.push(l);
    }
    for l in &ours {
        counts.entry(l.key(names)).or_default().1.push(l);
    }
    let context = Context::new(&theirs, &ours);
    let mut failures = Vec::new();
    for (key, (t, o)) in &counts {
        if t.len() == o.len() {
            continue;
        }
        let (a, b) = (t.first().copied(), o.first().copied());
        if divergence(a, b).is_some() || context.divergence(a, b).is_some() {
            continue;
        }
        failures.push(format!(
            "{name}: {} {:08x} size={} vsize={} folded={} {:?}: SizeBench {} ours {}",
            key.0,
            key.1,
            key.2,
            key.3,
            key.4,
            a.or(b).map(|l| &l.name),
            t.len(),
            o.len()
        ));
    }
    failures
}

#[test]
fn symbols_match_sizebench() {
    let mut names: Vec<String> = std::fs::read_dir(format!("{}/oracle", root()))
        .unwrap()
        .map(|e| {
            e.unwrap()
                .path()
                .file_stem()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string()
        })
        .collect();
    names.sort();
    let failures: Vec<String> = names.iter().flat_map(|n| compare(n)).collect();
    assert!(
        failures.is_empty(),
        "{} differences:\n{}",
        failures.len(),
        failures[..failures.len().min(60)].join("\n")
    );
}

#[test]
fn string_literal_lengths() {
    use symbols::string_literal_length as len;
    assert_eq!(len("??_C@_0BA@IEJMDDPN@dummy?5exception?$AA@"), Some(16));
    assert_eq!(len("??_C@_0BC@EOODALEL@Unknown?5exception?$AA@"), Some(18));
    assert_eq!(len("??_C@_0O@CDJKHIHK@a?5test?5string?$AA@"), Some(14));
    assert_eq!(len("??_C@_01KDCPPGHE@?$AA@"), Some(2));
    assert_eq!(len("??_C@_1BK@MGHPJBJL@?$AAt?$AAe?$AAs?$AAt@"), Some(26));
    assert_eq!(len("??_C@_0BBN@GPMLNJCF@A?5cast@"), Some(0x11D));
    // Not string literals, or malformed.
    assert_eq!(len("??_R0?AVtype_info@@@8"), None);
    assert_eq!(len("??_C@_2A@x@"), None);
    assert_eq!(len("??_C@_0"), None);
    assert_eq!(len("??_C@_0BA"), None);
    assert_eq!(len("??_C@_0BZ@x@"), None);
    // A length that overflows is rejected, not wrapped.
    assert_eq!(len("??_C@_0PPPPPPPPPPPPPPPPP@x@"), None);
}

/// Exception data is followed through untrusted RVAs: corrupting it must
/// give wrong symbols, never a panic or a hang.
#[test]
fn corrupted_exception_data_does_not_panic() {
    struct Nothing;
    impl hexcavator_size::eh::Context for Nothing {
        fn target_name(&self, _: u64) -> Option<String> {
            None
        }
        fn handler(&self, addr: u64) -> hexcavator_size::eh::Handler {
            // Pretend every handler is each kind in turn.
            match addr % 4 {
                0 => hexcavator_size::eh::Handler::Cxx3,
                1 => hexcavator_size::eh::Handler::Cxx4,
                2 => hexcavator_size::eh::Handler::GsSeh,
                _ => hexcavator_size::eh::Handler::GsCxx4,
            }
        }
    }
    for name in [
        "PEParser.Tests.Dllx64.dll",
        "PEParser.Tests.DllCxxFrameHandler4.dll",
        "PEParser.Tests.Dllarm32.dll",
    ] {
        let data = read(&format!("{}/bin/{name}", root()));
        let image = Image::parse(&data).unwrap();
        let pe = *image.pe().unwrap();
        // The .pdata and .xdata (in .rdata) file ranges.
        let ranges: Vec<(usize, usize)> = image
            .sections()
            .iter()
            .filter(|s| s.name == b".pdata" || s.name == b".rdata")
            .map(|s| {
                (
                    usize::try_from(s.file_offset).unwrap(),
                    usize::try_from(s.file_offset + s.file_size).unwrap(),
                )
            })
            .collect();
        let baseline = hexcavator_size::eh::symbols(&pe, &Nothing).len();
        assert!(baseline > 0, "{name}");
        let mut copy = data.clone();
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        for _ in 0..400 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let (start, end) = ranges[usize::try_from(seed % ranges.len() as u64).unwrap()];
            let at = start + usize::try_from((seed >> 8) % (end - start) as u64).unwrap();
            let original = copy[at];
            copy[at] = (seed >> 32).to_le_bytes()[0];
            if let Ok(image) = Image::parse(&copy) {
                let _ = hexcavator_size::eh::symbols(image.pe().unwrap(), &Nothing);
            }
            if !seed.is_multiple_of(3) {
                copy[at] = original;
            }
        }
    }
}

/// Imports, directories, and resources are also followed through untrusted
/// offsets and RVAs: corrupting them must never panic or hang.
#[test]
fn corrupted_imports_and_resources_do_not_panic() {
    for name in ["PEParser.Tests.Dllx64.dll", "PEParser.Tests.Dllx86.dll"] {
        let data = read(&format!("{}/bin/{name}", root()));
        let image = Image::parse(&data).unwrap();
        let pe = *image.pe().unwrap();
        assert!(
            !hexcavator_size::pe_symbols::symbols(&pe).is_empty(),
            "{name}"
        );
        assert!(!hexcavator_size::rsrc::symbols(&pe).is_empty(), "{name}");
        let ranges: Vec<(usize, usize)> = image
            .sections()
            .iter()
            .filter(|s| matches!(s.name, b".rdata" | b".idata" | b".rsrc" | b".data"))
            .map(|s| {
                (
                    usize::try_from(s.file_offset).unwrap(),
                    usize::try_from(s.file_offset + s.file_size).unwrap(),
                )
            })
            .collect();
        let mut copy = data.clone();
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        for _ in 0..2000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let (start, end) = ranges[usize::try_from(seed % ranges.len() as u64).unwrap()];
            let at = start + usize::try_from((seed >> 8) % (end - start) as u64).unwrap();
            let original = copy[at];
            copy[at] = (seed >> 32).to_le_bytes()[0];
            if let Ok(image) = Image::parse(&copy) {
                let pe = image.pe().unwrap();
                let _ = hexcavator_size::pe_symbols::symbols(pe);
                let _ = hexcavator_size::rsrc::symbols(pe);
            }
            if !seed.is_multiple_of(3) {
                copy[at] = original;
            }
        }
    }
}
