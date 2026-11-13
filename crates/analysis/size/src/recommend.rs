//! Recommendations: changes to a build that would make an image smaller,
//! each with the bytes it would save, measured from the image itself. What
//! can't be measured isn't recommended. The advice is in the terms of the
//! image's [`Toolchain`] (MSVC's options here):
//!
//! - Compile an object with `/Gy` (functions) or `/Gw` (data): what nothing
//!   reaches in its sections that aren't COMDATs, and the COMDATs only they
//!   refer to (see [`crate::xref::Kept`]). Objects from the toolset's own
//!   libraries are left out: they can't be rebuilt.
//! - Link with `/OPT:REF`: COMDATs nothing reaches, when the link didn't
//!   drop them.
//! - Link with `/OPT:ICF`: functions the linker could fold
//!   ([`crate::fingerprint::Mode::Foldable`]), when the link didn't fold.
//! - Define a duplicated variable once: a file-scope variable (or a
//!   `const` in a header) with the same bytes in several objects.
//!
//! Only a PDB records the link's options. Elsewhere ([`Link::judged`]) the
//! image is the evidence: functions nothing reaches that the linker could
//! have dropped alone weren't collected, and identical functions at
//! different addresses weren't folded.
//!
//! Each must save at least [`MIN_SAVING`] bytes.

use crate::findings::DuplicateData;
use crate::xref::{Kept, Xref};

/// One recommendation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recommendation {
    /// What kind it is: `function-sections`, `data-sections`, `gc`, `icf`,
    /// `duplicates`, `relr`, `hash-style`, `strip`.
    pub kind: &'static str,
    /// What to do.
    pub advice: String,
    /// The bytes it would save (in memory; at least).
    pub saving: u64,
    /// The largest things it would remove, with their sizes.
    pub examples: Vec<(String, u64)>,
}

/// Whose compiler and linker built an image: the options the advice names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Toolchain {
    /// MSVC (and clang-cl and lld-link): `/Gy`, `/OPT:REF`, ...
    Msvc,
    /// GCC or Clang with GNU ld, gold, or lld, for ELF (or PE with DWARF,
    /// as MinGW builds it): `-ffunction-sections`, `--gc-sections`, ...
    Gnu,
    /// Clang with Apple's linker (or `ld64.lld`), for Mach-O.
    Apple,
}

impl Toolchain {
    /// The toolchain of an image with this debug information.
    pub fn of(
        image: &hexcavator_image::Image<'_>,
        debug: &hexcavator_debuginfo::DebugInfo<'_>,
    ) -> Self {
        if image.macho().is_some() {
            Toolchain::Apple
        } else if image.pe().is_some() && debug.pdb().is_some() {
            Toolchain::Msvc
        } else {
            Toolchain::Gnu
        }
    }

    fn function_sections(self) -> &'static str {
        match self {
            Toolchain::Msvc => "/Gy",
            Toolchain::Gnu | Toolchain::Apple => "-ffunction-sections",
        }
    }

    fn data_sections(self) -> &'static str {
        match self {
            Toolchain::Msvc => "/Gw",
            Toolchain::Gnu | Toolchain::Apple => "-fdata-sections",
        }
    }

    fn gc(self) -> &'static str {
        match self {
            Toolchain::Msvc => "link with /OPT:REF: COMDATs nothing reaches are kept",
            Toolchain::Gnu => {
                "link with -Wl,--gc-sections (compiling with -ffunction-sections -fdata-sections): functions and data nothing reaches are kept"
            }
            Toolchain::Apple => {
                "link with -Wl,-dead_strip: functions and data nothing reaches are kept"
            }
        }
    }

    fn icf(self) -> &'static str {
        match self {
            Toolchain::Msvc => "link with /OPT:ICF",
            Toolchain::Gnu => "link with -Wl,--icf=all (lld or gold)",
            Toolchain::Apple => "link with ld64.lld --icf=all",
        }
    }
}

/// What a link did, from its command line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Link {
    /// `/OPT:REF`: unreferenced COMDATs dropped.
    pub opt_ref: bool,
    /// `/OPT:ICF`: identical COMDATs folded.
    pub opt_icf: bool,
}

impl Link {
    /// A link whose options aren't recorded: what it dropped and folded
    /// is judged from the image (nothing it could have dropped or folded
    /// is there if it did).
    pub fn judged() -> Link {
        Link {
            opt_ref: false,
            opt_icf: false,
        }
    }

    /// The options `command` (the linker's arguments) gives, with the
    /// linker's defaults: `/OPT:REF` and `/OPT:ICF` without `/DEBUG`, and
    /// neither with it; `/OPT:REF` (or `/OPT:ICF`) given explicitly, and
    /// `/OPT:ICF` along with `/OPT:REF` unless `NOICF`.
    pub fn from_command_line(command: &str) -> Link {
        let mut debug = false;
        let (mut opt_ref, mut opt_icf) = (None, None);
        for arg in split_args(command) {
            let Some(arg) = arg.strip_prefix(['/', '-']) else {
                continue;
            };
            let upper = arg.to_ascii_uppercase();
            if upper == "DEBUG" || upper.starts_with("DEBUG:") {
                debug = upper != "DEBUG:NONE";
            } else if let Some(opts) = upper.strip_prefix("OPT:") {
                for o in opts.split(',') {
                    match o {
                        "REF" => {
                            opt_ref = Some(true);
                            opt_icf.get_or_insert(true);
                        }
                        "NOREF" => opt_ref = Some(false),
                        "NOICF" => opt_icf = Some(false),
                        o if o == "ICF" || o.starts_with("ICF=") => opt_icf = Some(true),
                        _ => {}
                    }
                }
            }
        }
        Link {
            opt_ref: opt_ref.unwrap_or(!debug),
            opt_icf: opt_icf.unwrap_or(!debug),
        }
    }
}

/// Splits a command line into arguments: by spaces, but not inside quotes.
fn split_args(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut arg = String::new();
    let mut quoted = false;
    for c in command.chars() {
        match c {
            '"' => quoted = !quoted,
            ' ' | '\t' if !quoted => {
                if !arg.is_empty() {
                    out.push(std::mem::take(&mut arg));
                }
            }
            c => arg.push(c),
        }
    }
    if !arg.is_empty() {
        out.push(arg);
    }
    out
}

/// Whether `library` is one of the toolset's or the SDK's (its objects
/// can't be rebuilt with other options).
fn system_library(library: &str) -> bool {
    let lower = library.to_ascii_lowercase().replace('/', "\\");
    let file = lower.rsplit('\\').next().unwrap_or(&lower);
    const NAMES: [&str; 14] = [
        "msvcrt.lib",
        "msvcrtd.lib",
        "libcmt.lib",
        "libcmtd.lib",
        "vcruntime.lib",
        "vcruntimed.lib",
        "libvcruntime.lib",
        "libvcruntimed.lib",
        "ucrt.lib",
        "ucrtd.lib",
        "libucrt.lib",
        "libucrtd.lib",
        "msvcprt.lib",
        "libcpmt.lib",
    ];
    NAMES.contains(&file)
        || lower.contains("\\microsoft visual studio\\")
        || lower.contains("\\windows kits\\")
        || lower.contains("\\vctools\\")
        || lower.starts_with("import:")
}

/// How many examples a recommendation lists.
const EXAMPLES: usize = 5;

/// The least a recommendation must save to be made: a change to a build
/// for a few bytes isn't worth making.
pub const MIN_SAVING: u64 = 64;

/// The recommendations for an image: from its graph `x`, the
/// link's options (if known), the classes of [`crate::fingerprint::Mode::
/// Foldable`] (if computed), and its duplicated variables. Largest saving
/// first.
pub fn recommend(
    x: &Xref,
    toolchain: Toolchain,
    link: Option<Link>,
    foldable: Option<&[u64]>,
    duplicates: &[DuplicateData],
) -> Vec<Recommendation> {
    let mut out = Vec::new();
    let unreached: Vec<u32> = x
        .ids()
        .filter(|&n| !x.reach.is_reached(n) && x.kinds[n as usize].is_some())
        .collect();
    // Per object: what /Gy and /Gw would let /OPT:REF drop.
    let mut per_object: std::collections::BTreeMap<(u32, bool), Vec<u32>> =
        std::collections::BTreeMap::new();
    for &n in &unreached {
        let (owner, code) = match x.kept(n) {
            Kept::WithSection { code } => (n, code),
            Kept::ReferencedBy(by) => match x.kept(by) {
                Kept::WithSection { code } => (by, code),
                _ => continue,
            },
            _ => continue,
        };
        // Data a function owns (its unwind data, say) goes with it under
        // /Gy (an associative COMDAT).
        let code = code || owned_by_code(x, owner, 2);
        if let Some((c, _)) = x.contribution[owner as usize] {
            per_object.entry((c, code)).or_default().push(n);
        }
    }
    let library = |c: u32| x.libraries.get(c as usize).map_or("", String::as_str);
    for ((c, code), nodes) in per_object {
        let object = x.compilands.get(c as usize).map_or("", String::as_str);
        if system_library(library(c)) || system_library(object) {
            continue;
        }
        let saving = nodes.iter().map(|&n| x.size(n)).sum();
        let name = object.rsplit(['\\', '/']).next().unwrap_or(object);
        out.push(Recommendation {
            kind: if code { "function-sections" } else { "data-sections" },
            advice: if code {
                format!(
                    "compile {name} with {}: its functions nothing reaches are kept with the sections they share with ones that are used",
                    toolchain.function_sections()
                )
            } else {
                format!(
                    "compile {name} with {}: its data nothing reaches is kept with the sections it shares with data that is used",
                    toolchain.data_sections()
                )
            },
            saving,
            examples: examples(x, &nodes),
        });
    }
    if let Some(link) = link {
        if !link.opt_ref {
            let nodes: Vec<u32> = unreached
                .iter()
                .copied()
                .filter(|&n| matches!(x.kept(n), Kept::Comdat))
                .collect();
            let saving: u64 = nodes.iter().map(|&n| x.size(n)).sum();
            if saving > 0 {
                out.push(Recommendation {
                    kind: "gc",
                    advice: toolchain.gc().into(),
                    saving,
                    examples: examples(x, &nodes),
                });
            }
        }
        if !link.opt_icf
            && let Some(classes) = foldable
        {
            let groups = crate::fingerprint::identical(x, classes);
            let saving: u64 = groups.iter().map(|g| g.1).sum();
            if saving > 0 {
                let mut ex: Vec<(String, u64)> = groups
                    .iter()
                    .take(EXAMPLES)
                    .map(|(g, s)| {
                        (
                            format!("{} ({} copies)", x.names[g[0] as usize], g.len()),
                            *s,
                        )
                    })
                    .collect();
                ex.sort_by_key(|a| std::cmp::Reverse(a.1));
                out.push(Recommendation {
                    kind: "icf",
                    advice: format!(
                        "{}: {} groups of identical functions aren't folded",
                        toolchain.icf(),
                        groups.len()
                    ),
                    saving,
                    examples: ex,
                });
            }
        }
    }
    // Duplicated variables: all but one copy.
    let mut dup: Vec<(String, u64)> = duplicates
        .iter()
        .filter(|d| d.copies.len() > 1)
        .map(|d| {
            (
                format!("{} ({} copies)", d.name, d.copies.len()),
                d.size.vm.max(d.size.file) * (d.copies.len() as u64 - 1),
            )
        })
        .filter(|d| d.1 > 0)
        .collect();
    if !dup.is_empty() {
        dup.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let saving = dup.iter().map(|d| d.1).sum();
        out.push(Recommendation {
            kind: "duplicates",
            advice: format!(
                "define {} variables once: each has a copy in several objects (a file-scope `static`, or a `const` in a header: make it `inline` or `extern`)",
                dup.len()
            ),
            saving,
            examples: dup.into_iter().take(EXAMPLES).collect(),
        });
    }
    out.retain(|r| r.saving >= MIN_SAVING);
    out.sort_by(|a, b| {
        b.saving
            .cmp(&a.saving)
            .then_with(|| a.advice.cmp(&b.advice))
    });
    out
}

/// Whether a function owns `n`, directly or through at most `depth`
/// owners (a function owns its `.pdata` entry, which owns its unwind data).
fn owned_by_code(x: &Xref, n: u32, depth: u32) -> bool {
    depth > 0
        && x.graph.referrers(n).iter().any(|&(f, e)| {
            e == hexcavator_xref::Edge::Attached
                && (x.graph.nodes()[f as usize].code || owned_by_code(x, f, depth - 1))
        })
}

/// The largest of `nodes`, with their sizes.
fn examples(x: &Xref, nodes: &[u32]) -> Vec<(String, u64)> {
    let mut v: Vec<(String, u64)> = nodes
        .iter()
        .map(|&n| (x.names[n as usize].clone(), x.size(n)))
        .collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.truncate(EXAMPLES);
    v
}

/// What the image's own structure says could be smaller, by format, each
/// measured from it (at least [`MIN_SAVING`] bytes):
///
/// - ELF: relative relocations as RELR (`-z pack-relative-relocs`): the
///   `.rela.dyn` entries that would become a RELR table, less that table
///   (encoded here, as the linker would); and `.hash` beside `.gnu.hash`
///   (`--hash-style=gnu`).
/// - WebAssembly: custom sections a module doesn't need to run (names,
///   producers, DWARF, source map links): a module is downloaded whole.
pub fn structural(image: &hexcavator_image::Image<'_>) -> Vec<Recommendation> {
    let mut out = Vec::new();
    if let Some(elf) = image.elf() {
        elf_relr(elf, &mut out);
        elf_hash(elf, &mut out);
    }
    if let Some(m) = image.wasm() {
        wasm_custom(m, &mut out);
    }
    out.retain(|r| r.saving >= MIN_SAVING);
    out
}

/// The relative relocation type of `machine`.
fn relative_type(machine: u16) -> Option<u32> {
    use hexcavator_elf::consts::*;
    Some(match machine {
        EM_X86_64 | EM_386 => 8,
        EM_AARCH64 => 1027,
        EM_ARM => 23,
        EM_RISCV => 3,
        EM_PPC64 => 22,
        _ => return None,
    })
}

fn elf_relr(elf: &hexcavator_elf::ElfFile<'_>, out: &mut Vec<Recommendation>) {
    use hexcavator_elf::consts::*;
    let Some(relative) = relative_type(elf.header().machine) else {
        return;
    };
    let sections: Vec<_> = elf.sections().collect();
    if elf.is_object()
        || sections
            .iter()
            .any(|s| s.kind == SHT_RELR || s.kind == 0x6FFF_FF00)
    {
        return;
    }
    let word: u64 = if elf.class() == hexcavator_elf::Class::Elf64 {
        8
    } else {
        4
    };
    let mut offsets = Vec::new();
    let mut bytes = 0u64;
    for s in sections
        .iter()
        .filter(|s| (s.kind == SHT_RELA || s.kind == SHT_REL) && s.is_alloc())
    {
        let entry = if s.entsize != 0 {
            s.entsize
        } else if s.kind == SHT_RELA {
            3 * word
        } else {
            2 * word
        };
        for r in elf.relocations(s) {
            // (Only word-aligned ones: RELR encodes words.)
            if r.kind == relative && r.offset % word == 0 {
                offsets.push(r.offset);
                bytes += entry;
            }
        }
    }
    if offsets.is_empty() {
        return;
    }
    offsets.sort_unstable();
    offsets.dedup();
    let relr = relr_size(&offsets, word);
    out.push(Recommendation {
        kind: "relr",
        advice: format!(
            "link with -z pack-relative-relocs (lld; GNU ld 2.38 and later): its {} relative relocations ({bytes} bytes) become a {relr}-byte RELR table",
            offsets.len()
        ),
        saving: bytes.saturating_sub(relr),
        examples: Vec::new(),
    });
}

/// The size of a RELR table holding `offsets` (sorted), `word` bytes a
/// word, as linkers encode it: an address, then bitmaps of the words
/// after it.
pub fn relr_size(offsets: &[u64], word: u64) -> u64 {
    let bits = word * 8 - 1;
    let mut entries = 0u64;
    let mut i = 0;
    while i < offsets.len() {
        // An address entry, for the first offset not yet covered.
        let base = offsets[i];
        entries += 1;
        i += 1;
        let mut next = base + word;
        loop {
            // A bitmap entry for the next `bits` words, if any offset falls
            // there.
            let end = next + bits * word;
            let mut any = false;
            while i < offsets.len() && offsets[i] < end {
                any = true;
                i += 1;
            }
            if !any {
                break;
            }
            entries += 1;
            next = end;
        }
    }
    entries * word
}

fn elf_hash(elf: &hexcavator_elf::ElfFile<'_>, out: &mut Vec<Recommendation>) {
    use hexcavator_elf::consts::*;
    let sections: Vec<_> = elf.sections().collect();
    let (Some(hash), true) = (
        sections.iter().find(|s| s.kind == SHT_HASH),
        sections.iter().any(|s| s.kind == SHT_GNU_HASH),
    ) else {
        return;
    };
    out.push(Recommendation {
        kind: "hash-style",
        advice: "link with --hash-style=gnu: .hash only repeats what .gnu.hash says (for loaders older than 2006)".into(),
        saving: hash.size,
        examples: vec![(".hash".into(), hash.size)],
    });
}

fn wasm_custom(m: &hexcavator_wasm::Module<'_>, out: &mut Vec<Recommendation>) {
    let strippable = |name: &[u8]| {
        name == b"name"
            || name == b"producers"
            || name == b"sourceMappingURL"
            || name == b"external_debug_info"
            || name == b"build_id"
            || name.starts_with(b".debug_")
    };
    let mut examples: Vec<(String, u64)> = m
        .sections()
        .iter()
        .filter(|s| s.id == hexcavator_wasm::SECTION_CUSTOM && strippable(s.name))
        .map(|s| (String::from_utf8_lossy(s.name).into_owned(), s.size))
        .collect();
    if examples.is_empty() || m.is_object() {
        return;
    }
    examples.sort_by_key(|e| std::cmp::Reverse(e.1));
    let saving = examples.iter().map(|e| e.1).sum();
    out.push(Recommendation {
        kind: "strip",
        advice: "strip its custom sections a module doesn't need to run (wasm-opt --strip-debug --strip-producers, or wasm-strip; keep a copy for debugging): names, producers, DWARF".into(),
        saving,
        examples,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_options() {
        let l = |c: &str| Link::from_command_line(c);
        assert_eq!(
            l("/OUT:a.exe a.obj"),
            Link {
                opt_ref: true,
                opt_icf: true
            }
        );
        assert_eq!(
            l("/DEBUG a.obj"),
            Link {
                opt_ref: false,
                opt_icf: false
            }
        );
        assert_eq!(
            l("/debug:full /OPT:REF"),
            Link {
                opt_ref: true,
                opt_icf: true
            }
        );
        assert_eq!(
            l("-DEBUG -opt:ref,noicf"),
            Link {
                opt_ref: true,
                opt_icf: false
            }
        );
        assert_eq!(
            l("/DEBUG /OPT:ICF"),
            Link {
                opt_ref: false,
                opt_icf: true
            }
        );
        assert_eq!(
            l("/OPT:NOREF"),
            Link {
                opt_ref: false,
                opt_icf: true
            }
        );
        assert_eq!(
            l("/DEBUG:NONE"),
            Link {
                opt_ref: true,
                opt_icf: true
            }
        );
        assert_eq!(
            l("/DEBUG /OPT:ICF=3 \"/LIBPATH:C:\\a b\""),
            Link {
                opt_ref: false,
                opt_icf: true
            }
        );
        assert_eq!(split_args(" a  \"b c\"\td "), ["a", "b c", "d"]);
    }

    #[test]
    fn system_libraries() {
        assert!(system_library("msvcrt.lib"));
        assert!(system_library(
            r"C:\Program Files\Microsoft Visual Studio\18\VC\lib\x64\LIBCMT.lib"
        ));
        assert!(system_library(
            r"C:\Program Files (x86)\Windows Kits\10\lib\um\x64\kernel32.lib"
        ));
        assert!(system_library("Import:KERNEL32.dll"));
        assert!(!system_library(r"C:\src\app\build\mylib.lib"));
        assert!(!system_library(r"C:\src\app\dead.obj"));
    }
}
