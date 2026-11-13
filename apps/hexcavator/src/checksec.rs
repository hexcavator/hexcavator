//! `hexc checksec`: the exploit mitigations an image was built with (PE,
//! ELF, Mach-O), each on, off, or not applicable, with why; and, with
//! `-audit`, the compilers and options its objects were built with, from
//! its debug information (a PDB's S_COMPILE3 and build information; DWARF
//! units' DW_AT_producer), and the objects that differ from the rest.
//!
//! Everything is read from the files; nothing is run. Every list read
//! from them is bounded by them.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;
use std::process::ExitCode;

use hexcavator_mmap::Mmap;
use serde_json::{Value as Json, json};

const USAGE: &str = "\
usage: hexc checksec [options] <image>...

The exploit mitigations each image was built with: for PE images ASLR,
high-entropy ASLR, DEP, CFG, XFG, CET shadow stacks, EH continuation,
SafeSEH, /GS, and more; for ELF, PIE, RELRO, NX, stack canaries,
FORTIFY_SOURCE, CET (IBT, SHSTK), BTI and PAC, RPATH, text relocations;
for Mach-O, PIE, NX, canaries, ARC, pointer authentication (arm64e), the
code signature (hardened runtime, library validation, entitlements), and
encryption. Each is on, off, or n/a, with what says so.

options:
  -audit         also the compilers and options its objects were built with
                 (from the PDB's records, or DWARF's DW_AT_producer), and the
                 objects built differently from the rest
  -pdb <path>    its debug information (for -audit; or -debug)
  -json          as JSON";

#[derive(Default)]
struct Options {
    audit: bool,
    json: bool,
    pdb: Option<String>,
    files: Vec<String>,
}

pub fn run(args: &[String]) -> ExitCode {
    let mut o = Options::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.strip_prefix('-').or_else(|| a.strip_prefix('/')) {
            Some("audit") => o.audit = true,
            Some("json") => o.json = true,
            Some("pdb" | "debug") => match it.next() {
                Some(p) => o.pdb = Some(p.clone()),
                None => {
                    ereport!("hexc checksec: -pdb: expected a path");
                    return ExitCode::from(2);
                }
            },
            Some(x) if !x.is_empty() && !Path::new(a).exists() => {
                ereport!("hexc checksec: unknown option '{a}'\n\n{USAGE}");
                return ExitCode::from(2);
            }
            _ => o.files.push(a.clone()),
        }
    }
    if o.files.is_empty() {
        ereport!("{USAGE}");
        return ExitCode::from(2);
    }
    let mut status = ExitCode::SUCCESS;
    let mut all = Vec::new();
    let mut text = String::new();
    for f in &o.files {
        match check(f, &o) {
            Ok(report) => {
                if o.json {
                    all.push(report.json());
                } else {
                    report.text(&mut text);
                }
            }
            Err(e) => {
                ereport!("hexc checksec: {e}");
                status = ExitCode::FAILURE;
            }
        }
    }
    let text = if o.json {
        let v = if all.len() == 1 {
            all.remove(0)
        } else {
            Json::Array(all)
        };
        format!("{v}\n")
    } else {
        text
    };
    if !crate::out::printed(text.as_bytes()) {
        return ExitCode::FAILURE;
    }
    status
}

/// A mitigation's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    On,
    Partial,
    Off,
    /// Not applicable to this kind of image or architecture.
    NotApplicable,
    /// Information, not a mitigation.
    Info,
}

impl State {
    fn word(self) -> &'static str {
        match self {
            State::On => "yes",
            State::Partial => "partial",
            State::Off => "NO",
            State::NotApplicable => "n/a",
            State::Info => "",
        }
    }
    fn key(self) -> &'static str {
        match self {
            State::On => "on",
            State::Partial => "partial",
            State::Off => "off",
            State::NotApplicable => "n/a",
            State::Info => "info",
        }
    }
}

/// One check: its name, state, and what says so.
pub struct Check {
    pub name: &'static str,
    pub state: State,
    pub detail: String,
}

/// The linker's environment block (key, value pairs).
type Environment = Vec<(String, String)>;

/// An object's build, as its debug information records it.
#[derive(Clone, Debug, Default)]
pub struct Build {
    /// The object (module, or DWARF unit's name).
    pub object: String,
    /// The library it came from, if known.
    pub library: String,
    /// The compiler and its version.
    pub compiler: String,
    /// The options that matter, by name (`/GS`: `on`; `-O`: `2`).
    pub options: BTreeMap<String, String>,
    /// The command line it was built with (MSVC's arguments, from
    /// `LF_BUILDINFO`; or `DW_AT_producer`, with the switches recorded).
    pub command: String,
    /// The tool that built it (MSVC's `cl.exe` path).
    pub tool: String,
    /// The directory it was built in.
    pub cwd: String,
    /// Its source file.
    pub source: String,
    /// The PDB the compiler wrote (MSVC).
    pub pdb: String,
}

pub struct Report {
    pub path: String,
    pub format: &'static str,
    pub checks: Vec<Check>,
    pub builds: Option<Vec<Build>>,
    /// The linker's record of the link (a PDB's `S_ENVBLOCK`: `cwd`,
    /// `exe`, `pdb`, `cmd`).
    pub linker: Vec<(String, String)>,
    pub audit_note: Option<String>,
}

fn check(path: &str, o: &Options) -> Result<Report, String> {
    let map = Mmap::open(path).map_err(|e| format!("{path}: {e}"))?;
    let image = hexcavator_image::Image::parse(&map).map_err(|e| format!("{path}: {e}"))?;
    let (format, checks) = match &image {
        hexcavator_image::Image::Pe(pe) => ("pe", pe_checks(pe)),
        hexcavator_image::Image::Elf(elf) => ("elf", elf_checks(elf)),
        hexcavator_image::Image::MachO(m) => ("macho", macho_checks(m)),
        _ => return Err(format!("{path}: checksec reads PE, ELF, and Mach-O images")),
    };
    let (builds, linker, audit_note) = if o.audit {
        match audit(path, &image, o.pdb.as_deref()) {
            Ok((b, l)) => (Some(b), l, None),
            Err(e) => (None, Vec::new(), Some(e)),
        }
    } else {
        (None, Vec::new(), None)
    };
    Ok(Report {
        path: path.to_string(),
        format,
        checks,
        builds,
        linker,
        audit_note,
    })
}

fn c(name: &'static str, state: State, detail: impl Into<String>) -> Check {
    Check {
        name,
        state,
        detail: detail.into(),
    }
}

fn on_off(b: bool) -> State {
    if b { State::On } else { State::Off }
}

// --------------------------------------------------------------------- PE

fn pe_checks(pe: &hexcavator_pe::PeFile<'_>) -> Vec<Check> {
    use hexcavator_pe::consts::dll_characteristics as dc;
    use hexcavator_pe::consts::file_characteristics as fc;
    use hexcavator_pe::load_config::{field, guard_flags as gf};
    let mut out = Vec::new();
    let Some(h) = pe.optional_header() else {
        out.push(c("image", State::Info, "an object, not an image"));
        return out;
    };
    let dll = h.dll_characteristics();
    let file = pe.file_header().characteristics.get();
    let is64 = h.is_64();
    let machine = pe.machine();
    let x86 = machine == hexcavator_pe::consts::machine::I386;
    let relocs = pe.data_directory(5).is_some_and(|d| d.size.get() != 0);
    let dynamic = dll & dc::DYNAMIC_BASE != 0;
    out.push(
        match (dynamic, file & fc::RELOCS_STRIPPED != 0 || !relocs) {
            (true, false) => c("ASLR", State::On, "/DYNAMICBASE, with base relocations"),
            (true, true) => c(
                "ASLR",
                State::Partial,
                "/DYNAMICBASE, but no base relocations: loaded at its preferred base",
            ),
            (false, _) => c("ASLR", State::Off, "no /DYNAMICBASE"),
        },
    );
    out.push(if is64 {
        c(
            "High-entropy ASLR",
            on_off(dll & dc::HIGH_ENTROPY_VA != 0 && dynamic),
            if dll & dc::HIGH_ENTROPY_VA != 0 {
                "/HIGHENTROPYVA"
            } else {
                "no /HIGHENTROPYVA"
            },
        )
    } else {
        c("High-entropy ASLR", State::NotApplicable, "32-bit")
    });
    out.push(c(
        "DEP (NX)",
        on_off(dll & dc::NX_COMPAT != 0),
        if dll & dc::NX_COMPAT != 0 {
            "/NXCOMPAT"
        } else {
            "no /NXCOMPAT"
        },
    ));
    let lc = pe.load_config();
    let flags = lc
        .as_ref()
        .map_or(0, hexcavator_pe::load_config::LoadConfig::guard_flags);
    let cfg = dll & dc::GUARD_CF != 0 && flags & gf::CF_INSTRUMENTED != 0;
    out.push(c(
        "Control Flow Guard",
        on_off(cfg),
        match (dll & dc::GUARD_CF != 0, flags & gf::CF_INSTRUMENTED != 0) {
            (true, true) => format!(
                "/guard:cf, {} functions in its table",
                lc.as_ref().map_or(0, |l| l.guard_cf_functions().len())
            ),
            (true, false) => "the header asks for CFG, but no code is instrumented".into(),
            (false, true) => "instrumented code, but the header doesn't ask for CFG".into(),
            (false, false) => "no /guard:cf".into(),
        },
    ));
    out.push(c(
        "XFG",
        if flags & gf::XFG_ENABLED != 0 {
            State::On
        } else {
            State::Off
        },
        if flags & gf::XFG_ENABLED != 0 {
            "/guard:xfg"
        } else {
            "no /guard:xfg"
        },
    ));
    // CET: the extended DLL characteristics in the debug directory.
    let ex = pe
        .debug_entries()
        .find_map(|e| e.ex_dll_characteristics())
        .unwrap_or(0);
    out.push(if x86 || is64 {
        c(
            "CET shadow stack",
            on_off(ex & 1 != 0),
            if ex & 1 != 0 {
                "/CETCOMPAT"
            } else {
                "no /CETCOMPAT"
            },
        )
    } else {
        c("CET shadow stack", State::NotApplicable, "not x86")
    });
    let ehcont = flags & gf::EH_CONTINUATION_TABLE_PRESENT != 0;
    out.push(c(
        "EH continuation",
        on_off(ehcont),
        if ehcont {
            "/guard:ehcont"
        } else {
            "no /guard:ehcont"
        },
    ));
    // SafeSEH: x86 only; NO_SEH (no handlers at all) is safe too.
    out.push(if x86 {
        let n = lc
            .as_ref()
            .and_then(|l| l.get(field::SE_HANDLER_COUNT))
            .unwrap_or(0);
        if dll & dc::NO_SEH != 0 {
            c("SafeSEH", State::On, "/NOSEH: no exception handlers")
        } else {
            c(
                "SafeSEH",
                on_off(n > 0),
                if n > 0 {
                    format!("{n} registered handlers")
                } else {
                    "no handler table".into()
                },
            )
        }
    } else {
        c(
            "SafeSEH",
            State::NotApplicable,
            "table-based exception handling",
        )
    });
    let cookie = lc
        .as_ref()
        .and_then(|l| l.get(field::SECURITY_COOKIE))
        .unwrap_or(0);
    out.push(c(
        "Stack cookies (/GS)",
        on_off(cookie != 0),
        if cookie != 0 {
            "a security cookie in its load configuration"
        } else {
            "no security cookie"
        },
    ));
    if flags & gf::RETPOLINE_PRESENT != 0 {
        out.push(c(
            "Retpoline",
            State::Info,
            "dynamic value relocations for retpoline",
        ));
    }
    out.push(c(
        "Force integrity",
        if dll & dc::FORCE_INTEGRITY != 0 {
            State::On
        } else {
            State::Info
        },
        if dll & dc::FORCE_INTEGRITY != 0 {
            "/INTEGRITYCHECK: loads only signed"
        } else {
            "not required to be signed"
        },
    ));
    if dll & dc::APPCONTAINER != 0 {
        out.push(c("AppContainer", State::Info, "/APPCONTAINER"));
    }
    let signed = !pe.certificates().is_empty();
    out.push(c(
        "Authenticode",
        if signed { State::On } else { State::Off },
        if signed {
            "a signature (not validated)"
        } else {
            "unsigned"
        },
    ));
    // Writable and executable sections.
    let wx: Vec<String> = pe
        .sections()
        .iter()
        .filter(|s| {
            let ch = s.characteristics.get();
            ch & 0x2000_0000 != 0 && ch & 0x8000_0000 != 0
        })
        .map(|s| {
            String::from_utf8_lossy(s.name.split(|&b| b == 0).next().unwrap_or(&[])).into_owned()
        })
        .collect();
    out.push(if wx.is_empty() {
        c(
            "No W+X sections",
            State::On,
            "no section is both writable and executable",
        )
    } else {
        c(
            "No W+X sections",
            State::Off,
            format!("writable and executable: {}", wx.join(", ")),
        )
    });
    out
}

// -------------------------------------------------------------------- ELF

fn elf_checks(elf: &hexcavator_elf::ElfFile<'_>) -> Vec<Check> {
    use hexcavator_elf::consts::*;
    let mut out = Vec::new();
    if elf.is_object() {
        out.push(c("image", State::Info, "a relocatable object, not linked"));
    }
    let segs: Vec<_> = elf.segments().collect();
    let dynamic = elf.dynamic();
    let has = |tag: u64| dynamic.iter().find(|d| d.tag == tag).map(|d| d.value);
    let flags = has(DT_FLAGS).unwrap_or(0);
    let flags1 = has(DT_FLAGS_1).unwrap_or(0);
    let interp = segs.iter().any(|s| s.kind == PT_INTERP);
    let dyn_type = elf.header().kind == ET_DYN;
    // PIE: a shared object that is an executable (DF_1_PIE, or an
    // interpreter), or a library (always position-independent).
    out.push(if !dyn_type {
        c(
            "PIE",
            if elf.header().kind == ET_EXEC {
                State::Off
            } else {
                State::NotApplicable
            },
            "a fixed-address executable (ET_EXEC)",
        )
    } else if flags1 & 0x0800_0000 != 0 || interp {
        c("PIE", State::On, "a position-independent executable")
    } else {
        c(
            "PIE",
            State::NotApplicable,
            "a shared library (position-independent)",
        )
    });
    let relro = segs.iter().any(|s| s.kind == PT_GNU_RELRO);
    let now = flags & 0x8 != 0 || flags1 & 0x1 != 0 || has(DT_BIND_NOW).is_some();
    out.push(match (relro, now || dynamic.is_empty()) {
        (true, true) if dynamic.is_empty() => c(
            "RELRO",
            State::On,
            "PT_GNU_RELRO, and static: nothing is bound at run time",
        ),
        (true, true) => c(
            "RELRO",
            State::On,
            "full: PT_GNU_RELRO, and bound now (-z now)",
        ),
        (true, false) => c(
            "RELRO",
            State::Partial,
            "partial: PT_GNU_RELRO, but bound lazily (the GOT's PLT part stays writable)",
        ),
        (false, _) => c(
            "RELRO",
            if dynamic.is_empty() {
                State::NotApplicable
            } else {
                State::Off
            },
            "no PT_GNU_RELRO",
        ),
    });
    match segs.iter().find(|s| s.kind == PT_GNU_STACK) {
        Some(s) => out.push(c(
            "NX stack",
            on_off(s.flags & PF_X == 0),
            if s.flags & PF_X == 0 {
                "PT_GNU_STACK not executable"
            } else {
                "PT_GNU_STACK executable"
            },
        )),
        None => out.push(c(
            "NX stack",
            State::Off,
            "no PT_GNU_STACK: the stack is executable by default",
        )),
    }
    let wx: Vec<String> = segs
        .iter()
        .filter(|s| s.kind == PT_LOAD && s.flags & PF_W != 0 && s.flags & PF_X != 0)
        .map(|s| format!("{:#x}", s.vaddr))
        .collect();
    out.push(if wx.is_empty() {
        c(
            "No W+X segments",
            State::On,
            "no loadable segment is both writable and executable",
        )
    } else {
        c(
            "No W+X segments",
            State::Off,
            format!("writable and executable segments at {}", wx.join(", ")),
        )
    });
    // Symbols: the canary's and FORTIFY's (dynamic, and the symbol table's).
    let names: Vec<&[u8]> = elf.all_symbols().iter().map(|s| s.name).collect();
    let named = |n: &[u8]| names.contains(&n);
    let canary = named(b"__stack_chk_fail")
        || named(b"__stack_chk_guard")
        || named(b"__stack_chk_fail_local");
    out.push(c(
        "Stack canaries",
        on_off(canary),
        if canary {
            "calls __stack_chk_fail"
        } else {
            "no __stack_chk_fail"
        },
    ));
    let fortified: Vec<String> = {
        let mut v: Vec<String> = names
            .iter()
            .filter(|n| {
                n.starts_with(b"__") && n.ends_with(b"_chk") && !n.starts_with(b"__stack_chk")
            })
            .map(|n| String::from_utf8_lossy(n).into_owned())
            .collect();
        v.sort();
        v.dedup();
        v
    };
    const FORTIFIABLE: &[&str] = &[
        "memcpy",
        "memmove",
        "memset",
        "strcpy",
        "strncpy",
        "strcat",
        "strncat",
        "sprintf",
        "snprintf",
        "vsprintf",
        "vsnprintf",
        "printf",
        "fprintf",
        "gets",
        "read",
        "fgets",
        "realpath",
        "stpcpy",
    ];
    let plain: Vec<&str> = FORTIFIABLE
        .iter()
        .copied()
        .filter(|f| named(f.as_bytes()))
        .collect();
    out.push(match (fortified.is_empty(), plain.is_empty()) {
        (false, _) => c(
            "FORTIFY_SOURCE",
            if plain.is_empty() {
                State::On
            } else {
                State::Partial
            },
            format!(
                "{} checked calls ({}){}",
                fortified.len(),
                fortified
                    .iter()
                    .take(6)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", "),
                if plain.is_empty() {
                    String::new()
                } else {
                    format!("; unchecked: {}", plain.join(", "))
                }
            ),
        ),
        (true, false) => c(
            "FORTIFY_SOURCE",
            State::Off,
            format!("unchecked calls: {}", plain.join(", ")),
        ),
        (true, true) => c(
            "FORTIFY_SOURCE",
            State::NotApplicable,
            "no fortifiable calls",
        ),
    });
    // GNU properties: x86's IBT and SHSTK, AArch64's BTI and PAC.
    let (x86, arm) = gnu_properties(elf);
    let machine = elf.header().machine;
    if machine == EM_X86_64 || machine == EM_386 {
        out.push(c(
            "CET IBT",
            on_off(x86 & 1 != 0),
            if x86 & 1 != 0 {
                "GNU_PROPERTY_X86_FEATURE_1_IBT"
            } else {
                "not marked IBT (every object must be)"
            },
        ));
        out.push(c(
            "CET shadow stack",
            on_off(x86 & 2 != 0),
            if x86 & 2 != 0 {
                "GNU_PROPERTY_X86_FEATURE_1_SHSTK"
            } else {
                "not marked SHSTK (every object must be)"
            },
        ));
    } else if machine == EM_AARCH64 {
        out.push(c(
            "BTI",
            on_off(arm & 1 != 0),
            if arm & 1 != 0 {
                "GNU_PROPERTY_AARCH64_FEATURE_1_BTI"
            } else {
                "not marked BTI (every object must be)"
            },
        ));
        out.push(c(
            "PAC",
            on_off(arm & 2 != 0),
            if arm & 2 != 0 {
                "GNU_PROPERTY_AARCH64_FEATURE_1_PAC"
            } else {
                "not marked PAC"
            },
        ));
    }
    let text_rel = has(DT_TEXTREL).is_some() || flags & 0x4 != 0;
    out.push(c(
        "No text relocations",
        on_off(!text_rel),
        if text_rel {
            "DT_TEXTREL: the loader writes to code"
        } else {
            "none"
        },
    ));
    let strtab = has(DT_STRTAB).and_then(|a| elf.vaddr_to_offset(a));
    let dstr = |off: u64| -> String {
        let Some(base) = strtab else {
            return String::new();
        };
        let data = elf.data();
        let Ok(start) = usize::try_from(base.saturating_add(off)) else {
            return String::new();
        };
        let Some(rest) = data.get(start..) else {
            return String::new();
        };
        let end = rest
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(rest.len())
            .min(4096);
        String::from_utf8_lossy(&rest[..end]).into_owned()
    };
    for (tag, name) in [(DT_RPATH, "RPATH"), (DT_RUNPATH, "RUNPATH")] {
        if let Some(v) = has(tag) {
            let p = dstr(v);
            let risky = p.split(':').any(|e| {
                e.is_empty() || e == "." || !e.starts_with('/') && !e.starts_with("$ORIGIN")
            });
            out.push(c(
                if tag == DT_RPATH { "RPATH" } else { "RUNPATH" },
                if risky { State::Off } else { State::Info },
                format!(
                    "{name} {p}{}",
                    if risky {
                        " (relative: found from the current directory)"
                    } else {
                        ""
                    }
                ),
            ));
        }
    }
    let stripped = !elf.sections().any(|s| s.kind == SHT_SYMTAB);
    out.push(c(
        "Symbols",
        State::Info,
        if stripped { "stripped" } else { "not stripped" },
    ));
    out
}

/// The image's GNU properties: x86's and AArch64's feature bits.
fn gnu_properties(elf: &hexcavator_elf::ElfFile<'_>) -> (u32, u32) {
    let (mut x86, mut arm) = (0u32, 0u32);
    let word = if elf.class() == hexcavator_elf::Class::Elf64 {
        8
    } else {
        4
    };
    let big = elf.endian() == hexcavator_core::Endian::Big;
    let u32_at = |d: &[u8], at: usize| -> Option<u32> {
        let b: [u8; 4] = d.get(at..at + 4)?.try_into().ok()?;
        Some(if big {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        })
    };
    for s in elf
        .sections()
        .filter(|s| s.kind == hexcavator_elf::consts::SHT_NOTE)
    {
        for n in elf.notes(elf.section_data(&s)) {
            if n.kind != 5 || n.name != b"GNU\0" && n.name != b"GNU" {
                continue;
            }
            let d = n.desc;
            let mut at = 0usize;
            let mut count = 0;
            while at + 8 <= d.len() && count < 256 {
                let (Some(kind), Some(size)) = (u32_at(d, at), u32_at(d, at + 4)) else {
                    break;
                };
                let value = u32_at(d, at + 8).unwrap_or(0);
                match kind {
                    0xc000_0002 => x86 |= value,
                    0xc000_0000 => arm |= value,
                    _ => {}
                }
                let size = usize::try_from(size).unwrap_or(usize::MAX);
                at = at
                    .saturating_add(8)
                    .saturating_add(size.div_ceil(word) * word);
                count += 1;
            }
        }
    }
    (x86, arm)
}

// ----------------------------------------------------------------- Mach-O

fn macho_checks(m: &hexcavator_macho::MachO<'_>) -> Vec<Check> {
    use hexcavator_macho::consts::*;
    let mut out = Vec::new();
    let h = m.header();
    let exec = h.filetype == MH_EXECUTE;
    out.push(if exec {
        c(
            "PIE",
            on_off(h.flags & MH_PIE != 0),
            if h.flags & MH_PIE != 0 {
                "MH_PIE"
            } else {
                "not MH_PIE: loaded at a fixed address"
            },
        )
    } else {
        c("PIE", State::NotApplicable, "not an executable")
    });
    out.push(if exec {
        c(
            "NX stack",
            on_off(h.flags & MH_ALLOW_STACK_EXECUTION == 0),
            if h.flags & MH_ALLOW_STACK_EXECUTION != 0 {
                "MH_ALLOW_STACK_EXECUTION"
            } else {
                "the stack is not executable"
            },
        )
    } else {
        c("NX stack", State::NotApplicable, "not an executable")
    });
    if exec && h.flags & MH_NO_HEAP_EXECUTION != 0 {
        out.push(c("NX heap", State::On, "MH_NO_HEAP_EXECUTION"));
    }
    let syms = m.symbols();
    let named = |n: &[u8]| syms.iter().any(|s| s.name == n);
    let canary = named(b"___stack_chk_fail") || named(b"___stack_chk_guard");
    out.push(c(
        "Stack canaries",
        on_off(canary),
        if canary {
            "uses ___stack_chk_guard"
        } else {
            "no ___stack_chk_fail"
        },
    ));
    let objc = syms.iter().any(|s| s.name.starts_with(b"_objc_"));
    if objc {
        let arc = named(b"_objc_release") || named(b"_objc_retain") || named(b"_objc_storeStrong");
        out.push(c(
            "ARC",
            on_off(arc),
            if arc {
                "calls objc_release"
            } else {
                "Objective-C without ARC"
            },
        ));
    }
    let arm64 = h.cputype == CPU_TYPE_ARM64;
    out.push(if arm64 {
        let e = h.cpusubtype & !CPU_SUBTYPE_MASK == CPU_SUBTYPE_ARM64E;
        c(
            "Pointer authentication",
            on_off(e),
            if e { "arm64e" } else { "arm64, not arm64e" },
        )
    } else {
        c("Pointer authentication", State::NotApplicable, "not ARM64")
    });
    match m.code_signature() {
        Some(sig) => {
            let flags = sig.directory.as_ref().map_or(0, |d| d.flags);
            let adhoc = flags & 0x2 != 0;
            out.push(c(
                "Code signature",
                if adhoc { State::Partial } else { State::On },
                if adhoc {
                    "ad hoc (no identity)".to_string()
                } else {
                    format!(
                        "signed{}",
                        sig.directory
                            .as_ref()
                            .and_then(|d| d.team)
                            .map(|t| format!(", team {}", String::from_utf8_lossy(t)))
                            .unwrap_or_default()
                    )
                },
            ));
            out.push(c(
                "Hardened runtime",
                on_off(flags & 0x0001_0000 != 0),
                if flags & 0x0001_0000 != 0 {
                    "CS_RUNTIME"
                } else {
                    "no CS_RUNTIME"
                },
            ));
            if flags & 0x2000 != 0 {
                out.push(c("Library validation", State::On, "CS_REQUIRE_LV"));
            }
            let ents = entitlements(m);
            if ents.contains("get-task-allow") {
                out.push(c(
                    "No get-task-allow",
                    State::Off,
                    "com.apple.security.get-task-allow: debuggers may attach",
                ));
            }
            for risky in [
                "com.apple.security.cs.disable-library-validation",
                "com.apple.security.cs.allow-unsigned-executable-memory",
                "com.apple.security.cs.allow-dyld-environment-variables",
                "com.apple.security.cs.disable-executable-page-protection",
            ] {
                if ents.contains(risky) {
                    out.push(c("Entitlement", State::Off, risky));
                }
            }
        }
        None => out.push(c("Code signature", State::Off, "unsigned")),
    }
    let lcs = m.load_commands();
    if let Some(enc) = lcs
        .iter()
        .find(|l| l.cmd == LC_ENCRYPTION_INFO || l.cmd == LC_ENCRYPTION_INFO_64)
    {
        let id = enc
            .data
            .get(16..20)
            .map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap_or([0; 4])));
        out.push(c(
            "Encrypted",
            State::Info,
            if id != 0 {
                "yes (FairPlay)"
            } else {
                "no (cryptid 0)"
            },
        ));
    }
    let segs = m.segments();
    if exec {
        let zero = segs.iter().any(|s| s.name == b"__PAGEZERO");
        out.push(c(
            "__PAGEZERO",
            on_off(zero),
            if zero {
                "null page reserved"
            } else {
                "no __PAGEZERO"
            },
        ));
    }
    if segs.iter().any(|s| s.name == b"__RESTRICT") {
        out.push(c(
            "__RESTRICT",
            State::Info,
            "restricted: DYLD_ environment variables ignored",
        ));
    }
    let chained = lcs.iter().any(|l| l.cmd == LC_DYLD_CHAINED_FIXUPS);
    out.push(c(
        "Chained fixups",
        State::Info,
        if chained {
            "LC_DYLD_CHAINED_FIXUPS"
        } else {
            "dyld opcodes"
        },
    ));
    out
}

/// The entitlements in a Mach-O image's code signature, as text.
fn entitlements(m: &hexcavator_macho::MachO<'_>) -> String {
    let Some(sig) = m.code_signature() else {
        return String::new();
    };
    let Some(lc) = m
        .load_commands()
        .into_iter()
        .find(|l| l.cmd == hexcavator_macho::consts::LC_CODE_SIGNATURE)
    else {
        return String::new();
    };
    let Some((off, size)) = m.linkedit_data(&lc) else {
        return String::new();
    };
    let data = m.data();
    let Some(blob) = data.get(off as usize..(off as usize).saturating_add(size as usize)) else {
        return String::new();
    };
    for b in &sig.blobs {
        if b.magic == hexcavator_macho::info::CSMAGIC_EMBEDDED_ENTITLEMENTS {
            let s = b.offset as usize + 8;
            let e = (b.offset as usize)
                .saturating_add(b.length as usize)
                .min(blob.len());
            if let Some(x) = blob.get(s..e) {
                return String::from_utf8_lossy(x).into_owned();
            }
        }
    }
    String::new()
}

// ------------------------------------------------------------------ audit

/// The objects' builds: a PDB's modules (S_COMPILE3, and the command line
/// S_BUILDINFO names), or DWARF's units (DW_AT_producer).
fn audit(
    path: &str,
    image: &hexcavator_image::Image<'_>,
    pdb: Option<&str>,
) -> Result<(Vec<Build>, Environment), String> {
    let (_, map) = match hexcavator_program::find_debug(Path::new(path), image, pdb.map(Path::new))
    {
        Ok(found) => found,
        Err(e) => {
            // A Mach-O image's debug map: each object's units.
            let opened = hexcavator_program::Opened::open(Path::new(path), None)
                .map_err(|_| e.to_string())?;
            if !opened.is_debug_map() {
                return Err(e.to_string());
            }
            let mut out = Vec::new();
            for (name, data) in opened.debug_map_files() {
                if let Ok(builds) = dwarf_builds(data) {
                    // (An archive's member: `lib.a(member.o)`.)
                    let (library, object) =
                        match name.strip_suffix(')').and_then(|n| n.split_once('(')) {
                            Some((lib, member)) => (lib.to_string(), member.to_string()),
                            None => (String::new(), name.clone()),
                        };
                    out.extend(builds.into_iter().map(|mut b| {
                        b.library = library.clone();
                        b.object = object.clone();
                        b
                    }));
                }
            }
            return Ok((out, Vec::new()));
        }
    };
    if let Ok(p) = hexcavator_pdb::Pdb::parse(&map) {
        let linker = hexcavator_debuginfo::DebugInfo::parse(&map)
            .ok()
            .and_then(|d| d.linker_info().ok())
            .map(|i| i.environment)
            .unwrap_or_default();
        return Ok((pdb_builds(&p)?, linker));
    }
    Ok((dwarf_builds(&map)?, Vec::new()))
}

/// The most modules or units read.
const MAX_OBJECTS: usize = 1 << 20;

fn pdb_builds(pdb: &hexcavator_pdb::Pdb<'_>) -> Result<Vec<Build>, String> {
    use hexcavator_codeview::symbols::Symbol;
    let dbi = pdb.dbi().map_err(|e| e.to_string())?;
    let ids = pdb.ids().ok();
    let mut out = Vec::new();
    for m in dbi.modules().iter().take(MAX_OBJECTS) {
        let mut b = Build {
            object: String::from_utf8_lossy(m.name).into_owned(),
            library: String::from_utf8_lossy(m.object_name).into_owned(),
            ..Build::default()
        };
        if b.object == "* Linker *" {
            continue;
        }
        let Ok(Some(stream)) = pdb.module_stream(m) else {
            out.push(b);
            continue;
        };
        for rec in stream.symbols().take(64) {
            match rec.parse() {
                Ok(Symbol::Compile3 {
                    flags,
                    frontend,
                    backend,
                    version,
                    ..
                }) => {
                    // (Assemblers and tools leave the front end's version 0.)
                    let v = if frontend == [0; 4] {
                        backend
                    } else {
                        frontend
                    };
                    b.compiler = format!(
                        "{} {}.{}.{}.{}",
                        String::from_utf8_lossy(version),
                        v[0],
                        v[1],
                        v[2],
                        v[3]
                    );
                    let lang = flags & 0xFF;
                    b.options
                        .insert("language".into(), language_name(lang).into());
                    // What the linker made (import libraries' objects,
                    // resources) and assemblers aren't compiled: they have
                    // no compiler's options.
                    if matches!(lang, 3 | 7 | 8 | 9 | 20) {
                        b.options.insert("kind".into(), "not compiled".into());
                        break;
                    }
                    for (bit, name) in [
                        (13, "/GS"),
                        (10, "/LTCG"),
                        (18, "/GL PGO"),
                        (17, "/sdl"),
                        (14, "/hotpatch"),
                    ] {
                        b.options.insert(
                            name.into(),
                            if flags & (1 << bit) != 0 {
                                "on".into()
                            } else {
                                "off".into()
                            },
                        );
                    }
                }
                Ok(Symbol::BuildInfo { id }) => {
                    if let Some(ids) = &ids {
                        let info = build_info(ids, id);
                        let [cwd, tool, source, pdb, cmd] = info.map(Option::unwrap_or_default);
                        b.cwd = cwd;
                        b.tool = tool;
                        b.source = source;
                        b.pdb = pdb;
                        if !cmd.is_empty() {
                            b.command = cmd.clone();
                            for (k, v) in msvc_switches(&cmd) {
                                b.options.insert(k, v);
                            }
                            // A switch the command line doesn't give is
                            // at cl's default.
                            for (k, v) in [
                                ("/guard:cf", "off"),
                                ("/guard:ehcont", "off"),
                                ("/Qspectre", "off"),
                                ("runtime library", "/MT"),
                                ("optimization", "/Od"),
                            ] {
                                b.options.entry(k.into()).or_insert_with(|| v.into());
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        out.push(b);
    }
    Ok(out)
}

fn language_name(l: u32) -> &'static str {
    match l {
        0 => "C",
        1 => "C++",
        2 => "Fortran",
        3 => "MASM",
        4 => "Pascal",
        5 => "Basic",
        6 => "COBOL",
        7 => "LINK",
        8 => "CVTRES",
        9 => "CVTPGD",
        10 => "C#",
        11 => "Visual Basic",
        12 => "ILASM",
        13 => "Java",
        14 => "JScript",
        15 => "MSIL",
        16 => "HLSL",
        17 => "Objective-C",
        18 => "Objective-C++",
        19 => "Swift",
        20 => "ALIASOBJ",
        21 => "Rust",
        22 => "Go",
        _ => "other",
    }
}

/// What an `LF_BUILDINFO` names: its current directory, build tool, source
/// file, PDB, and command line (string IDs, perhaps continued in substring
/// lists).
fn build_info(
    ids: &hexcavator_pdb::tpi::TypeStream<'_>,
    id: hexcavator_codeview::TypeIndex,
) -> [Option<String>; 5] {
    let mut out = [None, None, None, None, None];
    let Some(rec) = ids.record(id) else {
        return out;
    };
    if rec.kind != hexcavator_codeview::types::leaf::LF_BUILDINFO {
        return out;
    }
    let d = rec.data;
    let Some(count) = d
        .get(0..2)
        .map(|c| usize::from(u16::from_le_bytes([c[0], c[1]])))
    else {
        return out;
    };
    for (k, slot) in out.iter_mut().enumerate().take(count) {
        let Some(arg) = d.get(2 + 4 * k..6 + 4 * k) else {
            break;
        };
        let arg = u32::from_le_bytes([arg[0], arg[1], arg[2], arg[3]]);
        *slot = string_id(ids, arg, 0);
    }
    out
}

fn string_id(ids: &hexcavator_pdb::tpi::TypeStream<'_>, id: u32, depth: usize) -> Option<String> {
    use hexcavator_codeview::types::leaf;
    if depth > 4 || id == 0 {
        return None;
    }
    let rec = ids.record(hexcavator_codeview::TypeIndex(id))?;
    match rec.kind {
        leaf::LF_STRING_ID => {
            let d = rec.data;
            let sub = u32::from_le_bytes(d.get(0..4)?.try_into().ok()?);
            let text = d.get(4..)?;
            let text = &text[..text.iter().position(|&b| b == 0).unwrap_or(text.len())];
            let mut s = String::new();
            if sub != 0 {
                let list = ids.record(hexcavator_codeview::TypeIndex(sub))?;
                if list.kind == leaf::LF_SUBSTR_LIST {
                    let ld = list.data;
                    let n = u32::from_le_bytes(ld.get(0..4)?.try_into().ok()?) as usize;
                    for i in 0..n.min(256) {
                        let part =
                            u32::from_le_bytes(ld.get(4 + 4 * i..8 + 4 * i)?.try_into().ok()?);
                        if let Some(p) = string_id(ids, part, depth + 1) {
                            s.push_str(&p);
                        }
                    }
                }
            }
            s.push_str(&String::from_utf8_lossy(text));
            Some(s)
        }
        _ => None,
    }
}

/// The options that matter of an MSVC command line, by name.
fn msvc_switches(cmd: &str) -> Vec<(String, String)> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for t in cmd.split_whitespace().take(4096) {
        let t = t.trim_matches('"');
        let Some(s) = t.strip_prefix('-').or_else(|| t.strip_prefix('/')) else {
            continue;
        };
        let set = |out: &mut BTreeMap<String, String>, k: &str, v: &str| {
            out.insert(k.to_string(), v.to_string());
        };
        match s {
            "MD" | "MDd" | "MT" | "MTd" => set(&mut out, "runtime library", &format!("/{s}")),
            "GS" => set(&mut out, "/GS", "on"),
            "GS-" => set(&mut out, "/GS", "off"),
            "sdl" => set(&mut out, "/sdl", "on"),
            "sdl-" => set(&mut out, "/sdl", "off"),
            "GL" => set(&mut out, "/GL", "on"),
            "Qspectre" | "Qspectre-load" | "Qspectre-load-cf" => {
                set(&mut out, "/Qspectre", &format!("/{s}"));
            }
            "guard:cf" => set(&mut out, "/guard:cf", "on"),
            "guard:cf-" => set(&mut out, "/guard:cf", "off"),
            "guard:ehcont" => set(&mut out, "/guard:ehcont", "on"),
            "guard:xfg" => set(&mut out, "/guard:xfg", "on"),
            "EHsc" | "EHs" | "EHa" | "EHs-c-" | "EHsc-" => {
                set(&mut out, "exceptions", &format!("/{s}"));
            }
            "GR-" => set(&mut out, "/GR (RTTI)", "off"),
            "Od" | "O1" | "O2" | "Ox" => set(&mut out, "optimization", &format!("/{s}")),
            "Zc:wchar_t-" => set(&mut out, "/Zc:wchar_t", "off"),
            _ if s.starts_with("std:") => set(&mut out, "language standard", &format!("/{s}")),
            _ if s.starts_with("arch:") => set(&mut out, "/arch", &format!("/{s}")),
            _ if s.starts_with("D_ITERATOR_DEBUG_LEVEL=")
                || s.starts_with("D_HAS_ITERATOR_DEBUGGING=") =>
            {
                set(
                    &mut out,
                    "_ITERATOR_DEBUG_LEVEL",
                    s.split('=').nth(1).unwrap_or(""),
                );
            }
            _ if s.starts_with("D_DEBUG") => set(&mut out, "_DEBUG", "defined"),
            _ => {}
        }
    }
    out.into_iter().collect()
}

fn dwarf_builds(data: &[u8]) -> Result<Vec<Build>, String> {
    use hexcavator_dwarf::consts::*;
    let info =
        hexcavator_debuginfo::dwarf_backend::DwarfInfo::parse(data).map_err(|e| e.to_string())?;
    let s = info.sections();
    let mut out = Vec::new();
    for unit in
        hexcavator_dwarf::Unit::iter(s, hexcavator_dwarf::UnitSection::Info, 0).take(MAX_OBJECTS)
    {
        let Some(abbrevs) =
            hexcavator_dwarf::Abbrevs::parse(s.abbrev, unit.abbrev_offset, s.endian)
        else {
            continue;
        };
        let mut unit = unit;
        let mut r = unit.dies();
        let mut attrs = Vec::new();
        let Some(a) = r.next(&abbrevs) else { continue };
        if r.attrs(&unit, a, &mut attrs).is_none() {
            continue;
        }
        unit.set_bases(&attrs);
        let text = |n: u16| -> String {
            attrs
                .iter()
                .find(|x| x.name == n)
                .and_then(|x| unit.string(&x.value))
                .map(|s| String::from_utf8_lossy(s.bytes).into_owned())
                .unwrap_or_default()
        };
        let producer = text(DW_AT_PRODUCER);
        let mut b = Build {
            object: text(DW_AT_NAME),
            source: text(DW_AT_NAME),
            cwd: text(DW_AT_COMP_DIR),
            command: producer.clone(),
            ..Build::default()
        };
        if let Some(l) = attrs
            .iter()
            .find(|x| x.name == DW_AT_LANGUAGE)
            .and_then(|x| unit.uint(&x.value))
        {
            b.options.insert(
                "language".into(),
                hexcavator_dwarf::spelling::language(l)
                    .unwrap_or("?")
                    .trim_start_matches("DW_LANG_")
                    .to_string(),
            );
        }
        let (compiler, opts) = gnu_producer(&producer);
        b.compiler = compiler;
        for (k, v) in opts {
            b.options.insert(k, v);
        }
        out.push(b);
    }
    Ok(out)
}

/// A DW_AT_producer's compiler, and the options in it that matter (GCC
/// with -grecord-gcc-switches and clang with -grecord-command-line record
/// them).
fn gnu_producer(p: &str) -> (String, Vec<(String, String)>) {
    let mut words = p.split_whitespace();
    let mut compiler = Vec::new();
    let mut opts: BTreeMap<String, String> = BTreeMap::new();
    for w in words.by_ref().take(4096) {
        if w.starts_with('-') {
            option(&mut opts, w);
            break;
        }
        compiler.push(w);
    }
    for w in words.take(4096) {
        option(&mut opts, w);
    }
    // (clang's recorded command line starts with the compiler's path.)
    (compiler.join(" "), opts.into_iter().collect())
}

fn option(opts: &mut BTreeMap<String, String>, w: &str) {
    let w = w.trim_matches('"');
    let set = |opts: &mut BTreeMap<String, String>, k: &str, v: &str| {
        opts.insert(k.to_string(), v.to_string());
    };
    match w {
        _ if w.starts_with("-O") => set(opts, "optimization", w),
        "-fstack-protector"
        | "-fstack-protector-strong"
        | "-fstack-protector-all"
        | "-fno-stack-protector" => set(opts, "stack protector", w),
        "-fPIC" | "-fpic" | "-fPIE" | "-fpie" | "-fno-pic" | "-fno-PIC" | "-fno-pie" => {
            set(opts, "position independence", w);
        }
        _ if w.starts_with("-fcf-protection") => set(opts, "-fcf-protection", w),
        _ if w.starts_with("-mbranch-protection") => set(opts, "-mbranch-protection", w),
        _ if w.starts_with("-D_FORTIFY_SOURCE") || w.starts_with("-U_FORTIFY_SOURCE") => {
            set(opts, "_FORTIFY_SOURCE", w);
        }
        _ if w.starts_with("-D_GLIBCXX_ASSERTIONS") => set(opts, "_GLIBCXX_ASSERTIONS", w),
        "-fstack-clash-protection" | "-fno-stack-clash-protection" => {
            set(opts, "stack clash protection", w);
        }
        "-ftrivial-auto-var-init=zero" | "-ftrivial-auto-var-init=pattern" => {
            set(opts, "auto-var-init", w);
        }
        "-fno-exceptions" | "-fexceptions" => set(opts, "exceptions", w),
        "-fno-rtti" | "-frtti" => set(opts, "RTTI", w),
        _ if w.starts_with("-std=") => set(opts, "language standard", w),
        _ if w.starts_with("-march=") => set(opts, "-march", w),
        _ if w.starts_with("-g") && !w.starts_with("-grecord") => set(opts, "debug information", w),
        "-flto" | "-flto=thin" | "-flto=full" => set(opts, "LTO", w),
        _ if w.starts_with("-fsanitize=") => set(opts, "sanitizers", w),
        _ => {}
    }
}

// ----------------------------------------------------------------- output

impl Report {
    fn text(&self, out: &mut String) {
        let _ = writeln!(out, "{}:", self.path);
        let w = self.checks.iter().map(|c| c.name.len()).max().unwrap_or(10);
        for ch in &self.checks {
            let _ = writeln!(
                out,
                "  {:<w$}  {:<7}  {}",
                ch.name,
                ch.state.word(),
                ch.detail
            );
        }
        if let Some(note) = &self.audit_note {
            let _ = writeln!(out, "\n  build options: {note}");
        }
        if let Some(builds) = &self.builds {
            audit_text(builds, out);
        }
        out.push('\n');
    }

    fn json(&self) -> Json {
        let checks: Vec<Json> = self
            .checks
            .iter()
            .map(|c| json!({ "name": c.name, "state": c.state.key(), "detail": c.detail }))
            .collect();
        let mut v = json!({ "path": self.path, "format": self.format, "checks": checks });
        if let Some(b) = &self.builds {
            v["audit"] = audit_json(b);
            if !self.linker.is_empty() {
                let mut l = json!({});
                for (k, x) in &self.linker {
                    l[k.as_str()] = json!(x);
                }
                v["audit"]["linker"] = l;
            }
        }
        if let Some(n) = &self.audit_note {
            v["auditError"] = json!(n);
        }
        v
    }
}

/// For each option (and the compiler): its values, and the objects with
/// each, the most common first.
fn spread(builds: &[Build]) -> BTreeMap<String, Vec<(String, Vec<usize>)>> {
    let mut by: BTreeMap<String, BTreeMap<String, Vec<usize>>> = BTreeMap::new();
    for (i, b) in builds.iter().enumerate() {
        if !b.compiler.is_empty() {
            by.entry("compiler".into())
                .or_default()
                .entry(b.compiler.clone())
                .or_default()
                .push(i);
        }
        let compiled = b.options.get("kind").is_none_or(|k| k != "not compiled");
        for (k, v) in &b.options {
            if k == "kind" || (!compiled && k != "language") {
                continue;
            }
            by.entry(k.clone())
                .or_default()
                .entry(v.clone())
                .or_default()
                .push(i);
        }
    }
    by.into_iter()
        .map(|(k, values)| {
            let mut v: Vec<(String, Vec<usize>)> = values.into_iter().collect();
            v.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(&b.0)));
            (k, v)
        })
        .collect()
}

/// Options whose differing values matter most: mixing them breaks or
/// weakens the image as a whole.
fn severity(option: &str) -> &'static str {
    match option {
        "runtime library" | "_ITERATOR_DEBUG_LEVEL" | "_DEBUG" | "/Zc:wchar_t" | "exceptions" => {
            "mismatch"
        }
        "/GS"
        | "stack protector"
        | "/guard:cf"
        | "/guard:ehcont"
        | "-fcf-protection"
        | "-mbranch-protection"
        | "/Qspectre"
        | "_FORTIFY_SOURCE"
        | "position independence"
        | "stack clash protection" => "weakens",
        _ => "differs",
    }
}

fn audit_text(builds: &[Build], out: &mut String) {
    let _ = writeln!(out, "\n  {} objects with build records", builds.len());
    if builds.is_empty() {
        return;
    }
    let sp = spread(builds);
    // (Objects with no compiler record count for neither.)
    let compiled = builds
        .iter()
        .filter(|b| {
            !b.compiler.is_empty() && b.options.get("kind").is_none_or(|k| k != "not compiled")
        })
        .count();
    let tools = builds
        .iter()
        .filter(|b| b.options.get("kind").is_some_and(|k| k == "not compiled"))
        .count();
    if tools > 0 {
        let _ = writeln!(
            out,
            "  ({tools} of them the linker's or an assembler's, without compiler options)"
        );
    }
    let mut uniform = Vec::new();
    let rank = |k: &str| match severity(k) {
        "mismatch" => 0,
        "weakens" => 1,
        _ => 2,
    };
    let mut keys: Vec<&String> = sp.keys().collect();
    keys.sort_by_key(|k| (rank(k), k.as_str()));
    for k in keys {
        let values = &sp[k];
        let recorded = builds.iter().filter(|b| !b.compiler.is_empty()).count();
        let population = if k == "compiler" || k == "language" {
            recorded
        } else {
            compiled
        };
        let missing = population.saturating_sub(values.iter().map(|v| v.1.len()).sum::<usize>());
        if values.len() == 1 && missing == 0 {
            uniform.push(format!("{k}: {}", values[0].0));
            continue;
        }
        let _ = writeln!(out, "\n  {k} ({}):", severity(k));
        for (v, objs) in values {
            let _ = writeln!(
                out,
                "    {:<40} {:>6} objects{}",
                v,
                objs.len(),
                sample(builds, objs)
            );
        }
        if missing > 0 {
            let _ = writeln!(out, "    {:<40} {:>6} objects (not recorded)", "-", missing);
        }
    }
    if !uniform.is_empty() {
        let _ = writeln!(out, "\n  the same in every object:");
        for u in uniform {
            let _ = writeln!(out, "    {u}");
        }
    }
}

/// A few of the objects' names, for the rarer values.
fn sample(builds: &[Build], objs: &[usize]) -> String {
    if objs.len() > 3 {
        return String::new();
    }
    let names: Vec<&str> = objs
        .iter()
        .map(|&i| {
            let o = builds[i].object.as_str();
            o.rsplit(['/', '\\']).next().unwrap_or(o)
        })
        .collect();
    format!(": {}", names.join(", "))
}

fn audit_json(builds: &[Build]) -> Json {
    let sp = spread(builds);
    let options: Vec<Json> = sp
        .iter()
        .map(|(k, values)| {
            json!({
                "option": k,
                "severity": severity(k),
                "values": values.iter().map(|(v, objs)| json!({
                    "value": v,
                    "objects": objs.iter().map(|&i| builds[i].object.clone()).collect::<Vec<_>>(),
                    // (Each object's library, where it came from one.)
                    "libraries": objs.iter().map(|&i| builds[i].library.clone()).collect::<Vec<_>>(),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    // Each object: what it was built from, with, and how.
    let list: Vec<Json> = builds
        .iter()
        .map(|b| {
            json!({
                "object": b.object,
                // (A module not from a library names its object twice.)
                "library": if b.library == b.object { "" } else { b.library.as_str() },
                "compiler": b.compiler,
                "language": b.options.get("language").cloned().unwrap_or_default(),
                "compiled": b.options.get("kind").is_none_or(|k| k != "not compiled"),
                "source": b.source,
                "cwd": b.cwd,
                "tool": b.tool,
                "pdb": b.pdb,
                "command": b.command,
                "options": b.options,
            })
        })
        .collect();
    json!({ "objects": builds.len(), "options": options, "builds": list })
}
