//! bloaty's *data sources* for an image: ways of labeling every byte of
//! the file and of the loaded image, combined into reports by
//! [`crate::rollup`].
//!
//! The base map labels each byte by where the file format puts it (the
//! headers, each section, the structures outside sections, and
//! `[Unmapped]` for the rest of the file) and relates memory addresses to
//! file offsets. Every other source labels what it knows (symbols,
//! compilands, ...) and leaves the rest to its *fallback*: the base map's
//! label, with section names written `[section .text]`, as bloaty does.

use hexcavator_image::Image;
use hexcavator_pe::PeFile;
use hexcavator_pe::consts::directory;

use crate::Model;
use crate::rangemap::{DualMap, Label, Labels};
use crate::symbols::Symbol;

/// A data source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Source {
    /// The image's sections (PE has no segments, so `segments` is the same).
    Sections,
    Segments,
    /// COFF groups (`.text$mn`, `.rdata$r`, ...).
    Groups,
    /// Symbols: functions, data, and the image's own structures, each
    /// function charged its unwind and exception data too. For ELF,
    /// names are demangled short, as bloaty's `symbols` (`shortsymbols`).
    Symbols,
    /// Symbols with names as mangled (bloaty's `rawsymbols`).
    RawSymbols,
    /// Symbols with names demangled in full (bloaty's `fullsymbols`).
    FullSymbols,
    /// Compilands (bloaty's `compileunits`): object files.
    CompileUnits,
    /// Archive members (bloaty's `armembers`): for an image, its
    /// compilands; for a library, its members.
    ArMembers,
    /// Libraries (bloaty's `armembers` names the archive members, which
    /// for an image are its compilands; this names the archives).
    Libraries,
    /// The input file's name.
    InputFiles,
    /// Source lines (bloaty's `inlines`): `file:line` for each span of code,
    /// from the DWARF line tables.
    Inlines,
    /// Source files: each span of code labeled by the file its line table
    /// names (a header's inlined code, the header's); PDB or DWARF.
    SourceFiles,
    /// The architecture of each image (of a universal Mach-O file, one
    /// per slice).
    Archs,
}

impl Source {
    pub const ALL: &[Source] = &[
        Source::Sections,
        Source::Segments,
        Source::Groups,
        Source::Symbols,
        Source::RawSymbols,
        Source::FullSymbols,
        Source::CompileUnits,
        Source::ArMembers,
        Source::Libraries,
        Source::InputFiles,
        Source::Inlines,
        Source::SourceFiles,
        Source::Archs,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Source::Sections => "sections",
            Source::Segments => "segments",
            Source::Groups => "groups",
            Source::Symbols => "symbols",
            Source::RawSymbols => "rawsymbols",
            Source::FullSymbols => "fullsymbols",
            Source::CompileUnits => "compileunits",
            Source::ArMembers => "armembers",
            Source::Libraries => "libraries",
            Source::InputFiles => "inputfiles",
            Source::Archs => "archs",
            Source::Inlines => "inlines",
            Source::SourceFiles => "sourcefiles",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Source::Sections => "the image's sections",
            Source::Segments => "the same as sections (PE has no segments)",
            Source::Groups => "COFF groups (.text$mn, ...), from the PDB",
            Source::Symbols => {
                "symbols: functions, data, and the image's structures (ELF: names short)"
            }
            Source::RawSymbols => "symbols, names as mangled (ELF; PE: as symbols)",
            Source::FullSymbols => "symbols, names demangled in full (ELF; PE: as symbols)",
            Source::CompileUnits => "compilands (object files), from the PDB",
            Source::ArMembers => "archive members (for an image, its compilands)",
            Source::Libraries => "libraries (archives), from the PDB",
            Source::InputFiles => "the input file",
            Source::Archs => "architectures (a universal file's slices)",
            Source::Inlines => "source lines (file:line), from DWARF line tables",
            Source::SourceFiles => {
                "source files: code by the file its line tables name (PDB or DWARF)"
            }
        }
    }

    /// The source named `name` (bloaty's names are accepted too).
    pub fn parse(name: &str) -> Option<Source> {
        Some(match name {
            "sections" => Source::Sections,
            "segments" => Source::Segments,
            "groups" | "coffgroups" => Source::Groups,
            "symbols" | "shortsymbols" => Source::Symbols,
            "rawsymbols" => Source::RawSymbols,
            "fullsymbols" => Source::FullSymbols,
            "compileunits" | "compilands" => Source::CompileUnits,
            "armembers" => Source::ArMembers,
            "libraries" | "libs" => Source::Libraries,
            "inputfiles" => Source::InputFiles,
            "archs" => Source::Archs,
            "inlines" => Source::Inlines,
            "sourcefiles" | "sources" => Source::SourceFiles,
            _ => return None,
        })
    }

    /// Whether this is one of the symbol sources.
    pub fn is_symbols(self) -> bool {
        matches!(
            self,
            Source::Symbols | Source::RawSymbols | Source::FullSymbols
        )
    }

    /// Whether the source needs the debug information.
    pub fn needs_debug_info(self) -> bool {
        matches!(
            self,
            Source::Groups
                | Source::Symbols
                | Source::RawSymbols
                | Source::FullSymbols
                | Source::CompileUnits
                | Source::ArMembers
                | Source::Libraries
                | Source::SourceFiles
        )
    }
}

/// Labels of the base map for what isn't a section.
pub const HEADERS: &str = "[PE Headers]";
pub const SECTION_HEADERS: &str = "[PE Section Headers]";
pub const UNMAPPED: &str = "[Unmapped]";
pub const CERTIFICATES: &str = "[PE Certificate Table]";
pub const COFF_SYMBOLS: &str = "[COFF Symbol Table]";
pub const COFF_STRINGS: &str = "[COFF String Table]";
pub const DEBUG_DATA: &str = "[PE Debug Data]";

/// The maps of one image, for several sources.
#[derive(Clone, Debug, Default)]
pub struct Maps {
    pub labels: Labels,
    pub base: DualMap,
    /// One map per requested source, in order.
    pub sources: Vec<(Source, DualMap)>,
    /// The file's size, all of which the maps label.
    pub file_size: u64,
    /// Whether rolling up counts short fallback ranges as padding of the
    /// range before them, as bloaty does (ELF, Mach-O, WebAssembly; not PE
    /// and COFF, whose reports follow SizeBench, which counts padding apart).
    pub absorb_padding: bool,
}

/// What the sources other than the sections need.
#[derive(Clone, Copy, Debug)]
pub struct Inputs<'a> {
    /// The size model (groups, compilands, libraries).
    pub model: Option<&'a Model>,
    pub symbols: Option<&'a [Symbol]>,
    /// The input file's name.
    pub file_name: &'a str,
    /// The line tables (for `sourcefiles`).
    pub lines: Option<&'a hexcavator_debuginfo::SourceLines>,
}

/// The base map of a PE image.
pub fn pe_base(pe: &PeFile<'_>, labels: &mut Labels) -> DualMap {
    let data = pe.data();
    let len = data.len() as u64;
    let clamp = |start: u64, size: u64| -> (u64, u64) {
        let start = start.min(len);
        (start, size.min(len - start))
    };
    let mut base = DualMap::default();
    // The headers are loaded at the image's base, byte for byte.
    let headers = pe
        .optional_header()
        .map_or(0, |h| u64::from(h.size_of_headers()));
    let table =
        pe.file_header_offset() + 20 + u64::from(pe.file_header().size_of_optional_header.get());
    let table_size = 40 * pe.sections().len() as u64;
    let section_headers = labels.intern(SECTION_HEADERS);
    let header_label = labels.intern(HEADERS);
    let (t, ts) = clamp(table, table_size);
    base.add_range(t, ts, t, ts, section_headers);
    let (h, hs) = clamp(0, headers.max(table + table_size));
    base.add_range(h, hs, h, hs, header_label);
    // Sections.
    for s in pe.sections() {
        let name = String::from_utf8_lossy(pe.section_name(s)).into_owned();
        let label = labels.intern(&name);
        let raw = u64::from(s.size_of_raw_data.get());
        let ptr = u64::from(s.pointer_to_raw_data.get());
        let (ptr, raw) = if ptr == 0 { (0, 0) } else { clamp(ptr, raw) };
        let vsize = match s.virtual_size.get() {
            0 => raw,
            v => u64::from(v),
        };
        base.add_range(u64::from(s.virtual_address.get()), vsize, ptr, raw, label);
    }
    // Structures the headers locate by file offset, outside the sections.
    let mut file_only = |start: u64, size: u64, name: &str| {
        let (s, n) = clamp(start, size);
        if n > 0 {
            let l = labels.intern(name);
            base.file.add(s, s + n, l);
        }
    };
    if let Some(d) = pe.data_directory(directory::SECURITY) {
        file_only(
            u64::from(d.virtual_address.get()),
            u64::from(d.size.get()),
            CERTIFICATES,
        );
    }
    let header = pe.file_header();
    let symbols = u64::from(header.pointer_to_symbol_table.get());
    if symbols != 0 {
        let size = 18 * u64::from(header.number_of_symbols.get());
        file_only(symbols, size, COFF_SYMBOLS);
        let strings = symbols + size;
        if let Some(b) = data.get(strings as usize..(strings as usize).saturating_add(4))
            && let Ok(b) = <[u8; 4]>::try_from(b)
        {
            file_only(
                strings,
                u64::from(u32::from_le_bytes(b)).max(4),
                COFF_STRINGS,
            );
        }
    }
    for d in pe.debug_directories().unwrap_or(&[]) {
        let ptr = u64::from(d.pointer_to_raw_data.get());
        if ptr != 0 {
            file_only(ptr, u64::from(d.size_of_data.get()), DEBUG_DATA);
        }
    }
    let unmapped = labels.intern(UNMAPPED);
    base.file.add(0, len, unmapped);
    base
}

/// Header structures, for the symbols source.
fn pe_header_symbols(pe: &PeFile<'_>, labels: &mut Labels, out: &mut DualMap, base: &DualMap) {
    let data_len = pe.data().len() as u64;
    let nt = pe.file_header_offset().saturating_sub(4);
    let optional = pe.file_header_offset() + 20;
    let optional_size = u64::from(pe.file_header().size_of_optional_header.get());
    let directories = pe.data_directories().len() as u64 * 8;
    let mut add = |start: u64, end: u64, name: &str| {
        let end = end.min(data_len);
        if start < end {
            let l = labels.intern(name);
            out.add_file(start, end, l, base);
        }
    };
    if pe.mz().is_some() {
        add(0, 64, "[DOS Header]");
        add(64, nt, "[DOS Stub]");
    }
    add(nt, optional, "[PE File Header]");
    let dirs_start = (optional + optional_size).saturating_sub(directories);
    add(optional, dirs_start, "[PE Optional Header]");
    add(
        dirs_start,
        optional + optional_size,
        "[PE Data Directories]",
    );
}

/// The fallback label for `label` of the base map: sections become
/// `[section <name>]`.
fn fallback(labels: &mut Labels, label: Label) -> Label {
    let name = labels.name(label);
    if name.starts_with('[') {
        label
    } else {
        let f = format!("[section {name}]");
        labels.intern(&f)
    }
}

fn fill(labels: &mut Labels, map: &mut DualMap, base: &DualMap) {
    let mut cache = std::collections::HashMap::new();
    map.fill_from(base, |l| {
        *cache.entry(l).or_insert_with(|| fallback(labels, l))
    });
}

/// bloaty's `DisassembleFindReferences` for a PE image: data that no
/// symbol labels, which functions' code refers to (string literals, jump
/// tables, constants a PDB leaves unnamed), to the first function that
/// refers to it. x64 (RIP-relative operands) and ARM64 (ADRP pairs, ADR,
/// literal loads) code; x86's references are absolute addresses, which
/// the base relocations say better (as ELF's x86 is left).
fn pe_references(pe: &PeFile<'_>, symbols: &[Symbol], map: &mut DualMap, base: &DualMap) {
    use crate::disasm::Arch;
    use crate::symbols::SymbolKind;
    use hexcavator_pe::consts::machine;
    let arch = match pe.machine() {
        machine::AMD64 => Arch::X64,
        machine::ARM64 => Arch::Arm64,
        _ => return,
    };
    let loaded: Vec<(u64, u64)> = pe
        .sections()
        .iter()
        .map(|s| {
            let at = u64::from(s.virtual_address.get());
            (at, at + u64::from(s.virtual_size.get()))
        })
        .collect();
    let functions: Vec<(u64, &[u8])> = symbols
        .iter()
        .filter(|s| {
            !s.folded
                && s.size.file > 0
                && matches!(
                    s.kind,
                    SymbolKind::Function | SymbolKind::PrimaryBlock | SymbolKind::SeparatedBlock
                )
        })
        .filter_map(|s| {
            let rva = u32::try_from(s.addr).ok()?;
            let size = u32::try_from(s.size.file).ok()?;
            Some((
                s.addr,
                pe.bytes_at_rva(hexcavator_core::Rva(rva), size).ok()?,
            ))
        })
        .collect();
    // The functions in parts, a thread each; their references in order
    // (the first to an address is charged).
    let threads = std::thread::available_parallelism()
        .map_or(1, std::num::NonZero::get)
        .min(functions.len().max(1));
    let chunk = functions.len().div_ceil(threads).max(1);
    let refs: Vec<crate::disasm::Reference> = std::thread::scope(|scope| {
        let handles: Vec<_> = functions
            .chunks(chunk)
            .map(|part| {
                scope.spawn(move || {
                    let mut out = Vec::new();
                    for &(at, code) in part {
                        // (Addresses are RVAs: the image starts at 0.)
                        crate::disasm::references_in_image(arch, code, at, Some(0), &mut out);
                    }
                    out
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap_or_default())
            .collect()
    });
    crate::disasm::charge(map, base, &refs, &loaded);
}

/// Builds the maps of `image` for `sources`. Sources that need debug
/// information get only their fallback labels without it.
pub fn maps(image: &Image<'_>, inputs: Inputs<'_>, sources: &[Source]) -> Maps {
    let mut labels = Labels::default();
    let Some(pe) = image.pe() else {
        return Maps::default();
    };
    let base = pe_base(pe, &mut labels);
    let mut out = Vec::new();
    for &source in sources {
        let mut map = DualMap::default();
        match source {
            Source::Sections | Source::Segments => map = base.clone(),
            // From PDB line information: not yet.
            Source::Inlines => fill(&mut labels, &mut map, &base),
            Source::SourceFiles => {
                if let Some(lines) = inputs.lines {
                    // (Spans may overlap: the first to cover a byte has it.)
                    let mut end = 0u64;
                    let ids: Vec<_> = lines.files.iter().map(|f| labels.intern(f)).collect();
                    for s in &lines.spans {
                        let start = s.addr.max(end);
                        let stop = s.addr.saturating_add(s.size);
                        if stop > start {
                            if let Some(&l) = ids.get(s.file as usize) {
                                map.add_vm(start, stop, l, &base);
                            }
                            end = stop;
                        }
                    }
                }
                fill(&mut labels, &mut map, &base);
            }
            Source::Archs => {
                let l = labels.intern(image.arch().name());
                map.fill_from(&base, |_| l);
            }
            Source::InputFiles => {
                let l = labels.intern(inputs.file_name);
                map.fill_from(&base, |_| l);
            }
            Source::Groups => {
                if let Some(model) = inputs.model {
                    for g in &model.groups {
                        let l = labels.intern(&g.name);
                        map.add_vm(g.addr, g.addr + g.extent(), l, &base);
                    }
                }
                fill(&mut labels, &mut map, &base);
            }
            Source::Symbols | Source::RawSymbols | Source::FullSymbols => {
                pe_header_symbols(pe, &mut labels, &mut map, &base);
                if let Some(symbols) = inputs.symbols {
                    for s in symbols.iter().filter(|s| !s.folded) {
                        let size = s.size.vm.max(s.size.file);
                        if size == 0 {
                            continue;
                        }
                        // A function's exception data (`[pdata] f`,
                        // `[unwind] f`, its C++ EH tables) is charged to
                        // the function, as ELF's unwind entries are; the
                        // sections source still tells them apart.
                        let name = s
                            .kind
                            .prefix()
                            .and_then(|p| s.name.strip_prefix(p))
                            .and_then(|n| n.strip_prefix(' '))
                            .unwrap_or(&s.name);
                        let l = labels.intern(name);
                        map.add_vm(s.addr, s.addr.saturating_add(size), l, &base);
                    }
                    pe_references(pe, symbols, &mut map, &base);
                }
                fill(&mut labels, &mut map, &base);
            }
            Source::CompileUnits | Source::ArMembers | Source::Libraries => {
                if let Some(model) = inputs.model {
                    let names: Vec<Label> = if source == Source::Libraries {
                        let libs: Vec<Label> = model
                            .libraries
                            .iter()
                            .map(|l| {
                                labels.intern(if l.name.is_empty() {
                                    "[no library]"
                                } else {
                                    &l.name
                                })
                            })
                            .collect();
                        model
                            .compilands
                            .iter()
                            .map(|c| libs[c.library as usize])
                            .collect()
                    } else {
                        model
                            .compilands
                            .iter()
                            .map(|c| {
                                labels.intern(if c.name.is_empty() {
                                    "[unknown compiland]"
                                } else {
                                    &c.name
                                })
                            })
                            .collect()
                    };
                    for p in &model.pieces {
                        let l = names[p.compiland as usize];
                        map.add_vm(p.range.addr, p.range.end(), l, &base);
                    }
                }
                fill(&mut labels, &mut map, &base);
            }
        }
        map.vm.compress();
        map.file.compress();
        out.push((source, map));
    }
    Maps {
        labels,
        base,
        sources: out,
        file_size: image.data().len() as u64,
        absorb_padding: false,
    }
}

#[cfg(test)]
#[path = "sources_tests.rs"]
mod tests;
