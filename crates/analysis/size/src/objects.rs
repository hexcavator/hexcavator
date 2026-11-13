//! bloaty-style data sources for COFF objects (`.obj`, `/bigobj`
//! included), import objects, and archives of them (`.lib`).
//!
//! Objects have no address space, so the sections the linker would load
//! (all but debug information, linker directives, and removed sections)
//! are given synthetic addresses, laid out one after another at their
//! alignments, member after member: memory sizes are what the object adds
//! to an image before the linker merges or discards anything.
//!
//! The base map labels each section by its full name (`.text$mn`); the
//! `sections` source by the image section it becomes (`.text`), and the
//! `groups` source by the full name (the COFF group). The `symbols` source
//! charges each section to the symbol it defines: a COMDAT's whole section
//! (its relocations, and its associative sections such as `.pdata` and
//! `.xdata`, too) to its COMDAT symbol, and other sections' bytes to the
//! symbol at or before them.

use hexcavator_archive::{Archive, MemberKind};
use hexcavator_core::Result;
use hexcavator_pe::consts::section_characteristics as scn;
use hexcavator_pe::import_object::ImportObject;
use hexcavator_pe::{CoffSymbol, PeFile, comdat_select};

use crate::rangemap::{DualMap, Label, Labels};
use crate::sources::{Maps, Source, UNMAPPED};

pub const COFF_HEADER: &str = "[COFF Header]";
pub const COFF_SECTION_HEADERS: &str = "[COFF Section Headers]";
pub const COFF_RELOCATIONS: &str = "[COFF Relocations]";
pub const COFF_LINE_NUMBERS: &str = "[COFF Line Numbers]";
pub const COFF_SYMBOLS: &str = "[COFF Symbol Table]";
pub const COFF_STRINGS: &str = "[COFF String Table]";
pub const IMPORT_OBJECT: &str = "[Import Object]";
pub const AR_HEADERS: &str = "[AR Headers]";
pub const AR_SYMBOLS: &str = "[AR Symbol Table]";
pub const AR_LONG_NAMES: &str = "[AR Long Names]";
pub const UNPARSED_MEMBER: &str = "[Unparsed Member]";

/// The image section an object section becomes: its name before `$`
/// (debug information, which becomes no image section, keeps its name).
pub fn image_section_name(name: &str) -> &str {
    if name.starts_with(".debug$") {
        return name;
    }
    name.split_once('$').map_or(name, |(s, _)| s)
}

/// Whether the linker loads an object section into the image.
fn loaded(characteristics: u32, name: &[u8]) -> bool {
    characteristics & (scn::LNK_REMOVE | scn::LNK_INFO | scn::MEM_DISCARDABLE) == 0
        && !name.starts_with(b".debug$")
}

/// One object's place in the input: where its data starts, its member
/// name, and (in the symbols source) its symbols' ranges.
struct Unit<'d> {
    offset: u64,
    member: String,
    pe: Option<PeFile<'d>>,
    import: Option<ImportObject<'d>>,
    len: u64,
}

/// A labeled byte range of one object section: offsets in the section.
#[derive(Clone, Copy, Debug)]
struct Piece {
    start: u64,
    end: u64,
    label: Label,
}

struct Builder {
    labels: Labels,
    base: DualMap,
    /// The next synthetic address.
    vm_next: u64,
    /// The input's size: no file range reaches past it.
    len: u64,
}

/// Each section's synthetic address, if loaded.
fn layout(pe: &PeFile<'_>, vm_next: &mut u64) -> Vec<Option<u64>> {
    pe.sections()
        .iter()
        .map(|s| {
            let flags = s.characteristics.get();
            if !loaded(flags, pe.section_name(s)) {
                return None;
            }
            let align = u64::from(scn::alignment(flags).unwrap_or(16));
            let addr = vm_next.next_multiple_of(align);
            *vm_next = addr + u64::from(s.size_of_raw_data.get());
            Some(addr)
        })
        .collect()
}

impl Builder {
    fn file(&mut self, start: u64, len: u64, name: &str) {
        let end = start.saturating_add(len).min(self.len);
        if start < end {
            let l = self.labels.intern(name);
            self.base.file.add(start, end, l);
        }
    }

    /// The base map's ranges for an object at `offset`.
    fn object(&mut self, offset: u64, pe: &PeFile<'_>, addrs: &[Option<u64>]) {
        let header = if pe.is_bigobj() { 56 } else { 20 };
        let header = header + u64::from(pe.file_header().size_of_optional_header.get());
        self.file(offset, header, COFF_HEADER);
        self.file(
            offset + header,
            40 * pe.sections().len() as u64,
            COFF_SECTION_HEADERS,
        );
        let len = pe.data().len() as u64;
        for (s, addr) in pe.sections().iter().zip(addrs) {
            let name = String::from_utf8_lossy(pe.section_name(s)).into_owned();
            let label = self.labels.intern(&name);
            let raw = u64::from(s.size_of_raw_data.get());
            let ptr = u64::from(s.pointer_to_raw_data.get());
            let file_len = if ptr == 0 {
                0
            } else {
                raw.min(len.saturating_sub(ptr))
            };
            match addr {
                Some(a) => self.base.add_range(*a, raw, offset + ptr, file_len, label),
                None if file_len > 0 => {
                    self.base
                        .file
                        .add(offset + ptr, offset + ptr + file_len, label);
                }
                None => {}
            }
            let relocs = relocation_bytes(pe, s);
            self.file(
                offset + u64::from(s.pointer_to_relocations.get()),
                relocs,
                COFF_RELOCATIONS,
            );
            self.file(
                offset + u64::from(s.pointer_to_linenumbers.get()),
                6 * u64::from(s.number_of_linenumbers.get()),
                COFF_LINE_NUMBERS,
            );
        }
        if let Ok(Some(symbols)) = pe.symbols() {
            let at = u64::from(pe.file_header().pointer_to_symbol_table.get());
            let size = (symbols.len() * symbols.record_size()) as u64;
            self.file(offset + at, size, COFF_SYMBOLS);
            self.file(
                offset + at + size,
                symbols.strings().size() as u64,
                COFF_STRINGS,
            );
        }
    }
}

/// The bytes of a section's relocation table (with the count entry of an
/// overflowed one).
fn relocation_bytes(pe: &PeFile<'_>, s: &hexcavator_pe::raw::SectionHeader) -> u64 {
    if s.pointer_to_relocations.get() == 0 {
        return 0;
    }
    let n = pe.section_relocations(s).len() as u64;
    let overflow = s.characteristics.get() & scn::LNK_NRELOC_OVFL != 0
        && s.number_of_relocations.get() == 0xFFFF;
    10 * (n + u64::from(overflow))
}

/// A symbol's name as reports show it: undecorated, if decorated.
fn display(demangler: &mut hexcavator_demangle::msvc::Demangler, name: &[u8]) -> String {
    let name = String::from_utf8_lossy(name);
    if name.starts_with('?') {
        demangler
            .demangle(&name, hexcavator_demangle::msvc::flags::NO_PTR64)
            .unwrap_or_else(|| name.into_owned())
    } else {
        hexcavator_demangle::swift::demangle(&name).unwrap_or_else(|| name.into_owned())
    }
}

/// Whether a symbol names a place worth charging bytes to (not a label,
/// a section's own symbol, or a file name).
fn charges(symbols: &hexcavator_pe::SymbolTable<'_>, s: &CoffSymbol<'_>) -> bool {
    use hexcavator_pe::consts::storage_class;
    if s.section <= 0 || s.section_definition().is_some() {
        return false;
    }
    if !matches!(
        s.storage_class,
        storage_class::EXTERNAL | storage_class::STATIC
    ) {
        return false;
    }
    let name = symbols.name(s).unwrap_or(b"");
    !(name.is_empty()
        || name.starts_with(b"$LN")
        || name.starts_with(b".")
        || name.starts_with(b"$M"))
}

/// The symbols source's pieces of each section of an object (by index).
fn symbol_pieces(pe: &PeFile<'_>, labels: &mut Labels) -> Vec<Vec<Piece>> {
    let sections = pe.sections();
    let mut out = vec![Vec::new(); sections.len()];
    let Ok(Some(symbols)) = pe.symbols() else {
        return out;
    };
    let mut demangler = hexcavator_demangle::msvc::Demangler::default();
    let comdats = symbols.comdat_symbols(sections.len());
    // Section definitions, for COMDAT selection and associations.
    let mut defs = vec![None; sections.len() + 1];
    // Symbols at offsets in non-COMDAT sections.
    let mut at: Vec<Vec<(u32, String)>> = vec![Vec::new(); sections.len()];
    for s in symbols.iter() {
        let Ok(n) = usize::try_from(s.section) else {
            continue;
        };
        if n == 0 || n > sections.len() {
            continue;
        }
        if let Some(d) = s.section_definition() {
            defs[n].get_or_insert(d);
        } else if charges(&symbols, &s) {
            at[n - 1].push((
                s.value,
                display(&mut demangler, symbols.name(&s).unwrap_or(b"")),
            ));
        }
    }
    // A COMDAT's label, following associations to their parents.
    let comdat_label = |n: usize,
                        labels: &mut Labels,
                        demangler: &mut hexcavator_demangle::msvc::Demangler|
     -> Option<Label> {
        let mut n = n;
        for _ in 0..8 {
            let comdat =
                sections.get(n.checked_sub(1)?)?.characteristics.get() & scn::LNK_COMDAT != 0;
            if !comdat {
                return None;
            }
            match defs.get(n).copied().flatten() {
                Some(d) if d.selection == comdat_select::ASSOCIATIVE => {
                    n = usize::try_from(d.number).ok()?;
                }
                _ => {
                    let s = comdats.get(n).copied().flatten()?;
                    let name = display(demangler, symbols.name(&s)?);
                    return Some(labels.intern(&name));
                }
            }
        }
        None
    };
    for (i, s) in sections.iter().enumerate() {
        let size = u64::from(s.size_of_raw_data.get());
        if let Some(label) = comdat_label(i + 1, labels, &mut demangler) {
            out[i].push(Piece {
                start: 0,
                end: size,
                label,
            });
            continue;
        }
        let list = &mut at[i];
        list.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        list.dedup_by_key(|e| e.0);
        for (k, (value, name)) in list.iter().enumerate() {
            let start = u64::from(*value).min(size);
            let end = list.get(k + 1).map_or(size, |n| u64::from(n.0).min(size));
            if start < end {
                let label = labels.intern(name);
                out[i].push(Piece { start, end, label });
            }
        }
    }
    out
}

/// The label of the piece holding `offset`, if any.
fn piece_at(pieces: &[Piece], offset: u64) -> Option<Label> {
    let i = pieces.partition_point(|p| p.start <= offset);
    let p = pieces.get(i.checked_sub(1)?)?;
    (offset < p.end).then_some(p.label)
}

/// Builds the maps of an object, an import object, or an archive of them.
pub fn maps(data: &[u8], file_name: &str, sources: &[Source]) -> Result<Maps> {
    let mut b = Builder {
        labels: Labels::default(),
        base: DualMap::default(),
        vm_next: 0x1000,
        len: data.len() as u64,
    };
    let mut units: Vec<Unit<'_>> = Vec::new();
    let mut library: Option<String> = None;
    if Archive::is_archive(data) {
        let ar = Archive::parse(data)?;
        library = Some(file_name.to_string());
        b.file(0, 8, AR_HEADERS);
        for m in ar.members() {
            b.file(m.header_offset, m.data_offset - m.header_offset, AR_HEADERS);
            let pad = m.end() - (m.data_offset + m.data.len() as u64);
            b.file(m.data_offset + m.data.len() as u64, pad, AR_HEADERS);
            match m.kind {
                MemberKind::SymbolTable | MemberKind::EcSymbolTable => {
                    b.file(m.data_offset, m.data.len() as u64, AR_SYMBOLS);
                }
                MemberKind::LongNames => b.file(m.data_offset, m.data.len() as u64, AR_LONG_NAMES),
                MemberKind::File => units.push(unit(
                    m.data,
                    m.data_offset,
                    String::from_utf8_lossy(&m.name).into_owned(),
                )),
            }
        }
    } else {
        units.push(unit(data, 0, file_name.to_string()));
    }
    let mut addrs: Vec<Vec<Option<u64>>> = Vec::new();
    for u in &units {
        match (&u.pe, &u.import) {
            (Some(pe), _) => {
                let a = layout(pe, &mut b.vm_next);
                b.object(u.offset, pe, &a);
                addrs.push(a);
            }
            (None, Some(_)) => {
                b.file(u.offset, u.len, IMPORT_OBJECT);
                addrs.push(Vec::new());
            }
            _ => {
                b.file(u.offset, u.len, UNPARSED_MEMBER);
                addrs.push(Vec::new());
            }
        }
    }
    let unmapped = b.labels.intern(UNMAPPED);
    b.base.file.add(0, data.len() as u64, unmapped);
    b.base.vm.compress();
    b.base.file.compress();

    let mut out = Vec::new();
    for &source in sources {
        let mut map = DualMap::default();
        match source {
            Source::Groups => map = b.base.clone(),
            Source::Sections | Source::Segments => {
                let mut cache = std::collections::HashMap::new();
                let labels = &mut b.labels;
                map.fill_from(&b.base, |l| {
                    *cache.entry(l).or_insert_with(|| {
                        let name = labels.name(l).to_string();
                        if name.starts_with('[') {
                            l
                        } else {
                            labels.intern(image_section_name(&name))
                        }
                    })
                });
            }
            Source::Inlines | Source::SourceFiles => fill(&mut b.labels, &mut map, &b.base),
            Source::Archs => {
                let name = units
                    .iter()
                    .find_map(|u| {
                        u.pe.as_ref()
                            .map(|p| hexcavator_image::coff_machine_name(p.machine()))
                    })
                    .unwrap_or("unknown");
                let l = b.labels.intern(name);
                map.fill_from(&b.base, |_| l);
            }
            Source::InputFiles => {
                let l = b.labels.intern(file_name);
                map.fill_from(&b.base, |_| l);
            }
            Source::Libraries => {
                let l = b
                    .labels
                    .intern(library.as_deref().unwrap_or("[no library]"));
                map.fill_from(&b.base, |_| l);
            }
            Source::CompileUnits | Source::ArMembers => {
                for (u, addrs) in units.iter().zip(&addrs) {
                    let l = b.labels.intern(&u.member);
                    map.add_file(u.offset, u.offset + u.len, l, &b.base);
                    // (Zero-fill sections have memory but no file bytes.)
                    if let Some(pe) = &u.pe {
                        for (s, a) in pe.sections().iter().zip(addrs) {
                            if let Some(a) = a {
                                let size = u64::from(s.size_of_raw_data.get());
                                map.add_vm(*a, a + size, l, &b.base);
                            }
                        }
                    }
                }
                fill(&mut b.labels, &mut map, &b.base);
            }
            Source::Symbols | Source::RawSymbols | Source::FullSymbols => {
                for (u, addrs) in units.iter().zip(&addrs) {
                    if let Some(i) = u.import {
                        let name = format!(
                            "[import] {} ({})",
                            String::from_utf8_lossy(i.symbol),
                            String::from_utf8_lossy(i.dll)
                        );
                        let l = b.labels.intern(&name);
                        map.add_file(u.offset, u.offset + u.len, l, &b.base);
                        continue;
                    }
                    let Some(pe) = &u.pe else { continue };
                    let pieces = symbol_pieces(pe, &mut b.labels);
                    for ((s, pieces), addr) in pe.sections().iter().zip(&pieces).zip(addrs) {
                        let ptr = u64::from(s.pointer_to_raw_data.get());
                        for p in pieces {
                            match (ptr, addr) {
                                (0, Some(a)) => {
                                    map.add_vm(a + p.start, a + p.end, p.label, &b.base);
                                }
                                (0, None) => {}
                                _ => {
                                    let at = u.offset + ptr;
                                    map.add_file(at + p.start, at + p.end, p.label, &b.base);
                                }
                            }
                        }
                        // Relocations, charged to what they patch.
                        let relocs = pe.section_relocations(s);
                        let table = u.offset + u64::from(s.pointer_to_relocations.get());
                        let first = table
                            + if relocs.len() as u64 * 10 < relocation_bytes(pe, s) {
                                10
                            } else {
                                0
                            };
                        for (k, r) in relocs.iter().enumerate() {
                            if let Some(l) = piece_at(pieces, u64::from(r.virtual_address.get())) {
                                let at = first + 10 * k as u64;
                                map.add_file(at, at + 10, l, &b.base);
                            }
                        }
                    }
                }
                fill(&mut b.labels, &mut map, &b.base);
            }
        }
        map.vm.compress();
        map.file.compress();
        out.push((source, map));
    }
    Ok(Maps {
        labels: b.labels,
        base: b.base,
        sources: out,
        file_size: data.len() as u64,
        absorb_padding: false,
    })
}

fn unit<'d>(data: &'d [u8], offset: u64, member: String) -> Unit<'d> {
    let import = ImportObject::is_import_object(data)
        .then(|| ImportObject::parse(data).ok())
        .flatten();
    let pe = if import.is_some() {
        None
    } else {
        PeFile::parse_object(data).ok()
    };
    Unit {
        offset,
        member,
        pe,
        import,
        len: data.len() as u64,
    }
}

/// Fills `map`'s unlabeled bytes from `base`, sections as `[section x]`.
fn fill(labels: &mut Labels, map: &mut DualMap, base: &DualMap) {
    let mut cache = std::collections::HashMap::new();
    map.fill_from(base, |l| {
        *cache.entry(l).or_insert_with(|| {
            let name = labels.name(l).to_string();
            if name.starts_with('[') {
                l
            } else {
                labels.intern(&format!("[section {name}]"))
            }
        })
    });
}

#[cfg(test)]
#[path = "objects_tests.rs"]
mod tests;
