//! bloaty's data sources for ELF files: executables, shared objects,
//! relocatable objects, and archives of objects (`.a`).
//!
//! This follows bloaty's `elf.cc`:
//!
//! - The base map is the `segments` source: each `PT_LOAD` segment as
//!   `LOAD #i [RWX]` (then `PT_TLS` as `TLS`), then the file header,
//!   section header table, and program header table, then `[Unmapped]`.
//!   Objects have no segments, so their sections stand in, named by their
//!   flags (`Section [AX]`), at synthetic addresses: section *i* of the
//!   input's sections (counted across an archive's members) at `i << 40`.
//! - `sections` names each section; `armembers` names the member (the file,
//!   outside an archive) that holds each section and byte.
//! - `symbols` (names demangled short, as abseil does), `fullsymbols`,
//!   and `rawsymbols` charge each sized symbol of `.symtab` its range (symbols
//!   in sections that aren't loaded, by file offset), then charges to the
//!   symbol at the address they describe: symbol table entries and their
//!   names, relocation entries, `.eh_frame` FDEs, and `.eh_frame_hdr`
//!   table entries. First, though, the code of each function (x86-64 and
//!   ARM64) is disassembled for the data it refers to (see
//!   [`crate::disasm`]), and data no symbol covers is charged to the first
//!   function that refers to it: a string literal, to the function that
//!   prints it. `compileunits` and `inlines` charge it, and the tables, to
//!   the unit or line of the referring code.
//! - Every source but `segments` falls back to `[section x]`, the headers,
//!   `[LOAD #i [RWX]]`, and `[Unmapped]`; `segments` skips the first two.
//!
//! Where bloaty is wrong we are not (see `baseline-divergence`): unnamed
//! sections are skipped rather than ending the section walk; the first
//! entry of a relocation table is charged like the others; `SHT_REL`
//! tables are charged too, not only `SHT_RELA`; an object's `.eh_frame`,
//! whose pointers are unrelocated, is not read for addresses; integers
//! are read in the file's byte order; referenced data runs to the next
//! referenced address, symbol, or section end, whichever is first (bloaty's
//! "unknown size" runs to whatever range happens to be added next), and
//! only data no symbol has is charged; ARM64 code is searched for
//! references too; objects, whose code is unrelocated, are not; and
//! `inlines` charges the tables and referenced data to lines (bloaty means
//! to, but labels every section before its tables pass, which then finds
//! nothing to charge).
//!
//! As bloaty does, a fallback range of at most 16 bytes right after a
//! labeled one is counted as its padding when rolling up (see
//! [`crate::rangemap::RangeMap::with_padding_absorbed`]).

use hexcavator_archive::{Archive, MemberKind};
use hexcavator_core::{Error, ErrorKind, Result};
use hexcavator_demangle::itanium::Demangler;
use hexcavator_elf::consts::*;
use hexcavator_elf::{ElfFile, Section};

use crate::rangemap::{DualMap, Label, Labels};
use crate::sources::{Maps, Source, UNMAPPED};

pub const ELF_HEADER: &str = "[ELF Header]";
pub const ELF_SECTION_HEADERS: &str = "[ELF Section Headers]";
pub const ELF_PROGRAM_HEADERS: &str = "[ELF Program Headers]";
pub const AR_HEADERS: &str = "[AR Headers]";
pub const AR_SYMBOLS: &str = "[AR Symbol Table]";
pub const AR_NON_ELF: &str = "[AR Non-ELF Member File]";

/// Whether `data` is an ELF file, or an archive whose first member file
/// is one.
pub fn is_elf_input(data: &[u8]) -> bool {
    if ElfFile::is_elf(data) {
        return true;
    }
    Archive::is_archive(data)
        && Archive::parse(data)
            .ok()
            .and_then(|ar| ar.files().next())
            .is_some_and(|m| ElfFile::is_elf(m.data))
}

/// One ELF file of the input: the whole input, or an archive member.
struct Unit<'d> {
    elf: ElfFile<'d>,
    /// Where its data starts in the input.
    offset: u64,
    /// Its member name (the input's name outside an archive).
    name: String,
    /// The number of sections of the units before it, for synthetic
    /// object addresses.
    index_base: u64,
}

impl Unit<'_> {
    /// `[offset, offset + size)` of the unit's data, clamped to it, as
    /// input file offsets.
    fn file_range(&self, offset: u64, size: u64) -> (u64, u64) {
        let len = self.elf.data().len() as u64;
        let start = offset.min(len);
        let end = start + size.min(len - start);
        (self.offset + start, self.offset + end)
    }

    /// A section's file extent (none for `SHT_NOBITS`), clamped.
    fn section_file(&self, s: &Section<'_>) -> (u64, u64) {
        self.file_range(s.offset, s.file_size())
    }
}

/// bloaty's `ToVMAddr`: in objects (and archives), section-relative
/// addresses become `(section << 40) | addr`.
fn to_vm(addr: u64, section: u64, object: bool) -> Option<u64> {
    if !object {
        return Some(addr);
    }
    (section < 1 << 24 && addr < 1 << 40).then_some((section << 40) | addr)
}

fn flags_label(flags: u64) -> String {
    let mut s = String::from("Section [");
    for (bit, c) in [(SHF_ALLOC, 'A'), (SHF_WRITE, 'W'), (SHF_EXECINSTR, 'X')] {
        if flags & bit != 0 {
            s.push(c);
        }
    }
    s.push(']');
    s
}

fn segment_label(index: usize, flags: u32, escaped: bool) -> String {
    let mut s = format!("LOAD #{index} [");
    for (bit, c) in [(PF_R, 'R'), (PF_W, 'W'), (PF_X, 'X')] {
        if flags & bit != 0 {
            s.push(c);
        }
    }
    s.push(']');
    if escaped { format!("[{s}]") } else { s }
}

/// How `sections_into` names sections.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SectionsBy {
    Name,
    Escaped,
    Flags,
    Member,
}

/// A symbol's name as `source` shows it (demangled or not).
fn symbol_name(
    sym: &hexcavator_elf::Symbol<'_>,
    source: Source,
    demangler: &mut Demangler,
    buf: &mut String,
) -> String {
    if sym.name.is_empty() {
        return format!("[Anonymous symbol #{}]", sym.index);
    }
    let raw = String::from_utf8_lossy(sym.name);
    buf.clear();
    let ok = match source {
        Source::Symbols => demangler.demangle_short_into(&raw, buf),
        Source::FullSymbols => demangler.demangle_into(&raw, buf),
        _ => false,
    };
    if ok { buf.clone() } else { raw.into_owned() }
}

/// The largest MiniDebugInfo (`.gnu_debugdata`) read: a symbol table.
const MAX_MINI_DEBUG: u64 = 1 << 28;

/// An ELF image's MiniDebugInfo: the ELF file (a symbol table) its
/// `.gnu_debugdata` section holds, xz-compressed, decompressed.
pub fn mini_debug_info(data: &[u8]) -> Option<Vec<u8>> {
    let elf = ElfFile::parse(data).ok()?;
    let sec = elf.sections().find(|s| s.name == b".gnu_debugdata")?;
    hexcavator_debuginfo::decompress::xz(elf.section_data(&sec), MAX_MINI_DEBUG)
}

struct Builder<'d> {
    data: &'d [u8],
    units: Vec<Unit<'d>>,
    /// The archive's own structures: (offset, size, label name).
    ar_ranges: Vec<(u64, u64, &'static str)>,
    object: bool,
    labels: Labels,
}

impl Builder<'_> {
    fn ar_into(&mut self, map: &mut DualMap, base: Option<&DualMap>) {
        for &(at, size, name) in &self.ar_ranges {
            let l = self.labels.intern(name);
            add_file(map, at, at + size, l, base);
        }
    }

    fn sections_into(&mut self, map: &mut DualMap, by: SectionsBy) {
        for u in &self.units {
            for s in u.elf.sections().skip(1) {
                if s.name.is_empty() {
                    continue;
                }
                let name = match by {
                    SectionsBy::Name => String::from_utf8_lossy(s.name).into_owned(),
                    SectionsBy::Escaped => format!("[section {}]", String::from_utf8_lossy(s.name)),
                    SectionsBy::Flags => flags_label(s.flags),
                    SectionsBy::Member => u.name.clone(),
                };
                let l = self.labels.intern(&name);
                let vm_size = if s.is_alloc() { s.size } else { 0 };
                let (fs, fe) = u.section_file(&s);
                let Some(vm) = to_vm(s.addr, u.index_base + s.index as u64, self.object) else {
                    continue;
                };
                map.add_range(vm, vm_size.min(u64::MAX - vm), fs, fe - fs, l);
            }
        }
    }

    fn segments_into(&mut self, map: &mut DualMap, escaped: bool) {
        for u in &self.units {
            for p in u.elf.segments().filter(|p| p.kind == PT_LOAD) {
                let l = self
                    .labels
                    .intern(&segment_label(p.index, p.flags, escaped));
                let (fs, fe) = u.file_range(p.offset, p.filesz);
                map.add_range(p.vaddr, p.memsz.min(u64::MAX - p.vaddr), fs, fe - fs, l);
            }
        }
        for u in &self.units {
            for p in u.elf.segments().filter(|p| p.kind == PT_TLS) {
                let l = self.labels.intern("TLS");
                let (fs, fe) = u.file_range(p.offset, p.filesz);
                map.add_range(p.vaddr, p.memsz.min(u64::MAX - p.vaddr), fs, fe - fs, l);
            }
        }
    }

    fn headers_into(&mut self, map: &mut DualMap, base: Option<&DualMap>) {
        for u in &self.units {
            let (hs, hn) = u.elf.header_range();
            let (ss, sn) = u.elf.section_headers_range();
            let (ps, pn) = u.elf.program_headers_range();
            for (at, size, name) in [
                (hs, hn, ELF_HEADER),
                (ss, sn, ELF_SECTION_HEADERS),
                (ps, pn, ELF_PROGRAM_HEADERS),
            ] {
                let (s, e) = u.file_range(at, size);
                let l = self.labels.intern(name);
                add_file(map, s, e, l, base);
            }
        }
    }

    /// bloaty's `AddCatchAll`, for a source other than the base.
    fn catch_all(&mut self, map: &mut DualMap, base: &DualMap, segments: bool) {
        if !segments {
            self.sections_into(map, SectionsBy::Escaped);
            self.headers_into(map, Some(base));
        }
        self.segments_into(map, true);
        let l = self.labels.intern(UNMAPPED);
        map.add_file(0, self.data.len() as u64, l, base);
    }

    /// bloaty's `DisassembleFindReferences`: data that nothing in `map`
    /// labels yet, referred to by a function's code, to whoever has the
    /// code (the function, its compile unit, or its line).
    fn references_into(&mut self, map: &mut DualMap, base: &DualMap) {
        if self.object {
            return;
        }
        let mut refs = Vec::new();
        for u in &self.units {
            // (x86's references are absolute addresses, which the
            // relocations say better.)
            let arch = hexcavator_elf::arch(u.elf.header().machine, u.elf.class());
            if !matches!(arch, crate::disasm::Arch::X64 | crate::disasm::Arch::Arm64) {
                continue;
            }
            let sections: Vec<Section<'_>> = u.elf.sections().collect();
            let loaded: Vec<(u64, u64)> = sections
                .iter()
                .filter(|s| s.is_alloc())
                .map(|s| (s.addr, s.addr.saturating_add(s.size)))
                .collect();
            refs.clear();
            for table in sections.iter().filter(|s| s.kind == SHT_SYMTAB) {
                for sym in u.elf.symbols(table) {
                    if sym.kind != STT_FUNC || sym.size == 0 {
                        continue;
                    }
                    let Some(s) = sections.get(sym.shndx as usize) else {
                        continue;
                    };
                    if !s.is_alloc() || s.kind == SHT_NOBITS || sym.value < s.addr {
                        continue;
                    }
                    let data = u.elf.section_data(s);
                    let Ok(start) = usize::try_from(sym.value - s.addr) else {
                        continue;
                    };
                    let Some(code) = data.get(start..) else {
                        continue;
                    };
                    let code = &code[..code
                        .len()
                        .min(usize::try_from(sym.size).unwrap_or(usize::MAX))];
                    crate::disasm::references(arch, code, sym.value, &mut refs);
                }
            }
            crate::disasm::charge(map, base, &refs, &loaded);
        }
    }

    /// `source` names symbols: short (`symbols`), as mangled, or in full.
    fn symbols_into(
        &mut self,
        map: &mut DualMap,
        base: &DualMap,
        source: Source,
        debug: Option<&ElfFile<'_>>,
    ) {
        let mut demangler = Demangler::new();
        let mut buf = String::new();
        // A linked image's separate debug file (or MiniDebugInfo) has the
        // symbol table bloaty reads (a stripped image has none): its
        // symbols' addresses are the image's.
        if let Some(d) = debug.filter(|_| !self.object) {
            let sections: Vec<Section<'_>> = d.sections().collect();
            for table in sections.iter().filter(|s| s.kind == SHT_SYMTAB) {
                for sym in d.symbols(table).iter().skip(1) {
                    if sym.kind == STT_SECTION
                        || sym.shndx == u32::from(SHN_UNDEF)
                        || sym.shndx >= u32::from(SHN_LORESERVE)
                        || sym.size == 0
                        || !sections
                            .get(sym.shndx as usize)
                            .is_some_and(Section::is_alloc)
                    {
                        continue;
                    }
                    let name = symbol_name(sym, source, &mut demangler, &mut buf);
                    let l = self.labels.intern(&name);
                    map.add_vm(sym.value, sym.value.saturating_add(sym.size), l, base);
                }
            }
            return;
        }
        for u in &self.units {
            let sections: Vec<Section<'_>> = u.elf.sections().collect();
            for table in sections.iter().filter(|s| s.kind == SHT_SYMTAB) {
                for sym in u.elf.symbols(table).iter().skip(1) {
                    if sym.kind == STT_SECTION || sym.shndx == u32::from(SHN_UNDEF) || sym.size == 0
                    {
                        continue;
                    }
                    let name = symbol_name(sym, source, &mut demangler, &mut buf);
                    let l = self.labels.intern(&name);
                    if sym.shndx < u32::from(SHN_LORESERVE)
                        && let Some(s) = sections.get(sym.shndx as usize)
                        && !s.is_alloc()
                    {
                        // Not loaded: by file offset.
                        let at = s.offset.wrapping_add(sym.value.wrapping_sub(s.addr));
                        let (fs, fe) = u.file_range(at, sym.size);
                        map.add_file(fs, fe, l, base);
                        continue;
                    }
                    if let Some(vm) =
                        to_vm(sym.value, u.index_base + u64::from(sym.shndx), self.object)
                    {
                        map.add_vm(vm, vm.saturating_add(sym.size), l, base);
                    }
                }
            }
        }
    }

    /// bloaty's `ReadELFTables`: table entries charged to the symbol at
    /// the address they describe.
    fn tables_into(&mut self, map: &mut DualMap, base: &DualMap) {
        let object = self.object;
        for u in &self.units {
            let sections: Vec<Section<'_>> = u.elf.sections().collect();
            let charge = |map: &mut DualMap, vm: Option<u64>, at: u64, size: u64| {
                if let Some(vm) = vm
                    && let Some(e) = map.vm.get(vm)
                {
                    let (fs, fe) = u.file_range(at, size);
                    map.add_file(fs, fe, e.label, base);
                }
            };
            for s in &sections {
                match s.kind {
                    SHT_SYMTAB | SHT_DYNSYM => {
                        let entry = if u.elf.class() == hexcavator_elf::Class::Elf64 {
                            24
                        } else {
                            16
                        };
                        let stride = if s.entsize == 0 { entry } else { s.entsize };
                        let strings = sections
                            .get(s.link as usize)
                            .filter(|t| t.kind == SHT_STRTAB);
                        for sym in u.elf.symbols(s).iter().skip(1) {
                            if sym.kind == STT_SECTION || sym.shndx == u32::from(SHN_UNDEF) {
                                continue;
                            }
                            let vm = to_vm(sym.value, u.index_base + u64::from(sym.shndx), object);
                            if !sym.name.is_empty()
                                && let Some(t) = strings
                            {
                                // The name, and its terminator.
                                let name_at = t.offset.saturating_add(u64::from(sym.name_offset));
                                charge(map, vm, name_at, sym.name.len() as u64 + 1);
                            }
                            charge(map, vm, s.offset + sym.index as u64 * stride, stride);
                        }
                    }
                    SHT_RELA | SHT_REL => {
                        for r in u.elf.relocations(s) {
                            let vm = to_vm(r.offset, u.index_base + u64::from(s.info), object);
                            charge(map, vm, r.file_offset, r.size);
                        }
                    }
                    _ => {}
                }
                if !object {
                    let entries = match s.name {
                        b".eh_frame" => u.elf.eh_frame(s),
                        b".eh_frame_hdr" => u.elf.eh_frame_hdr(s),
                        _ => Vec::new(),
                    };
                    for e in entries {
                        charge(map, Some(e.pc), s.offset + e.offset, e.size);
                    }
                }
            }
        }
    }
}

/// Labels `[start, end)` of the file: translated through `base` when
/// there is one (a source), directly when not (the base itself).
fn add_file(map: &mut DualMap, start: u64, end: u64, label: Label, base: Option<&DualMap>) {
    if start >= end {
        return;
    }
    match base {
        Some(b) => {
            map.add_file(start, end, label, b);
        }
        None => map.file.add(start, end, label),
    }
}

/// `compileunits` from an ELF file's own DWARF.
/// `in_input`: whether `elf` is (part of) the input, whose DWARF bytes
/// are then charged too, or a separate debug file.
fn elf_compile_units(
    elf: &ElfFile<'_>,
    file_offset: u64,
    file_len: u64,
    labels: &mut Labels,
    map: &mut DualMap,
    base: &DualMap,
    in_input: bool,
) {
    // Compressed sections' contents are not the file's bytes to charge.
    let input = crate::dwarf_units::DwarfInput {
        endian: elf.endian(),
        sections: crate::decompress::elf_dwarf_sections(elf, in_input.then_some(file_offset)),
    };
    // Symbol sizes, by start address, for variables' locations.
    let mut sizes = std::collections::HashMap::new();
    for table in elf.sections().filter(|t| t.kind == SHT_SYMTAB) {
        for sym in elf.symbols(&table) {
            if sym.kind != STT_SECTION && sym.shndx != u32::from(SHN_UNDEF) && sym.size > 0 {
                sizes.entry(sym.value).or_insert(sym.size);
            }
        }
    }
    crate::dwarf_units::compile_units(&input, &sizes, file_len, labels, map, base);
}

/// `inlines` from an ELF file's DWARF line tables.
fn elf_inlines(
    elf: &ElfFile<'_>,
    labels: &mut Labels,
    map: &mut DualMap,
    base: &DualMap,
    with_line: bool,
) {
    let input = crate::dwarf_units::DwarfInput {
        endian: elf.endian(),
        sections: crate::decompress::elf_dwarf_sections(elf, None),
    };
    if with_line {
        crate::dwarf_units::inlines(&input, labels, map, base);
    } else {
        crate::dwarf_units::source_files(&input, labels, map, base);
    }
}

/// The architecture an ELF machine number names.
fn machine_name(machine: u16) -> String {
    match machine {
        EM_X86_64 => "x86_64".into(),
        EM_386 => "i386".into(),
        EM_AARCH64 => "aarch64".into(),
        EM_ARM => "arm".into(),
        EM_RISCV => "riscv".into(),
        m => format!("machine_{m}"),
    }
}

/// Whether `name` (as given on the command line) names the symbol `raw`:
/// as the symbol table has it, or demangled, short or in full.
pub(crate) fn names_symbol(demangler: &mut Demangler, raw: &str, name: &str) -> bool {
    let mut buf = String::new();
    raw == name || (demangler.demangle_short_into(raw, &mut buf) && buf == name) || {
        buf.clear();
        demangler.demangle_into(raw, &mut buf) && buf == name
    }
}

/// bloaty's `--disassemble`: the function `name` (see `names_symbol`),
/// and the names of the file's addresses.
pub fn function<'d>(
    data: &'d [u8],
    name: &str,
) -> std::result::Result<crate::disasm::Function<'d>, String> {
    use crate::disasm::Arch;
    if Archive::is_archive(data) {
        return Err("give one of the archive's objects to disassemble".into());
    }
    let elf = ElfFile::parse(data).map_err(|e| e.to_string())?;
    let isa: Arch = hexcavator_elf::arch(elf.header().machine, elf.class());
    // (Big-endian ARM code is little-endian only when linked BE8.)
    const EF_ARM_BE8: u32 = 0x0080_0000;
    let be32 = isa == Arch::Arm
        && elf.endian() == hexcavator_core::Endian::Big
        && elf.header().flags & EF_ARM_BE8 == 0;
    if !hexcavator_code::decodes(isa) || be32 {
        return Err(format!(
            "no disassembler for {}{}",
            machine_name(elf.header().machine),
            if be32 { " (big-endian BE32 code)" } else { "" }
        ));
    }
    let sections: Vec<Section<'_>> = elf.sections().collect();
    let mut demangler = Demangler::new();
    let mut names: Vec<(u64, String)> = Vec::new();
    let mut data_marks: Vec<u64> = Vec::new();
    let mut found = None;
    let mut alone = crate::disasm::ByNameAlone::new(name);
    let mut short = String::new();
    for table in sections
        .iter()
        .filter(|s| s.kind == SHT_SYMTAB || s.kind == SHT_DYNSYM)
    {
        for sym in elf.symbols(table).iter().skip(1) {
            if sym.name.is_empty()
                || sym.shndx == u32::from(SHN_UNDEF)
                || matches!(sym.kind, STT_SECTION | STT_FILE)
            {
                continue;
            }
            // (ARM's mapping symbols mark code and data: `$d` starts data.)
            if isa == crate::disasm::Arch::Arm && is_mapping_symbol(sym.name) {
                if sym.name.starts_with(b"$d") {
                    data_marks.push(sym.value);
                }
                continue;
            }
            let raw = String::from_utf8_lossy(sym.name);
            short.clear();
            let shown = if demangler.demangle_short_into(&raw, &mut short) {
                short.clone()
            } else {
                raw.clone().into_owned()
            };
            if found.is_none() && sym.kind == STT_FUNC && sym.size > 0 {
                if names_symbol(&mut demangler, &raw, name) {
                    found = Some((*sym, shown.clone()));
                } else {
                    alone.offer(sym.value, &shown, || (*sym, shown.clone()));
                }
            }
            // (Thumb functions' symbols are at odd addresses.)
            let at = if isa == crate::disasm::Arch::Arm && sym.kind == STT_FUNC {
                sym.value & !1
            } else {
                sym.value
            };
            names.push((at, shown));
        }
    }
    names.sort_by_key(|n| n.0);
    names.dedup_by_key(|n| n.0);
    let (sym, shown) = found
        .or_else(|| alone.take())
        .ok_or_else(|| format!("no function named '{name}'"))?;
    let sec = sections
        .get(sym.shndx as usize)
        .filter(|s| s.kind != SHT_NOBITS && sym.value >= s.addr)
        .ok_or_else(|| format!("{shown}: not in a section with contents"))?;
    let data = elf.section_data(sec);
    let start =
        usize::try_from((sym.value & !u64::from(isa == crate::disasm::Arch::Arm)) - sec.addr)
            .unwrap_or(usize::MAX);
    let code = data
        .get(start..)
        .map(|c| &c[..c.len().min(usize::try_from(sym.size).unwrap_or(usize::MAX))])
        .ok_or_else(|| format!("{shown}: outside its section"))?;
    // (An ARM function's literal pool: data, from its `$d`.)
    let begin = sym.value & !1;
    let data_from = data_marks
        .iter()
        .copied()
        .filter(|&d| d > begin && d < begin + code.len() as u64)
        .min();
    // (A 32-bit ARM function at an odd address is Thumb code, at the
    // even one.)
    let thumb = isa == crate::disasm::Arch::Arm && sym.value & 1 == 1;
    Ok(crate::disasm::Function {
        name: shown,
        isa,
        thumb,
        data: data_from,
        address: sym.value & !u64::from(thumb),
        code,
        symbols: names,
    })
}

/// Whether an ELF symbol is one of ARM's mapping symbols (`$a`, `$t`,
/// `$d`, perhaps with `.something` after).
pub(crate) fn is_mapping_symbol(name: &[u8]) -> bool {
    matches!(
        name,
        [b'$', b'a' | b't' | b'd' | b'x'] | [b'$', b'a' | b't' | b'd' | b'x', b'.', ..]
    )
}

/// Builds the maps of an ELF file, or an archive of them, for `sources`.
pub fn maps(data: &[u8], file_name: &str, sources: &[Source]) -> Result<Maps> {
    maps_with_debug(data, file_name, sources, None)
}

/// [`maps`], with a separate debug file (an ELF file with the DWARF a
/// stripped image lacks) for `compileunits`.
pub fn maps_with_debug(
    data: &[u8],
    file_name: &str,
    sources: &[Source],
    debug: Option<&[u8]>,
) -> Result<Maps> {
    // Without a debug file, the image's MiniDebugInfo, if it has one.
    let mini = if debug.is_none() {
        mini_debug_info(data)
    } else {
        None
    };
    let debug = debug.or(mini.as_deref());
    let debug = debug.map(ElfFile::parse).transpose()?;
    // A debug file for another build would misattribute everything.
    if let Some(d) = &debug
        && let Ok(main) = ElfFile::parse(data)
        && let (Some(a), Some(b)) = (main.build_id(), d.build_id())
        && a != b
    {
        return Err(Error::new(
            ErrorKind::Malformed,
            0,
            "debug file build ID (it is for another build)",
        ));
    }
    let mut units = Vec::new();
    let mut ar_ranges = Vec::new();
    let mut object = false;
    let mut index_base = 0u64;
    if Archive::is_archive(data) {
        object = true;
        let ar = Archive::parse(data)?;
        ar_ranges.push((0, 8, AR_HEADERS));
        for m in ar.members() {
            let end = m.data_offset + m.data.len() as u64;
            ar_ranges.push((m.header_offset, m.data_offset - m.header_offset, AR_HEADERS));
            ar_ranges.push((end, m.end().saturating_sub(end), AR_HEADERS));
            match m.kind {
                MemberKind::SymbolTable | MemberKind::EcSymbolTable => {
                    ar_ranges.push((m.data_offset, m.data.len() as u64, AR_SYMBOLS));
                }
                MemberKind::LongNames => {
                    ar_ranges.push((m.data_offset, m.data.len() as u64, AR_HEADERS));
                }
                MemberKind::File => match ElfFile::parse(m.data) {
                    Ok(elf) => {
                        let n = u64::from(elf.header().shnum);
                        units.push(Unit {
                            elf,
                            offset: m.data_offset,
                            name: String::from_utf8_lossy(&m.name).into_owned(),
                            index_base,
                        });
                        index_base += n;
                    }
                    Err(_) => ar_ranges.push((m.data_offset, m.data.len() as u64, AR_NON_ELF)),
                },
            }
        }
    } else {
        let elf = ElfFile::parse(data)?;
        if elf.header().kind == ET_REL {
            object = true;
        }
        units.push(Unit {
            elf,
            offset: 0,
            name: file_name.to_string(),
            index_base: 0,
        });
    }
    if units.is_empty() && ar_ranges.is_empty() {
        return Err(Error::new(ErrorKind::Malformed, 0, "ELF input"));
    }
    let mut b = Builder {
        data,
        units,
        ar_ranges,
        object,
        labels: Labels::default(),
    };

    // The base map: the segments source, then the catch-all.
    let mut base = DualMap::default();
    b.ar_into(&mut base, None);
    if object {
        b.sections_into(&mut base, SectionsBy::Flags);
    } else {
        b.segments_into(&mut base, false);
    }
    b.headers_into(&mut base, None);
    b.segments_into(&mut base, true);
    let unmapped = b.labels.intern(UNMAPPED);
    base.file.add(0, data.len() as u64, unmapped);
    base.vm.compress();
    base.file.compress();

    let mut out = Vec::new();
    for &source in sources {
        let mut map = DualMap::default();
        b.ar_into(&mut map, Some(&base));
        match source {
            Source::Segments => {
                if object {
                    b.sections_into(&mut map, SectionsBy::Flags);
                } else {
                    b.segments_into(&mut map, false);
                }
                b.catch_all(&mut map, &base, true);
            }
            Source::Sections => {
                b.sections_into(&mut map, SectionsBy::Name);
                b.catch_all(&mut map, &base, false);
            }
            Source::ArMembers => {
                b.sections_into(&mut map, SectionsBy::Member);
                for i in 0..b.units.len() {
                    let u = &b.units[i];
                    let (s, e) = (u.offset, u.offset + u.elf.data().len() as u64);
                    let l = b.labels.intern(&u.name.clone());
                    map.add_file(s, e, l, &base);
                }
                b.catch_all(&mut map, &base, false);
            }
            Source::Symbols | Source::RawSymbols | Source::FullSymbols => {
                b.symbols_into(&mut map, &base, source, debug.as_ref());
                b.references_into(&mut map, &base);
                b.tables_into(&mut map, &base);
                b.catch_all(&mut map, &base, false);
            }
            Source::Archs => {
                let name = b.units.first().map_or_else(
                    || String::from("unknown"),
                    |u| machine_name(u.elf.header().machine),
                );
                let l = b.labels.intern(&name);
                map.fill_from(&base, |_| l);
            }
            Source::InputFiles => {
                let l = b.labels.intern(file_name);
                map.fill_from(&base, |_| l);
            }
            Source::CompileUnits => {
                // From DWARF, for linked files (bloaty refuses objects,
                // whose debug information needs relocating).
                if !object {
                    if let Some(d) = &debug {
                        elf_compile_units(
                            d,
                            0,
                            data.len() as u64,
                            &mut b.labels,
                            &mut map,
                            &base,
                            false,
                        );
                    }
                    for u in &b.units {
                        elf_compile_units(
                            &u.elf,
                            u.offset,
                            data.len() as u64,
                            &mut b.labels,
                            &mut map,
                            &base,
                            true,
                        );
                    }
                    b.references_into(&mut map, &base);
                    b.tables_into(&mut map, &base);
                }
                b.catch_all(&mut map, &base, false);
            }
            Source::Inlines | Source::SourceFiles => {
                if !object {
                    let with_line = source == Source::Inlines;
                    match &debug {
                        Some(d) => elf_inlines(d, &mut b.labels, &mut map, &base, with_line),
                        None => {
                            for u in &b.units {
                                elf_inlines(&u.elf, &mut b.labels, &mut map, &base, with_line);
                            }
                        }
                    }
                    b.references_into(&mut map, &base);
                    b.tables_into(&mut map, &base);
                }
                b.catch_all(&mut map, &base, false);
            }
            // PE notions.
            Source::Groups | Source::Libraries => {
                b.catch_all(&mut map, &base, false);
            }
        }
        map.vm.compress();
        map.file.compress();
        out.push((source, map));
    }
    Ok(Maps {
        labels: b.labels,
        base,
        sources: out,
        file_size: data.len() as u64,
        absorb_padding: true,
    })
}

#[cfg(test)]
#[path = "elf_tests.rs"]
mod tests;
