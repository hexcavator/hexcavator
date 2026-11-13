//! bloaty's data sources for Mach-O files: executables, dylibs, bundles,
//! objects, and universal files of them.
//!
//! This follows bloaty's `macho.cc`:
//!
//! - The base map is the `segments` source: the Mach header and every load
//!   command as `[Mach-O Headers]`; each segment by name (`__TEXT`; one
//!   with no access, `__PAGEZERO`, only in the file); the link-edit tables
//!   the load commands locate (`Symbol Table`, `String Table`, `Rebase
//!   Info`, `Chained Fixups`, `Code Signature`, ...); then the fallbacks.
//! - `sections` names each section `__TEXT,__text`, with the same headers
//!   and link-edit tables.
//! - `symbols` (and `fullsymbols`, `rawsymbols`) charges each symbol from
//!   its address to the next symbol's (or its section's end), and the
//!   symbol table entries and names to the symbol they describe.
//! - `symbols`, `compileunits`, and `inlines` then charge data no symbol
//!   covers (string literals in `__cstring`, constants, jump tables) to
//!   whoever has the code that refers to it, found by disassembling each
//!   code symbol's extent (x86-64 and ARM64; see [`crate::disasm`]), as
//!   bloaty does for ELF only.
//! - Every source falls back to `[__TEXT,__text]`, `[__TEXT]`, and
//!   `[Unmapped]`.
//! - `archs` names each image of a universal file by its architecture.
//! - Static libraries (`.a`, possibly universal) are read member by member:
//!   the archive's own structures are `[AR Headers]` and `[AR Symbol
//!   Table]`, `armembers` names each member, and each member's addresses
//!   are moved to their own range (member *i* at `i << 40`), as bloaty does
//!   for ELF objects, so that they don't collide.
//!
//! Where bloaty is wrong we are not: big-endian files are read (bloaty
//! refuses them); a universal file's whole header table is
//! `[Mach-O Headers]` (bloaty labels only its first 8 bytes); a symbol's
//! extent stops at its section's end; an object's sections are named by
//! their own segment names (bloaty gives `,__text`, from the objects'
//! single unnamed segment); `armembers` gives the file's name (bloaty
//! refuses the source); a symbol defined in a section at address 0 (the
//! first function of an object) is kept (bloaty drops every symbol at 0,
//! meaning to drop undefined ones); where symbols share an address, a real
//! name wins over an assembler-private label (`ltmp0`), which objects put
//! first; and static libraries are read as
//! Mach-O (bloaty reads them as ELF archives, every member `[AR Non-ELF
//! Member File]`).

use hexcavator_archive::{Archive, MemberKind};
use hexcavator_core::{Error, ErrorKind, Result};
use hexcavator_demangle::itanium::Demangler;
use hexcavator_macho::consts::*;
use hexcavator_macho::{MachO, fat_archs, fat_header_size, is_fat};

use crate::dwarf_units::DwarfInput;
use crate::elf::{AR_HEADERS, AR_SYMBOLS};
use crate::rangemap::{DualMap, Label, Labels};
use crate::sources::{Maps, Source, UNMAPPED};

pub const MACHO_HEADERS: &str = "[Mach-O Headers]";
pub const AR_NON_MACHO: &str = "[AR Non-Mach-O Member File]";

/// Whether `data` is a Mach-O file, a static library whose first member
/// file is one, or a universal file of them.
pub fn is_macho_input(data: &[u8]) -> bool {
    hexcavator_macho::is_macho(data) || is_fat(data) || is_macho_archive(data)
}

fn is_macho_archive(data: &[u8]) -> bool {
    Archive::is_archive(data)
        && Archive::parse(data)
            .ok()
            .and_then(|ar| ar.files().next())
            .is_some_and(|m| hexcavator_macho::is_macho(m.data))
}

/// One image: the whole file, a slice of a universal one, or a member of
/// a static library (in either).
struct Image<'d> {
    m: MachO<'d>,
    /// Where it starts in the input.
    offset: u64,
    /// Added to its addresses: nonzero for archive members, which would
    /// otherwise overlap.
    vm: u64,
    /// Its archive member name, if it is one.
    member: Option<String>,
}

impl Image<'_> {
    /// An address of the image, as a map address.
    fn addr(&self, a: u64) -> u64 {
        a.saturating_add(self.vm)
    }

    /// A file range of the image, clamped to it, as input offsets.
    fn range(&self, at: u64, size: u64) -> (u64, u64) {
        let len = self.m.data().len() as u64;
        let s = at.min(len);
        (self.offset + s, self.offset + s + size.min(len - s))
    }
}

/// How `commands_into` labels segments.
#[derive(Clone, Copy, PartialEq, Eq)]
enum By {
    Segments,
    Sections,
    /// Only the headers (the symbols source).
    HeadersOnly,
}

struct Builder<'d> {
    images: Vec<Image<'d>>,
    fat_header: Option<u64>,
    /// Each architecture's part of the input: (offset, size, name).
    slices: Vec<(u64, u64, String)>,
    /// Archive structures: (offset, size, label name).
    ar_ranges: Vec<(u64, u64, &'static str)>,
    /// Whether any input is an archive (whose objects' DWARF, unrelocated,
    /// isn't read).
    archive: bool,
    labels: Labels,
    len: u64,
}

fn add_file(map: &mut DualMap, (s, e): (u64, u64), l: Label, base: Option<&DualMap>) {
    if s >= e {
        return;
    }
    match base {
        Some(b) => {
            map.add_file(s, e, l, b);
        }
        None => map.file.add(s, e, l),
    }
}

impl Builder<'_> {
    /// bloaty's `ParseLoadCommands` (or, for symbols, just the header
    /// overhead `ForEachLoadCommand` adds).
    fn commands_into(&mut self, map: &mut DualMap, by: By, base: Option<&DualMap>) {
        let headers = self.labels.intern(MACHO_HEADERS);
        if let Some(n) = self.fat_header {
            add_file(map, (0, n.min(self.len)), headers, base);
        }
        for img in &self.images {
            let m = &img.m;
            add_file(map, img.range(0, m.header().size), headers, base);
            let segments = m.segments();
            for lc in m.load_commands() {
                if by != By::HeadersOnly {
                    match lc.cmd {
                        LC_SEGMENT | LC_SEGMENT_64 => {
                            if let Some(seg) = segments.iter().find(|s| s.command == lc.index) {
                                let unmapped = seg.maxprot == VM_PROT_NONE;
                                if by == By::Segments {
                                    let l = self.labels.intern(&String::from_utf8_lossy(seg.name));
                                    let (fs, fe) = img.range(seg.fileoff, seg.filesize);
                                    if unmapped {
                                        add_file(map, (fs, fe), l, base);
                                    } else {
                                        range(
                                            map,
                                            img.addr(seg.vmaddr),
                                            seg.vmsize,
                                            fs,
                                            fe - fs,
                                            l,
                                        );
                                    }
                                } else {
                                    for s in &seg.sections {
                                        let name = section_label(seg.name, s);
                                        let l = self.labels.intern(&name);
                                        let (fs, fe) =
                                            img.range(u64::from(s.offset), s.file_size());
                                        if unmapped {
                                            add_file(map, (fs, fe), l, base);
                                        } else {
                                            range(map, img.addr(s.addr), s.size, fs, fe - fs, l);
                                        }
                                    }
                                }
                            }
                        }
                        LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                            if let Some(info) = m.dyld_info(&lc) {
                                for ((off, size), name) in [
                                    (info.rebase, "Rebase Info"),
                                    (info.bind, "Binding Info"),
                                    (info.weak_bind, "Weak Binding Info"),
                                    (info.lazy_bind, "Lazy Binding Info"),
                                    (info.export, "Export Info"),
                                ] {
                                    let l = self.labels.intern(name);
                                    add_file(
                                        map,
                                        img.range(u64::from(off), u64::from(size)),
                                        l,
                                        base,
                                    );
                                }
                            }
                        }
                        LC_SYMTAB => {
                            if let Some(st) = m.symtab() {
                                let l = self.labels.intern("Symbol Table");
                                add_file(
                                    map,
                                    img.range(
                                        u64::from(st.symoff),
                                        u64::from(st.nsyms) * m.nlist_size(),
                                    ),
                                    l,
                                    base,
                                );
                                let l = self.labels.intern("String Table");
                                add_file(
                                    map,
                                    img.range(u64::from(st.stroff), u64::from(st.strsize)),
                                    l,
                                    base,
                                );
                            }
                        }
                        LC_DYSYMTAB => {
                            if let Some(d) = m.dysymtab() {
                                // bloaty sizes the module table with 64-bit
                                // entries, whatever the image.
                                let module = if m.header().is64 { 56 } else { 52 };
                                for (off, n, size, name) in [
                                    (d.tocoff, d.ntoc, 8, "Table of Contents"),
                                    (d.modtaboff, d.nmodtab, module, "Module Table"),
                                    (d.extrefsymoff, d.nextrefsyms, 4, "Referenced Symbol Table"),
                                    (
                                        d.indirectsymoff,
                                        d.nindirectsyms,
                                        4,
                                        "Indirect Symbol Table",
                                    ),
                                    (d.extreloff, d.nextrel, 8, "External Relocation Entries"),
                                    (d.locreloff, d.nlocrel, 8, "Local Relocation Entries"),
                                ] {
                                    let l = self.labels.intern(name);
                                    add_file(
                                        map,
                                        img.range(u64::from(off), u64::from(n) * size),
                                        l,
                                        base,
                                    );
                                }
                            }
                        }
                        cmd => {
                            let name = match cmd {
                                LC_CODE_SIGNATURE => "Code Signature",
                                LC_SEGMENT_SPLIT_INFO => "Segment Split Info",
                                LC_FUNCTION_STARTS => "Function Start Addresses",
                                LC_DATA_IN_CODE => "Table of Non-instructions",
                                LC_DYLIB_CODE_SIGN_DRS => "Code Signing DRs",
                                LC_LINKER_OPTIMIZATION_HINT => "Optimization Hints",
                                LC_DYLD_CHAINED_FIXUPS => "Chained Fixups",
                                LC_DYLD_EXPORTS_TRIE => "Exports Trie",
                                _ => "",
                            };
                            if !name.is_empty()
                                && let Some((off, size)) = m.linkedit_data(&lc)
                            {
                                let l = self.labels.intern(name);
                                add_file(map, img.range(u64::from(off), u64::from(size)), l, base);
                            }
                        }
                    }
                }
                add_file(map, img.range(lc.offset, u64::from(lc.size)), headers, base);
            }
        }
    }

    /// The archives' own structures.
    fn ar_into(&mut self, map: &mut DualMap, base: Option<&DualMap>) {
        for &(at, size, name) in &self.ar_ranges {
            let l = self.labels.intern(name);
            add_file(map, (at, at.saturating_add(size).min(self.len)), l, base);
        }
    }

    /// bloaty's `AddMachOFallback` (`base` is `None` for the base map
    /// itself).
    fn fallback_into(&mut self, map: &mut DualMap, base: Option<&DualMap>) {
        for img in &self.images {
            for seg in img.m.segments() {
                if seg.maxprot == VM_PROT_NONE {
                    continue;
                }
                let segname = String::from_utf8_lossy(seg.name);
                for s in &seg.sections {
                    let l = self
                        .labels
                        .intern(&format!("[{}]", section_label(seg.name, s)));
                    let (fs, fe) = img.range(u64::from(s.offset), s.file_size());
                    range(map, img.addr(s.addr), s.size, fs, fe - fs, l);
                }
                let l = self.labels.intern(&format!("[{segname}]"));
                let (fs, fe) = img.range(seg.fileoff, seg.filesize);
                range(map, img.addr(seg.vmaddr), seg.vmsize, fs, fe - fs, l);
            }
        }
        let l = self.labels.intern(UNMAPPED);
        add_file(map, (0, self.len), l, base);
    }

    /// bloaty's `ParseSymbols`, names as `source` asks.
    fn symbols_into(&mut self, map: &mut DualMap, base: &DualMap, source: Source) {
        let mut demangler = Demangler::new();
        let mut buf = String::new();
        for img in &self.images {
            let m = &img.m;
            let Some(st) = m.symtab() else { continue };
            for (s, end) in extents(m) {
                let raw = String::from_utf8_lossy(s.name);
                buf.clear();
                let ok = match source {
                    Source::Symbols => demangler.demangle_short_into(&raw, &mut buf),
                    Source::FullSymbols => demangler.demangle_into(&raw, &mut buf),
                    _ => false,
                };
                let name = if ok { buf.clone() } else { raw.into_owned() };
                let l = self.labels.intern(&name);
                map.add_vm(img.addr(s.n_value), img.addr(end), l, base);
                // The entry and its name go to whoever has the address.
                if let Some(e) = map.vm.get(img.addr(s.n_value)) {
                    let at = u64::from(st.symoff) + s.index as u64 * m.nlist_size();
                    add_file(map, img.range(at, m.nlist_size()), e.label, Some(base));
                    let name_at = u64::from(st.stroff) + u64::from(s.strx);
                    add_file(
                        map,
                        img.range(name_at, s.name.len() as u64 + 1),
                        e.label,
                        Some(base),
                    );
                }
            }
        }
    }
}

impl Builder<'_> {
    /// Data that nothing in `map` labels yet, referred to by code, to
    /// whoever has the code. Archive members' code is unrelocated, so it is
    /// not read.
    fn references_into(&mut self, map: &mut DualMap, base: &DualMap) {
        let mut refs = Vec::new();
        for img in &self.images {
            if img.member.is_some() {
                continue;
            }
            let m = &img.m;
            let arch = hexcavator_macho::arch(m.header().cputype);
            if !matches!(arch, crate::disasm::Arch::X64 | crate::disasm::Arch::Arm64) {
                continue;
            }
            let sections = m.sections();
            let code = |s: &hexcavator_macho::Section<'_>| {
                s.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) != 0
            };
            refs.clear();
            for (sym, end) in extents(m) {
                let Some(s) = sections
                    .iter()
                    .find(|x| sym.n_value >= x.addr && sym.n_value - x.addr < x.size)
                else {
                    continue;
                };
                if !code(s) {
                    continue;
                }
                let at = u64::from(s.offset) + (sym.n_value - s.addr);
                let (Ok(start), Ok(stop)) = (
                    usize::try_from(at),
                    usize::try_from(at + (end - sym.n_value)),
                ) else {
                    continue;
                };
                if let Some(bytes) = m.data().get(start..stop) {
                    crate::disasm::references(arch, bytes, sym.n_value, &mut refs);
                }
            }
            let loaded: Vec<(u64, u64)> = sections
                .iter()
                .map(|s| (s.addr, s.addr.saturating_add(s.size)))
                .collect();
            crate::disasm::charge(map, base, &refs, &loaded);
        }
    }

    /// `compileunits`: the DWARF of each image (its own `__DWARF`, or the
    /// matching image of `debug`, a dSYM or other debug file), then the
    /// symbol table entries, to the unit at their addresses.
    fn compile_units_into(&mut self, map: &mut DualMap, base: &DualMap, debug: Option<&[u8]>) {
        for i in 0..self.images.len() {
            let img = &self.images[i];
            let input = dwarf_input(img, debug);
            let sizes: std::collections::HashMap<u64, u64> = extents(&img.m)
                .into_iter()
                .map(|(s, end)| (s.n_value, end - s.n_value))
                .collect();
            crate::dwarf_units::compile_units(
                &input,
                &sizes,
                self.len,
                &mut self.labels,
                map,
                base,
            );
            // Symbol table entries and names, to whoever has the address.
            let m = img.m;
            if let Some(st) = m.symtab() {
                for s in m.symbols() {
                    if !is_defined(&s) {
                        continue;
                    }
                    if let Some(e) = map.vm.get(img.addr(s.n_value)) {
                        let at = u64::from(st.symoff) + s.index as u64 * m.nlist_size();
                        add_file(map, img.range(at, m.nlist_size()), e.label, Some(base));
                        let name_at = u64::from(st.stroff) + u64::from(s.strx);
                        add_file(
                            map,
                            img.range(name_at, s.name.len() as u64 + 1),
                            e.label,
                            Some(base),
                        );
                    }
                }
            }
        }
    }
}

impl<'d> Builder<'d> {
    /// Adds a Mach-O file, or a static library of them, at `offset` in the
    /// input.
    fn add_input(&mut self, data: &'d [u8], offset: u64) -> Result<()> {
        if !Archive::is_archive(data) {
            let m = MachO::parse(data)?;
            self.images.push(Image {
                m,
                offset,
                vm: 0,
                member: None,
            });
            return Ok(());
        }
        let ar = Archive::parse(data)?;
        self.archive = true;
        self.ar_ranges.push((offset, 8, AR_HEADERS));
        for m in ar.members() {
            let start = offset + m.header_offset;
            let data_at = offset + m.data_offset;
            let size = m.data.len() as u64;
            let end = data_at + size;
            self.ar_ranges.push((start, data_at - start, AR_HEADERS));
            self.ar_ranges
                .push((end, (offset + m.end()).saturating_sub(end), AR_HEADERS));
            match m.kind {
                MemberKind::SymbolTable | MemberKind::EcSymbolTable => {
                    self.ar_ranges.push((data_at, size, AR_SYMBOLS));
                }
                MemberKind::LongNames => self.ar_ranges.push((data_at, size, AR_HEADERS)),
                MemberKind::File => match MachO::parse(m.data) {
                    Ok(macho) => {
                        // Member i (counted across the input) at i << 40.
                        let vm = (self.images.len() as u64 + 1) << 40;
                        self.images.push(Image {
                            m: macho,
                            offset: data_at,
                            vm,
                            member: Some(String::from_utf8_lossy(&m.name).into_owned()),
                        });
                    }
                    Err(_) => self.ar_ranges.push((data_at, size, AR_NON_MACHO)),
                },
            }
        }
        Ok(())
    }
}

/// An image's DWARF: from the matching image of `debug` (a dSYM or other
/// debug file), or its own `__DWARF` sections, whose bytes are then the
/// input's.
fn dwarf_input<'d>(img: &Image<'d>, debug: Option<&'d [u8]>) -> DwarfInput<'d> {
    let (dwarf_image, in_input) = match debug.and_then(|d| debug_image(d, &img.m, img.m.uuid())) {
        Some(d) => (d, false),
        None => (img.m, true),
    };
    let mut input = DwarfInput {
        endian: dwarf_image.endian(),
        sections: Vec::new(),
    };
    for s in dwarf_image.sections() {
        let start = s.offset as usize;
        let Some((name, gnu)) =
            crate::decompress::debug_name(s.sectname, b"__debug_", b"__zdebug_")
        else {
            continue;
        };
        let Some(bytes) = dwarf_image
            .data()
            .get(start..start.saturating_add(usize::try_from(s.file_size()).unwrap_or(usize::MAX)))
        else {
            continue;
        };
        if gnu {
            // Compressed: not the file's bytes to charge.
            if let Some(d) = crate::decompress::gnu_zdebug(bytes) {
                input.sections.push((name, d.into(), None));
            }
        } else {
            let at = in_input.then(|| img.offset + u64::from(s.offset));
            input.sections.push((name, bytes.into(), at));
        }
    }
    input
}

/// The image of a debug file (thin or universal) that goes with `m`: by
/// UUID when both have one, else by architecture.
fn debug_image<'d>(debug: &'d [u8], m: &MachO<'_>, uuid: Option<[u8; 16]>) -> Option<MachO<'d>> {
    let candidates: Vec<MachO<'d>> = match fat_archs(debug) {
        Some(archs) => archs
            .iter()
            .filter_map(|a| {
                debug.get(
                    usize::try_from(a.offset).ok()?
                        ..usize::try_from(a.offset + a.size).ok()?.min(debug.len()),
                )
            })
            .filter_map(|d| MachO::parse(d).ok())
            .collect(),
        None => MachO::parse(debug).ok().into_iter().collect(),
    };
    let same_arch = |c: &MachO<'_>| c.header().cputype == m.header().cputype;
    match uuid {
        Some(u) => candidates
            .into_iter()
            .find(|c| c.uuid().is_none_or(|cu| cu == u) && same_arch(c)),
        None => candidates.into_iter().find(same_arch),
    }
}

/// Whether a symbol is one to charge: not STABS, and at a nonzero address
/// or defined in a section (an object's first function is at 0).
fn is_defined(s: &hexcavator_macho::Nlist<'_>) -> bool {
    !s.is_stab() && (s.n_value != 0 || s.is_section_defined())
}

/// Each defined symbol (see [`is_defined`]) and where it ends: at
/// the next symbol's address or its section's end, whichever is first.
/// Symbols outside every section are left out.
fn extents<'d>(m: &MachO<'d>) -> Vec<(hexcavator_macho::Nlist<'d>, u64)> {
    let sections = m.sections();
    let syms: Vec<_> = m.symbols().into_iter().filter(is_defined).collect();
    let mut starts: Vec<u64> = syms.iter().map(|s| s.n_value).collect();
    starts.sort_unstable();
    starts.dedup();
    let mut out = Vec::new();
    for s in syms {
        let Some(sec) = sections
            .iter()
            .find(|x| s.n_value >= x.addr && s.n_value - x.addr < x.size)
        else {
            continue;
        };
        let next = starts.partition_point(|&a| a <= s.n_value);
        let end = starts
            .get(next)
            .map_or(sec.addr + sec.size, |&n| n.min(sec.addr + sec.size));
        out.push((s, end));
    }
    // Where symbols share an address, the first claims it: let that be a
    // real name, not an assembler-private label (`ltmp0`, `l_.str`; C
    // names start with `_`). Symbols at different addresses never overlap,
    // so only ties are affected.
    out.sort_by_key(|(s, _)| matches!(s.name.first(), Some(b'l' | b'L')));
    out
}

/// `__TEXT,__text`: the section's segment and name. An object's sections
/// share one unnamed segment, so their own segment names are used.
fn section_label(segment: &[u8], s: &hexcavator_macho::Section<'_>) -> String {
    let seg = if segment.is_empty() {
        s.segname
    } else {
        segment
    };
    format!(
        "{},{}",
        String::from_utf8_lossy(seg),
        String::from_utf8_lossy(s.sectname)
    )
}

/// A dual range in a map: memory and file, as bloaty's `AddRange`.
fn range(map: &mut DualMap, vm: u64, vm_size: u64, file: u64, file_size: u64, l: Label) {
    map.add_range(vm, vm_size.min(u64::MAX - vm), file, file_size, l);
}

/// bloaty's `--disassemble`: the function `name` (as the symbol table has
/// it, without its leading `_`, or demangled), in a thin file or the first
/// image of a universal one, and the names of the image's addresses.
pub fn function<'d>(
    data: &'d [u8],
    name: &str,
) -> std::result::Result<crate::disasm::Function<'d>, String> {
    use crate::disasm::Arch;
    let image = match fat_archs(data) {
        Some(archs) => archs
            .iter()
            .find_map(|a| {
                let s = usize::try_from(a.offset).ok()?;
                let n = usize::try_from(a.size).ok()?;
                MachO::parse(data.get(s..s.checked_add(n)?)?).ok()
            })
            .ok_or("no image in the universal file")?,
        None if Archive::is_archive(data) => {
            return Err("give one of the archive's objects to disassemble".into());
        }
        None => MachO::parse(data).map_err(|e| e.to_string())?,
    };
    let isa: Arch = hexcavator_macho::arch(image.header().cputype);
    if !hexcavator_code::decodes(isa) {
        return Err(format!(
            "no disassembler for CPU type {:#x}",
            image.header().cputype
        ));
    }
    let sections = image.sections();
    let mut demangler = Demangler::new();
    let mut names = Vec::new();
    let mut found = None;
    let mut alone = crate::disasm::ByNameAlone::new(name);
    let mut short = String::new();
    for (s, end) in extents(&image) {
        let raw = String::from_utf8_lossy(s.name);
        short.clear();
        let shown = if demangler.demangle_short_into(&raw, &mut short) {
            short.clone()
        } else {
            raw.clone().into_owned()
        };
        let code = sections.iter().any(|x| {
            s.n_value >= x.addr
                && s.n_value - x.addr < x.size
                && x.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) != 0
        });
        if found.is_none() && code {
            if raw.strip_prefix('_') == Some(name)
                || crate::elf::names_symbol(&mut demangler, &raw, name)
            {
                found = Some((s, end, shown.clone()));
            } else {
                alone.offer(s.n_value, &shown, || (s, end, shown.clone()));
            }
        }
        names.push((s.n_value, shown));
    }
    names.sort_by_key(|n| n.0);
    names.dedup_by_key(|n| n.0);
    let (s, end, shown) = found
        .or_else(|| alone.take())
        .ok_or_else(|| format!("no function named '{name}'"))?;
    let sec = sections
        .iter()
        .find(|x| s.n_value >= x.addr && s.n_value - x.addr < x.size)
        .ok_or("no section")?;
    let at = u64::from(sec.offset) + (s.n_value - sec.addr);
    let code = usize::try_from(at)
        .ok()
        .zip(usize::try_from(at + (end - s.n_value)).ok())
        .and_then(|(a, b)| image.data().get(a..b))
        .ok_or_else(|| format!("{shown}: outside the file"))?;
    // (N_ARM_THUMB_DEF: a Thumb function.)
    let thumb = isa == crate::disasm::Arch::Arm && s.n_desc & 0x0008 != 0;
    Ok(crate::disasm::Function {
        name: shown,
        isa,
        thumb,
        data: None,
        address: s.n_value,
        code,
        symbols: names,
    })
}

/// Builds the maps of a Mach-O or universal file for `sources`.
pub fn maps(data: &[u8], file_name: &str, sources: &[Source]) -> Result<Maps> {
    maps_with_debug(data, file_name, sources, None)
}

/// [`maps`], with the DWARF of a separate debug file (a dSYM's) for
/// `compileunits`.
pub fn maps_with_debug(
    data: &[u8],
    file_name: &str,
    sources: &[Source],
    debug: Option<&[u8]>,
) -> Result<Maps> {
    let mut b = Builder {
        images: Vec::new(),
        fat_header: None,
        slices: Vec::new(),
        ar_ranges: Vec::new(),
        archive: false,
        labels: Labels::default(),
        len: data.len() as u64,
    };
    if let Some(archs) = fat_archs(data) {
        b.fat_header = Some(fat_header_size(data));
        for a in archs {
            let (Ok(s), Ok(n)) = (usize::try_from(a.offset), usize::try_from(a.size)) else {
                continue;
            };
            let Some(slice) = data.get(s..s.saturating_add(n).min(data.len())) else {
                continue;
            };
            let arch = hexcavator_macho::arch_name(a.cputype, a.cpusubtype);
            if b.add_input(slice, a.offset).is_ok() {
                b.slices.push((a.offset, slice.len() as u64, arch));
            }
        }
        if b.images.is_empty() && b.ar_ranges.is_empty() {
            return Err(Error::new(ErrorKind::Malformed, 0, "universal file"));
        }
    } else {
        b.add_input(data, 0)?;
        let arch = b.images.first().map_or_else(
            || String::from("unknown"),
            |i| hexcavator_macho::arch_name(i.m.header().cputype, i.m.header().cpusubtype),
        );
        b.slices.push((0, data.len() as u64, arch));
    }

    let mut base = DualMap::default();
    b.ar_into(&mut base, None);
    b.commands_into(&mut base, By::Segments, None);
    b.fallback_into(&mut base, None);
    base.vm.compress();
    base.file.compress();

    let mut out = Vec::new();
    for &source in sources {
        let mut map = DualMap::default();
        // An architecture or the input file owns its archive structures too.
        if !matches!(source, Source::Archs | Source::InputFiles) {
            b.ar_into(&mut map, Some(&base));
        }
        match source {
            Source::Segments => b.commands_into(&mut map, By::Segments, Some(&base)),
            Source::Sections => b.commands_into(&mut map, By::Sections, Some(&base)),
            Source::Symbols | Source::RawSymbols | Source::FullSymbols => {
                b.commands_into(&mut map, By::HeadersOnly, Some(&base));
                b.symbols_into(&mut map, &base, source);
                b.references_into(&mut map, &base);
            }
            Source::ArMembers => {
                // Each member's bytes, and the memory of its sections.
                for i in 0..b.images.len() {
                    let Some(name) = b.images[i].member.clone() else {
                        continue;
                    };
                    let l = b.labels.intern(&name);
                    let img = &b.images[i];
                    for s in img.m.sections() {
                        let (fs, fe) = img.range(u64::from(s.offset), s.file_size());
                        range(&mut map, img.addr(s.addr), s.size, fs, fe - fs, l);
                    }
                    let r = img.range(0, img.m.data().len() as u64);
                    add_file(&mut map, r, l, Some(&base));
                }
                let l = b.labels.intern(file_name);
                map.fill_from(&base, |_| l);
            }
            Source::InputFiles => {
                let l = b.labels.intern(file_name);
                map.fill_from(&base, |_| l);
            }
            Source::Archs => {
                for i in 0..b.slices.len() {
                    let (at, size) = (b.slices[i].0, b.slices[i].1);
                    let name = b.slices[i].2.clone();
                    let l = b.labels.intern(&name);
                    add_file(&mut map, (at, at + size), l, Some(&base));
                }
            }
            Source::CompileUnits => {
                b.commands_into(&mut map, By::HeadersOnly, Some(&base));
                if !b.archive {
                    b.compile_units_into(&mut map, &base, debug);
                    b.references_into(&mut map, &base);
                }
            }
            Source::Inlines | Source::SourceFiles => {
                b.commands_into(&mut map, By::HeadersOnly, Some(&base));
                if !b.archive {
                    for img in &b.images {
                        let input = dwarf_input(img, debug);
                        if source == Source::Inlines {
                            crate::dwarf_units::inlines(&input, &mut b.labels, &mut map, &base);
                        } else {
                            crate::dwarf_units::source_files(
                                &input,
                                &mut b.labels,
                                &mut map,
                                &base,
                            );
                        }
                    }
                    b.references_into(&mut map, &base);
                }
            }
            // PE notions.
            Source::Groups | Source::Libraries => {
                b.commands_into(&mut map, By::HeadersOnly, Some(&base));
            }
        }
        b.fallback_into(&mut map, Some(&base));
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
#[path = "macho_tests.rs"]
mod tests;
