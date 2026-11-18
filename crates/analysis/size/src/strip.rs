//! What stripping a file removes: the file ranges [`crate::sources::Maps::strip`]
//! takes out of its maps, for a report on the file as it would be shipped.
//! The debug information and symbols are still read to label what is left;
//! only their own bytes stop counting.
//!
//! - ELF: what `strip` (`--strip-all`) removes from an executable or
//!   shared object: the debug sections (`.debug_*`, `.zdebug_*`,
//!   `.gnu.debuglto_*`, `.stab*`, and MiniDebugInfo's `.gnu_debugdata`),
//!   the symbol table (`.symtab`) and its string table, the relocations of
//!   those, and their section headers. From an object (or an archive's), as
//!   `strip --strip-debug` does: the debug sections and their relocations,
//!   keeping the symbol table, which linking needs.
//! - Mach-O: the debug sections (`__DWARF`, or `S_ATTR_DEBUG`) and their
//!   relocations; the symbol table's debugger (STABS) entries, the debug
//!   map; and the symbols `strip` drops with them: from an executable, all
//!   but the undefined and the dynamically referenced (`strip`'s default,
//!   `-u -r`); from a dynamic library or bundle, the local ones (`strip
//!   -x`); from an object, none. The names only they use go too.
//! - WebAssembly: the custom sections `wasm-opt --strip-debug` removes:
//!   `.debug_*`, `name`, `sourceMappingURL`, and `external_debug_info`.
//! - PE and COFF: nothing (their debug information is in the PDB).
//!
//! Alignment padding before what is removed, and the names of removed ELF
//! sections in `.shstrtab`, are kept: a few bytes each.

use hexcavator_archive::{Archive, MemberKind};
use hexcavator_elf::ElfFile;
use hexcavator_elf::consts::*;
use hexcavator_macho::MachO;
use hexcavator_macho::consts::{MH_EXECUTE, MH_OBJECT, N_EXT, N_TYPE, N_UNDF, S_ATTR_DEBUG};

/// `n_desc`'s `REFERENCED_DYNAMICALLY`: a symbol `strip` keeps in an
/// executable (`__mh_execute_header`).
const REFERENCED_DYNAMICALLY: u16 = 0x10;

/// The file ranges, `[start, end)`, sorted and disjoint, that stripping the
/// file (`data`) removes; empty if it is of a format with nothing to strip.
pub fn ranges(data: &[u8]) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    if crate::wasm::is_wasm_input(data) {
        wasm(data, &mut out);
    } else if crate::macho::is_macho_input(data) {
        match hexcavator_macho::fat_archs(data) {
            Some(archs) => {
                for a in archs {
                    let (Ok(s), Ok(n)) = (usize::try_from(a.offset), usize::try_from(a.size))
                    else {
                        continue;
                    };
                    if let Some(slice) = data.get(s..s.saturating_add(n).min(data.len())) {
                        macho_input(slice, a.offset, &mut out);
                    }
                }
            }
            None => macho_input(data, 0, &mut out),
        }
    } else if crate::elf::is_elf_input(data) {
        if Archive::is_archive(data) {
            if let Ok(ar) = Archive::parse(data) {
                for m in ar.files() {
                    if let Ok(e) = ElfFile::parse(m.data) {
                        elf(&e, m.data_offset, &mut out);
                    }
                }
            }
        } else if let Ok(e) = ElfFile::parse(data) {
            elf(&e, 0, &mut out);
        }
    }
    merged(out)
}

/// `ranges`, sorted, with those that touch or overlap made one.
fn merged(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.retain(|&(s, e)| s < e);
    ranges.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (s, e) in ranges {
        match out.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => out.push((s, e)),
        }
    }
    out
}

/// `[at, at + size)` of an input part `len` bytes long that starts at
/// `offset` in the file: clamped to the part, as file offsets.
fn clamped(offset: u64, len: u64, at: u64, size: u64) -> (u64, u64) {
    let s = at.min(len);
    (offset + s, offset + s + size.min(len - s))
}

/// A debug section's name, as `strip --strip-debug` knows them.
fn elf_debug_name(name: &[u8]) -> bool {
    [&b".debug"[..], b".zdebug", b".gnu.debuglto_", b".stab"]
        .iter()
        .any(|p| name.starts_with(p))
        || name == b".gnu_debugdata"
}

/// What stripping removes of the ELF file `e`, at `offset` in the input.
fn elf(e: &ElfFile<'_>, offset: u64, out: &mut Vec<(u64, u64)>) {
    let sections: Vec<_> = e.sections().collect();
    let object = e.header().kind == ET_REL;
    let shstrndx = e.header().shstrndx as usize;
    let kept_anyway =
        |s: &hexcavator_elf::Section<'_>| s.flags & SHF_ALLOC != 0 || !s.has_file_data();
    let mut gone = vec![false; sections.len()];
    for s in &sections {
        if !kept_anyway(s) && (elf_debug_name(s.name) || (!object && s.kind == SHT_SYMTAB)) {
            gone[s.index] = true;
        }
    }
    // The removed symbol tables' string tables, if nothing kept uses them;
    // then relocations of what is removed, or against its symbols.
    let tables: Vec<usize> = sections
        .iter()
        .filter(|s| gone[s.index] && s.kind == SHT_SYMTAB)
        .map(|s| s.link as usize)
        .collect();
    for t in tables {
        let used = sections
            .iter()
            .any(|s| !gone[s.index] && s.index != t && s.link as usize == t);
        if t != shstrndx
            && !used
            && let Some(s) = sections.get(t)
            && s.kind == SHT_STRTAB
            && !kept_anyway(s)
        {
            gone[t] = true;
        }
    }
    for s in &sections {
        let on_gone = |i: u32| gone.get(i as usize).copied().unwrap_or(false);
        if matches!(s.kind, SHT_REL | SHT_RELA)
            && !kept_anyway(s)
            && (on_gone(s.info) || on_gone(s.link))
        {
            gone[s.index] = true;
        }
    }
    let len = e.data().len() as u64;
    let (shoff, shentsize) = (e.header().shoff, u64::from(e.header().shentsize));
    for s in sections.iter().filter(|s| gone[s.index]) {
        out.push(clamped(offset, len, s.offset, s.size));
        if shoff != 0 {
            out.push(clamped(
                offset,
                len,
                shoff + s.index as u64 * shentsize,
                shentsize,
            ));
        }
    }
    // A kept symbol table's (an object's) section symbols of what is
    // removed.
    for t in sections
        .iter()
        .filter(|s| s.kind == SHT_SYMTAB && !gone[s.index])
    {
        let stride = match (t.entsize, e.class()) {
            (0, hexcavator_elf::Class::Elf32) => 16,
            (0, hexcavator_elf::Class::Elf64) => 24,
            (n, _) => n,
        };
        for sym in e.symbols(t) {
            if sym.kind == STT_SECTION && gone.get(sym.shndx as usize).copied().unwrap_or(false) {
                out.push(clamped(
                    offset,
                    len,
                    t.offset + sym.index as u64 * stride,
                    stride,
                ));
            }
        }
    }
    // The names only removed sections have, in the section-name table.
    if let Some(names) = sections
        .get(shstrndx)
        .filter(|n| !gone[n.index] && n.has_file_data())
    {
        let name = |s: &hexcavator_elf::Section<'_>| {
            let at = u64::from(s.name_offset);
            (at, at + s.name.len() as u64 + 1)
        };
        let kept = merged(
            sections
                .iter()
                .filter(|s| !gone[s.index])
                .map(name)
                .collect(),
        );
        let removed = merged(
            sections
                .iter()
                .filter(|s| gone[s.index] && s.name_offset != 0)
                .map(name)
                .collect(),
        );
        for (s, e) in without(&removed, &kept) {
            let e = e.min(names.size);
            if s < e {
                out.push(clamped(offset, len, names.offset + s, e - s));
            }
        }
    }
}

/// What stripping removes of a Mach-O input (an image, or a static
/// library of objects) at `offset` in the file.
fn macho_input(data: &[u8], offset: u64, out: &mut Vec<(u64, u64)>) {
    if !Archive::is_archive(data) {
        if let Ok(m) = MachO::parse(data) {
            macho(&m, offset, out);
        }
        return;
    }
    let Ok(ar) = Archive::parse(data) else { return };
    for member in ar.members().filter(|m| m.kind == MemberKind::File) {
        if let Ok(m) = MachO::parse(member.data) {
            macho(&m, offset + member.data_offset, out);
        }
    }
}

/// What stripping removes of the Mach-O image `m`, at `offset` in the file.
fn macho(m: &MachO<'_>, offset: u64, out: &mut Vec<(u64, u64)>) {
    let len = m.data().len() as u64;
    let commands = m.load_commands();
    // (A segment command's size, and its sections' headers' after it.)
    let (command, header) = if m.header().is64 { (72, 80) } else { (56, 68) };
    for seg in m.segments() {
        for (j, s) in seg.sections.iter().enumerate() {
            if s.segname == b"__DWARF" || s.flags & S_ATTR_DEBUG != 0 {
                if s.offset != 0 {
                    out.push(clamped(offset, len, u64::from(s.offset), s.size));
                }
                out.push(clamped(
                    offset,
                    len,
                    u64::from(s.reloff),
                    u64::from(s.nreloc) * 8,
                ));
                if let Some(lc) = commands.get(seg.command) {
                    out.push(clamped(
                        offset,
                        len,
                        lc.offset + command + j as u64 * header,
                        header,
                    ));
                }
            }
        }
    }
    let Some(st) = m.symtab() else { return };
    let filetype = m.header().filetype;
    let keep = |n: &hexcavator_macho::Nlist<'_>| {
        if n.is_stab() {
            return false;
        }
        match filetype {
            MH_OBJECT => true,
            MH_EXECUTE => {
                (n.n_type & N_TYPE == N_UNDF && n.n_type & N_EXT != 0)
                    || n.n_desc & REFERENCED_DYNAMICALLY != 0
            }
            _ => n.n_type & N_EXT != 0,
        }
    };
    let size = m.nlist_size();
    let mut kept_names = Vec::new();
    let mut gone_names = Vec::new();
    for n in m.symbols() {
        // (A name's bytes, and its terminator; 0 is everyone's empty name.)
        let name = (
            u64::from(n.strx),
            u64::from(n.strx) + n.name.len() as u64 + 1,
        );
        if keep(&n) {
            kept_names.push(name);
        } else {
            out.push(clamped(
                offset,
                len,
                u64::from(st.symoff) + n.index as u64 * size,
                size,
            ));
            if n.strx != 0 {
                gone_names.push(name);
            }
        }
    }
    let kept = merged(kept_names);
    for (s, e) in without(&merged(gone_names), &kept) {
        let e = e.min(u64::from(st.strsize));
        if s < e {
            out.push(clamped(offset, len, u64::from(st.stroff) + s, e - s));
        }
    }
}

/// The parts of `ranges` outside `holes` (both sorted and disjoint).
fn without(ranges: &[(u64, u64)], holes: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut h = 0;
    for &(mut s, e) in ranges {
        while h < holes.len() && holes[h].1 <= s {
            h += 1;
        }
        let mut k = h;
        while s < e {
            match holes.get(k) {
                Some(&(hs, he)) if hs < e => {
                    if hs > s {
                        out.push((s, hs));
                    }
                    s = s.max(he);
                    k += 1;
                }
                _ => {
                    out.push((s, e));
                    break;
                }
            }
        }
    }
    out
}

/// What stripping removes of a WebAssembly module.
fn wasm(data: &[u8], out: &mut Vec<(u64, u64)>) {
    let Ok(m) = hexcavator_wasm::Module::parse(data) else {
        return;
    };
    for s in m.sections() {
        let debug = s.name.starts_with(b".debug_")
            || matches!(
                s.name,
                b"name" | b"sourceMappingURL" | b"external_debug_info"
            );
        if s.id == hexcavator_wasm::SECTION_CUSTOM && debug {
            out.push((s.offset, s.offset + s.size));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merging_and_subtracting() {
        assert_eq!(
            merged(vec![(5, 9), (0, 2), (2, 4), (8, 12), (20, 20)]),
            vec![(0, 4), (5, 12)]
        );
        assert_eq!(
            without(&[(0, 10), (20, 30)], &[(2, 4), (8, 22), (25, 26)]),
            vec![(0, 2), (4, 8), (22, 25), (26, 30)]
        );
        assert_eq!(without(&[(0, 10)], &[]), vec![(0, 10)]);
        assert_eq!(without(&[(5, 6)], &[(0, 10)]), Vec::<(u64, u64)>::new());
    }

    #[test]
    fn removing_ranges() {
        use crate::rangemap::RangeMap;
        let mut m = RangeMap::new();
        m.add_dual(0, 10, Some(100), 1);
        m.add(10, 20, 2);
        let gone = m.remove(5, 12);
        let cut: Vec<_> = gone
            .iter()
            .map(|e| (e.start, e.end, e.label, e.other))
            .collect();
        assert_eq!(cut, vec![(5, 10, 1, Some(105)), (10, 12, 2, None)]);
        let left: Vec<_> = m
            .iter()
            .map(|e| (e.start, e.end, e.label, e.other))
            .collect();
        assert_eq!(left, vec![(0, 5, 1, Some(100)), (12, 20, 2, None)]);
        assert!(m.remove(30, 40).is_empty());
    }

    /// Stripping forgets the bytes in every map, and the memory loaded
    /// from them, but not memory another part of the file has there.
    #[test]
    fn stripping_maps() {
        use crate::rangemap::DualMap;
        use crate::sources::{Maps, Source};
        let mut base = DualMap::default();
        // File [0, 8) loaded at 0x1000; [8, 16) not loaded; [16, 24), another
        // slice's, at 0x2000; and [24, 32), a third's, at 0x1000 too (the
        // first has the memory).
        base.add_range(0x1000, 8, 0, 8, 1);
        base.file.add(8, 16, 2);
        base.add_range(0x2000, 8, 16, 8, 3);
        base.add_range(0x1000, 8, 24, 8, 4);
        let mut maps = Maps {
            base: base.clone(),
            sources: vec![(Source::Sections, base)],
            file_size: 32,
            ..Maps::default()
        };
        maps.strip(&[(4, 10), (20, 22), (28, 99)]);
        assert_eq!(maps.file_size, 32 - 6 - 2 - 4);
        for m in [&maps.base, &maps.sources[0].1] {
            assert_eq!(m.file.total(), 20);
            assert_eq!(m.vm.total(), 4 + 6);
            assert!(m.vm.get(0x1004).is_none() && m.vm.get(0x1003).is_some());
            assert!(m.vm.get(0x2004).is_none() && m.vm.get(0x2006).is_some());
        }
        // (The third's stripping left the first's memory.)
        let mut maps = Maps {
            base: maps.base.clone(),
            file_size: 32,
            ..Maps::default()
        };
        let before = maps.base.vm.total();
        maps.strip(&[(24, 32)]);
        assert_eq!(maps.base.vm.total(), before);
    }
}
