//! The Mach-O backend.

use alloc::vec::Vec;

use hexcavator_macho::MachO;
use hexcavator_macho::consts::*;

use crate::{DebugId, Kind, Section, SectionFlags};

pub(crate) fn kind(m: &MachO<'_>) -> Kind {
    match m.header().filetype {
        MH_OBJECT => Kind::Object,
        MH_CORE => Kind::Dump,
        MH_DSYM => Kind::Debug,
        _ => Kind::Linked,
    }
}

/// Translates a section's flags (and its segment's name and protection)
/// to [`SectionFlags`].
pub(crate) fn flags(segname: &[u8], prot: u32, flags: u32, object: bool) -> SectionFlags {
    let kind = flags & SECTION_TYPE;
    let code = flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) != 0;
    let zero = matches!(kind, S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL);
    let mut f = 0;
    if code {
        f |= SectionFlags::CODE;
    }
    if zero {
        f |= SectionFlags::ZERO_FILL;
    } else if !code {
        f |= SectionFlags::DATA;
    }
    // An object's one segment is mapped every way: what its sections will
    // be is in their segment names.
    let prot = if object {
        let mut p = VM_PROT_READ;
        if code {
            p |= VM_PROT_EXECUTE;
        }
        if segname != b"__TEXT" {
            p |= VM_PROT_WRITE;
        }
        p
    } else {
        prot
    };
    for (bit, flag) in [
        (VM_PROT_READ, SectionFlags::READ),
        (VM_PROT_WRITE, SectionFlags::WRITE),
        (VM_PROT_EXECUTE, SectionFlags::EXECUTE),
    ] {
        if prot & bit != 0 {
            f |= flag;
        }
    }
    if flags & S_ATTR_DEBUG != 0 || segname == b"__DWARF" {
        f |= SectionFlags::NOT_LOADED;
    }
    // The linker's own sections (`__LD,__compact_unwind`): consumed by it.
    if segname == b"__LD" {
        f |= SectionFlags::LINKER_INFO | SectionFlags::NOT_LOADED;
    }
    if kind == S_COALESCED {
        f |= SectionFlags::COMDAT;
    }
    SectionFlags(f)
}

pub(crate) fn sections<'data>(m: &MachO<'data>) -> Vec<Section<'data>> {
    let object = m.is_object();
    m.segments()
        .into_iter()
        .flat_map(|seg| {
            seg.sections
                .into_iter()
                .map(move |s| (seg.name, seg.initprot, s))
        })
        .map(|(segname, prot, s)| {
            // A section's data can't be at offset 0 (the header is): a dSYM's
            // copies of the image's sections, say, have none.
            let file_size = if s.offset == 0 { 0 } else { s.file_size() };
            Section {
                index: s.index,
                name: s.sectname,
                addr: s.addr,
                vm_size: s.size,
                file_offset: u64::from(s.offset),
                file_size,
                flags: flags(segname, prot, s.flags, object),
                raw_flags: s.flags,
            }
        })
        .collect()
}

pub(crate) fn debug_ids<'data>(m: &MachO<'data>) -> Vec<DebugId<'data>> {
    m.uuid().map(DebugId::Uuid).into_iter().collect()
}

pub(crate) fn pointer_slots(m: &MachO<'_>) -> Vec<crate::PointerSlot> {
    if m.is_object() {
        return Vec::new();
    }
    m.fixups()
        .into_iter()
        .map(|f| crate::PointerSlot {
            addr: f.addr,
            width: f.width,
            target: match f.kind {
                hexcavator_macho::FixupKind::Rebase { target } => Some(target),
                hexcavator_macho::FixupKind::Bind { .. } => None,
            },
        })
        .collect()
}

pub(crate) fn bytes_at<'data>(m: &MachO<'data>, addr: u64, len: u64) -> Option<&'data [u8]> {
    let s = m.sections().into_iter().find(|s| {
        s.offset != 0
            && !s.is_zerofill()
            && addr >= s.addr
            && addr - s.addr < s.size
            && len <= s.size - (addr - s.addr)
    })?;
    let at = u64::from(s.offset).checked_add(addr - s.addr)?;
    let start = usize::try_from(at).ok()?;
    m.data()
        .get(start..start.checked_add(usize::try_from(len).ok()?)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RX: u32 = VM_PROT_READ | VM_PROT_EXECUTE;
    const RW: u32 = VM_PROT_READ | VM_PROT_WRITE;

    #[test]
    fn text_and_data() {
        let text = flags(b"__TEXT", RX, S_ATTR_PURE_INSTRUCTIONS, false);
        assert!(text.contains(SectionFlags::CODE | SectionFlags::EXECUTE | SectionFlags::READ));
        assert!(!text.contains(SectionFlags::WRITE | SectionFlags::DATA));
        let data = flags(b"__DATA", RW, S_REGULAR, false);
        assert!(data.contains(SectionFlags::DATA | SectionFlags::WRITE));
        let bss = flags(b"__DATA", RW, S_ZEROFILL, false);
        assert!(bss.contains(SectionFlags::ZERO_FILL));
        assert!(!bss.contains(SectionFlags::DATA));
    }

    #[test]
    fn objects_take_protection_from_segment_names() {
        let all = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
        let text = flags(b"__TEXT", all, S_ATTR_SOME_INSTRUCTIONS, true);
        assert!(text.contains(SectionFlags::EXECUTE));
        assert!(!text.contains(SectionFlags::WRITE));
        let cstr = flags(b"__TEXT", all, S_CSTRING_LITERALS, true);
        assert!(!cstr.contains(SectionFlags::EXECUTE));
        let data = flags(b"__DATA", all, S_REGULAR, true);
        assert!(data.contains(SectionFlags::WRITE));
        assert!(!data.contains(SectionFlags::EXECUTE));
    }

    #[test]
    fn debug_linker_and_coalesced() {
        assert!(flags(b"__DWARF", RW, S_ATTR_DEBUG, false).contains(SectionFlags::NOT_LOADED));
        let ld = flags(b"__LD", RW, S_REGULAR, true);
        assert!(ld.contains(SectionFlags::LINKER_INFO | SectionFlags::NOT_LOADED));
        assert!(flags(b"__TEXT", RX, S_COALESCED, true).contains(SectionFlags::COMDAT));
    }
}
