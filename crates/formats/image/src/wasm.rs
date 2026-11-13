//! The WebAssembly backend.
//!
//! A module's code has no addresses of its own. Its tools (DWARF, source
//! maps, symbolizers) address code by offset into the code section's
//! contents, so here the code section alone has an extent in memory: at
//! address 0, of its contents' size. Linear memory, where data segments
//! go, is another address space, which sections don't map.

use alloc::vec::Vec;

use hexcavator_wasm::{Module, SECTION_CODE, SECTION_CUSTOM, SECTION_DATA};

use crate::{DebugId, Kind, Section, SectionFlags};

pub(crate) fn kind(m: &Module<'_>) -> Kind {
    if m.is_object() {
        Kind::Object
    } else {
        Kind::Linked
    }
}

pub(crate) fn flags(id: u8) -> SectionFlags {
    SectionFlags(match id {
        SECTION_CODE => SectionFlags::READ | SectionFlags::EXECUTE | SectionFlags::CODE,
        SECTION_DATA => SectionFlags::READ | SectionFlags::WRITE | SectionFlags::DATA,
        // Custom sections (names, DWARF, producers, linking) are read by
        // tools, not by the engine.
        SECTION_CUSTOM => SectionFlags::NOT_LOADED,
        // Types, imports, functions, tables, memories, globals, exports,
        // the start function, elements, tags: what the engine reads.
        _ => SectionFlags::READ,
    })
}

pub(crate) fn sections<'data>(m: &Module<'data>) -> Vec<Section<'data>> {
    m.sections()
        .iter()
        .enumerate()
        .map(|(index, s)| {
            // (A custom section's data follows its name.)
            let name = s.data_offset - s.contents_offset;
            Section {
                index,
                name: s.name,
                addr: 0,
                vm_size: if s.id == SECTION_CODE {
                    s.contents_size
                } else {
                    0
                },
                file_offset: s.data_offset,
                file_size: s.contents_size - name,
                flags: flags(s.id),
                raw_flags: u32::from(s.id),
            }
        })
        .collect()
}

pub(crate) fn debug_ids<'data>(m: &Module<'data>) -> Vec<DebugId<'data>> {
    let mut out = Vec::new();
    if let Some(id) = m.build_id() {
        out.push(DebugId::BuildId(id));
    }
    if let Some(path) = m.external_debug_info() {
        out.push(DebugId::DebugLink { path, crc: None });
    }
    out
}

/// Bytes of the code section, by offset into its contents.
pub(crate) fn bytes_at<'data>(m: &Module<'data>, addr: u64, len: u64) -> Option<&'data [u8]> {
    if m.is_object() {
        return None;
    }
    let s = m.sections().iter().find(|s| s.id == SECTION_CODE)?;
    if addr >= s.contents_size || len > s.contents_size - addr {
        return None;
    }
    let start = usize::try_from(s.contents_offset.checked_add(addr)?).ok()?;
    m.data()
        .get(start..start.checked_add(usize::try_from(len).ok()?)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_flags() {
        assert!(flags(SECTION_CODE).contains(SectionFlags::CODE | SectionFlags::EXECUTE));
        assert!(flags(SECTION_DATA).contains(SectionFlags::DATA | SectionFlags::WRITE));
        assert!(flags(SECTION_CUSTOM).contains(SectionFlags::NOT_LOADED));
        assert_eq!(
            flags(hexcavator_wasm::SECTION_TYPE),
            SectionFlags(SectionFlags::READ)
        );
    }
}
