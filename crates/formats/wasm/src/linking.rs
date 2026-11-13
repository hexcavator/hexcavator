//! A relocatable object's linking metadata (the tool conventions'
//! `Linking.md`): the `linking` section's symbol table and segment
//! information, and the `reloc.*` sections' relocations; and the import
//! section's entries, which name undefined symbols.

use alloc::vec::Vec;

use crate::{Module, Reader, SECTION_CUSTOM, SECTION_IMPORT, Section, limits};

/// The symbol table's subsection.
const WASM_SYMBOL_TABLE: u8 = 8;
/// The segment information subsection.
const WASM_SEGMENT_INFO: u8 = 5;

/// A symbol: a function's (0), data's (1), a global's (2), a section's
/// (3), a tag's (4), or a table's (5).
pub const SYMBOL_FUNCTION: u8 = 0;
/// A data symbol.
pub const SYMBOL_DATA: u8 = 1;
/// A global's symbol.
pub const SYMBOL_GLOBAL: u8 = 2;
/// A section's symbol.
pub const SYMBOL_SECTION: u8 = 3;
/// A tag's symbol.
pub const SYMBOL_TAG: u8 = 4;
/// A table's symbol.
pub const SYMBOL_TABLE: u8 = 5;

/// An undefined symbol (an import).
pub const SYMBOL_UNDEFINED: u32 = 0x10;
/// A symbol whose name is given though it is an import's.
pub const SYMBOL_EXPLICIT_NAME: u32 = 0x40;

/// A symbol of the `linking` section's table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkingSymbol<'d> {
    /// Its kind (`SYMBOL_*`).
    pub kind: u8,
    /// Its flags (`WASM_SYM_*`: binding, visibility, undefined, ...).
    pub flags: u32,
    /// Its name, if the table gives one (an undefined symbol's is its
    /// import's otherwise).
    pub name: Option<&'d [u8]>,
    /// What it is in its index space (a function's, global's, table's, or
    /// tag's index; a section's), for all but data.
    pub index: u32,
    /// A defined data symbol's segment, offset in it, and size.
    pub data: Option<(u32, u64, u64)>,
}

/// A data segment's linking information: its name, alignment (log 2),
/// and flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentInfo<'d> {
    /// Its name (`.rodata.x`).
    pub name: &'d [u8],
    /// Its alignment, as a power of 2.
    pub alignment: u32,
    /// Its flags.
    pub flags: u32,
}

/// An import: its module and field names, and its kind (`EXTERNAL_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Import<'d> {
    /// The module it is from.
    pub module: &'d [u8],
    /// Its name there.
    pub field: &'d [u8],
    /// Its kind: 0 a function, 1 a table, 2 a memory, 3 a global, 4 a tag.
    pub kind: u8,
}

/// A relocation of a `reloc.*` section.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Relocation {
    /// Its type (`R_WASM_*`).
    pub kind: u8,
    /// Where it applies, in its section's contents.
    pub offset: u64,
    /// The symbol it refers to (or a type's index, for a type index's).
    pub index: u32,
    /// Its addend, for the types that have one.
    pub addend: Option<i64>,
}

/// A relocation type's name (`R_WASM_*`), if known.
pub fn relocation_name(kind: u8) -> Option<&'static str> {
    const NAMES: [&str; 27] = [
        "R_WASM_FUNCTION_INDEX_LEB",
        "R_WASM_TABLE_INDEX_SLEB",
        "R_WASM_TABLE_INDEX_I32",
        "R_WASM_MEMORY_ADDR_LEB",
        "R_WASM_MEMORY_ADDR_SLEB",
        "R_WASM_MEMORY_ADDR_I32",
        "R_WASM_TYPE_INDEX_LEB",
        "R_WASM_GLOBAL_INDEX_LEB",
        "R_WASM_FUNCTION_OFFSET_I32",
        "R_WASM_SECTION_OFFSET_I32",
        "R_WASM_TAG_INDEX_LEB",
        "R_WASM_MEMORY_ADDR_REL_SLEB",
        "R_WASM_TABLE_INDEX_REL_SLEB",
        "R_WASM_GLOBAL_INDEX_I32",
        "R_WASM_MEMORY_ADDR_LEB64",
        "R_WASM_MEMORY_ADDR_SLEB64",
        "R_WASM_MEMORY_ADDR_I64",
        "R_WASM_MEMORY_ADDR_REL_SLEB64",
        "R_WASM_TABLE_INDEX_SLEB64",
        "R_WASM_TABLE_INDEX_I64",
        "R_WASM_TABLE_NUMBER_LEB",
        "R_WASM_MEMORY_ADDR_TLS_SLEB",
        "R_WASM_FUNCTION_OFFSET_I64",
        "R_WASM_MEMORY_ADDR_LOCREL_I32",
        "R_WASM_TABLE_INDEX_REL_SLEB64",
        "R_WASM_MEMORY_ADDR_TLS_SLEB64",
        "R_WASM_FUNCTION_INDEX_I32",
    ];
    NAMES.get(usize::from(kind)).copied()
}

/// Whether a relocation type has an addend (memory addresses', and
/// function and section offsets').
pub fn relocation_has_addend(kind: u8) -> bool {
    matches!(
        kind,
        3 | 4 | 5 | 8 | 9 | 11 | 14 | 15 | 16 | 17 | 21 | 22 | 23 | 25
    )
}

/// The most entries a table may claim: no more than its bytes could hold.
fn bounded(count: u64, r: &Reader<'_>) -> usize {
    let left = r.data.len().saturating_sub(r.pos) as u64;
    usize::try_from(count.min(left)).unwrap_or(usize::MAX)
}

impl<'d> Module<'d> {
    /// A custom section's data (after its name).
    fn custom_data(&self, s: &Section<'d>) -> Reader<'d> {
        let start = usize::try_from(s.data_offset).unwrap_or(self.data.len());
        let end = usize::try_from(s.offset + s.size).unwrap_or(self.data.len());
        Reader {
            data: &self.data[..end.min(self.data.len())],
            pos: start,
        }
    }

    /// The import section's entries, in order.
    pub fn imports(&self) -> Vec<Import<'d>> {
        let mut out = Vec::new();
        let Some(s) = self.sections.iter().find(|s| s.id == SECTION_IMPORT) else {
            return out;
        };
        let mut r = self.contents(s);
        let Some(count) = r.uleb() else { return out };
        for _ in 0..bounded(count, &r) {
            let (Some(module), Some(field), Some(kind)) = (r.name(), r.name(), r.u8()) else {
                break;
            };
            let ok = match kind {
                0 => r.u32().is_some(),
                1 => r.u8().is_some() && limits(&mut r),
                2 => limits(&mut r),
                3 => r.u8().is_some() && r.u8().is_some(),
                4 => r.u8().is_some() && r.u32().is_some(),
                _ => false,
            };
            if !ok {
                break;
            }
            out.push(Import {
                module,
                field,
                kind,
            });
        }
        out
    }

    /// The `linking` section's symbol table, in order (empty for a linked
    /// module, or where it is damaged: the entries up to there).
    pub fn linking_symbols(&self) -> Vec<LinkingSymbol<'d>> {
        let mut out = Vec::new();
        self.linking_subsections(|kind, mut r| {
            if kind != WASM_SYMBOL_TABLE {
                return;
            }
            let Some(count) = r.uleb() else { return };
            for _ in 0..bounded(count, &r) {
                let (Some(kind), Some(flags)) = (r.u8(), r.u32()) else {
                    return;
                };
                let undefined = flags & SYMBOL_UNDEFINED != 0;
                let explicit = flags & SYMBOL_EXPLICIT_NAME != 0;
                let mut s = LinkingSymbol {
                    kind,
                    flags,
                    name: None,
                    index: 0,
                    data: None,
                };
                match kind {
                    SYMBOL_FUNCTION | SYMBOL_GLOBAL | SYMBOL_TAG | SYMBOL_TABLE => {
                        let Some(index) = r.u32() else { return };
                        s.index = index;
                        if !undefined || explicit {
                            let Some(name) = r.name() else { return };
                            s.name = Some(name);
                        }
                    }
                    SYMBOL_DATA => {
                        let Some(name) = r.name() else { return };
                        s.name = Some(name);
                        if !undefined {
                            let (Some(segment), Some(offset), Some(size)) =
                                (r.u32(), r.uleb(), r.uleb())
                            else {
                                return;
                            };
                            s.data = Some((segment, offset, size));
                        }
                    }
                    SYMBOL_SECTION => {
                        let Some(index) = r.u32() else { return };
                        s.index = index;
                    }
                    _ => return,
                }
                out.push(s);
            }
        });
        out
    }

    /// The `linking` section's data segment information, in order.
    pub fn segment_info(&self) -> Vec<SegmentInfo<'d>> {
        let mut out = Vec::new();
        self.linking_subsections(|kind, mut r| {
            if kind != WASM_SEGMENT_INFO {
                return;
            }
            let Some(count) = r.uleb() else { return };
            for _ in 0..bounded(count, &r) {
                let (Some(name), Some(alignment), Some(flags)) = (r.name(), r.u32(), r.u32())
                else {
                    return;
                };
                out.push(SegmentInfo {
                    name,
                    alignment,
                    flags,
                });
            }
        });
        out
    }

    /// Calls `f` with each of the `linking` section's subsections: its
    /// kind and a reader of its payload.
    fn linking_subsections(&self, mut f: impl FnMut(u8, Reader<'d>)) {
        let Some(s) = self.custom(b"linking") else {
            return;
        };
        let mut r = self.custom_data(s);
        // (Version 2.)
        if r.u32().is_none() {
            return;
        }
        while r.pos < r.data.len() {
            let (Some(kind), Some(size)) = (r.u8(), r.uleb()) else {
                return;
            };
            let Ok(size) = usize::try_from(size) else {
                return;
            };
            let Some(end) = r.pos.checked_add(size).filter(|&e| e <= r.data.len()) else {
                return;
            };
            f(
                kind,
                Reader {
                    data: &r.data[..end],
                    pos: r.pos,
                },
            );
            r.pos = end;
        }
    }

    /// The relocations of each section that has a `reloc.*` section: the
    /// section's index (among all, from 0), and its relocations in order.
    pub fn relocations(&self) -> Vec<(u32, Vec<Relocation>)> {
        let mut out = Vec::new();
        for s in self
            .sections
            .iter()
            .filter(|s| s.id == SECTION_CUSTOM && s.name.starts_with(b"reloc."))
        {
            let mut r = self.custom_data(s);
            let (Some(section), Some(count)) = (r.u32(), r.uleb()) else {
                continue;
            };
            let mut relocs = Vec::new();
            for _ in 0..bounded(count, &r) {
                let (Some(kind), Some(offset), Some(index)) = (r.u8(), r.uleb(), r.u32()) else {
                    break;
                };
                let addend = if relocation_has_addend(kind) {
                    match crate::sleb(&mut r) {
                        Some(a) => Some(a),
                        None => break,
                    }
                } else {
                    None
                };
                relocs.push(Relocation {
                    kind,
                    offset,
                    index,
                    addend,
                });
            }
            out.push((section, relocs));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use crate::Module;

    #[test]
    fn an_objects_symbols_segments_and_relocations() {
        let data = include_bytes!("../../../../testdata/wasm/sample.o");
        let m = Module::parse(data).unwrap();
        assert!(m.is_object());
        let symbols = m.linking_symbols();
        assert_eq!(symbols.len(), 20);
        let sp = symbols
            .iter()
            .find(|s| s.kind == super::SYMBOL_GLOBAL)
            .unwrap();
        // (Undefined, named by its import.)
        assert_eq!(sp.flags & super::SYMBOL_UNDEFINED, super::SYMBOL_UNDEFINED);
        assert_eq!(sp.name, None);
        let globals: alloc::vec::Vec<_> = m.imports().into_iter().filter(|i| i.kind == 3).collect();
        assert_eq!(globals[sp.index as usize].field, b"__stack_pointer");
        let table = symbols
            .iter()
            .find(|s| s.kind == super::SYMBOL_DATA)
            .unwrap();
        assert_eq!(table.name, Some(&b".Lswitch.table.classify"[..]));
        assert_eq!(table.data, Some((0, 0, 6)));
        assert_eq!(m.segment_info()[0].name, b".rodata..Lswitch.table.classify");
        let relocs = m.relocations();
        assert_eq!(relocs.len(), 1);
        let (section, list) = &relocs[0];
        assert_eq!(*section, 4);
        assert_eq!(list.len(), 18);
        assert_eq!(list[0].kind, 6);
        assert_eq!(list[0].offset, 0xD3);
        assert_eq!(list[2].addend, Some(0));
        assert_eq!(
            super::relocation_name(list[2].kind),
            Some("R_WASM_MEMORY_ADDR_LEB")
        );
    }

    #[test]
    fn damaged_tables_end_early() {
        let data = include_bytes!("../../../../testdata/wasm/sample.o");
        // Every prefix, and each byte of the linking section flipped.
        for n in (0..data.len()).step_by(7) {
            if let Ok(m) = Module::parse(&data[..n]) {
                let _ = (
                    m.linking_symbols(),
                    m.segment_info(),
                    m.relocations(),
                    m.imports(),
                );
            }
        }
        let m = Module::parse(data).unwrap();
        let s = m.custom(b"linking").unwrap();
        let mut copy = data.to_vec();
        let (start, end) = (
            usize::try_from(s.data_offset).unwrap(),
            usize::try_from(s.offset + s.size).unwrap(),
        );
        for at in start..end {
            copy[at] ^= 0xFF;
            if let Ok(m) = Module::parse(&copy) {
                let _ = (m.linking_symbols(), m.segment_info());
            }
            copy[at] ^= 0xFF;
        }
    }
}
