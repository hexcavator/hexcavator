//! The PDB backend.

use std::collections::HashMap;

use hexcavator_codeview::symbols::{Symbol, SymbolIter, kind};
use hexcavator_codeview::{TypeFormatter, TypeIndex};
use hexcavator_core::{Error, ErrorKind, Reader, Result};
use hexcavator_image::DebugId;
use hexcavator_pdb::{Pdb, info};

use crate::{
    BasicType, Class, Compiland, Contribution, EnclosingFunction, Group, Method, MethodKind,
    PointerKind, Qualifiers, Symbol as DebugSymbol, SymbolKind, TypeRef, TypeShape,
};

/// The name of the module that holds what the linker itself produced.
pub const LINKER_MODULE: &[u8] = b"* Linker *";

/// What the debug information records about the link.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LinkerInfo {
    /// The linker's environment block (`S_ENVBLOCK`): key/value pairs such
    /// as `cwd`, `exe`, `pdb`, and `cmd`.
    pub environment: Vec<(String, String)>,
    /// Whether this is a minimal (`/DEBUG:FASTLINK`) PDB, whose module
    /// symbols stay in the objects' own PDBs.
    pub minimal: bool,
}

impl LinkerInfo {
    /// The value of `key` in the environment block.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.environment
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// The linker command line (its arguments; see also `exe`).
    pub fn command_line(&self) -> Option<&str> {
        self.get("cmd")
    }
}

pub struct PdbInfo<'data> {
    pdb: Pdb<'data>,
    /// Section (virtual address, virtual size), from the PDB's copy of the
    /// image's section headers; section `n` is at index `n - 1`.
    sections: Vec<(u32, u32)>,
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

impl<'data> PdbInfo<'data> {
    pub fn parse(data: &'data [u8]) -> Result<Self> {
        hexcavator_pdb::check(data)?;
        let pdb = Pdb::parse(data)?;
        let sections = pdb
            .sections()?
            .into_iter()
            .map(|(va, size, _)| (va, size))
            .collect();
        Ok(Self { pdb, sections })
    }

    pub fn pdb(&self) -> &Pdb<'data> {
        &self.pdb
    }

    /// The RVA of `section:offset` (1-based section).
    fn rva(&self, section: u16, offset: u32) -> Option<u64> {
        let (va, _) = *self.sections.get(usize::from(section).checked_sub(1)?)?;
        Some(u64::from(va) + u64::from(offset))
    }

    pub fn matches(&self, id: &DebugId<'_>) -> bool {
        match *id {
            DebugId::Pdb { guid, age, .. } => {
                let info = self.pdb.info();
                // The age the image records is the DBI stream's age; the
                // info stream's age can be higher (it counts every write).
                let dbi_age = self.pdb.dbi().map(|d| d.header.age.get()).ok();
                info.guid() == guid && (dbi_age == Some(age) || info.age() == age)
            }
            // (PDB 2.0, and other formats' identities: not this PDB.)
            _ => false,
        }
    }

    pub fn compilands(&self) -> Result<Vec<Compiland>> {
        let dbi = self.pdb.dbi()?;
        Ok(dbi
            .modules()
            .iter()
            .map(|m| Compiland {
                name: lossy(m.name),
                library: lossy(m.object_name),
            })
            .collect())
    }

    pub fn contributions(&self) -> Result<Vec<Contribution>> {
        let dbi = self.pdb.dbi()?;
        let contribs = dbi.section_contribs()?;
        let mut out = Vec::with_capacity(contribs.len());
        for c in contribs.iter() {
            let (Ok(offset), Ok(size)) =
                (u32::try_from(c.offset.get()), u64::try_from(c.size.get()))
            else {
                continue;
            };
            let Some(addr) = self.rva(c.section.get(), offset) else {
                continue;
            };
            out.push(Contribution {
                addr,
                size,
                compiland: u32::from(c.module_index.get()),
                characteristics: c.characteristics.get(),
            });
        }
        // The DBI stream sorts by section and offset; sections are sorted by
        // address in every image we have seen, but don't rely on it.
        out.sort_by_key(|c| (c.addr, c.size));
        Ok(out)
    }

    /// The `* Linker *` module's symbols.
    fn linker_symbols(&self, mut f: impl FnMut(Symbol<'_>)) -> Result<()> {
        let dbi = self.pdb.dbi()?;
        let Some(module) = dbi.modules().iter().find(|m| m.name == LINKER_MODULE) else {
            return Ok(());
        };
        let Some(stream) = self.pdb.module_stream(module)? else {
            return Ok(());
        };
        for record in stream.symbols() {
            if let Ok(symbol) = record.parse() {
                f(symbol);
            }
        }
        Ok(())
    }

    pub fn groups(&self) -> Result<Vec<Group>> {
        let mut out = Vec::new();
        self.linker_symbols(|symbol| {
            if let Symbol::CoffGroup {
                size,
                characteristics,
                offset,
                segment,
                name,
            } = symbol
                && let Some(addr) = self.rva(segment, offset)
            {
                out.push(Group {
                    name: lossy(name),
                    addr,
                    size: u64::from(size),
                    characteristics,
                });
            }
        })?;
        out.sort_by_key(|g| (g.addr, g.size));
        Ok(out)
    }

    /// Every inline site of every module, with its code (from its binary
    /// annotations, relative to its outermost enclosing procedure). Modules
    /// are decoded in parallel; each inlined function is named once.
    pub fn inline_sites(&self) -> Result<crate::InlineSites> {
        let dbi = self.pdb.dbi()?;
        let mut streams = Vec::new();
        for module in dbi.modules() {
            if let Some(stream) = self.pdb.module_stream(module)? {
                streams.push((u32::try_from(module.index).unwrap_or(u32::MAX), stream));
            }
        }
        let threads = std::thread::available_parallelism()
            .map_or(1, std::num::NonZero::get)
            .min(streams.len().max(1));
        let chunk = streams.len().div_ceil(threads).max(1);
        let sections = &self.sections;
        // Sites with their inlinees' id records for now.
        let mut sites: Vec<crate::InlineSite> = std::thread::scope(|scope| {
            let handles: Vec<_> = streams
                .chunks(chunk)
                .map(|part| {
                    scope.spawn(move || {
                        let mut out = Vec::new();
                        for (compiland, stream) in part {
                            module_inline_sites(sections, *compiland, stream.symbols(), &mut out);
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
        // Name each inlinee once.
        let types = self.pdb.types()?;
        types.build_offsets();
        let ids = self.pdb.ids()?;
        ids.build_offsets();
        let formatter = TypeFormatter { types };
        // (Id records of one name are one function: an index per name.)
        let mut index: HashMap<u32, u32> = HashMap::new();
        let mut by_name: HashMap<String, u32> = HashMap::new();
        let mut inlinees: Vec<String> = Vec::new();
        for s in &mut sites {
            let id = s.inlinee;
            s.inlinee = *index.entry(id).or_insert_with(|| {
                let name = inlinee_name(ids, &formatter, id)
                    .unwrap_or_else(|| format!("<inlinee {id:#x}>"));
                *by_name.entry(name.clone()).or_insert_with(|| {
                    inlinees.push(name);
                    u32::try_from(inlinees.len() - 1).unwrap_or(u32::MAX)
                })
            });
        }
        Ok(crate::InlineSites { inlinees, sites })
    }

    /// Every module's annotations, by address.
    pub fn variables(
        &self,
        compiland: Option<u32>,
        addr: u64,
    ) -> Result<Option<crate::FunctionVariables>> {
        let dbi = self.pdb.dbi()?;
        let modules = dbi.modules();
        // Its compiland's module first, then the rest.
        let first = compiland.and_then(|c| {
            modules
                .iter()
                .position(|m| u32::try_from(m.index).ok() == Some(c))
        });
        let order = first
            .into_iter()
            .chain((0..modules.len()).filter(|&i| Some(i) != first));
        for i in order {
            let Some(stream) = self.pdb.module_stream(&modules[i])? else {
                continue;
            };
            if let Some(v) = function_variables(&self.sections, addr, stream.symbols()) {
                return Ok(Some(v));
            }
        }
        Ok(None)
    }

    pub fn annotations(&self) -> Result<Vec<crate::Annotation>> {
        let dbi = self.pdb.dbi()?;
        let mut out = Vec::new();
        for module in dbi.modules() {
            let Some(stream) = self.pdb.module_stream(module)? else {
                continue;
            };
            let compiland = u32::try_from(module.index).unwrap_or(u32::MAX);
            // The open scopes: whether each is (in) an inline site.
            let mut scopes: Vec<bool> = Vec::new();
            for record in stream.symbols() {
                if kind::closes_scope(record.kind) {
                    scopes.pop();
                }
                let inlined = scopes.last().copied().unwrap_or(false);
                if kind::opens_scope(record.kind) {
                    let site = matches!(record.parse(), Ok(Symbol::InlineSite { .. }));
                    scopes.push(inlined || site);
                    continue;
                }
                let Ok(Symbol::Annotation {
                    offset,
                    segment,
                    strings,
                    count,
                }) = record.parse()
                else {
                    continue;
                };
                let Some(addr) = rva_in(&self.sections, segment, offset) else {
                    continue;
                };
                let strings = strings
                    .split(|&b| b == 0)
                    .take(usize::from(count))
                    .map(lossy)
                    .collect();
                out.push(crate::Annotation {
                    addr,
                    strings,
                    compiland,
                    inlined,
                });
            }
        }
        // An annotation's record is in its function's scope even when its
        // code is an inlined copy's: it is inlined if its address is in one.
        if !out.is_empty() {
            let mut ranges: Vec<(u64, u64)> = self
                .inline_sites()?
                .sites
                .iter()
                .flat_map(|s| s.ranges.iter().copied())
                .collect();
            ranges.sort_unstable();
            for a in &mut out {
                let i = ranges.partition_point(|r| r.0 <= a.addr);
                a.inlined |= ranges[..i]
                    .iter()
                    .rev()
                    .take(64)
                    .any(|r| a.addr < r.0 + r.1);
            }
        }
        out.sort_by(|a, b| a.addr.cmp(&b.addr).then_with(|| a.strings.cmp(&b.strings)));
        Ok(out)
    }

    /// Every module's line tables, as spans of code with their file and
    /// line (a line's code runs to the next line's, or the block's end).
    pub fn source_lines(&self) -> Result<crate::SourceLines> {
        let dbi = self.pdb.dbi()?;
        let names = self.pdb.names()?;
        let mut files: Vec<String> = Vec::new();
        let mut file_index: HashMap<String, u32> = HashMap::new();
        let mut spans = Vec::new();
        for module in dbi.modules() {
            let Some(stream) = self.pdb.module_stream(module)? else {
                continue;
            };
            let compiland = u32::try_from(module.index).unwrap_or(u32::MAX);
            // A module's checksum offsets name its files: look each up once.
            let mut by_offset: HashMap<u32, u32> = HashMap::new();
            for block in stream.line_blocks() {
                let Some(start) = rva_in(&self.sections, block.segment, block.offset) else {
                    continue;
                };
                let file = *by_offset.entry(block.file).or_insert_with(|| {
                    let path = stream
                        .file_checksum(block.file)
                        .and_then(|c| names.get_str(c.name))
                        .unwrap_or("")
                        .to_string();
                    *file_index.entry(path.clone()).or_insert_with(|| {
                        files.push(path);
                        u32::try_from(files.len() - 1).unwrap_or(u32::MAX)
                    })
                });
                for (i, line) in block.lines.iter().enumerate() {
                    let at = line.offset.get();
                    let end = block
                        .lines
                        .get(i + 1)
                        .map_or(block.code_size, |n| n.offset.get())
                        .min(block.code_size);
                    if end <= at {
                        continue;
                    }
                    spans.push(crate::LineSpan {
                        addr: start + u64::from(at),
                        size: u64::from(end - at),
                        file,
                        line: line.line(),
                        compiland,
                    });
                }
            }
        }
        spans.sort_by_key(|s| (s.addr, s.size));
        Ok(crate::SourceLines { files, spans })
    }

    pub fn symbols(&self) -> Result<Vec<DebugSymbol>> {
        let dbi = self.pdb.dbi()?;
        // Read the module streams first (gathering any that are not
        // contiguous), then decode them in parallel: they are independent.
        let mut streams = Vec::new();
        for module in dbi.modules() {
            if let Some(stream) = self.pdb.module_stream(module)? {
                // Module indexes come from a 16-bit field.
                streams.push((u32::try_from(module.index).unwrap_or(u32::MAX), stream));
            }
        }
        let threads = std::thread::available_parallelism()
            .map_or(1, std::num::NonZero::get)
            .min(streams.len().max(1));
        let chunk = streams.len().div_ceil(threads).max(1);
        let sections = &self.sections;
        let mut out: Vec<DebugSymbol> = std::thread::scope(|scope| {
            let handles: Vec<_> = streams
                .chunks(chunk)
                .map(|part| {
                    scope.spawn(move || {
                        let mut out = Vec::new();
                        for (index, stream) in part {
                            module_symbols(sections, *index, stream.symbols(), &mut out);
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

        // Publics and global data, from the shared symbol record stream.
        for record in SymbolIter::new(self.pdb.symbol_records(), 0) {
            let Ok(symbol) = record.parse() else { continue };
            if let Some(s) = shared_symbol(sections, symbol) {
                out.push(s);
            }
        }

        // Data sizes from their types (looked up once per type).
        let types = self.pdb.types()?;
        // Many lookups follow: index every record once.
        types.build_offsets();
        let formatter = TypeFormatter { types };
        // Functions' statics in inlined copies: name the inlined function.
        if out.iter().any(|s| s.flags & INLINEE_PENDING != 0) {
            let ids = self.pdb.ids().ok();
            if let Some(ids) = ids {
                ids.build_offsets();
            }
            let mut names: HashMap<u64, Option<(String, TypeRef)>> = HashMap::new();
            for s in out.iter_mut().filter(|s| s.flags & INLINEE_PENDING != 0) {
                s.flags &= !INLINEE_PENDING;
                let Some(f) = s.function.as_mut() else {
                    continue;
                };
                let id = f.ty.0;
                let named = names.entry(id).or_insert_with(|| {
                    ids.and_then(|ids| inlinee(ids, &formatter, index(TypeRef(id)).0))
                });
                match named {
                    Some((name, ty)) => {
                        f.name = name.clone();
                        f.ty = *ty;
                    }
                    None => s.function = None,
                }
            }
        }
        let mut sizes: HashMap<u64, Option<u64>> = HashMap::new();
        for s in out.iter_mut().filter(|s| s.kind == SymbolKind::Data) {
            s.size = *sizes
                .entry(s.type_index)
                .or_insert_with(|| formatter.size_of(index(TypeRef(s.type_index))));
        }

        // Copies without a compiland sort after those with one, so that
        // `dedup_by` keeps the one with.
        out.sort_by(|a, b| {
            (
                a.addr,
                a.kind,
                &a.name,
                a.type_index,
                a.compiland.is_none(),
                a.compiland,
            )
                .cmp(&(
                    b.addr,
                    b.kind,
                    &b.name,
                    b.type_index,
                    b.compiland.is_none(),
                    b.compiland,
                ))
        });
        // The same symbol from two places: a module's static and its copy
        // in the global stream (which has no compiland), say. (Overloads
        // folded together in one module share an address and a name, but
        // not a type.)
        out.dedup_by(|b, a| {
            a.addr == b.addr
                && a.kind == b.kind
                && a.name == b.name
                && a.type_index == b.type_index
                && a.size == b.size
                && (a.compiland == b.compiland || b.compiland.is_none())
        });
        Ok(out)
    }

    pub fn classes(&self) -> Result<Vec<Class>> {
        use hexcavator_codeview::types::{Field, leaf};
        let types = self.pdb.types()?;
        types.build_offsets();
        let mut out = Vec::new();
        for (ti, rec) in types.iter() {
            if !leaf::is_class(rec.kind) {
                continue;
            }
            let Some(udt) = rec.udt() else { continue };
            if udt.is_forward_ref() || udt.field_list.0 == 0 {
                continue;
            }
            let mut class = Class {
                name: lossy(udt.name),
                ty: to_ref(ti),
                bases: Vec::new(),
                methods: Vec::new(),
            };
            // A field list can continue in others (LF_INDEX); bounded.
            let mut list = udt.field_list;
            for _ in 0..64 {
                let Some(fields) = types.record(list) else {
                    break;
                };
                let mut next = None;
                for f in fields.fields() {
                    match f {
                        Field::BaseClass { ty, .. } | Field::VirtualBaseClass { ty, .. } => {
                            class.bases.push(to_ref(types.resolve_forward(ty)));
                        }
                        Field::OneMethod {
                            attributes,
                            ty,
                            name,
                            ..
                        } => class.methods.push(Method {
                            name: lossy(name),
                            ty: to_ref(ty),
                            kind: method_kind(attributes),
                        }),
                        Field::Method {
                            method_list, name, ..
                        } => {
                            if let Some(ml) = types.record(method_list) {
                                for (attributes, ty) in ml.method_list() {
                                    class.methods.push(Method {
                                        name: lossy(name),
                                        ty: to_ref(ty),
                                        kind: method_kind(attributes),
                                    });
                                }
                            }
                        }
                        Field::Index { ty } => next = Some(ty),
                        _ => {}
                    }
                }
                match next {
                    Some(n) if n != list => list = n,
                    _ => break,
                }
            }
            out.push(class);
        }
        Ok(out)
    }

    pub fn type_size(&self, ty: TypeRef) -> Option<u64> {
        let types = self.pdb.types().ok()?;
        TypeFormatter { types }.size_of(index(ty))
    }

    pub fn enumerators(&self, ty: TypeRef) -> Option<crate::Enumerators> {
        use hexcavator_codeview::types::{Field, leaf};
        let types = self.pdb.types().ok()?;
        let ti = types.resolve_forward(index(ty));
        let rec = types.record(ti)?;
        if rec.kind != leaf::LF_ENUM {
            return None;
        }
        let udt = rec.udt()?;
        let signed = matches!(
            simple_shape(udt.underlying.0),
            TypeShape::Basic {
                kind: BasicType::Int | BasicType::Long | BasicType::Char,
                ..
            }
        ) && udt.underlying.is_simple();
        let mut values = Vec::new();
        if let Some(list) = types.record(udt.field_list) {
            for field in list.fields() {
                if let Field::Enumerate { value, name, .. } = field {
                    values.push((String::from_utf8_lossy(name).into_owned(), value.as_u64()));
                }
            }
        }
        Some(crate::Enumerators { signed, values })
    }

    /// The type's name, as C++.
    pub fn type_name(&self, ty: TypeRef) -> String {
        match self.pdb.types() {
            Ok(types) => TypeFormatter { types }.name(index(ty)),
            Err(_) => String::new(),
        }
    }

    pub fn layout(&self, ty: TypeRef) -> Option<crate::layout::Layout> {
        let types = self.pdb.types().ok()?;
        hexcavator_codeview::layout::layout(types, index(ty)).map(neutral_layout)
    }

    pub fn layouts(&self) -> Result<Vec<crate::layout::Layout>> {
        let types = self.pdb.types()?;
        Ok(hexcavator_codeview::layout::all(types)
            .into_iter()
            .map(neutral_layout)
            .collect())
    }

    pub fn type_shape(&self, ty: TypeRef) -> TypeShape {
        if index(ty).is_simple() {
            return simple_shape(index(ty).0);
        }
        let Ok(types) = self.pdb.types() else {
            return TypeShape::Unknown;
        };
        types.build_offsets();
        let Some(rec) = types.record(index(ty)) else {
            return TypeShape::Unknown;
        };
        record_shape(types, rec.kind, rec.data).unwrap_or(TypeShape::Unknown)
    }

    /// Where type `ty` is defined (its definition's, or a forward
    /// reference's definition's): the IPI stream's `LF_UDT_SRC_LINE` (the
    /// file a string ID) or `LF_UDT_MOD_SRC_LINE` (the file in the names
    /// stream) for it.
    pub fn type_definition(&self, ty: TypeRef) -> Option<(String, u32)> {
        use hexcavator_codeview::types::leaf;
        let ids = self.pdb.ids().ok()?;
        let mut wanted = vec![ty.pdb_index().0];
        if let Ok(types) = self.pdb.types() {
            let defined = types.resolve_forward(ty.pdb_index()).0;
            if defined != wanted[0] {
                wanted.push(defined);
            }
        }
        let u32_at = |d: &[u8], at: usize| -> Option<u32> {
            Some(u32::from_le_bytes(d.get(at..at + 4)?.try_into().ok()?))
        };
        for (_, rec) in ids.iter() {
            if rec.kind != leaf::LF_UDT_SRC_LINE && rec.kind != leaf::LF_UDT_MOD_SRC_LINE {
                continue;
            }
            let d = rec.data;
            let Some(t) = u32_at(d, 0) else { continue };
            if !wanted.contains(&t) {
                continue;
            }
            let (src, line) = (u32_at(d, 4)?, u32_at(d, 8)?);
            let file = if rec.kind == leaf::LF_UDT_SRC_LINE {
                // An LF_STRING_ID: (substrings, unused for paths) then text.
                let s = ids.record(TypeIndex(src))?;
                if s.kind != leaf::LF_STRING_ID {
                    return None;
                }
                let text = s.data.get(4..)?;
                String::from_utf8_lossy(
                    &text[..text.iter().position(|&b| b == 0).unwrap_or(text.len())],
                )
                .into_owned()
            } else {
                self.pdb.names().ok()?.get_str(src)?.to_string()
            };
            return Some((file, line));
        }
        None
    }

    pub fn linker_info(&self) -> Result<LinkerInfo> {
        let mut environment = Vec::new();
        let mut error = None;
        self.linker_symbols(|symbol| {
            if let Symbol::Other {
                kind: kind::S_ENVBLOCK,
                data,
            } = symbol
            {
                match parse_env_block(data) {
                    Ok(pairs) => environment = pairs,
                    Err(e) => error = Some(e),
                }
            }
        })?;
        if let Some(e) = error {
            return Err(e);
        }
        Ok(LinkerInfo {
            environment,
            minimal: self
                .pdb
                .info()
                .has_feature(info::feature::MINIMAL_DEBUG_INFO),
        })
    }
}

/// The shape of a simple (built-in) type index: a basic type, or a pointer
/// to one by the index's mode bits.
/// A type index as a [`TypeRef`].
/// A PDB type's parts, laid out with the holes between them.
fn neutral_layout(l: hexcavator_codeview::layout::Layout) -> crate::layout::Layout {
    use crate::layout::PartKind as K;
    use hexcavator_codeview::layout::PartKind as P;
    let kind = |k: P| match k {
        P::Base => K::Base,
        P::VirtualBase => K::VirtualBase,
        P::VfPtr => K::VfPtr,
        P::VbPtr => K::VbPtr,
        // (Member, and kinds the PDB crate adds before this does.)
        _ => K::Member,
    };
    let parts = l
        .parts
        .into_iter()
        .map(|p| crate::layout::Part {
            offset: p.offset,
            size: p.size,
            bits: p.bits,
            kind: kind(p.kind),
            name: p.name,
            type_name: p.type_name,
            ty: to_ref(p.ty),
        })
        .collect();
    let mut out = crate::layout::fill(l.name, l.size, l.union, parts);
    out.ty = to_ref(l.ti);
    out.key = l.key;
    out.incomplete = l.incomplete;
    out
}

fn to_ref(ti: TypeIndex) -> TypeRef {
    TypeRef(u64::from(ti.0))
}

/// A [`TypeRef`] as a type index (one wider than any is no type).
fn index(r: TypeRef) -> TypeIndex {
    TypeIndex(u32::try_from(r.0).unwrap_or(0))
}

fn simple_shape(ti: u32) -> TypeShape {
    use hexcavator_codeview::types::simple::*;
    if !is_valid(ti) {
        return TypeShape::Unknown;
    }
    let mode = mode(ti);
    if mode != CV_TM_DIRECT {
        let size = match mode {
            CV_TM_NPTR => 2,
            CV_TM_FPTR | CV_TM_HPTR | CV_TM_NPTR32 => 4,
            CV_TM_FPTR32 => 6,
            CV_TM_NPTR64 => 8,
            CV_TM_NPTR128 => 16,
            _ => 0,
        };
        return TypeShape::Pointer {
            target: TypeRef(u64::from(kind(ti))),
            kind: PointerKind::Pointer,
            qualifiers: Qualifiers::default(),
            size,
        };
    }
    use BasicType::*;
    let (kind, size) = match kind(ti) {
        T_NOTYPE => (None, 0),
        T_VOID => (Void, 0),
        T_HRESULT => (HResult, 4),
        T_CHAR | T_INT1 => (Int, 1),
        T_UCHAR | T_UINT1 => (UInt, 1),
        T_RCHAR => (Char, 1),
        T_WCHAR => (WideChar, 2),
        T_CHAR16 => (Char16, 2),
        T_CHAR32 => (Char32, 4),
        T_CHAR8 => (Char8, 1),
        T_SHORT | T_INT2 => (Int, 2),
        T_USHORT | T_UINT2 => (UInt, 2),
        T_LONG => (Long, 4),
        T_ULONG => (ULong, 4),
        T_INT4 => (Int, 4),
        T_UINT4 => (UInt, 4),
        T_QUAD | T_INT8 => (Int, 8),
        T_UQUAD | T_UINT8 => (UInt, 8),
        T_OCT | T_INT16 => (Int, 16),
        T_UOCT | T_UINT16 => (UInt, 16),
        T_BOOL08 => (Bool, 1),
        T_BOOL16 => (Bool, 2),
        T_BOOL32 => (Bool, 4),
        T_BOOL64 => (Bool, 8),
        T_REAL16 => (Float, 2),
        T_REAL32 => (Float, 4),
        T_REAL64 => (Float, 8),
        T_REAL80 => (Float, 10),
        T_REAL128 => (Float, 16),
        _ => return TypeShape::Unknown,
    };
    TypeShape::Basic { kind, size }
}

/// The shape of a type record.
fn record_shape(
    types: &hexcavator_pdb::TypeStream<'_>,
    kind: u16,
    data: &[u8],
) -> Option<TypeShape> {
    use hexcavator_codeview::types::leaf;
    let mut r = Reader::new(data);
    let ti = |r: &mut Reader<'_>| r.u32_le().map(|t| TypeRef(u64::from(t))).ok();
    let qualifiers_of_modifier = |mods: u16| Qualifiers {
        is_const: mods & 1 != 0,
        is_volatile: mods & 2 != 0,
        is_unaligned: mods & 4 != 0,
        is_restrict: false,
    };
    // The argument types of an `LF_ARGLIST`.
    let args_of = |list: TypeRef| -> Vec<TypeRef> {
        let Some(rec) = types.record(index(list)) else {
            return Vec::new();
        };
        let mut r = Reader::new(rec.data);
        let count = r.u32_le().unwrap_or(0);
        (0..count)
            .map_while(|_| r.u32_le().ok().map(|t| TypeRef(u64::from(t))))
            .collect()
    };
    Some(match kind {
        leaf::LF_POINTER => {
            let target = ti(&mut r)?;
            let attrs = r.u32_le().ok()?;
            use hexcavator_codeview::types::pointer::*;
            let kind = match (attrs >> PTRMODE_SHIFT) & PTRMODE_MASK {
                CV_PTR_MODE_LVREF => PointerKind::LValueReference,
                CV_PTR_MODE_PMEM | CV_PTR_MODE_PMFUNC => PointerKind::Member,
                CV_PTR_MODE_RVREF => PointerKind::RValueReference,
                _ => PointerKind::Pointer,
            };
            TypeShape::Pointer {
                target,
                kind,
                qualifiers: Qualifiers {
                    is_const: attrs & ISCONST != 0,
                    is_volatile: attrs & ISVOLATILE != 0,
                    is_unaligned: attrs & ISUNALIGNED != 0,
                    is_restrict: attrs & ISRESTRICT != 0,
                },
                size: u64::from((attrs >> SIZE_SHIFT) & SIZE_MASK),
            }
        }
        leaf::LF_MODIFIER => TypeShape::Modified {
            base: ti(&mut r)?,
            qualifiers: qualifiers_of_modifier(r.u16_le().ok()?),
        },
        k if leaf::is_class(k) || leaf::is_union(k) => {
            let rec = hexcavator_codeview::TypeRecord { kind, data };
            TypeShape::Udt {
                name: lossy(rec.udt()?.name),
            }
        }
        leaf::LF_ENUM => {
            let rec = hexcavator_codeview::TypeRecord { kind, data };
            TypeShape::Enum {
                name: lossy(rec.udt()?.name),
            }
        }
        leaf::LF_ARRAY => {
            let element = ti(&mut r)?;
            let _index = ti(&mut r)?;
            let size = hexcavator_codeview::types::read_numeric(&mut r)
                .ok()?
                .as_u64();
            TypeShape::Array { element, size }
        }
        leaf::LF_PROCEDURE => {
            let ret = ti(&mut r)?;
            r.skip(4).ok()?; // calling convention, attributes, count
            let args = args_of(ti(&mut r)?);
            TypeShape::Function {
                ret,
                args,
                class: None,
                this_qualifiers: None,
            }
        }
        leaf::LF_MFUNCTION => {
            let ret = ti(&mut r)?;
            let class = ti(&mut r)?;
            let this = ti(&mut r)?;
            r.skip(4).ok()?;
            let args = args_of(ti(&mut r)?);
            // `this` points to the (possibly qualified) class; a static
            // member function has no `this`.
            let this_qualifiers = (this.0 != 0).then(|| {
                let pointee = types.record(index(this)).and_then(|p| {
                    let mut r = Reader::new(p.data);
                    (p.kind == leaf::LF_POINTER)
                        .then(|| r.u32_le().ok())
                        .flatten()
                });
                pointee
                    .and_then(|t| types.record(TypeIndex(t)))
                    .filter(|m| m.kind == leaf::LF_MODIFIER)
                    .and_then(|m| {
                        let mut r = Reader::new(m.data);
                        r.u32_le().ok()?;
                        r.u16_le().ok().map(qualifiers_of_modifier)
                    })
                    .unwrap_or_default()
            });
            TypeShape::Function {
                ret,
                args,
                class: Some(class),
                this_qualifiers,
            }
        }
        _ => return None,
    })
}

/// The RVA of `section:offset` (1-based section), given the sections'
/// virtual addresses.
fn rva_in(sections: &[(u32, u32)], section: u16, offset: u32) -> Option<u64> {
    let (va, _) = *sections.get(usize::from(section).checked_sub(1)?)?;
    Some(u64::from(va) + u64::from(offset))
}

fn symbol(kind: SymbolKind, addr: u64, name: &[u8]) -> DebugSymbol {
    DebugSymbol {
        kind,
        addr,
        size: None,
        name: lossy(name),
        compiland: None,
        global: false,
        thread_local: false,
        parent: None,
        function: None,
        type_index: 0,
        flags: 0,
    }
}

/// One module's inline sites, each with its inlinee's id record (for the
/// caller to name).
fn module_inline_sites(
    sections: &[(u32, u32)],
    compiland: u32,
    records: SymbolIter<'_>,
    out: &mut Vec<crate::InlineSite>,
) {
    // The open scopes: each one's procedure start, and how many inline
    // sites it is within.
    let mut scopes: Vec<(Option<u64>, u32)> = Vec::new();
    for record in records {
        if kind::closes_scope(record.kind) {
            scopes.pop();
        }
        if !kind::opens_scope(record.kind) {
            continue;
        }
        let (enclosing, depth) = scopes.last().copied().unwrap_or((None, 0));
        match record.parse() {
            Ok(Symbol::Procedure {
                offset, segment, ..
            }) => {
                // A procedure in an inlined copy is still its own.
                scopes.push((rva_in(sections, segment, offset), 0));
            }
            Ok(Symbol::InlineSite {
                inlinee,
                annotations,
                ..
            }) => {
                scopes.push((enclosing, depth + 1));
                let Some(base) = enclosing else { continue };
                let site = hexcavator_codeview::annotations::decode(annotations);
                out.push(crate::InlineSite {
                    inlinee: inlinee.0,
                    function: base,
                    ranges: site
                        .ranges
                        .iter()
                        .map(|&(o, l)| (base + u64::from(o), u64::from(l)))
                        .collect(),
                    compiland,
                    depth,
                });
            }
            _ => scopes.push((enclosing, depth)),
        }
    }
}

/// The variables of the procedure that starts at `addr` in one module's
/// records: its S_LOCALs with their S_DEFRANGE_* ranges, and its
/// S_REGREL32, S_BPREL32, and S_REGISTER variables (whole-scope), in its
/// blocks and inlined functions too.
fn function_variables(
    sections: &[(u32, u32)],
    addr: u64,
    records: SymbolIter<'_>,
) -> Option<crate::FunctionVariables> {
    use crate::{FunctionVariables, Place, VarRange, Variable};
    let mut out: Option<FunctionVariables> = None;
    // Scopes open inside the procedure: each one's range, and whether it
    // is an inline site.
    let mut scopes: Vec<((u64, u64), bool)> = Vec::new();
    let mut depth_in = 0usize;
    for record in records {
        if let Some(f) = &out {
            if kind::closes_scope(record.kind) {
                if scopes.len() <= depth_in {
                    // The procedure's own end.
                    return out;
                }
                scopes.pop();
                continue;
            }
            let (scope, _) = scopes.last().copied().unwrap_or(((f.start, f.end), false));
            let inlined = scopes.iter().any(|s| s.1);
            let Ok(sym) = record.parse() else {
                if kind::opens_scope(record.kind) {
                    scopes.push((scope, false));
                }
                continue;
            };
            let f = out.as_mut()?;
            match sym {
                Symbol::Block {
                    len,
                    offset,
                    segment,
                    ..
                } => {
                    let start = rva_in(sections, segment, offset).unwrap_or(scope.0);
                    scopes.push(((start, start + u64::from(len)), false));
                }
                Symbol::InlineSite { .. } => scopes.push((scope, true)),
                _ if kind::opens_scope(record.kind) => scopes.push((scope, false)),
                Symbol::FrameProc { flags, .. } => {
                    f.frame = (((flags >> 14) & 3) as u8, ((flags >> 16) & 3) as u8);
                }
                Symbol::Local { ty, flags, name } => f.variables.push(Variable {
                    name: String::from_utf8_lossy(name).into_owned(),
                    type_index: u64::from(ty.0),
                    param: flags & 1 != 0,
                    inlined,
                    ranges: Vec::new(),
                }),
                Symbol::DefRange { kind: k, data } => {
                    let Some(v) = f.variables.last_mut() else {
                        continue;
                    };
                    if let Some(range) = def_range(sections, k, data, (f.start, f.end)) {
                        v.ranges.push(range);
                    }
                }
                Symbol::RegisterRelative {
                    offset,
                    ty,
                    register,
                    name,
                } => f.variables.push(Variable {
                    name: String::from_utf8_lossy(name).into_owned(),
                    type_index: u64::from(ty.0),
                    param: false,
                    inlined,
                    ranges: vec![VarRange {
                        start: scope.0,
                        end: scope.1,
                        gaps: Vec::new(),
                        place: Place::Relative { register, offset },
                    }],
                }),
                Symbol::BpRelative { offset, ty, name } => f.variables.push(Variable {
                    name: String::from_utf8_lossy(name).into_owned(),
                    type_index: u64::from(ty.0),
                    param: false,
                    inlined,
                    ranges: vec![VarRange {
                        start: scope.0,
                        end: scope.1,
                        gaps: Vec::new(),
                        place: Place::Frame {
                            offset,
                            param: offset > 0,
                        },
                    }],
                }),
                Symbol::Register { ty, register, name } => f.variables.push(Variable {
                    name: String::from_utf8_lossy(name).into_owned(),
                    type_index: u64::from(ty.0),
                    param: false,
                    inlined,
                    ranges: vec![VarRange {
                        start: scope.0,
                        end: scope.1,
                        gaps: Vec::new(),
                        place: Place::Register(register),
                    }],
                }),
                _ => {}
            }
            // A variable recorded twice (an S_LOCAL, then its home slot as
            // an S_REGREL32): one, with both's places.
            if let Some(last) = f.variables.last()
                && let Some(i) = f.variables[..f.variables.len() - 1].iter().position(|v| {
                    v.name == last.name
                        && v.type_index == last.type_index
                        && v.inlined == last.inlined
                })
                && matches!(
                    record.kind,
                    kind::S_REGREL32 | kind::S_BPREL32 | kind::S_REGISTER
                )
            {
                let last = f.variables.pop()?;
                f.variables[i].ranges.extend(last.ranges);
            }
            continue;
        }
        // Before it: a procedure that starts at `addr` opens it.
        if let Ok(Symbol::Procedure {
            offset,
            segment,
            len,
            ..
        }) = record.parse()
            && rva_in(sections, segment, offset) == Some(addr)
        {
            out = Some(FunctionVariables {
                start: addr,
                end: addr + u64::from(len),
                ..FunctionVariables::default()
            });
            depth_in = 0;
            scopes.clear();
        }
    }
    out
}

/// An S_DEFRANGE_* record's place and range (the procedure's, for a
/// full-scope one), or `None` for the forms not read (S_DEFRANGE's DIA
/// programs).
fn def_range(
    sections: &[(u32, u32)],
    k: u16,
    data: &[u8],
    whole: (u64, u64),
) -> Option<crate::VarRange> {
    use crate::{Place, VarRange};
    let mut r = Reader::new(data);
    let place = match k {
        kind::S_DEFRANGE_REGISTER => {
            let register = r.u16_le().ok()?;
            r.u16_le().ok()?;
            Place::Register(register)
        }
        kind::S_DEFRANGE_FRAMEPOINTER_REL => Place::Frame {
            offset: r.u32_le().ok()? as i32,
            param: false,
        },
        kind::S_DEFRANGE_SUBFIELD_REGISTER => {
            let register = r.u16_le().ok()?;
            r.u16_le().ok()?;
            Place::Field {
                register,
                field: r.u32_le().ok()? & hexcavator_codeview::symbols::OFFSET_PARENT_MASK,
            }
        }
        kind::S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE => {
            let offset = r.u32_le().ok()? as i32;
            return Some(VarRange {
                start: whole.0,
                end: whole.1,
                gaps: Vec::new(),
                place: Place::Frame {
                    offset,
                    param: false,
                },
            });
        }
        kind::S_DEFRANGE_REGISTER_REL => {
            let register = r.u16_le().ok()?;
            r.u16_le().ok()?;
            Place::Relative {
                register,
                offset: r.u32_le().ok()? as i32,
            }
        }
        _ => return None,
    };
    // CV_LVAR_ADDR_RANGE, then gaps (each an offset from the range's start
    // and a length).
    let offset = r.u32_le().ok()?;
    let segment = r.u16_le().ok()?;
    let len = r.u16_le().ok()?;
    let start = rva_in(sections, segment, offset)?;
    let mut gaps = Vec::new();
    while let (Ok(at), Ok(n)) = (r.u16_le(), r.u16_le()) {
        gaps.push((start + u64::from(at), u64::from(n)));
    }
    Some(VarRange {
        start,
        end: start + u64::from(len),
        gaps,
        place,
    })
}

/// The addressed symbols of one module's stream.
fn module_symbols(
    sections: &[(u32, u32)],
    module: u32,
    records: SymbolIter<'_>,
    out: &mut Vec<DebugSymbol>,
) {
    let push = |out: &mut Vec<DebugSymbol>, mut s: DebugSymbol| {
        s.compiland = Some(module);
        out.push(s);
    };
    // Procedures by the offset of their record, which nested records name
    // as their parent.
    let mut procedures: HashMap<u32, (u64, &[u8], u32)> = HashMap::new();
    let mut last_procedure: Option<(u64, &[u8], u32)> = None;
    // The procedures seen (address, name, type, parameters), and the open
    // scopes, each with the procedure it lies in, if any, and whether it is
    // that procedure's own scope (where its parameters are).
    let mut procs: Vec<Proc<'_>> = Vec::new();
    let mut scopes: Vec<(Option<usize>, bool)> = Vec::new();
    // Data declared in procedures: (index in `out`, procedure).
    let mut statics: Vec<(usize, usize)> = Vec::new();
    for record in records {
        if kind::closes_scope(record.kind) {
            scopes.pop();
        }
        let (enclosing, top) = scopes.last().copied().unwrap_or((None, false));
        if kind::opens_scope(record.kind) {
            let own = match record.parse() {
                Ok(Symbol::Procedure {
                    offset,
                    segment,
                    name,
                    ty,
                    ..
                }) => {
                    procs.push(Proc {
                        addr: rva_in(sections, segment, offset),
                        name,
                        ty: ty.0,
                        params: Vec::new(),
                        inlinee: None,
                    });
                    Some(procs.len() - 1)
                }
                // An inlined copy of a function: its locals are that
                // function's (named from its id, later).
                Ok(Symbol::InlineSite { inlinee, .. }) => {
                    procs.push(Proc {
                        addr: enclosing.and_then(|p| procs[p].addr),
                        name: b"",
                        ty: 0,
                        params: Vec::new(),
                        inlinee: Some(inlinee.0),
                    });
                    Some(procs.len() - 1)
                }
                _ => None,
            };
            // (Bounded: a stream can't nest deeper than it has records.)
            scopes.push((own.or(enclosing), own.is_some()));
        }
        // A procedure's parameters are its own scope's locals flagged as
        // such (`this` is the object pointer, not a parameter).
        if top
            && let Some(p) = enclosing
            && let Ok(Symbol::Local { ty, flags, name }) = record.parse()
            && flags & 1 != 0
            && name != b"this"
        {
            procs[p].params.push((lossy(name), to_ref(ty)));
            continue;
        }
        let Ok(parsed) = record.parse() else { continue };
        match parsed {
            Symbol::Procedure {
                global,
                len,
                ty,
                offset,
                segment,
                flags,
                name,
                ..
            } => {
                let Some(addr) = rva_in(sections, segment, offset) else {
                    continue;
                };
                procedures.insert(record.offset, (addr, name, ty.0));
                last_procedure = Some((addr, name, ty.0));
                push(
                    out,
                    DebugSymbol {
                        size: Some(u64::from(len)),
                        global,
                        type_index: u64::from(ty.0),
                        flags: u32::from(flags),
                        ..symbol(SymbolKind::Function, addr, name)
                    },
                );
            }
            Symbol::SeparatedCode {
                parent,
                len,
                offset,
                segment,
                ..
            } => {
                let Some(addr) = rva_in(sections, segment, offset) else {
                    continue;
                };
                // The function is the record's lexical parent, if it has
                // one, or else (as the linker writes them, at the top level
                // right after the function) the procedure before it. The
                // record's parent address fields are no help: for a function
                // folded by ICF they give the address of the copy that was
                // discarded.
                let function = if parent != 0 {
                    procedures.get(&parent).copied()
                } else {
                    last_procedure
                };
                push(
                    out,
                    DebugSymbol {
                        size: Some(u64::from(len)),
                        parent: function.map(|p| p.0),
                        type_index: function.map_or(0, |p| u64::from(p.2)),
                        ..symbol(
                            SymbolKind::SeparatedBlock,
                            addr,
                            function.map_or(&b""[..], |p| p.1),
                        )
                    },
                );
            }
            Symbol::Block {
                len,
                offset,
                segment,
                name,
                ..
            } => {
                let Some(addr) = rva_in(sections, segment, offset) else {
                    continue;
                };
                push(
                    out,
                    DebugSymbol {
                        size: Some(u64::from(len)),
                        ..symbol(SymbolKind::Block, addr, name)
                    },
                );
            }
            Symbol::Thunk {
                offset,
                segment,
                len,
                name,
                ..
            } => {
                let Some(addr) = rva_in(sections, segment, offset) else {
                    continue;
                };
                push(
                    out,
                    DebugSymbol {
                        size: Some(u64::from(len)),
                        ..symbol(SymbolKind::Thunk, addr, name)
                    },
                );
            }
            Symbol::Label {
                offset,
                segment,
                flags,
                name,
            } => {
                let Some(addr) = rva_in(sections, segment, offset) else {
                    continue;
                };
                push(
                    out,
                    DebugSymbol {
                        flags: u32::from(flags),
                        ..symbol(SymbolKind::Label, addr, name)
                    },
                );
            }
            Symbol::Data {
                global,
                thread,
                ty,
                offset,
                segment,
                name,
            } => {
                let Some(addr) = rva_in(sections, segment, offset) else {
                    continue;
                };
                push(
                    out,
                    DebugSymbol {
                        global,
                        thread_local: thread,
                        type_index: u64::from(ty.0),
                        parent: enclosing.and_then(|p| procs[p].addr),
                        ..symbol(SymbolKind::Data, addr, name)
                    },
                );
                if let Some(p) = enclosing {
                    statics.push((out.len() - 1, p));
                }
            }
            _ => {}
        }
    }
    for (i, p) in statics {
        let p = &procs[p];
        out[i].function = Some(Box::new(EnclosingFunction {
            name: lossy(p.name),
            ty: TypeRef(u64::from(p.ty)),
            params: p.params.clone(),
        }));
        if let Some(id) = p.inlinee {
            // Resolved from the id stream once all modules are read.
            out[i].function.as_mut().expect("just set").ty = TypeRef(u64::from(id));
            out[i].flags |= INLINEE_PENDING;
        }
    }
}

/// A method's kind, from its attributes (`CV_fldattr_t`, bits 2-4).
fn method_kind(attributes: u16) -> MethodKind {
    match (attributes >> 2) & 7 {
        1 => MethodKind::Virtual,
        2 => MethodKind::Static,
        3 => MethodKind::Friend,
        4 => MethodKind::IntroVirtual,
        5 => MethodKind::PureVirtual,
        6 => MethodKind::PureIntroVirtual,
        _ => MethodKind::Plain,
    }
}

/// A procedure, or an inlined copy of one, that holds declarations.
struct Proc<'a> {
    addr: Option<u64>,
    name: &'a [u8],
    ty: u32,
    params: Vec<(String, TypeRef)>,
    /// For an inlined copy: the inlined function's id (IPI).
    inlinee: Option<u32>,
}

/// Set in a data symbol's flags while its enclosing function is an
/// inlinee id still to be named (data symbols' flags are otherwise 0).
const INLINEE_PENDING: u32 = 1 << 31;

/// An inlined function's qualified name, from its id record.
fn inlinee_name(
    ids: &hexcavator_pdb::TypeStream<'_>,
    formatter: &TypeFormatter<'_>,
    id: u32,
) -> Option<String> {
    inlinee(ids, formatter, id).map(|(name, _)| name)
}

/// An inlined function's qualified name and type, from its id record
/// (`LF_FUNC_ID`: scope string, type, name; `LF_MFUNC_ID`: class, type,
/// name).
fn inlinee(
    ids: &hexcavator_pdb::TypeStream<'_>,
    formatter: &TypeFormatter<'_>,
    id: u32,
) -> Option<(String, TypeRef)> {
    use hexcavator_codeview::types::leaf;
    let rec = ids.record(TypeIndex(id))?;
    let mut r = Reader::new(rec.data);
    let scope = r.u32_le().ok()?;
    let ty = r.u32_le().ok()?;
    let name = lossy(r.cstr().ok()?);
    let qualified = match rec.kind {
        leaf::LF_FUNC_ID if scope != 0 => {
            let s = ids.record(TypeIndex(scope)).and_then(|s| s.name());
            match s {
                Some(s) if !s.is_empty() => format!("{}::{name}", lossy(s)),
                _ => name,
            }
        }
        leaf::LF_FUNC_ID => name,
        leaf::LF_MFUNC_ID => {
            let class = formatter.name(TypeIndex(scope));
            // Id records name constructors and destructors `{ctor}` and
            // `{dtor}`; procedures, by the class's own name.
            let name = match name.as_str() {
                "{ctor}" => last_component(&class).to_string(),
                "{dtor}" => format!("~{}", last_component(&class)),
                _ => name,
            };
            format!("{class}::{name}")
        }
        _ => return None,
    };
    Some((qualified, TypeRef(u64::from(ty))))
}

/// The last `::`-separated component of a qualified name, ignoring `::`
/// within template arguments, without its template arguments.
fn last_component(name: &str) -> &str {
    let bytes = name.as_bytes();
    let mut depth = 0i32;
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'<' | b'(' => depth += 1,
            b'>' | b')' => depth -= 1,
            b':' if depth == 0 && bytes.get(i + 1) == Some(&b':') => {
                start = i + 2;
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    let last = &name[start..];
    last.find('<').map_or(last, |t| &last[..t])
}

/// A public or global data symbol from the shared record stream.
fn shared_symbol(sections: &[(u32, u32)], parsed: Symbol<'_>) -> Option<DebugSymbol> {
    Some(match parsed {
        Symbol::Public {
            flags,
            offset,
            segment,
            name,
        } => DebugSymbol {
            flags,
            ..symbol(SymbolKind::Public, rva_in(sections, segment, offset)?, name)
        },
        Symbol::Data {
            global,
            thread,
            ty,
            offset,
            segment,
            name,
        } => DebugSymbol {
            global,
            thread_local: thread,
            type_index: u64::from(ty.0),
            ..symbol(SymbolKind::Data, rva_in(sections, segment, offset)?, name)
        },
        _ => return None,
    })
}

/// Parses an `S_ENVBLOCK` body: a flags byte, then alternating key and
/// value strings, ending at an empty key.
pub(crate) fn parse_env_block(data: &[u8]) -> Result<Vec<(String, String)>> {
    let mut r = Reader::new(data);
    r.u8()?;
    let mut pairs = Vec::new();
    while !r.is_empty() {
        let key = r.cstr()?;
        if key.is_empty() {
            break;
        }
        let value = r.cstr().map_err(|_| {
            Error::new(
                ErrorKind::Truncated,
                r.position() as u64,
                "S_ENVBLOCK value",
            )
        })?;
        pairs.push((lossy(key), lossy(value)));
    }
    Ok(pairs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn def_ranges() {
        use crate::Place;
        // One section, at RVA 0x1000.
        let sections = [(0x1000u32, 0x1000u32)];
        let range = |offset: u32, len: u16| {
            let mut b = offset.to_le_bytes().to_vec();
            b.extend_from_slice(&1u16.to_le_bytes());
            b.extend_from_slice(&len.to_le_bytes());
            b
        };
        // In rcx (330) from +0x10 for 0x20 bytes, but for a gap at +4 of 2.
        let mut data = 330u16.to_le_bytes().to_vec();
        data.extend_from_slice(&[0, 0]);
        data.extend(range(0x10, 0x20));
        data.extend_from_slice(&4u16.to_le_bytes());
        data.extend_from_slice(&2u16.to_le_bytes());
        let r = def_range(&sections, kind::S_DEFRANGE_REGISTER, &data, (0, 0)).unwrap();
        assert_eq!(
            (r.start, r.end, r.place.clone()),
            (0x1010, 0x1030, Place::Register(330))
        );
        assert_eq!(r.gaps, [(0x1014, 2)]);
        // A field (at 4) in edx (19).
        let mut data = 19u16.to_le_bytes().to_vec();
        data.extend_from_slice(&[0, 0]);
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend(range(0, 8));
        let r = def_range(&sections, kind::S_DEFRANGE_SUBFIELD_REGISTER, &data, (0, 0)).unwrap();
        assert_eq!(
            r.place,
            Place::Field {
                register: 19,
                field: 4
            }
        );
        // [rsp+0x40] (335).
        let mut data = 335u16.to_le_bytes().to_vec();
        data.extend_from_slice(&[0, 0]);
        data.extend_from_slice(&0x40i32.to_le_bytes());
        data.extend(range(0, 8));
        let r = def_range(&sections, kind::S_DEFRANGE_REGISTER_REL, &data, (0, 0)).unwrap();
        assert_eq!(
            r.place,
            Place::Relative {
                register: 335,
                offset: 0x40
            }
        );
        // The frame, over the whole function.
        let r = def_range(
            &sections,
            kind::S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE,
            &(-8i32).to_le_bytes(),
            (0x1000, 0x1080),
        )
        .unwrap();
        assert_eq!(
            (r.start, r.end, r.place),
            (
                0x1000,
                0x1080,
                Place::Frame {
                    offset: -8,
                    param: false
                }
            )
        );
        // DIA programs aren't read; truncated records give nothing; a
        // section not there, nothing.
        assert!(def_range(&sections, kind::S_DEFRANGE, &[1, 2, 3, 4], (0, 0)).is_none());
        for n in 0..data.len() - 1 {
            assert!(
                def_range(&sections, kind::S_DEFRANGE_REGISTER_REL, &data[..n], (0, 0)).is_none()
            );
        }
        assert!(def_range(&[], kind::S_DEFRANGE_REGISTER_REL, &data, (0, 0)).is_none());
    }

    fn record(out: &mut Vec<u8>, kind: u16, body: &[u8]) {
        let mut body = body.to_vec();
        while !(body.len() + 2).is_multiple_of(4) {
            body.push(0);
        }
        out.extend_from_slice(&u16::try_from(body.len() + 2).unwrap().to_le_bytes());
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&body);
    }

    fn cstr(body: &mut Vec<u8>, s: &str) {
        body.extend_from_slice(s.as_bytes());
        body.push(0);
    }

    fn procedure(out: &mut Vec<u8>, offset: u32, ty: u32, name: &str) {
        let mut b = Vec::new();
        for v in [0u32, 0, 0, 0x10, 0, 0, ty, offset] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&1u16.to_le_bytes());
        b.push(0);
        cstr(&mut b, name);
        record(out, kind::S_GPROC32, &b);
    }

    fn local(out: &mut Vec<u8>, ty: u32, flags: u16, name: &str) {
        let mut b = ty.to_le_bytes().to_vec();
        b.extend_from_slice(&flags.to_le_bytes());
        cstr(&mut b, name);
        record(out, kind::S_LOCAL, &b);
    }

    fn data(out: &mut Vec<u8>, offset: u32, ty: u32, name: &str) {
        let mut b = ty.to_le_bytes().to_vec();
        b.extend_from_slice(&offset.to_le_bytes());
        b.extend_from_slice(&2u16.to_le_bytes());
        cstr(&mut b, name);
        record(out, kind::S_LDATA32, &b);
    }

    fn inline_site(out: &mut Vec<u8>, inlinee: u32) {
        let mut b = Vec::new();
        for v in [0u32, 0, inlinee] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        record(out, kind::S_INLINESITE, &b);
    }

    fn walk(stream: &[u8]) -> Vec<DebugSymbol> {
        let mut out = Vec::new();
        module_symbols(
            &[(0x1000, 0x1000), (0x2000, 0x1000)],
            3,
            SymbolIter::new(stream, 0),
            &mut out,
        );
        out
    }

    #[test]
    fn statics_know_their_functions_and_parameters() {
        let mut s = Vec::new();
        procedure(&mut s, 0x10, 0x1001, "C::f");
        local(&mut s, 0x1002, 1, "this");
        local(&mut s, 0x74, 1, "x");
        local(&mut s, 0x74, 0, "y");
        data(&mut s, 0, 0x74, "counter");
        inline_site(&mut s, 0x1234);
        local(&mut s, 0x22, 1, "p");
        data(&mut s, 4, 0x74, "inner");
        record(&mut s, kind::S_INLINESITE_END, &[]);
        // A block inside the function: still the function's.
        let mut b = vec![0u8; 12];
        b.extend_from_slice(&0x14u32.to_le_bytes());
        b.extend_from_slice(&1u16.to_le_bytes());
        cstr(&mut b, "");
        record(&mut s, kind::S_BLOCK32, &b);
        local(&mut s, 0x74, 1, "not_a_parameter");
        data(&mut s, 8, 0x74, "in_block");
        record(&mut s, kind::S_END, &[]);
        record(&mut s, kind::S_END, &[]);
        data(&mut s, 12, 0x74, "file_scope");
        let out = walk(&s);
        let find = |n: &str| out.iter().find(|d| d.name == n).unwrap();
        let counter = find("counter");
        assert_eq!(counter.addr, 0x2000);
        assert_eq!(counter.parent, Some(0x1010));
        assert_eq!(counter.compiland, Some(3));
        let f = counter.function.as_deref().unwrap();
        assert_eq!((f.name.as_str(), f.ty), ("C::f", TypeRef(0x1001)));
        assert_eq!(f.params, [("x".to_string(), TypeRef(0x74))]);
        // In an inlined copy: the inlinee's (named later, from its id).
        let inner = find("inner");
        assert_eq!(inner.parent, Some(0x1010));
        assert_eq!(inner.flags & INLINEE_PENDING, INLINEE_PENDING);
        let f = inner.function.as_deref().unwrap();
        assert_eq!(f.ty, TypeRef(0x1234));
        assert_eq!(f.params, [("p".to_string(), TypeRef(0x22))]);
        // In a block of the function: the function's, whose parameters
        // are its own scope's only.
        let f = find("in_block").function.as_deref().unwrap();
        assert_eq!(f.name, "C::f");
        assert_eq!(f.params.len(), 1);
        let outside = find("file_scope");
        assert_eq!((outside.parent, outside.function.is_none()), (None, true));
    }

    #[test]
    fn unbalanced_scopes_do_not_panic() {
        let mut s = Vec::new();
        record(&mut s, kind::S_END, &[]);
        record(&mut s, kind::S_INLINESITE_END, &[]);
        data(&mut s, 0, 0x74, "a");
        for _ in 0..1000 {
            inline_site(&mut s, 0x1000);
        }
        data(&mut s, 4, 0x74, "deep");
        let out = walk(&s);
        assert!(
            out.iter()
                .find(|d| d.name == "a")
                .unwrap()
                .function
                .is_none()
        );
        assert!(
            out.iter()
                .find(|d| d.name == "deep")
                .unwrap()
                .function
                .is_some()
        );
    }

    #[test]
    fn last_components() {
        assert_eq!(last_component("A"), "A");
        assert_eq!(last_component("ns::A"), "A");
        assert_eq!(last_component("ns::A<x::y, z>"), "A");
        assert_eq!(last_component("a::B<c::D>::E<f::G>"), "E");
        assert_eq!(last_component(""), "");
    }

    #[test]
    fn env_block() {
        let data = b"\0cwd\0C:\\src\0cmd\0 /DLL /DEBUG\0\0";
        assert_eq!(
            parse_env_block(data).unwrap(),
            [
                ("cwd".to_string(), "C:\\src".to_string()),
                ("cmd".to_string(), " /DLL /DEBUG".to_string())
            ]
        );
    }

    #[test]
    fn env_block_edge_cases() {
        // Only the flags byte; no terminator.
        assert!(parse_env_block(b"\0").unwrap().is_empty());
        // Terminator right away.
        assert!(parse_env_block(b"\0\0").unwrap().is_empty());
        // Empty input lacks the flags byte.
        assert!(parse_env_block(b"").is_err());
        // A key with no value.
        assert!(parse_env_block(b"\0cwd\0").is_err());
        // A key with no terminator.
        assert!(parse_env_block(b"\0cwd").is_err());
        // An empty value is fine.
        assert_eq!(
            parse_env_block(b"\0src\0\0\0").unwrap(),
            [("src".to_string(), String::new())]
        );
    }
}
