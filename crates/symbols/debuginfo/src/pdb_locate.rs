//! [`crate::Locator`] for PDBs: the module whose contribution holds an
//! address (from the section contributions), its procedure there, the
//! inline sites in that procedure whose code holds it (from their binary
//! annotations), and their lines: an inline site's line from its
//! annotations (counted from its inlinee's first line, in the module's
//! inlinee lines), the procedure's from the module's line table. A site's
//! line at an address of a site nested in it is where it calls the nested
//! one, as is the procedure's at an address of its sites'.

use std::collections::HashMap;

use hexcavator_codeview::TypeFormatter;
use hexcavator_codeview::annotations;
use hexcavator_codeview::lines::{self, subsection};
use hexcavator_codeview::symbols::{Symbol, kind};
use hexcavator_pdb::{LazyTypeStream, ModuleStream, StringTable};

use crate::locate::{Frame, MAX_FRAMES};
use crate::pdb_backend::{
    PdbInfo, function_line_blocks, inlinee_name, last_component, line_spans, rva_in,
};

/// How many modules' tables are kept at once.
const MAX_KEPT: usize = 512;

pub(crate) struct PdbLocator<'a, 'data> {
    info: &'a PdbInfo<'data>,
    /// Modules read, by index.
    modules: HashMap<u16, Option<ModuleTables<'data>>>,
    /// Inlinees' names, by id.
    names: HashMap<u32, String>,
    /// The string table source files' names are in.
    strings: Option<StringTable<'a>>,
    /// The id and type streams, read a record at a time (inlinees' names
    /// need few of their records).
    lazy: Option<(LazyTypeStream<'a, 'data>, LazyTypeStream<'a, 'data>)>,
}

/// What a lookup needs of one module.
struct ModuleTables<'data> {
    stream: ModuleStream<'data>,
    /// Its procedures and separated blocks of code: (start, end, record
    /// offset, the procedure's start), sorted by start.
    code: Vec<(u64, u64, u32, u64)>,
    /// Its line table: (start, end, file, line), sorted by start.
    lines: Vec<(u64, u64, u32, u32)>,
    /// Each inlinee's (file, first line).
    inlinees: HashMap<u32, (u32, u32)>,
}

impl ModuleTables<'_> {
    /// The path of the file whose checksum entry is at `offset`.
    fn path(&self, strings: Option<&StringTable<'_>>, offset: u32) -> Option<String> {
        let c = self.stream.file_checksum(offset)?;
        Some(strings?.get_str(c.name)?.to_string())
    }
}

/// An inline site within a procedure: its parent (another site's index),
/// its inlinee's id, and its annotations decoded.
struct Site {
    parent: Option<usize>,
    inlinee: u32,
    decoded: annotations::Site,
}

impl<'a, 'data> PdbLocator<'a, 'data> {
    pub(crate) fn new(info: &'a PdbInfo<'data>) -> Self {
        Self {
            info,
            modules: HashMap::new(),
            names: HashMap::new(),
            strings: info.pdb().names().ok(),
            lazy: info.pdb().lazy_ids().ok().zip(info.pdb().lazy_types().ok()),
        }
    }

    pub(crate) fn frames(&mut self, addr: u64) -> Vec<Frame> {
        let Ok(rva) = u32::try_from(addr) else {
            return Vec::new();
        };
        let info = self.info;
        let Some((section, offset)) = section_of(info.section_table(), rva) else {
            return Vec::new();
        };
        let pdb = info.pdb();
        let module = pdb.dbi().ok().and_then(|d| {
            d.contribution_at(section, offset)
                .map(|c| c.module_index.get())
        });
        let mut frames = match module {
            Some(m) => self.module_frames(m, addr),
            None => Vec::new(),
        };
        if frames.is_empty()
            && let Ok(Some((record, distance))) = pdb.public_at(section, offset)
            && let Ok(Symbol::Public { name, .. }) = record.parse()
            && !self.past_procedure(addr - u64::from(distance), addr)
        {
            // (Code no procedure covers: assembly, a stub, a stripped
            // PDB. Its line, if its module has one.)
            let (file, line) = match module {
                Some(m) => self.line(m, addr),
                None => (None, 0),
            };
            frames.push(Frame {
                function: String::from_utf8_lossy(name).into_owned(),
                decorated: true,
                start: Some(addr - u64::from(distance)),
                file,
                line,
                inlined: false,
            });
        }
        frames
    }

    /// Whether a procedure starts at `start` and ends before `addr` (which
    /// is then padding after it, not its code).
    fn past_procedure(&mut self, start: u64, addr: u64) -> bool {
        let info = self.info;
        let m = u32::try_from(start)
            .ok()
            .and_then(|rva| section_of(info.section_table(), rva))
            .and_then(|(s, o)| {
                info.pdb()
                    .dbi()
                    .ok()?
                    .contribution_at(s, o)
                    .map(|c| c.module_index.get())
            });
        let Some(t) = m.and_then(|m| tables(&mut self.modules, info, m)) else {
            return false;
        };
        let i = t.code.partition_point(|c| c.0 < start);
        t.code[i..]
            .iter()
            .take_while(|c| c.0 == start)
            .any(|c| c.1 <= addr)
    }

    /// The file and line of `addr` in module `m`'s line table.
    fn line(&mut self, m: u16, addr: u64) -> (Option<String>, u32) {
        let Some(t) = tables(&mut self.modules, self.info, m) else {
            return (None, 0);
        };
        let strings = self.strings.as_ref();
        line_at(&t.lines, addr).map_or((None, 0), |(f, l)| (t.path(strings, f), l))
    }

    fn module_frames(&mut self, m: u16, addr: u64) -> Vec<Frame> {
        let strings = self.strings.as_ref();
        let Some(t) = tables(&mut self.modules, self.info, m) else {
            return Vec::new();
        };
        let i = t.code.partition_point(|c| c.0 <= addr);
        let Some(&(_, end, record, start)) = i.checked_sub(1).and_then(|i| t.code.get(i)) else {
            return Vec::new();
        };
        if addr >= end {
            return Vec::new();
        }
        // The procedure: its name, and the inline sites in its scope.
        let Some(proc) = t.stream.symbol_at(record) else {
            return Vec::new();
        };
        let (name, scope_end, base) = match proc.parse() {
            Ok(Symbol::Procedure { name, end, .. }) => (name, end, record),
            Ok(Symbol::SeparatedCode { parent, .. }) => {
                // A block separated from its procedure: the procedure's.
                match t.stream.symbol_at(parent).and_then(|p| p.parse().ok()) {
                    Some(Symbol::Procedure { name, end, .. }) => (name, end, parent),
                    _ => return Vec::new(),
                }
            }
            _ => return Vec::new(),
        };
        let function = String::from_utf8_lossy(name).into_owned();
        let sites = proc_sites(&t.stream, base, scope_end);
        // (Annotations' offsets are from the procedure's start.)
        let Ok(offset) = u32::try_from(addr - start) else {
            return Vec::new();
        };
        let chain = site_chain(&sites, offset);
        let mut frames = Vec::with_capacity(chain.len() + 1);
        let mut pending = Vec::new();
        for &s in &chain {
            let site = &sites[s];
            let (file, first) = t
                .inlinees
                .get(&site.inlinee)
                .copied()
                .unwrap_or((u32::MAX, 0));
            let (delta, changed) = line_in_site(&site.decoded, offset);
            let file = changed.unwrap_or(file);
            frames.push(Frame {
                function: String::new(),
                decorated: false,
                start: None,
                file: t.path(strings, file),
                line: first.saturating_add_signed(delta),
                inlined: true,
            });
            pending.push(site.inlinee);
        }
        let (file, line) =
            line_at(&t.lines, addr).map_or((None, 0), |(f, l)| (t.path(strings, f), l));
        frames.push(Frame {
            function,
            decorated: false,
            start: Some(start),
            file,
            line,
            inlined: false,
        });
        // The inlinees' names (from the id stream, each once).
        for (frame, id) in frames.iter_mut().zip(pending) {
            frame.function = inlinee(&mut self.names, self.lazy.as_ref(), self.info, id);
        }
        frames
    }
}

/// Module `m`'s tables, read if they haven't been (`None` if it has no
/// symbols).
fn tables<'m, 'data>(
    modules: &'m mut HashMap<u16, Option<ModuleTables<'data>>>,
    info: &PdbInfo<'data>,
    m: u16,
) -> Option<&'m ModuleTables<'data>> {
    if !modules.contains_key(&m) {
        if modules.len() >= MAX_KEPT {
            modules.clear();
        }
        modules.insert(m, read_module(info, m));
    }
    modules.get(&m)?.as_ref()
}

/// Inlinee `id`'s qualified name (kept in `names`): from the records it
/// needs (`lazy`), else from the whole id and type streams.
fn inlinee(
    names: &mut HashMap<u32, String>,
    lazy: Option<&(LazyTypeStream<'_, '_>, LazyTypeStream<'_, '_>)>,
    info: &PdbInfo<'_>,
    id: u32,
) -> String {
    if let Some(n) = names.get(&id) {
        return n.clone();
    }
    let name = lazy
        .and_then(|(ids, types)| lazy_inlinee(ids, types, id))
        .or_else(|| {
            let pdb = info.pdb();
            let (ids, types) = (pdb.ids().ok()?, pdb.types().ok()?);
            inlinee_name(ids, &TypeFormatter { types }, id)
        })
        .unwrap_or_else(|| format!("<inlinee {id:#x}>"));
    names.insert(id, name.clone());
    name
}

/// Inlinee `id`'s qualified name, as [`inlinee_name`] gives it, from the
/// few records it needs: its id record (`LF_FUNC_ID`: scope string, type,
/// name; `LF_MFUNC_ID`: class, type, name), and its scope's or class's.
fn lazy_inlinee(
    ids: &LazyTypeStream<'_, '_>,
    types: &LazyTypeStream<'_, '_>,
    id: u32,
) -> Option<String> {
    use hexcavator_codeview::types::{TypeIndex, leaf};
    let lossy = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    let (kind, scope, name) = ids.with_record(TypeIndex(id), |rec| {
        let mut r = hexcavator_core::Reader::new(rec.data);
        let scope = r.u32_le().ok()?;
        let _ty = r.u32_le().ok()?;
        Some((rec.kind, scope, lossy(r.cstr().ok()?)))
    })??;
    let named = |s: &LazyTypeStream<'_, '_>, ti: u32| {
        s.with_record(TypeIndex(ti), |r| r.name().map(lossy))
            .flatten()
    };
    Some(match kind {
        leaf::LF_FUNC_ID if scope != 0 => match named(ids, scope) {
            Some(s) if !s.is_empty() => format!("{s}::{name}"),
            _ => name,
        },
        leaf::LF_FUNC_ID => name,
        leaf::LF_MFUNC_ID => {
            // (A class whose record isn't a user-defined type's: as the
            // whole streams name it.)
            let class = named(types, scope)?;
            let name = match (name.as_str(), last_component(&class)) {
                ("{ctor}", own) if !own.is_empty() => own.to_string(),
                ("{dtor}", own) if !own.is_empty() => format!("~{own}"),
                _ => name,
            };
            format!("{class}::{name}")
        }
        _ => return None,
    })
}

/// The section (1-based) and offset of `rva`.
fn section_of(sections: &[(u32, u32)], rva: u32) -> Option<(u16, u32)> {
    sections.iter().zip(1u16..).find_map(|(&(va, size), n)| {
        let offset = rva.checked_sub(va)?;
        // (A section's virtual size can be 0 in old images: its raw size
        // isn't recorded here, so the next section's start bounds it.)
        (offset < size.max(1)).then_some((n, offset))
    })
}

/// Module `m`'s tables (`None` if it has no symbol stream).
fn read_module<'data>(info: &PdbInfo<'data>, m: u16) -> Option<ModuleTables<'data>> {
    let pdb = info.pdb();
    let dbi = pdb.dbi().ok()?;
    let module = dbi.modules().get(usize::from(m))?;
    let stream = pdb.module_stream(module).ok()??;
    let sections = info.section_table();
    let mut code = Vec::new();
    for record in stream.symbols() {
        if !kind::opens_scope(record.kind) {
            continue;
        }
        match record.parse() {
            Ok(Symbol::Procedure {
                offset,
                segment,
                len,
                ..
            }) => {
                if let Some(at) = rva_in(sections, segment, offset) {
                    code.push((at, at + u64::from(len), record.offset, at));
                }
            }
            Ok(Symbol::SeparatedCode {
                offset,
                segment,
                len,
                parent_offset,
                parent_segment,
                ..
            }) => {
                if let (Some(at), Some(parent)) = (
                    rva_in(sections, segment, offset),
                    rva_in(sections, parent_segment, parent_offset),
                ) {
                    code.push((at, at + u64::from(len), record.offset, parent));
                }
            }
            _ => {}
        }
    }
    code.sort_unstable_by_key(|c| (c.0, c.1));
    // The line table, and the inlinees' first lines.
    let mut table = Vec::new();
    let mut entries = Vec::new();
    for group in &function_line_blocks(&stream) {
        let Some(block) = group.first() else { continue };
        let Some(start) = rva_in(sections, block.segment, block.offset) else {
            continue;
        };
        entries.clear();
        entries.extend(group.iter().flat_map(|b| {
            b.lines
                .iter()
                .map(move |l| (l.offset.get(), b.file, l.line()))
        }));
        line_spans(
            &mut entries,
            block.code_size,
            true,
            |at, end, file, line| {
                table.push((start + u64::from(at), start + u64::from(end), file, line));
            },
        );
    }
    table.sort_unstable_by_key(|l| (l.0, l.1));
    let mut inlinees = HashMap::new();
    for (k, body) in stream.subsections() {
        if k == subsection::DEBUG_S_INLINEELINES {
            for e in lines::inlinee_lines(body) {
                inlinees.insert(e.inlinee, (e.file, e.line));
            }
        }
    }
    Some(ModuleTables {
        stream,
        code,
        lines: table,
        inlinees,
    })
}

/// The inline sites in the scope of the procedure whose record is at
/// `start`, which ends with the record at `end`.
fn proc_sites(stream: &ModuleStream<'_>, start: u32, end: u32) -> Vec<Site> {
    let mut sites = Vec::new();
    // The open scopes: each one's site, if it is one.
    let mut open: Vec<Option<usize>> = Vec::new();
    for record in stream.symbols_from(start) {
        if record.offset > end {
            break;
        }
        if kind::closes_scope(record.kind) {
            open.pop();
            if open.is_empty() {
                break;
            }
            continue;
        }
        if !kind::opens_scope(record.kind) {
            continue;
        }
        let parent = open.iter().rev().find_map(|s| *s);
        match record.parse() {
            Ok(Symbol::InlineSite {
                inlinee,
                annotations,
                ..
            }) => {
                sites.push(Site {
                    parent,
                    inlinee: inlinee.0,
                    decoded: annotations::decode(annotations),
                });
                open.push(Some(sites.len() - 1));
            }
            _ => open.push(None),
        }
    }
    sites
}

/// The sites whose code holds `offset`, innermost first: the deepest site
/// whose ranges hold it, then the sites it is nested in.
fn site_chain(sites: &[Site], offset: u32) -> Vec<usize> {
    let holds = |s: &Site| {
        s.decoded
            .ranges
            .iter()
            .any(|&(at, len)| offset >= at && offset - at < len)
    };
    let depth = |mut i: usize| {
        let mut d = 0;
        while let Some(p) = sites[i].parent {
            // (Parents come before their children: a chain can't loop.)
            if p >= i || d >= MAX_FRAMES {
                break;
            }
            i = p;
            d += 1;
        }
        d
    };
    let Some(deepest) = (0..sites.len())
        .filter(|&i| holds(&sites[i]))
        .max_by_key(|&i| (depth(i), i))
    else {
        return Vec::new();
    };
    let mut chain = vec![deepest];
    let mut at = deepest;
    while let Some(p) = sites[at].parent {
        if p >= at || chain.len() >= MAX_FRAMES {
            break;
        }
        chain.push(p);
        at = p;
    }
    chain
}

/// A site's line at `offset` (a delta from its inlinee's first line), and
/// the file its annotations changed to, if they did: as of its last line
/// entry at or before `offset` (at an offset of a site nested in it, the
/// line that calls that site).
fn line_in_site(site: &annotations::Site, offset: u32) -> (i32, Option<u32>) {
    let i = site.lines.partition_point(|l| l.0 <= offset);
    match i.checked_sub(1).and_then(|i| site.lines.get(i)) {
        Some(&(_, line, file)) => (line, file),
        // (Before its first entry: its first line.)
        None => site.lines.first().map_or((0, None), |&(_, l, f)| (l, f)),
    }
}

/// The (file, line) of the line table entry holding `addr`.
fn line_at(table: &[(u64, u64, u32, u32)], addr: u64) -> Option<(u32, u32)> {
    let i = table.partition_point(|l| l.0 <= addr);
    let &(_, end, file, line) = table.get(i.checked_sub(1)?)?;
    (addr < end).then_some((file, line))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(parent: Option<usize>, ranges: &[(u32, u32)], lines: &[(u32, i32)]) -> Site {
        Site {
            parent,
            inlinee: 0,
            decoded: annotations::Site {
                ranges: ranges.to_vec(),
                lines: lines.iter().map(|&(o, l)| (o, l, None)).collect(),
            },
        }
    }

    #[test]
    fn chains_are_innermost_first() {
        // lines.exe's third: sum_of_squares [0, 0xB), square [0, 3) and
        // [6, 0xB), square [3, 6).
        let sites = [
            site(None, &[(0, 0xB)], &[(0, 0)]),
            site(Some(0), &[(0, 3), (6, 5)], &[(0, 0), (6, 0)]),
            site(Some(0), &[(3, 3)], &[(3, 0)]),
        ];
        assert_eq!(site_chain(&sites, 0), [1, 0]);
        assert_eq!(site_chain(&sites, 4), [2, 0]);
        assert_eq!(site_chain(&sites, 0xA), [1, 0]);
        assert!(site_chain(&sites, 0xB).is_empty());
        // A parent whose ranges leave out its child's code still encloses
        // it.
        let gap = [
            site(None, &[(0, 2)], &[(0, 1)]),
            site(Some(0), &[(2, 2)], &[(2, 0)]),
        ];
        assert_eq!(site_chain(&gap, 3), [1, 0]);
    }

    #[test]
    fn hostile_parents_do_not_loop() {
        let sites = [site(Some(1), &[(0, 4)], &[]), site(Some(0), &[(0, 4)], &[])];
        assert!(site_chain(&sites, 1).len() <= 2);
        let own = [site(Some(0), &[(0, 4)], &[])];
        assert_eq!(site_chain(&own, 0), [0]);
    }

    #[test]
    fn site_lines_are_their_last_entry() {
        let s = site(None, &[(0x10, 0x20)], &[(0x10, 0), (0x14, 2), (0x18, -1)]).decoded;
        assert_eq!(line_in_site(&s, 0x10).0, 0);
        assert_eq!(line_in_site(&s, 0x17).0, 2);
        assert_eq!(line_in_site(&s, 0x2F).0, -1);
        assert_eq!(line_in_site(&s, 0).0, 0);
        assert_eq!(line_in_site(&annotations::Site::default(), 5), (0, None));
    }

    #[test]
    fn line_table_lookups() {
        let t = [(0x10, 0x14, 1, 7), (0x14, 0x20, 1, 8), (0x30, 0x31, 2, 9)];
        assert_eq!(line_at(&t, 0x10), Some((1, 7)));
        assert_eq!(line_at(&t, 0x1F), Some((1, 8)));
        assert_eq!(line_at(&t, 0x20), None);
        assert_eq!(line_at(&t, 0x30), Some((2, 9)));
        assert_eq!(line_at(&t, 0), None);
        assert_eq!(line_at(&[], 5), None);
    }

    #[test]
    fn line_spans_merge_files_and_share_offsets() {
        // A function's lines in two files: each entry runs to the next of
        // either; of two at one offset, the first.
        // either; of two at one offset, the first at it (exactly), the
        // last after.
        let lines = || vec![(0, 1, 12), (0, 1, 13), (6, 1, 14), (2, 2, 36), (4, 2, 37)];
        let mut out = Vec::new();
        line_spans(&mut lines(), 8, true, |a, b, f, l| out.push((a, b, f, l)));
        assert_eq!(
            out,
            [
                (0, 1, 1, 12),
                (1, 2, 1, 13),
                (2, 4, 2, 36),
                (4, 6, 2, 37),
                (6, 8, 1, 14)
            ]
        );
        // For the code's bytes: the last.
        out.clear();
        line_spans(&mut lines(), 8, false, |a, b, f, l| out.push((a, b, f, l)));
        assert_eq!(
            out,
            [(0, 2, 1, 13), (2, 4, 2, 36), (4, 6, 2, 37), (6, 8, 1, 14)]
        );
        // Entries past the code, or a block of none: nothing.
        out.clear();
        line_spans(&mut [(9, 1, 1)], 8, true, |a, b, f, l| {
            out.push((a, b, f, l));
        });
        assert!(out.is_empty());
        line_spans(&mut [], 8, true, |_, _, _, _| unreachable!());
    }

    #[test]
    fn sections_by_rva() {
        let s = [(0x1000, 0x200), (0x2000, 0x10)];
        assert_eq!(section_of(&s, 0x1000), Some((1, 0)));
        assert_eq!(section_of(&s, 0x11FF), Some((1, 0x1FF)));
        assert_eq!(section_of(&s, 0x1200), None);
        assert_eq!(section_of(&s, 0x200F), Some((2, 0xF)));
        assert_eq!(section_of(&s, 0x10), None);
    }
}
