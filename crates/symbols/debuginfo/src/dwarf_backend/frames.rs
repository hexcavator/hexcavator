//! [`crate::Locator`] for DWARF: the compile unit whose code holds an
//! address (by its ranges, or the address ranges table), its function
//! there and the inlined subroutines in it that hold the address (one walk
//! of the unit's DIEs, past functions that don't), and their lines: the
//! innermost's from the unit's line table, each other's from the call
//! inlined into it (`DW_AT_call_file`, `DW_AT_call_line`).

use std::collections::HashMap;

use hexcavator_dwarf::consts::*;
use hexcavator_dwarf::{Die, UnitSection, line_program};

use super::{DwarfInfo, MAX_DEPTH, UnitMeta, is_scope, locate as place, to_ref};
use crate::TypeRef;
use crate::locate::{Frame, MAX_FRAMES};

/// How many units' tables are kept at once.
const MAX_KEPT: usize = 512;

pub(crate) struct DwarfLocator<'a, 'data> {
    info: &'a DwarfInfo<'data>,
    /// The units' code: (start, end, unit index), sorted by start.
    code: Option<Vec<(u64, u64, usize)>>,
    /// Per unit (by index) read: its line table.
    tables: HashMap<usize, Table<'a>>,
    /// Per unit walked: the enclosing scope of each DIE in one.
    parents: HashMap<usize, HashMap<u64, u64>>,
    /// Per unit walked: its functions' code, as (start, end, the
    /// function's DIE's offset), sorted.
    functions: HashMap<usize, Vec<(u64, u64, u64)>>,
}

/// A unit's line table: its rows, sorted by address, as (address, end,
/// file index, line), and its files (and the directory they're relative
/// to).
#[derive(Default)]
struct Table<'a> {
    rows: Vec<(u64, u64, u64, u32)>,
    files: Option<(hexcavator_dwarf::LineProgram<'a>, String)>,
}

impl Table<'_> {
    fn path(&self, index: Option<u64>) -> Option<String> {
        let (program, dir) = self.files.as_ref()?;
        program.path(index?, dir.as_bytes())
    }
}

/// A DIE the address's code is in: a function or an inlined subroutine.
struct Found {
    at: TypeRef,
    depth: i64,
    inlined: bool,
    /// Where the call inlined here is (an inlined subroutine's).
    call: (Option<u64>, u32),
    /// Its first address (a function's).
    start: Option<u64>,
}

impl<'a, 'data> DwarfLocator<'a, 'data> {
    pub(crate) fn new(info: &'a DwarfInfo<'data>) -> Self {
        Self {
            info,
            code: None,
            tables: HashMap::new(),
            parents: HashMap::new(),
            functions: HashMap::new(),
        }
    }

    pub(crate) fn frames(&mut self, addr: u64) -> Vec<Frame> {
        let units = self.units_at(addr);
        for unit in units {
            let frames = self.unit_frames(unit, addr);
            if !frames.is_empty() {
                return frames;
            }
        }
        Vec::new()
    }

    /// The units whose code holds `addr`, nearest start first.
    fn units_at(&mut self, addr: u64) -> Vec<usize> {
        let info = self.info;
        let code = self.code.get_or_insert_with(|| unit_code(info));
        let i = code.partition_point(|c| c.0 <= addr);
        let mut out: Vec<usize> = code[..i]
            .iter()
            .rev()
            .filter(|c| addr < c.1)
            .map(|c| c.2)
            .collect();
        out.dedup();
        out
    }

    fn unit_frames(&mut self, unit: usize, addr: u64) -> Vec<Frame> {
        let info = self.info;
        let index = info.index();
        let Some(m) = index.units.get(unit) else {
            return Vec::new();
        };
        // The DIEs: a skeleton's split unit's, if it has one.
        let dies = m
            .compiland
            .and_then(|c| {
                index
                    .units
                    .iter()
                    .position(|s| s.split && s.compiland == Some(c))
            })
            .filter(|_| !m.split)
            .unwrap_or(unit);
        let Some(chain) = self.chain(dies, Some(addr)) else {
            return Vec::new();
        };
        if chain.is_empty() {
            return Vec::new();
        }
        if index.units.get(dies).is_none() {
            return Vec::new();
        }
        // The innermost frame's line, from the unit's line table; the
        // others', where the calls inlined into them are.
        self.table(unit, unit);
        if dies != unit {
            self.table(dies, unit);
        }
        // (A split unit without a line table of its own numbers its calls'
        // files by its skeleton's.)
        let lines = &self.tables[&unit];
        let calls = Some(&self.tables[&dies])
            .filter(|t| t.files.is_some())
            .unwrap_or(lines);
        let mut location = match row_at(&lines.rows, addr) {
            Some((file, line)) => (lines.path(Some(file)), line),
            None => (None, 0),
        };
        let mut frames = Vec::with_capacity(chain.len());
        for f in chain.iter().rev() {
            frames.push(Frame {
                function: String::new(),
                decorated: false,
                start: f.start.filter(|_| !f.inlined),
                file: location.0.take(),
                line: location.1,
                inlined: f.inlined,
            });
            location = (calls.path(f.call.0), f.call.1);
        }
        // Their names, by the scopes of the units their declarations are
        // in (each walked once).
        for (frame, f) in frames.iter_mut().zip(chain.iter().rev()) {
            let (decl, name) = info.origin(f.at);
            frame.function = match unit_of(info, decl) {
                Some(u) => {
                    let parents = self.unit_parents(u);
                    info.qualified_in(decl, name, parents)
                }
                None => info.qualified_in(decl, name, &HashMap::new()),
            };
        }
        frames
    }

    /// The enclosing scope of each DIE of unit `unit` in one (found once).
    fn unit_parents(&mut self, unit: usize) -> &HashMap<u64, u64> {
        if !self.parents.contains_key(&unit) {
            // (A walk for no address finds no chain, only the scopes.)
            let _ = self.chain(unit, None);
        }
        static NONE: std::sync::LazyLock<HashMap<u64, u64>> =
            std::sync::LazyLock::new(HashMap::new);
        self.parents.get(&unit).unwrap_or(&NONE)
    }

    /// Reads (once) the line table of unit `unit`, whose skeleton (or
    /// itself) is unit `of`: a skeleton's or whole unit's rows and files,
    /// or a split unit's files (for its calls).
    fn table(&mut self, unit: usize, of: usize) {
        if self.tables.contains_key(&unit) {
            return;
        }
        if self.tables.len() >= MAX_KEPT {
            self.tables.clear();
        }
        let info = self.info;
        let units = &info.index().units;
        let table = match (units.get(unit), units.get(of)) {
            (Some(m), _) if unit == of => info.unit_lines(m).map_or_else(Table::default, |l| {
                let mut rows: Vec<_> = l
                    .rows
                    .iter()
                    .map(|&(a, n, f, line)| (a, a.saturating_add(n), f, line))
                    .collect();
                rows.sort_unstable_by_key(|r| (r.0, r.1));
                Table {
                    rows,
                    files: Some((l.program, l.comp_dir)),
                }
            }),
            (Some(dm), Some(m)) => Table {
                rows: Vec::new(),
                files: split_files(info, dm, m),
            },
            _ => Table::default(),
        };
        self.tables.insert(unit, table);
    }

    /// The function and inlined subroutines of unit `unit` whose code
    /// holds `addr`, outermost first (`None` if the unit can't be read).
    /// The first walk of a unit reads all of it, for its scopes; later
    /// ones stop past the function.
    fn chain(&mut self, unit: usize, addr: Option<u64>) -> Option<Vec<Found>> {
        let info = self.info;
        let m = info.index().units.get(unit)?;
        let (u, abbrevs) = info.unit(m)?;
        // Walked before: from the function whose code holds it.
        if let (Some(addr), Some(functions)) = (addr, self.functions.get(&unit)) {
            let i = functions.partition_point(|f| f.0 <= addr);
            for &(_, end, at) in functions[..i].iter().rev().take(16) {
                if addr < end {
                    let chain = walk(info, m, &u, abbrevs, u.dies_at(at), Some(addr), None)?;
                    if !chain.is_empty() {
                        return Some(chain);
                    }
                }
            }
            return Some(Vec::new());
        }
        let mut walked = Walked::default();
        let chain = walk(info, m, &u, abbrevs, u.dies(), addr, Some(&mut walked))?;
        if self.parents.len() >= MAX_KEPT {
            self.parents.clear();
            self.functions.clear();
        }
        walked.functions.sort_unstable();
        self.parents.insert(unit, walked.parents);
        self.functions.insert(unit, walked.functions);
        Some(chain)
    }
}

/// What a whole unit's walk finds besides the chain: each DIE's enclosing
/// scope, and the functions' code (start, end, DIE offset).
#[derive(Default)]
struct Walked {
    parents: HashMap<u64, u64>,
    functions: Vec<(u64, u64, u64)>,
}

/// The function and inlined subroutines whose code holds `addr`, outermost
/// first, from the DIEs `r` reads: a whole unit's (finding `walked` too),
/// or one function's and what follows it (stopping past it).
fn walk<'u>(
    info: &DwarfInfo<'_>,
    m: &UnitMeta,
    u: &hexcavator_dwarf::Unit<'u>,
    abbrevs: &hexcavator_dwarf::Abbrevs,
    mut r: hexcavator_dwarf::DieReader<'u>,
    addr: Option<u64>,
    mut walked: Option<&mut Walked>,
) -> Option<Vec<Found>> {
    let whole = walked.is_some();
    let mut stack: Vec<(i64, TypeRef, u16)> = Vec::new();
    let mut chain: Vec<Found> = Vec::new();
    let mut done = false;
    let mut first = true;
    let mut attrs = Vec::new();
    while let Some(a) = r.next(abbrevs) {
        let offset = r.offset;
        let depth = r.depth - i64::from(a.children);
        r.attrs(u, a, &mut attrs)?;
        // (One function's walk: past its subtree, done.)
        if !whole && !first && depth <= 0 {
            break;
        }
        first = false;
        while stack.last().is_some_and(|s| s.0 >= depth) {
            stack.pop();
        }
        if chain.last().is_some_and(|f| f.depth >= depth) {
            // Past the innermost DIE found: the chain is whole.
            done = true;
            if !whole {
                break;
            }
        }
        let at = to_ref(m.file, m.section, offset);
        if let Some(w) = walked.as_deref_mut()
            && let Some(&(_, p, tag)) = stack.last()
            && is_scope(tag)
        {
            w.parents.insert(at.0, p.0);
        }
        let die = Die {
            offset,
            tag: a.tag,
            children: a.children,
            attrs: std::mem::take(&mut attrs),
            next: r.position(),
        };
        let mut skip = false;
        if matches!(
            a.tag,
            DW_TAG_SUBPROGRAM | DW_TAG_INLINED_SUBROUTINE | DW_TAG_LEXICAL_BLOCK
        ) {
            let ranges = info.ranges(u, &die);
            if a.tag == DW_TAG_SUBPROGRAM
                && let Some(w) = walked.as_deref_mut()
            {
                w.functions.extend(
                    ranges
                        .iter()
                        .map(|&(s, n)| (s, s.saturating_add(n), offset)),
                );
            }
            let holds =
                addr.is_some_and(|addr| ranges.iter().any(|&(s, n)| addr >= s && addr - s < n));
            if ranges.is_empty() {
                // (A declaration, or an abstract function: no code.)
                skip = a.tag != DW_TAG_LEXICAL_BLOCK;
            } else if !holds || done {
                // (A whole walk still reads functions nested in others.)
                skip = !(whole && a.tag == DW_TAG_SUBPROGRAM);
            } else if a.tag != DW_TAG_LEXICAL_BLOCK
                && (a.tag == DW_TAG_INLINED_SUBROUTINE) == !chain.is_empty()
                && chain.len() < MAX_FRAMES
            {
                let call_line = DwarfInfo::uint(u, &die, DW_AT_CALL_LINE)
                    .map_or(0, |l| u32::try_from(l).unwrap_or(u32::MAX));
                chain.push(Found {
                    at,
                    depth,
                    inlined: a.tag == DW_TAG_INLINED_SUBROUTINE,
                    call: (DwarfInfo::uint(u, &die, DW_AT_CALL_FILE), call_line),
                    start: ranges.first().map(|r| r.0),
                });
            }
        }
        if a.children {
            if skip || depth >= MAX_DEPTH {
                r.skip_children(u, abbrevs, a)?;
            } else {
                stack.push((depth, at, a.tag));
            }
        }
        attrs = die.attrs;
    }
    Some(chain)
}

/// The index of the unit holding the DIE `r`.
fn unit_of(info: &DwarfInfo<'_>, r: TypeRef) -> Option<usize> {
    let (file, section, offset) = place(r)?;
    let units = &info.index().units;
    let i = units.partition_point(|m| (m.file, m.section, m.offset) <= (file, section, offset));
    let i = i.checked_sub(1)?;
    let m = units.get(i)?;
    (m.file == file && m.section == section && offset < m.end).then_some(i)
}

/// Every unit's code: (start, end, unit index), sorted by start. A
/// compile or skeleton unit's ranges; else the address ranges table's.
fn unit_code(info: &DwarfInfo<'_>) -> Vec<(u64, u64, usize)> {
    let index = info.index();
    let mut out = Vec::new();
    for (i, m) in index.units.iter().enumerate() {
        if m.compiland.is_none() || m.split {
            continue;
        }
        let Some((u, a)) = info.unit(m) else { continue };
        let Some(d) = u.entry(a, u.dies) else {
            continue;
        };
        for (at, size) in info.ranges(&u, &d) {
            out.push((at, at.saturating_add(size), i));
        }
    }
    // Units without ranges: the address ranges table's.
    if out.is_empty() {
        let s = info.sections();
        let by_offset: HashMap<u64, usize> = index
            .units
            .iter()
            .enumerate()
            .filter(|(_, m)| m.file == 0 && m.section == UnitSection::Info && !m.split)
            .map(|(i, m)| (m.offset, i))
            .collect();
        for e in hexcavator_dwarf::aranges(s.aranges, s.endian) {
            if let Some(&i) = by_offset.get(&e.info_offset)
                && e.length > 0
            {
                out.push((e.address, e.address.saturating_add(e.length), i));
            }
        }
    }
    out.sort_unstable();
    out
}

/// The files a split unit `dm`'s calls name: its own line table's (in its
/// `.debug_line.dwo`), relative to its skeleton `m`'s compilation
/// directory.
fn split_files<'a>(
    info: &'a DwarfInfo<'_>,
    dm: &UnitMeta,
    m: &UnitMeta,
) -> Option<(hexcavator_dwarf::LineProgram<'a>, String)> {
    let comp_dir = |um: &UnitMeta| {
        let (u, a) = info.unit(um)?;
        let d = u.entry(a, u.dies)?;
        DwarfInfo::string(&u, &d, DW_AT_COMP_DIR)
    };
    let dir = comp_dir(m).or_else(|| comp_dir(dm)).unwrap_or_default();
    let (u, a) = info.unit(dm)?;
    let d = u.entry(a, u.dies)?;
    let offset = DwarfInfo::uint(&u, &d, DW_AT_STMT_LIST).unwrap_or(0);
    let s = info.sections_of(dm.file);
    let program = line_program(&s, offset, u.address_size)?;
    Some((program, dir))
}

/// The (file index, line) of the row holding `addr` (of rows sorted by
/// address; the last to start at or before it, of those that hold it).
fn row_at(rows: &[(u64, u64, u64, u32)], addr: u64) -> Option<(u64, u32)> {
    let i = rows.partition_point(|r| r.0 <= addr);
    rows[..i]
        .iter()
        .rev()
        .take(16)
        .find(|r| addr < r.1)
        .map(|r| (r.2, r.3))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_by_address() {
        let rows = [(0x10, 0x14, 1, 5), (0x14, 0x20, 1, 6), (0x30, 0x34, 2, 9)];
        assert_eq!(row_at(&rows, 0x10), Some((1, 5)));
        assert_eq!(row_at(&rows, 0x13), Some((1, 5)));
        assert_eq!(row_at(&rows, 0x1F), Some((1, 6)));
        assert_eq!(row_at(&rows, 0x20), None);
        assert_eq!(row_at(&rows, 0x33), Some((2, 9)));
        assert_eq!(row_at(&rows, 0x0F), None);
        assert_eq!(row_at(&[], 1), None);
        // An overlapping sequence's row: the last that holds it.
        let overlap = [(0x10, 0x40, 1, 1), (0x18, 0x1C, 1, 2)];
        assert_eq!(row_at(&overlap, 0x19), Some((1, 2)));
        assert_eq!(row_at(&overlap, 0x20), Some((1, 1)));
    }
}
