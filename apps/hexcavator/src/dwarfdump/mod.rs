//! `hexc dwarf`: a file's DWARF, as `llvm-dwarfdump` shows it: units and
//! their DIEs (`-info`, in llvm-dwarfdump's layout: each attribute's
//! value as it prints them, expressions, location and range lists, and
//! referenced types by name), line tables (`-lines`), address ranges
//! (`-aranges`), abbreviations (`-abbrev`), strings (`-str`), call frame
//! information (`-frames`: CIEs, FDEs, and their unwind rows), and a
//! summary of what is there (the default).
//!
//! The counterpart of `hexc pdb` for DWARF. The file is an ELF or Mach-O
//! image or object with its own DWARF, a separate debug file (a dSYM's
//! DWARF, a `.debug` file), or an image whose debug file is found as
//! every command finds it.
//!
//! Every walk is bounded by the input: DIEs by their unit, nesting by
//! [`MAX_DEPTH`], type names by [`MAX_TYPE_DEPTH`], lists by their
//! sections.

use std::fmt::Write as _;
use std::path::Path;
use std::process::ExitCode;

use hexcavator_core::Arch;
use hexcavator_dwarf::consts::*;
use hexcavator_dwarf::spelling;
use hexcavator_dwarf::{Abbrevs, Attr, Die, Reader, Sections, Unit, UnitSection, Value};
use hexcavator_mmap::Mmap;

mod types;
use types::Types;

const USAGE: &str = "\
usage: hexc dwarf [options] <file>

A file's DWARF, as llvm-dwarfdump shows it. The file: an ELF or Mach-O
image or object with DWARF, a separate debug file (a dSYM's DWARF, a .debug
file), or an image whose debug file is found as every command finds it.

options:
  -summary        the sections, their sizes, and each unit (default)
  -info           each unit's DIEs and their attributes (llvm-dwarfdump
                  --debug-info's layout)
  -lines          each line table: its directories, files, and rows
  -aranges        .debug_aranges
  -abbrev         the abbreviation tables
  -str            .debug_str's strings
  -frames         .eh_frame and .debug_frame: CIEs, FDEs, and unwind rows
  -find <name>    the DIEs named <name> (and their children)
  -lookup <addr>  the unit, function, and line at an address
  -all            everything above except -find and -lookup
  -debug <path>   the debug file to read (default: the file's own DWARF, or
                  the one it names)";

/// The deepest DIE nesting shown (deeper DIEs are counted, not shown).
pub const MAX_DEPTH: i64 = 256;

/// How deep a referenced type's name is followed.
pub const MAX_TYPE_DEPTH: usize = 16;

#[derive(Default)]
struct Options {
    summary: bool,
    info: bool,
    lines: bool,
    aranges: bool,
    abbrev: bool,
    str: bool,
    frames: bool,
    find: Option<String>,
    lookup: Option<u64>,
    debug: Option<String>,
    file: Option<String>,
}

fn parse(args: &[String]) -> Result<Options, String> {
    let mut o = Options::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.strip_prefix('-').or_else(|| a.strip_prefix('/')) {
            Some("summary") => o.summary = true,
            Some("info") => o.info = true,
            Some("lines") => o.lines = true,
            Some("aranges") => o.aranges = true,
            Some("abbrev") => o.abbrev = true,
            Some("str") => o.str = true,
            Some("frames") => o.frames = true,
            Some("all") => {
                o.summary = true;
                o.info = true;
                o.lines = true;
                o.aranges = true;
                o.abbrev = true;
                o.str = true;
                o.frames = true;
            }
            Some("find") => o.find = Some(it.next().ok_or("-find: expected a name")?.clone()),
            Some("lookup") => {
                let v = it.next().ok_or("-lookup: expected an address")?;
                let t = v.trim_start_matches("0x").trim_start_matches("0X");
                o.lookup = Some(
                    u64::from_str_radix(t, 16)
                        .map_err(|_| format!("-lookup: not an address: {v}"))?,
                );
            }
            Some("debug" | "pdb") => {
                o.debug = Some(it.next().ok_or("-debug: expected a path")?.clone());
            }
            Some(other) if !other.is_empty() && o.file.is_none() && !a.starts_with('-') => {
                // (A path that starts with '/'.)
                o.file = Some(a.clone());
            }
            Some(other) => return Err(format!("unknown option '-{other}'")),
            None if o.file.is_none() => o.file = Some(a.clone()),
            None => return Err(format!("unexpected argument '{a}'")),
        }
    }
    if o.file.is_none() {
        return Err("expected a file".into());
    }
    let any = o.info || o.lines || o.aranges || o.abbrev || o.str || o.frames;
    if !any && o.find.is_none() && o.lookup.is_none() {
        o.summary = true;
    }
    Ok(o)
}

pub fn run(args: &[String]) -> ExitCode {
    if args.is_empty() {
        ereport!("{USAGE}");
        return ExitCode::from(2);
    }
    let o = match parse(args) {
        Ok(o) => o,
        Err(e) => {
            ereport!("hexc dwarf: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match dump(&o) {
        Ok(text) => crate::out::print(text.as_bytes()),
        Err(e) => {
            ereport!("hexc dwarf: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The file holding the DWARF to show: `-debug`'s, the file itself if it
/// has DWARF, or its debug file.
fn open(o: &Options) -> Result<(String, Mmap, Mmap), String> {
    let file = o.file.as_deref().unwrap_or_default();
    let image = Mmap::open(file).map_err(|e| format!("{file}: {e}"))?;
    if let Some(d) = &o.debug {
        let map = Mmap::open(d).map_err(|e| format!("{d}: {e}"))?;
        return Ok((d.clone(), image, map));
    }
    if hexcavator_debuginfo::dwarf_backend::DwarfInfo::parse(&image).is_ok() {
        let again = Mmap::open(file).map_err(|e| format!("{file}: {e}"))?;
        return Ok((file.to_string(), image, again));
    }
    let parsed = hexcavator_image::Image::parse(&image).map_err(|e| format!("{file}: {e}"))?;
    let (path, map) = hexcavator_program::find_debug(Path::new(file), &parsed, None)
        .map_err(|e| e.to_string())?;
    if hexcavator_pdb::check(&map).is_ok() {
        return Err(format!("{}: a PDB (see hexc pdb)", path.display()));
    }
    Ok((path.display().to_string(), image, map))
}

fn dump(o: &Options) -> Result<String, String> {
    let (path, image, debug) = match open(o) {
        Ok(found) => found,
        Err(e) => return debug_map(o, e),
    };
    dump_one(o, &path, &image, &debug)
}

/// A Mach-O image without a dSYM: each object file of its debug map,
/// dumped in turn (as llvm-dwarfdump dumps each of several files).
fn debug_map(o: &Options, why: String) -> Result<String, String> {
    let file = o.file.as_deref().unwrap_or_default();
    if o.debug.is_some() {
        return Err(why);
    }
    let Ok(opened) = hexcavator_program::Opened::open(Path::new(file), None) else {
        return Err(why);
    };
    if !opened.is_debug_map() {
        return Err(why);
    }
    let mut out = String::new();
    for (name, data) in opened.debug_map_files() {
        out.push_str(&dump_one(o, &name, data, data)?);
    }
    Ok(out)
}

fn dump_one(o: &Options, path: &str, image: &[u8], debug: &[u8]) -> Result<String, String> {
    let info = hexcavator_debuginfo::dwarf_backend::DwarfInfo::parse(debug)
        .map_err(|e| format!("{path}: {e}"))?;
    let s = info.sections();
    let mut d = Dumper {
        s,
        arch: info.arch(),
        out: String::new(),
        index: std::rc::Rc::new(Index {
            units: Vec::new(),
            parents: Default::default(),
        }),
    };
    d.index = std::rc::Rc::new(Index {
        units: d.units(),
        parents: Default::default(),
    });
    if o.summary {
        d.summary(path, debug);
    }
    if o.info {
        d.info();
    }
    if let Some(name) = &o.find {
        d.find(name);
    }
    if let Some(addr) = o.lookup {
        d.lookup(addr);
    }
    if o.lines {
        d.lines();
    }
    if o.aranges {
        d.aranges();
    }
    if o.abbrev {
        d.abbrev();
    }
    if o.str {
        d.strings();
    }
    if o.frames {
        // (Call frame information is the image's, not the debug file's,
        // unless the debug file has .debug_frame.)
        d.frames(image);
        if !std::ptr::eq(image.as_ptr(), debug.as_ptr()) {
            d.frames(debug);
        }
    }
    Ok(d.out)
}

struct Dumper<'d> {
    s: Sections<'d>,
    arch: Arch,
    out: String,
    index: std::rc::Rc<Index<'d>>,
}

/// A unit, ready to read: its abbreviations and its first DIE's
/// attributes (which set its bases), and its line table.
pub struct Ready<'d> {
    pub unit: Unit<'d>,
    pub abbrevs: Abbrevs,
    line: Option<hexcavator_dwarf::LineProgram<'d>>,
    comp_dir: Vec<u8>,
    /// Its `DW_AT_language`.
    pub language: Option<u64>,
}

/// Every unit of the file, ready to read, to find any DIE by its offset
/// (references across units, `DW_FORM_ref_addr`).
pub struct Index<'d> {
    pub units: Vec<Ready<'d>>,
    /// Each unit's DIEs' parents, built when first asked for.
    parents: std::cell::RefCell<
        std::collections::HashMap<usize, std::rc::Rc<std::collections::HashMap<u64, u64>>>,
    >,
}

impl<'d> Index<'d> {
    /// The unit of `section` whose DIEs include `offset`.
    pub fn unit_of(&self, section: UnitSection, offset: u64) -> Option<usize> {
        let i = self
            .units
            .partition_point(|u| (u.unit.section, u.unit.offset) <= (section, offset));
        let i = i.checked_sub(1)?;
        let u = &self.units[i].unit;
        (u.section == section && u.contains(offset)).then_some(i)
    }

    /// The DIE an attribute of unit `from` refers to: its unit and offset.
    pub fn resolve(&self, from: usize, a: &Attr<'d>) -> Option<(usize, u64)> {
        let u = &self.units.get(from)?.unit;
        let off = u.reference(a)?;
        if a.form == DW_FORM_REF_ADDR {
            return Some((self.unit_of(UnitSection::Info, off)?, off));
        }
        Some((from, off))
    }

    /// The DIE at `offset` of unit `unit`'s section.
    pub fn node(&self, unit: usize, offset: u64) -> Option<types::Node<'d>> {
        let u = self.units.get(unit)?;
        let die = u.unit.entry(&u.abbrevs, offset)?;
        Some(types::Node { unit, die })
    }

    /// The parent of the DIE at `offset` of unit `unit`.
    pub fn parent(&self, unit: usize, offset: u64) -> Option<u64> {
        let map = {
            let mut all = self.parents.borrow_mut();
            std::rc::Rc::clone(
                all.entry(unit)
                    .or_insert_with(|| std::rc::Rc::new(self.build_parents(unit))),
            )
        };
        map.get(&offset).copied()
    }

    fn build_parents(&self, unit: usize) -> std::collections::HashMap<u64, u64> {
        let mut parents = std::collections::HashMap::new();
        let Some(u) = self.units.get(unit) else {
            return parents;
        };
        let mut stack: Vec<(i64, u64)> = Vec::new();
        let mut r = u.unit.dies();
        let mut attrs = Vec::new();
        while let Some(a) = r.next(&u.abbrevs) {
            let offset = r.offset;
            let depth = r.depth - i64::from(a.children);
            if r.attrs(&u.unit, a, &mut attrs).is_none() {
                break;
            }
            while stack.last().is_some_and(|&(d, _)| d >= depth) {
                stack.pop();
            }
            if let Some(&(_, p)) = stack.last() {
                parents.insert(offset, p);
            }
            if a.children {
                stack.push((depth, offset));
            }
        }
        parents
    }
}

impl<'d> Dumper<'d> {
    fn units(&self) -> Vec<Ready<'d>> {
        let mut out = Vec::new();
        for section in [UnitSection::Info, UnitSection::Types] {
            for mut unit in Unit::iter(self.s, section, 0) {
                let Some(abbrevs) =
                    Abbrevs::parse(self.s.abbrev, unit.abbrev_offset, self.s.endian)
                else {
                    continue;
                };
                let mut r = unit.dies();
                let mut attrs = Vec::new();
                let mut comp_dir = Vec::new();
                let mut stmt = None;
                let mut language = None;
                if let Some(a) = r.next(&abbrevs)
                    && r.attrs(&unit, a, &mut attrs).is_some()
                {
                    unit.set_bases(&attrs);
                    for at in &attrs {
                        match at.name {
                            DW_AT_COMP_DIR => {
                                if let Some(sr) = unit.string(&at.value) {
                                    comp_dir = sr.bytes.to_vec();
                                }
                            }
                            DW_AT_STMT_LIST => stmt = unit.uint(&at.value),
                            DW_AT_LANGUAGE => language = unit.uint(&at.value),
                            _ => {}
                        }
                    }
                }
                let line = stmt.and_then(|off| {
                    hexcavator_dwarf::line_program(&self.s, off, unit.address_size)
                });
                out.push(Ready {
                    unit,
                    abbrevs,
                    line,
                    comp_dir,
                    language,
                });
            }
        }
        // (Sorted, for finding a unit by offset.)
        out.sort_by_key(|u| (u.unit.section, u.unit.offset));
        out
    }

    // ------------------------------------------------------------ summary

    fn summary(&mut self, path: &str, data: &[u8]) {
        let s = self.s;
        let _ = writeln!(
            self.out,
            "{path}: DWARF, {} bytes, {:?}, {}",
            data.len(),
            s.endian,
            self.arch.name()
        );
        let _ = writeln!(self.out, "\nsections:");
        for (name, bytes) in [
            ("info", s.info),
            ("types", s.types),
            ("abbrev", s.abbrev),
            ("line", s.line),
            ("str", s.str),
            ("line_str", s.line_str),
            ("str_offsets", s.str_offsets),
            ("addr", s.addr),
            ("ranges", s.ranges),
            ("rnglists", s.rnglists),
            ("loc", s.loc),
            ("loclists", s.loclists),
            ("aranges", s.aranges),
            ("pubnames", s.pubnames),
            ("pubtypes", s.pubtypes),
            ("names", s.names),
        ] {
            if !bytes.is_empty() {
                let _ = writeln!(self.out, "  .debug_{name:<12} {:>12} bytes", bytes.len());
            }
        }
        let index = std::rc::Rc::clone(&self.index);
        let units = &index.units;
        let _ = writeln!(self.out, "\n{} units:", units.len());
        let _ = writeln!(
            self.out,
            "  offset      version  type                   DIEs  name"
        );
        for u in units {
            let (count, name) = self.count_dies(u);
            let ut = spelling::unit_type(u64::from(u.unit.unit_type)).unwrap_or("DW_UT_?");
            let _ = writeln!(
                self.out,
                "  0x{:08x}  {:>7}  {:<21} {:>5}  {}",
                u.unit.offset, u.unit.version, ut, count, name
            );
        }
    }

    /// How many DIEs a unit has, and its first DIE's name.
    fn count_dies(&self, u: &Ready<'d>) -> (u64, String) {
        let mut r = u.unit.dies();
        let mut attrs = Vec::new();
        let mut n = 0u64;
        let mut name = String::new();
        while let Some(a) = r.next(&u.abbrevs) {
            if r.attrs(&u.unit, a, &mut attrs).is_none() {
                break;
            }
            if n == 0
                && let Some(v) = attrs.iter().find(|at| at.name == DW_AT_NAME)
            {
                name = u
                    .unit
                    .string(&v.value)
                    .map(|s| lossy(s.bytes))
                    .unwrap_or_default();
            }
            n += 1;
        }
        (n, name)
    }

    // --------------------------------------------------------------- info

    fn info(&mut self) {
        let index = std::rc::Rc::clone(&self.index);
        let units = &index.units;
        if units.iter().any(|u| u.unit.section == UnitSection::Info) {
            self.out.push_str(".debug_info contents:\n");
        }
        let mut types_header = false;
        for (ui, u) in units.iter().enumerate() {
            if u.unit.section == UnitSection::Types && !types_header {
                self.out.push_str("\n.debug_types contents:\n");
                types_header = true;
            }
            self.unit_header(&u.unit);
            self.dies(ui, None);
        }
    }

    fn unit_header(&mut self, u: &Unit<'d>) {
        let kind = match u.unit_type {
            DW_UT_TYPE | DW_UT_SPLIT_TYPE => "Type Unit",
            DW_UT_PARTIAL => "Partial Unit",
            DW_UT_SKELETON => "Skeleton Unit",
            DW_UT_SPLIT_COMPILE => "Split Compile Unit",
            _ => "Compile Unit",
        };
        let initial = if u.dwarf64 { 12 } else { 4 };
        let length = u.end - u.offset - initial;
        let mut line = format!(
            "0x{:08x}: {kind}: length = 0x{:0w$x}, format = {}, version = 0x{:04x}",
            u.offset,
            length,
            if u.dwarf64 { "DWARF64" } else { "DWARF32" },
            u.version,
            w = if u.dwarf64 { 16 } else { 8 },
        );
        if u.version >= 5 {
            let _ = write!(
                line,
                ", unit_type = {}",
                spelling::unit_type(u64::from(u.unit_type)).unwrap_or("DW_UT_?")
            );
        }
        let _ = write!(
            line,
            ", abbr_offset = 0x{:04x}, addr_size = 0x{:02x}",
            u.abbrev_offset, u.address_size
        );
        if let Some(id) = u.dwo_id {
            let _ = write!(line, ", DWO_id = 0x{id:016x}");
        }
        if let Some((sig, at)) = u.type_signature() {
            let _ = write!(
                line,
                ", name = '', type_signature = 0x{sig:016x}, type_offset = 0x{:04x}",
                at - u.offset
            );
        }
        let _ = writeln!(self.out, "{line} (next unit at 0x{:08x})\n", u.end);
    }

    /// The unit's DIEs: all of them, or (`only`) those at and under the
    /// DIE offsets given.
    fn dies(&mut self, ui: usize, only: Option<&[u64]>) {
        let index = std::rc::Rc::clone(&self.index);
        let u = &index.units[ui];
        let types = Types::new(&index);
        let mut r = u.unit.dies();
        let mut attrs = Vec::new();
        let mut prev_end: Option<u64> = None;
        let mut depth_before: i64 = 0;
        // (With `only`: the depth of the DIE being shown, while under it.)
        let mut shown: Option<i64> = None;
        loop {
            let before = r.depth;
            let Some(a) = r.next(&u.abbrevs) else { break };
            let offset = r.offset;
            // The null entries skipped (each ends one level of children).
            if let Some(end) = prev_end {
                let mut depth = depth_before;
                for at in end..offset {
                    depth -= 1;
                    if shown.is_some_and(|d| depth > d) || (only.is_none() && depth < MAX_DEPTH) {
                        let _ = writeln!(
                            self.out,
                            "0x{at:08x}: {}NULL\n",
                            "  ".repeat(usize::try_from(depth.max(0)).unwrap_or(0) + 1)
                        );
                    }
                    if shown.is_some_and(|d| depth <= d) {
                        shown = None;
                    }
                }
            }
            let _ = before;
            let depth = r.depth - i64::from(a.children);
            if r.attrs(&u.unit, a, &mut attrs).is_none() {
                break;
            }
            if let Some(list) = only
                && shown.is_none()
                && list.contains(&offset)
            {
                shown = Some(depth);
            }
            let show = match (only, shown) {
                (None, _) => depth < MAX_DEPTH,
                (Some(_), Some(d)) => depth >= d,
                (Some(_), None) => false,
            };
            if show {
                let die = Die {
                    offset,
                    tag: a.tag,
                    children: a.children,
                    attrs: attrs.clone(),
                    next: r.position(),
                };
                self.die(
                    ui,
                    u,
                    &types,
                    &die,
                    usize::try_from(depth.max(0)).unwrap_or(0),
                );
            }
            if let Some(d) = shown
                && depth <= d
                && !a.children
                && only.is_some_and(|l| l.contains(&offset))
            {
                shown = None;
            }
            prev_end = Some(r.position());
            depth_before = r.depth;
        }
        // The nulls at the end of the unit.
        if let Some(end) = prev_end {
            let mut depth = depth_before;
            let stop = u.unit.end;
            let data = self.unit_bytes(&u.unit);
            let mut at = end;
            while at < stop
                && depth > 0
                && data.get(usize::try_from(at).unwrap_or(usize::MAX)) == Some(&0)
            {
                depth -= 1;
                if only.is_none() || shown.is_some_and(|d| depth > d) {
                    let _ = writeln!(
                        self.out,
                        "0x{at:08x}: {}NULL\n",
                        "  ".repeat(usize::try_from(depth.max(0)).unwrap_or(0) + 1)
                    );
                }
                at += 1;
            }
            // (The unit's last null entry has no blank line after it.)
            if only.is_none()
                && self.out.ends_with(
                    "NULL

",
                )
            {
                self.out.pop();
            }
        }
    }

    fn unit_bytes(&self, u: &Unit<'d>) -> &'d [u8] {
        match u.section {
            UnitSection::Info => self.s.info,
            UnitSection::Types => self.s.types,
        }
    }

    fn die(
        &mut self,
        ui: usize,
        u: &Ready<'d>,
        types: &Types<'_, 'd>,
        die: &Die<'d>,
        depth: usize,
    ) {
        let tag = spelling::tag(u64::from(die.tag))
            .map_or_else(|| format!("DW_TAG_unknown_{:x}", die.tag), str::to_string);
        let _ = writeln!(
            self.out,
            "0x{:08x}: {}{tag}",
            die.offset,
            "  ".repeat(depth)
        );
        let indent = 12 + 2 * depth + 2;
        let low_pc = die.attr(DW_AT_LOW_PC).and_then(|a| self.address(u, a));
        for a in &die.attrs {
            let name = spelling::attribute(u64::from(a.name))
                .map_or_else(|| format!("DW_AT_unknown_{:x}", a.name), str::to_string);
            let value = self.value(ui, u, types, die, a, low_pc, indent);
            let _ = writeln!(self.out, "{}{name}\t({value})", " ".repeat(indent));
        }
        self.out.push('\n');
    }

    fn address(&self, u: &Ready<'d>, a: &Attr<'d>) -> Option<u64> {
        match a.value {
            Value::Addr(v) => Some(v),
            Value::AddrIndex(i) => u.unit.indexed_address(i),
            _ => None,
        }
    }

    /// An attribute's value, as llvm-dwarfdump prints it.
    #[allow(clippy::too_many_arguments)]
    fn value(
        &self,
        ui: usize,
        u: &Ready<'d>,
        types: &Types<'_, 'd>,
        die: &Die<'d>,
        a: &Attr<'d>,
        low_pc: Option<u64>,
        indent: usize,
    ) -> String {
        let unit = &u.unit;
        // Strings.
        if matches!(
            a.value,
            Value::Str(_) | Value::StrOffset(..) | Value::StrIndex(_)
        ) {
            return match unit.string(&a.value) {
                Some(s) => format!("\"{}\"", llvm_escaped(s.bytes)),
                None => "<invalid string>".into(),
            };
        }
        // References: the offset, and the DIE's name (a type's, as written).
        if is_reference(a.form) {
            let Some((tu, target)) = self.index.resolve(ui, a) else {
                return match a.value {
                    Value::Uint(v) if a.form == DW_FORM_REF_SIG8 => format!("0x{v:016x}"),
                    Value::Uint(v) => format!("0x{v:08x}"),
                    _ => "<invalid reference>".into(),
                };
            };
            // (As llvm-dwarfdump: types by their qualified names; the DIEs
            // a few attributes name, by their linkage names, else names.)
            let name = if matches!(a.name, DW_AT_TYPE | DW_AT_CONTAINING_TYPE) {
                types.name(tu, target).to_string()
            } else if matches!(
                a.name,
                DW_AT_SPECIFICATION
                    | DW_AT_ABSTRACT_ORIGIN
                    | DW_AT_CALL_ORIGIN
                    | DW_AT_IMPORT
                    | 0x3e14
            ) {
                self.linkage_or_name(tu, target, 0).unwrap_or_default()
            } else {
                String::new()
            };
            // (DW_FORM_ref_addr's offsets, as LLVM prints them: 16 digits.)
            let at = if a.form == DW_FORM_REF_ADDR {
                format!("0x{target:016x}")
            } else {
                format!("0x{target:08x}")
            };
            return if name.is_empty() {
                at
            } else {
                format!("{at} \"{name}\"")
            };
        }
        // Addresses, as wide as the unit's (16 digits, or 8 for 32-bit).
        let width = usize::from(unit.address_size) * 2;
        if let Some(addr) = self.address(u, a) {
            // (A dead function's code, as linkers mark it.)
            if a.name == DW_AT_LOW_PC && addr == unit.max_address() {
                return "dead code".into();
            }
            return if matches!(a.value, Value::AddrIndex(_))
                && a.name != DW_AT_LOW_PC
                && a.name != DW_AT_HIGH_PC
                && a.name != DW_AT_CALL_RETURN_PC
                && a.name != DW_AT_CALL_PC
                && a.name != DW_AT_ENTRY_PC
            {
                format!(
                    "indexed (0x{:08x}) address = 0x{addr:0w$x}",
                    index_of(&a.value),
                    w = width
                )
            } else {
                format!("0x{addr:0width$x}")
            };
        }
        // DW_AT_high_pc as an offset from DW_AT_low_pc.
        if a.name == DW_AT_HIGH_PC
            && let (Some(lo), Some(off)) = (low_pc, unit.uint(&a.value))
        {
            // (Dead code's: the offset alone.)
            if lo == unit.max_address() {
                return format!("0x{off:0width$x}");
            }
            return format!("0x{:0width$x}", lo.wrapping_add(off));
        }
        // Expressions and blocks.
        if let Value::Block(b) = a.value {
            if is_exprloc(a.form) || is_location(a.name) {
                return self.expression(unit, b);
            }
            return block(b);
        }
        // Location and range lists.
        if is_location(a.name)
            && (a.form == DW_FORM_SEC_OFFSET
                || a.form == DW_FORM_LOCLISTX
                || (unit.version < 4 && matches!(a.form, DW_FORM_DATA4 | DW_FORM_DATA8)))
        {
            return self.location_list(u, a, indent);
        }
        if matches!(a.name, DW_AT_RANGES | DW_AT_START_SCOPE)
            && (a.form == DW_FORM_SEC_OFFSET || a.form == DW_FORM_RNGLISTX || unit.version < 4)
        {
            return self.range_list(u, a, indent);
        }
        if a.form == DW_FORM_FLAG_PRESENT {
            return "true".into();
        }
        if a.form == DW_FORM_FLAG {
            return if unit.uint(&a.value).unwrap_or(0) != 0 {
                "true"
            } else {
                "false"
            }
            .into();
        }
        let v = match a.value {
            Value::Uint(v) => v,
            Value::Data(d) if d.len() <= 8 => match unit.uint(&a.value) {
                Some(v) => v,
                None => return block(d),
            },
            // (Signed forms: their bits, printed signed below.)
            Value::Sint(v) => v as u64,
            Value::Data(d) => return block(d),
            _ => return "<unknown>".into(),
        };
        // Objective-C property attributes: the value, and each bit's name.
        if a.name == 0x3feb && v != 0 {
            let mut names = Vec::new();
            let mut rest = v;
            while rest != 0 {
                let bit = 1u64 << rest.trailing_zeros();
                names.push(
                    spelling::apple_property(bit)
                        .map_or_else(|| format!("DW_APPLE_PROPERTY_{bit:x}"), str::to_string),
                );
                rest ^= bit;
            }
            let shown = match a.form {
                DW_FORM_DATA1 => format!("0x{v:02x}"),
                DW_FORM_DATA2 => format!("0x{v:04x}"),
                DW_FORM_DATA4 => format!("0x{v:08x}"),
                DW_FORM_DATA8 => format!("0x{v:016x}"),
                _ => format!("0x{v:x}"),
            };
            return format!("{shown} ({})", names.join(", "));
        }
        // Enumerated values, by name.
        let named = match a.name {
            DW_AT_LANGUAGE | 0x3fe6 => spelling::language(v),
            DW_AT_ENCODING => spelling::encoding(v),
            DW_AT_INLINE => spelling::inline(v),
            DW_AT_ACCESSIBILITY => spelling::accessibility(v),
            DW_AT_VISIBILITY => spelling::visibility(v),
            DW_AT_VIRTUALITY => spelling::virtuality(v),
            DW_AT_CALLING_CONVENTION => spelling::calling_convention(v),
            DW_AT_IDENTIFIER_CASE => spelling::identifier_case(v),
            DW_AT_ORDERING => spelling::array_ordering(v),
            DW_AT_ENDIANITY => spelling::endianity(v),
            DW_AT_DEFAULTED => spelling::defaulted(v),
            DW_AT_DISCR_VALUE if false => None,
            _ => None,
        };
        if let Some(n) = named {
            return n.to_string();
        }
        // Files, by the unit's line table.
        if matches!(a.name, DW_AT_DECL_FILE | DW_AT_CALL_FILE)
            && let Some(p) = u.line.as_ref().and_then(|l| l.path(v, &u.comp_dir))
        {
            return format!("\"{p}\"");
        }
        if matches!(
            a.name,
            DW_AT_DECL_LINE | DW_AT_CALL_LINE | DW_AT_DECL_COLUMN | DW_AT_CALL_COLUMN
        ) {
            return format!("{v}");
        }
        let _ = die;
        match a.form {
            DW_FORM_DATA1 | DW_FORM_REF1 => format!("0x{v:02x}"),
            DW_FORM_DATA2 | DW_FORM_REF2 => format!("0x{v:04x}"),
            DW_FORM_DATA4 | DW_FORM_REF4 => format!("0x{v:08x}"),
            DW_FORM_DATA8 | DW_FORM_REF8 => format!("0x{v:016x}"),
            DW_FORM_SEC_OFFSET | DW_FORM_STRP | DW_FORM_LINE_STRP => {
                if unit.dwarf64 {
                    format!("0x{v:016x}")
                } else {
                    format!("0x{v:08x}")
                }
            }
            DW_FORM_SDATA | DW_FORM_IMPLICIT_CONST => format!("{}", v as i64),
            // (As LLVM's DWARFFormValue: udata in decimal.)
            DW_FORM_UDATA => format!("{v}"),
            _ => format!("0x{v:x}"),
        }
    }

    /// A DIE's name, if it has one.
    fn die_name(&self, u: &Ready<'d>, offset: u64) -> Option<String> {
        let die = u.unit.entry(&u.abbrevs, offset)?;
        let a = die
            .attr(DW_AT_NAME)
            .or_else(|| die.attr(DW_AT_LINKAGE_NAME))?;
        u.unit.string(&a.value).map(|s| lossy(s.bytes))
    }

    /// A DIE's linkage name, else its name, from it or the DIEs its
    /// specification or abstract origin names (as LLVM's `findRecursively`),
    /// in any unit.
    fn linkage_or_name(&self, unit: usize, offset: u64, depth: usize) -> Option<String> {
        let node = self.index.node(unit, offset)?;
        let mut seen = vec![(unit, offset)];
        let name = self.find_recursively(
            &node,
            &[DW_AT_LINKAGE_NAME, DW_AT_MIPS_LINKAGE_NAME],
            &mut seen,
            depth,
        );
        if name.is_some() {
            return name;
        }
        seen.truncate(1);
        self.find_recursively(&node, &[DW_AT_NAME], &mut seen, depth)
    }

    fn find_recursively(
        &self,
        node: &types::Node<'d>,
        attrs: &[u16],
        seen: &mut Vec<(usize, u64)>,
        depth: usize,
    ) -> Option<String> {
        let unit = &self.index.units[node.unit].unit;
        for &attr in attrs {
            if let Some(a) = node.die.attr(attr) {
                return unit.string(&a.value).map(|s| lossy(s.bytes));
            }
        }
        if depth > MAX_TYPE_DEPTH {
            return None;
        }
        for via in [DW_AT_ABSTRACT_ORIGIN, DW_AT_SPECIFICATION, DW_AT_SIGNATURE] {
            let Some(a) = node.die.attr(via) else {
                continue;
            };
            let Some(target) = self.index.resolve(node.unit, a) else {
                continue;
            };
            if seen.contains(&target) {
                continue;
            }
            seen.push(target);
            if let Some(next) = self.index.node(target.0, target.1)
                && let Some(n) = self.find_recursively(&next, attrs, seen, depth + 1)
            {
                return Some(n);
            }
        }
        None
    }

    /// A location or range list attribute's list, entry by entry.
    fn location_list(&self, u: &Ready<'d>, a: &Attr<'d>, indent: usize) -> String {
        let unit = &u.unit;
        let (offset, head) = match a.value {
            Value::ListIndex(i) => match unit.loclist_offset(i) {
                Some(o) => (o, format!("indexed (0x{i:x}) loclist = 0x{o:08x}: ")),
                None => return format!("indexed (0x{i:x}) loclist = <invalid>"),
            },
            _ => {
                let o = unit.uint(&a.value).unwrap_or(0);
                (o, format!("0x{o:08x}: "))
            }
        };
        let mut s = head;
        let w = usize::from(unit.address_size) * 2;
        match unit.location_list(offset) {
            Some(entries) => {
                for (lo, hi, expr) in entries {
                    let _ = write!(
                        s,
                        "\n{}[0x{lo:0w$x}, 0x{hi:0w$x}): {}",
                        " ".repeat(indent + 3),
                        self.expression(unit, expr)
                    );
                }
            }
            None => s.push_str("<invalid>"),
        }
        s
    }

    fn range_list(&self, u: &Ready<'d>, a: &Attr<'d>, indent: usize) -> String {
        let unit = &u.unit;
        let (list, head) = match a.value {
            Value::ListIndex(i) => match unit.rnglist_offset(i) {
                Some(o) => (
                    unit.rnglist(o),
                    format!("indexed (0x{i:x}) rangelist = 0x{o:08x}"),
                ),
                None => return format!("indexed (0x{i:x}) rangelist = <invalid>"),
            },
            _ => {
                let o = unit.uint(&a.value).unwrap_or(0);
                let list = if unit.version >= 5 {
                    unit.rnglist(o)
                } else {
                    unit.range_list(o, unit.low_pc)
                };
                (list, format!("0x{o:08x}"))
            }
        };
        let mut s = head;
        let w = usize::from(unit.address_size) * 2;
        // (Tombstones, a dead function's range at the highest addresses as
        // linkers mark them, are left out, as LLVM does.)
        let tombstone = unit.max_address().saturating_sub(1);
        for (start, size) in list.map(|(l, _)| l).unwrap_or_default() {
            if start >= tombstone {
                continue;
            }
            let _ = write!(
                s,
                "\n{}[0x{start:0w$x}, 0x{:0w$x})",
                " ".repeat(indent + 3),
                start.wrapping_add(size)
            );
        }
        s
    }

    /// A DWARF expression, operation by operation, as llvm-dwarfdump prints
    /// it (`DW_OP_reg7 RSP`, `DW_OP_consts +0, DW_OP_stack_value`).
    fn expression(&self, unit: &Unit<'d>, expr: &[u8]) -> String {
        let ui = self.index.unit_of(unit.section, unit.dies);
        let base = |rel: u64| -> Option<(u64, String)> {
            let ui = ui?;
            let at = unit.offset.checked_add(rel)?;
            let node = self.index.node(ui, at)?;
            let name = node
                .die
                .attr(DW_AT_NAME)
                .and_then(|a| unit.string(&a.value))
                .map(|s| lossy(s.bytes));
            Some((at, name.unwrap_or_default()))
        };
        expression_with(
            expr,
            self.s.endian,
            unit.address_size,
            unit.dwarf64,
            self.arch,
            0,
            &base,
        )
    }

    // --------------------------------------------------------------- find

    fn find(&mut self, name: &str) {
        let index = std::rc::Rc::clone(&self.index);
        let units = &index.units;
        let mut found = 0;
        for (ui, u) in units.iter().enumerate() {
            let mut r = u.unit.dies();
            let mut attrs = Vec::new();
            let mut hits = Vec::new();
            while let Some(a) = r.next(&u.abbrevs) {
                let offset = r.offset;
                if r.attrs(&u.unit, a, &mut attrs).is_none() {
                    break;
                }
                let named = attrs.iter().any(|at| {
                    matches!(
                        at.name,
                        DW_AT_NAME | DW_AT_LINKAGE_NAME | DW_AT_MIPS_LINKAGE_NAME
                    ) && u
                        .unit
                        .string(&at.value)
                        .is_some_and(|s| s.bytes == name.as_bytes())
                });
                if named {
                    hits.push(offset);
                }
            }
            if !hits.is_empty() {
                found += hits.len();
                self.dies(ui, Some(&hits));
            }
        }
        if found == 0 {
            let _ = writeln!(self.out, "no DIE named '{name}'");
        }
    }

    // ------------------------------------------------------------- lookup

    fn lookup(&mut self, addr: u64) {
        let index = std::rc::Rc::clone(&self.index);
        let units = &index.units;
        for u in units {
            let mut r = u.unit.dies();
            let mut attrs = Vec::new();
            let mut stack: Vec<(i64, u64, u16, String)> = Vec::new();
            let mut best: Vec<(u64, u16, String)> = Vec::new();
            while let Some(a) = r.next(&u.abbrevs) {
                let offset = r.offset;
                let depth = r.depth - i64::from(a.children);
                if r.attrs(&u.unit, a, &mut attrs).is_none() {
                    break;
                }
                stack.retain(|e| e.0 < depth);
                let die = Die {
                    offset,
                    tag: a.tag,
                    children: a.children,
                    attrs: attrs.clone(),
                    next: r.position(),
                };
                if !matches!(
                    a.tag,
                    DW_TAG_COMPILE_UNIT
                        | DW_TAG_SUBPROGRAM
                        | DW_TAG_INLINED_SUBROUTINE
                        | DW_TAG_LEXICAL_BLOCK
                        | DW_TAG_PARTIAL_UNIT
                ) {
                    continue;
                }
                if !self.covers(u, &die, addr) {
                    continue;
                }
                let name = die
                    .attr(DW_AT_NAME)
                    .and_then(|v| u.unit.string(&v.value))
                    .map(|s| lossy(s.bytes))
                    .or_else(|| {
                        die.attr(DW_AT_ABSTRACT_ORIGIN)
                            .and_then(|o| u.unit.reference(o))
                            .and_then(|o| self.die_name(u, o))
                    })
                    .unwrap_or_default();
                stack.push((depth, offset, a.tag, name.clone()));
                best = stack.iter().map(|e| (e.1, e.2, e.3.clone())).collect();
            }
            if best.is_empty() {
                continue;
            }
            let _ = writeln!(self.out, "Lookup 0x{addr:x}:");
            for (offset, tag, name) in &best {
                let _ = writeln!(
                    self.out,
                    "  0x{offset:08x}: {} {name}",
                    spelling::tag(u64::from(*tag)).unwrap_or("?")
                );
            }
            if let Some(l) = &u.line {
                // The row that covers the address: the last before it in
                // its sequence.
                let mut hit = None;
                for w in l.rows.windows(2) {
                    if !w[0].end_sequence && w[0].address <= addr && addr < w[1].address {
                        hit = Some(w[0]);
                    }
                }
                if let Some(row) = hit {
                    let file = l.path(row.file, &u.comp_dir).unwrap_or_default();
                    let _ = writeln!(self.out, "  line: {file}:{}:{}", row.line, row.column);
                }
            }
            return;
        }
        let _ = writeln!(self.out, "no unit covers 0x{addr:x}");
    }

    fn covers(&self, u: &Ready<'d>, die: &Die<'d>, addr: u64) -> bool {
        let lo = die.attr(DW_AT_LOW_PC).and_then(|a| self.address(u, a));
        if let (Some(lo), Some(hi)) = (lo, die.attr(DW_AT_HIGH_PC)) {
            let end = match hi.value {
                Value::Addr(_) | Value::AddrIndex(_) => self.address(u, hi),
                _ => u.unit.uint(&hi.value).map(|o| lo.wrapping_add(o)),
            };
            if let Some(end) = end {
                return lo <= addr && addr < end;
            }
        }
        if let Some(r) = die.attr(DW_AT_RANGES) {
            let list = match r.value {
                Value::ListIndex(i) => u.unit.rnglist_offset(i).and_then(|o| u.unit.rnglist(o)),
                _ => u.unit.uint(&r.value).and_then(|o| {
                    if u.unit.version >= 5 {
                        u.unit.rnglist(o)
                    } else {
                        u.unit.range_list(o, u.unit.low_pc)
                    }
                }),
            };
            return list.is_some_and(|(l, _)| l.iter().any(|&(s, n)| s <= addr && addr - s < n));
        }
        false
    }

    // -------------------------------------------------------------- lines

    fn lines(&mut self) {
        self.out.push_str("\n.debug_line contents:\n");
        let index = std::rc::Rc::clone(&self.index);
        let units = &index.units;
        let mut seen = Vec::new();
        for u in units {
            let Some(l) = &u.line else { continue };
            let mut attrs = Vec::new();
            let mut r = u.unit.dies();
            let mut offset = None;
            if let Some(a) = r.next(&u.abbrevs)
                && r.attrs(&u.unit, a, &mut attrs).is_some()
            {
                offset = attrs
                    .iter()
                    .find(|at| at.name == DW_AT_STMT_LIST)
                    .and_then(|at| u.unit.uint(&at.value));
            }
            let Some(offset) = offset else { continue };
            if seen.contains(&offset) {
                continue;
            }
            seen.push(offset);
            let _ = writeln!(self.out, "debug_line[0x{offset:08x}]");
            let _ = writeln!(self.out, "         version: {}", l.version);
            for (i, d) in l.directories.iter().enumerate() {
                let _ = writeln!(self.out, "include_directories[{i:>3}] = \"{}\"", escape(d));
            }
            for (i, f) in l.files.iter().enumerate() {
                let _ = writeln!(
                    self.out,
                    "file_names[{i:>3}]:\n           name: \"{}\"\n      dir_index: {}",
                    escape(f.name),
                    f.directory
                );
            }
            self.out.push_str("\nAddress            Line   Column File   Flags\n------------------ ------ ------ ------ -------------\n");
            for row in &l.rows {
                let mut flags = String::new();
                if row.is_stmt {
                    flags.push_str(" is_stmt");
                }
                if row.end_sequence {
                    flags.push_str(" end_sequence");
                }
                let _ = writeln!(
                    self.out,
                    "0x{:016x} {:>6} {:>6} {:>6}{flags}",
                    row.address, row.line, row.column, row.file
                );
            }
            self.out.push('\n');
        }
    }

    // ------------------------------------------------------------ aranges

    fn aranges(&mut self) {
        self.out.push_str("\n.debug_aranges contents:\n");
        let mut last = None;
        for e in hexcavator_dwarf::aranges(self.s.aranges, self.s.endian) {
            if last != Some(e.info_offset) {
                let _ = writeln!(
                    self.out,
                    "Address Range Header: cu_offset = 0x{:08x}, addr_size = 0x{:02x}",
                    e.info_offset, e.address_size
                );
                last = Some(e.info_offset);
            }
            let _ = writeln!(
                self.out,
                "[0x{:016x}, 0x{:016x})",
                e.address,
                e.address.wrapping_add(e.length)
            );
        }
    }

    // ------------------------------------------------------------- abbrev

    fn abbrev(&mut self) {
        self.out.push_str("\n.debug_abbrev contents:\n");
        let mut offsets: Vec<u64> = self.units().iter().map(|u| u.unit.abbrev_offset).collect();
        offsets.sort_unstable();
        offsets.dedup();
        for off in offsets {
            let Some(t) = Abbrevs::parse(self.s.abbrev, off, self.s.endian) else {
                continue;
            };
            let _ = writeln!(self.out, "Abbrev table for offset: 0x{off:08x}");
            for a in t.iter() {
                let _ = writeln!(
                    self.out,
                    "[{}] {}\t{}",
                    a.code,
                    spelling::tag(u64::from(a.tag)).unwrap_or("DW_TAG_?"),
                    if a.children {
                        "DW_CHILDREN_yes"
                    } else {
                        "DW_CHILDREN_no"
                    }
                );
                for at in &a.attrs {
                    let _ = write!(
                        self.out,
                        "\t{}\t{}",
                        spelling::attribute(u64::from(at.name)).unwrap_or("DW_AT_?"),
                        spelling::form(u64::from(at.form)).unwrap_or("DW_FORM_?")
                    );
                    if at.form == DW_FORM_IMPLICIT_CONST {
                        let _ = write!(self.out, "\t{}", at.implicit);
                    }
                    self.out.push('\n');
                }
                self.out.push('\n');
            }
        }
    }

    // ---------------------------------------------------------------- str

    fn strings(&mut self) {
        self.out.push_str("\n.debug_str contents:\n");
        let data = self.s.str;
        let mut at = 0usize;
        while at < data.len() {
            let end = data[at..]
                .iter()
                .position(|&b| b == 0)
                .map_or(data.len(), |n| at + n);
            let _ = writeln!(self.out, "0x{at:08x}: \"{}\"", llvm_escaped(&data[at..end]));
            at = end + 1;
        }
    }

    // ------------------------------------------------------------- frames

    fn frames(&mut self, data: &[u8]) {
        let Ok(image) = hexcavator_image::Image::parse(data) else {
            return;
        };
        for s in image.sections() {
            let (kind, label) = match s.name {
                b".eh_frame" | b"__eh_frame" => {
                    (hexcavator_dwarf::cfi::CfiKind::EhFrame, ".eh_frame")
                }
                b".debug_frame" | b"__debug_frame" => {
                    (hexcavator_dwarf::cfi::CfiKind::DebugFrame, ".debug_frame")
                }
                _ => continue,
            };
            let (Ok(at), Ok(len)) = (usize::try_from(s.file_offset), usize::try_from(s.file_size))
            else {
                continue;
            };
            let Some(bytes) = data.get(at..at.saturating_add(len)) else {
                continue;
            };
            if bytes.is_empty() {
                continue;
            }
            let cfi = hexcavator_dwarf::cfi::Cfi {
                data: bytes,
                kind,
                endian: image.endian(),
                address: s.addr.wrapping_add(image.image_base()),
                address_size: image.arch().pointer_size().unwrap_or(8),
                text_base: None,
                data_base: None,
            };
            let _ = writeln!(self.out, "\n{label} contents:\n");
            let mut cies = std::collections::HashMap::new();
            for e in cfi.entries() {
                match e {
                    hexcavator_dwarf::cfi::Entry::Cie(c) => {
                        let _ = writeln!(
                            self.out,
                            "{:08x} CIE\n  Version:               {}\n  Augmentation:          \"{}\"\n  Code alignment factor: {}\n  Data alignment factor: {}\n  Return address column: {}\n",
                            c.offset,
                            c.version,
                            escape(c.augmentation),
                            c.code_alignment,
                            c.data_alignment,
                            c.return_address_register
                        );
                        cies.insert(c.offset, c);
                    }
                    hexcavator_dwarf::cfi::Entry::Fde(f) => {
                        let _ = writeln!(
                            self.out,
                            "{:08x} FDE cie={:08x} pc={:08x}...{:08x}",
                            f.offset,
                            f.cie,
                            f.pc_begin,
                            f.pc_begin.wrapping_add(f.pc_range)
                        );
                        if let Some(c) = cies.get(&f.cie) {
                            for row in hexcavator_dwarf::cfi::rows(&cfi, c, &f).unwrap_or_default()
                            {
                                let _ = writeln!(
                                    self.out,
                                    "  0x{:x}: {}",
                                    row.address,
                                    self.unwind_row(&row)
                                );
                            }
                        }
                        self.out.push('\n');
                    }
                }
            }
        }
    }

    fn unwind_row(&self, row: &hexcavator_dwarf::cfi::UnwindRow<'_>) -> String {
        use hexcavator_dwarf::cfi::{CfaRule, RegisterRule};
        let reg = |n: u16| register_name(self.arch, n);
        let mut s = match row.cfa {
            CfaRule::RegisterOffset { register, offset } => {
                format!("CFA={}{offset:+}", reg(register))
            }
            CfaRule::Expression(e) => format!(
                "CFA={}",
                expression(e, self.s.endian, 8, false, self.arch, 0)
            ),
        };
        for (r, rule) in &row.registers {
            let text = match rule {
                RegisterRule::Undefined => "undefined".to_string(),
                RegisterRule::SameValue => "same".to_string(),
                RegisterRule::Offset(o) => format!("[CFA{o:+}]"),
                RegisterRule::ValOffset(o) => format!("CFA{o:+}"),
                RegisterRule::Register(r) => reg(*r),
                RegisterRule::Expression(e) => {
                    format!("[{}]", expression(e, self.s.endian, 8, false, self.arch, 0))
                }
                RegisterRule::ValExpression(e) => {
                    expression(e, self.s.endian, 8, false, self.arch, 0)
                }
            };
            let _ = write!(s, ": {}={text}", reg(*r));
        }
        s
    }
}

fn index_of(v: &Value<'_>) -> u64 {
    match *v {
        Value::AddrIndex(i) | Value::ListIndex(i) | Value::StrIndex(i) => i,
        _ => 0,
    }
}

fn is_reference(form: u16) -> bool {
    matches!(
        form,
        DW_FORM_REF1
            | DW_FORM_REF2
            | DW_FORM_REF4
            | DW_FORM_REF8
            | DW_FORM_REF_UDATA
            | DW_FORM_REF_ADDR
            | DW_FORM_REF_SIG8
    )
}

fn is_exprloc(form: u16) -> bool {
    form == DW_FORM_EXPRLOC
}

/// Attributes whose blocks are expressions, and whose offsets are
/// location lists.
fn is_location(name: u16) -> bool {
    matches!(
        name,
        DW_AT_LOCATION
            | DW_AT_FRAME_BASE
            | DW_AT_DATA_MEMBER_LOCATION
            | DW_AT_USE_LOCATION
            | DW_AT_VTABLE_ELEM_LOCATION
            | DW_AT_STRING_LENGTH
            | DW_AT_RETURN_ADDR
            | DW_AT_STATIC_LINK
            | DW_AT_CALL_VALUE
            | DW_AT_CALL_TARGET
            | DW_AT_CALL_DATA_LOCATION
            | DW_AT_CALL_DATA_VALUE
            | DW_AT_DATA_LOCATION
            | DW_AT_GNU_CALL_SITE_VALUE
            | DW_AT_GNU_CALL_SITE_TARGET
    )
}

/// A block's bytes: `<0x02> 01 02`.
fn block(b: &[u8]) -> String {
    let mut s = format!("<0x{:02x}>", b.len());
    for x in b.iter().take(4096) {
        let _ = write!(s, " {x:02x}");
    }
    s
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// A string as LLVM's `write_escaped` writes it (as llvm-dwarfdump shows
/// string attributes): backslash, tab, newline, and quote escaped,
/// printable ASCII as it is, and every other byte in octal (`\303\251`).
fn llvm_escaped(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len());
    for &c in b {
        match c {
            b'\\' => s.push_str("\\\\"),
            b'\t' => s.push_str("\\t"),
            b'\n' => s.push_str("\\n"),
            b'"' => s.push_str("\\\""),
            0x20..=0x7E => s.push(char::from(c)),
            _ => {
                let _ = write!(s, "\\{c:03o}");
            }
        }
    }
    s
}

/// Text as our own sections (`-lines`, `-frames`) quote it: printable
/// text as it is, the rest escaped.
fn escape(b: &[u8]) -> String {
    let text = String::from_utf8_lossy(b);
    let mut s = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\n' => s.push_str("\\n"),
            '\t' => s.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                let _ = write!(s, "\\x{:02x}", c as u32);
            }
            c => s.push(c),
        }
    }
    s
}

/// A DWARF register's name as llvm-dwarfdump prints it: LLVM's (`RSP`;
/// on AArch64, `W29`, `WSP`, `B0`), else `reg<n>`.
pub fn register_name(arch: Arch, n: u16) -> String {
    if arch == Arch::Arm64 {
        // (LLVM names a DWARF register by the first of its registers with
        // the number: W0 before X0, B0 before V0.)
        return match n {
            0..=30 => format!("W{n}"),
            31 => "WSP".into(),
            64..=95 => format!("B{}", n - 64),
            _ => hexcavator_dwarf::registers::name(arch, n)
                .map_or_else(|| format!("reg{n}"), |s| s.to_ascii_uppercase()),
        };
    }
    hexcavator_dwarf::registers::name(arch, n)
        .map_or_else(|| format!("reg{n}"), |s| s.to_ascii_uppercase())
}

/// The most operations of one expression shown, and the deepest nesting
/// (`DW_OP_entry_value`'s expressions) followed.
const MAX_OPS: usize = 4096;
const MAX_NESTING: usize = 8;

/// An expression, operation by operation, as llvm-dwarfdump prints it.
pub fn expression(
    expr: &[u8],
    endian: hexcavator_core::Endian,
    addr_size: u8,
    dwarf64: bool,
    arch: Arch,
    nesting: usize,
) -> String {
    expression_with(expr, endian, addr_size, dwarf64, arch, nesting, &|_| None)
}

/// A base type an operation names (`DW_OP_convert`'s), by its offset in
/// the unit: its offset in the section, and its name.
pub type BaseTypes<'a> = dyn Fn(u64) -> Option<(u64, String)> + 'a;

/// [`expression`], naming base types (`DW_OP_convert (0x0000287b)
/// "DW_ATE_signed_32"`) by `base`.
#[allow(clippy::too_many_arguments)]
pub fn expression_with(
    expr: &[u8],
    endian: hexcavator_core::Endian,
    addr_size: u8,
    dwarf64: bool,
    arch: Arch,
    nesting: usize,
    base: &BaseTypes<'_>,
) -> String {
    let mut r = Reader::new(expr, 0, endian);
    let mut parts: Vec<String> = Vec::new();
    while !r.is_empty() && parts.len() < MAX_OPS {
        let Some(op) = r.u8() else { break };
        let name = spelling::operation(u64::from(op))
            .map_or_else(|| format!("DW_OP_unknown_{op:x}"), str::to_string);
        let Some(text) = operands(
            &mut r, op, &name, addr_size, dwarf64, arch, endian, nesting, base,
        ) else {
            parts.push(format!("{name} <decoding error>"));
            break;
        };
        parts.push(text);
    }
    parts.join(", ")
}

#[allow(
    clippy::too_many_arguments,
    clippy::cast_possible_truncation,
    reason = "operands are read at their encoded width, then reinterpreted"
)]
fn operands(
    r: &mut Reader<'_>,
    op: u8,
    name: &str,
    addr_size: u8,
    dwarf64: bool,
    arch: Arch,
    endian: hexcavator_core::Endian,
    nesting: usize,
    base: &BaseTypes<'_>,
) -> Option<String> {
    // A base type reference, as LLVM prints one (0: the generic type).
    let base_ref = |v: u64| -> String {
        if v == 0 {
            return " 0x0".into();
        }
        match base(v) {
            Some((at, name)) if name.is_empty() => format!(" (0x{at:08x})"),
            Some((at, name)) => format!(" (0x{at:08x}) \"{name}\""),
            None => format!(" <invalid base_type ref: 0x{v:x}>"),
        }
    };
    let hex = |v: u64| format!("{name} 0x{v:x}");
    let signed = |v: i64| format!("{name} {v:+}");
    let offset_size = if dwarf64 { 8 } else { 4 };
    Some(match op {
        DW_OP_ADDR => hex(r.uint(usize::from(addr_size))?),
        0x08 => hex(r.uint(1)?),
        0x09 => signed(i64::from(r.uint(1)? as u8 as i8)),
        0x0a => hex(r.uint(2)?),
        0x0b => signed(i64::from(r.uint(2)? as u16 as i16)),
        0x0c => hex(r.uint(4)?),
        0x0d => signed(i64::from(r.uint(4)? as u32 as i32)),
        0x0e => hex(r.uint(8)?),
        0x0f => signed(r.uint(8)? as i64),
        0x10 => hex(r.uleb()?),
        0x11 => signed(r.sleb()?),
        0x15 => hex(r.uint(1)?),
        0x23 => hex(r.uleb()?),
        0x2f | 0x28 => format!("{name} {}", r.uint(2)? as u16 as i16),
        0x50..=0x6f => format!("{name} {}", register_name(arch, u16::from(op - 0x50))),
        0x70..=0x8f => {
            let o = r.sleb()?;
            format!("{name} {}{o:+}", register_name(arch, u16::from(op - 0x70)))
        }
        0x90 => format!(
            "{name} {}",
            register_name(arch, u16::try_from(r.uleb()?).ok()?)
        ),
        0x91 => signed(r.sleb()?),
        0x92 => {
            let reg = u16::try_from(r.uleb()?).ok()?;
            let o = r.sleb()?;
            format!("{name} {}{o:+}", register_name(arch, reg))
        }
        0x93 => hex(r.uleb()?),
        0x94 | 0x95 => hex(r.uint(1)?),
        0x98 => hex(r.uint(2)?),
        0x99 => hex(r.uint(4)?),
        0x9a => hex(r.uint(offset_size)?),
        0x9d => {
            let a = r.uleb()?;
            let b = r.uleb()?;
            format!("{name} 0x{a:x} 0x{b:x}")
        }
        0x9e => {
            let n = r.uleb()?;
            let bytes = r.bytes(n)?;
            let mut s = format!("{name} 0x{n:x}");
            for b in bytes.iter().take(4096) {
                let _ = write!(s, " 0x{b:02x}");
            }
            s
        }
        0xa0 | 0xf2 => {
            let o = r.uint(offset_size)?;
            let v = r.sleb()?;
            format!("{name} 0x{o:x} {v:+}")
        }
        0xa1 | 0xa2 | 0xfb | 0xfc => hex(r.uleb()?),
        // DW_OP_WASM_location: a kind (0 a local, 1 a global, 2 the operand
        // stack, 3 a global by a fixed 4-byte index), then the index.
        0xed => {
            let kind = r.uint(1)?;
            let index = if kind == 3 { r.uint(4)? } else { r.uleb()? };
            format!("{name} 0x{kind:x} 0x{index:x}")
        }
        0xa3 | 0xf3 => {
            let n = r.uleb()?;
            let inner = r.bytes(n)?;
            let text = if nesting < MAX_NESTING {
                expression_with(inner, endian, addr_size, dwarf64, arch, nesting + 1, base)
            } else {
                "...".into()
            };
            format!("{name}({text})")
        }
        0xa4 => {
            let t = r.uleb()?;
            let n = r.uint(1)?;
            let bytes = r.bytes(n)?;
            let mut s = format!("{name}{} 0x{n:02x}", base_ref(t));
            for b in bytes {
                let _ = write!(s, " 0x{b:02x}");
            }
            s
        }
        0xa5 => {
            let reg = r.uleb()?;
            let t = r.uleb()?;
            format!(
                "{name} {}{}",
                register_name(arch, u16::try_from(reg).ok()?),
                base_ref(t)
            )
        }
        0xa6 | 0xa7 => {
            let n = r.uint(1)?;
            let t = r.uleb()?;
            format!("{name} 0x{n:02x}{}", base_ref(t))
        }
        0xa8 | 0xa9 => format!("{name}{}", base_ref(r.uleb()?)),
        0xfa => hex(r.uint(4)?),
        _ => name.to_string(),
    })
}
