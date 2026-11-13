//! `hexc pdb`: dumps PDB contents.

use std::io::{self, Write};
use std::process::ExitCode;

use hexcavator_codeview::TypeIndex;
use hexcavator_codeview::symbols::{Symbol, kind};
use hexcavator_codeview::types::{Field, TypeFormatter, leaf};
use hexcavator_pdb::{Pdb, info::format_guid};

pub const USAGE: &str = "\
usage: hexc pdb [options] <file.pdb>

options:
  -summary          header, GUID/age, stream counts (default)
  -streams          stream directory
  -modules          modules and their source files
  -contribs         section contributions
  -publics          public symbols (in address order)
  -globals          global symbols
  -symbols          each module's symbols
  -lines            each module's line numbers
  -types            type records (TPI)
  -ids              id records (IPI)
  -linker           the linker's recorded environment (command line, ...)
  -find <name>      look up a global, public, and type by name
  -addr <sec:off>   the public symbol and source line at an address
  -all              everything above except -find/-addr
  -diaformat        the line format of tools/diadump (for comparison tests)";

#[derive(Default)]
struct Options {
    summary: bool,
    streams: bool,
    modules: bool,
    contribs: bool,
    publics: bool,
    globals: bool,
    symbols: bool,
    lines: bool,
    types: bool,
    ids: bool,
    linker: bool,
    find: Vec<String>,
    addr: Vec<(u16, u32)>,
    dia: bool,
}

pub fn run(args: &[String]) -> ExitCode {
    let mut o = Options::default();
    let mut path = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.trim_start_matches(['-', '/']) {
            "summary" => o.summary = true,
            "streams" => o.streams = true,
            "modules" => o.modules = true,
            "contribs" => o.contribs = true,
            "publics" => o.publics = true,
            "globals" => o.globals = true,
            "symbols" => o.symbols = true,
            "lines" => o.lines = true,
            "types" => o.types = true,
            "ids" => o.ids = true,
            "linker" => o.linker = true,
            "all" => {
                o.summary = true;
                o.streams = true;
                o.modules = true;
                o.contribs = true;
                o.publics = true;
                o.globals = true;
                o.symbols = true;
                o.lines = true;
                o.types = true;
                o.ids = true;
                o.linker = true;
            }
            "diaformat" => o.dia = true,
            "find" => o.find.extend(it.next().cloned()),
            "addr" => {
                if let Some((s, off)) = it.next().and_then(|v| v.split_once(':'))
                    && let (Ok(s), Ok(off)) =
                        (u16::from_str_radix(s, 16), u32::from_str_radix(off, 16))
                {
                    o.addr.push((s, off));
                }
            }
            _ if !a.starts_with('-') => path = Some(a.clone()),
            _ => {
                ereport!("hexc pdb: unknown option '{a}'\n\n{USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    let Some(path) = path else {
        ereport!("{USAGE}");
        return ExitCode::from(2);
    };
    let has_any = o.streams
        || o.modules
        || o.contribs
        || o.publics
        || o.globals
        || o.symbols
        || o.lines
        || o.types
        || o.ids
        || o.linker;
    if !has_any && !o.dia && o.find.is_empty() && o.addr.is_empty() {
        o.summary = true;
    }
    let map = match hexcavator_mmap::Mmap::open(&path) {
        Ok(m) => m,
        Err(e) => {
            ereport!("hexc: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let pdb = match Pdb::parse(&map) {
        Ok(p) => p,
        Err(e) => {
            ereport!("hexc: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut out = io::BufWriter::new(crate::out::stdout());
    let result = if o.dia {
        dia_format(&mut out, &pdb)
    } else {
        dump(&mut out, &pdb, &o).and_then(|()| {
            if o.linker {
                linker(&mut out, &map)
            } else {
                Ok(())
            }
        })
    };
    match result.and_then(|_| out.flush()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(e) => {
            ereport!("hexc: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The linker's environment block (`S_ENVBLOCK` in `* Linker *`).
fn linker(out: &mut impl Write, data: &[u8]) -> io::Result<()> {
    let info = hexcavator_debuginfo::DebugInfo::parse(data)
        .and_then(|d| d.linker_info())
        .map_err(io::Error::other)?;
    writeln!(out, "Linker")?;
    if info.minimal {
        writeln!(out, "  minimal (/DEBUG:FASTLINK) PDB")?;
    }
    if info.environment.is_empty() {
        writeln!(out, "  (no environment recorded)")?;
    }
    for (key, value) in &info.environment {
        writeln!(out, "  {key:<4} {value}")?;
    }
    writeln!(out)
}

/// How deep the symbol dump indents nested scopes; deeper ones say their
/// depth.
const MAX_INDENT: usize = 32;

fn s(b: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(b)
}

fn err(e: hexcavator_core::Error) -> io::Error {
    io::Error::other(e.to_string())
}

fn dump(out: &mut dyn Write, pdb: &Pdb<'_>, o: &Options) -> io::Result<()> {
    let dbi = pdb.dbi().map_err(err)?;
    if o.summary {
        let info = pdb.info();
        writeln!(out, "Summary")?;
        writeln!(out, "  Block size:        {}", pdb.msf().block_size())?;
        writeln!(out, "  Streams:           {}", pdb.msf().stream_count())?;
        writeln!(out, "  Version:           {}", info.version())?;
        writeln!(out, "  GUID:              {}", format_guid(&info.guid()))?;
        writeln!(out, "  Age:               {}", info.age())?;
        writeln!(out, "  Machine:           {:#06x}", dbi.machine())?;
        writeln!(out, "  Modules:           {}", dbi.modules().len())?;
        let types = pdb.types().map_err(err)?;
        let ids = pdb.ids().map_err(err)?;
        writeln!(
            out,
            "  Types:             {} ({:#x}..{:#x})",
            types.len(),
            types.begin().0,
            types.end().0
        )?;
        writeln!(
            out,
            "  Ids:               {} ({:#x}..{:#x})",
            ids.len(),
            ids.begin().0,
            ids.end().0
        )?;
        writeln!(
            out,
            "  Public symbols:    {}",
            pdb.publics().map_err(err)?.address_map().len()
        )?;
        writeln!(
            out,
            "  Global symbols:    {}",
            pdb.globals().map_err(err)?.records().len()
        )?;
        for (name, index) in info.named_streams() {
            writeln!(out, "  Named stream:      {} = {index}", s(name))?;
        }
        writeln!(out)?;
    }
    if o.streams {
        writeln!(out, "Streams")?;
        for i in 0..u32::try_from(pdb.msf().stream_count()).unwrap_or(u32::MAX) {
            match pdb.msf().stream_size(i) {
                Some(size) => writeln!(out, "  {i:5}: {size:10} bytes")?,
                None => writeln!(out, "  {i:5}: (nil)")?,
            }
        }
        writeln!(out)?;
    }
    if o.modules {
        writeln!(out, "Modules")?;
        for m in dbi.modules() {
            writeln!(out, "  [{:4}] {}", m.index, m.name_str())?;
            writeln!(out, "         obj: {}", s(m.object_name))?;
            for f in dbi.module_files(m.index).map_err(err)? {
                writeln!(out, "         src: {}", s(f))?;
            }
        }
        writeln!(out)?;
    }
    if o.contribs {
        writeln!(out, "Section contributions")?;
        for c in dbi.section_contribs().map_err(err)?.iter() {
            writeln!(
                out,
                "  {:04X}:{:08X} size {:8X} chars {:08X} module {}",
                c.section.get(),
                c.offset.get(),
                c.size.get(),
                c.characteristics.get(),
                c.module_index.get()
            )?;
        }
        writeln!(out)?;
    }
    let records = pdb.symbol_records();
    if o.publics {
        writeln!(out, "Public symbols")?;
        for off in pdb.publics().map_err(err)?.address_map() {
            if let Some(Ok(Symbol::Public {
                flags,
                offset,
                segment,
                name,
            })) = hexcavator_pdb::gsi::symbol_at(records, off.get()).map(|r| r.parse())
            {
                writeln!(
                    out,
                    "  {segment:04X}:{offset:08X} flags {flags:X} {}",
                    s(name)
                )?;
            }
        }
        writeln!(out)?;
    }
    let types = pdb.types().map_err(err)?;
    let tf = TypeFormatter { types };
    if o.globals {
        writeln!(out, "Global symbols")?;
        for h in pdb.globals().map_err(err)?.records() {
            if let Some(rec) = hexcavator_pdb::gsi::symbol_at(records, (h.offset.get() - 1) as u32)
            {
                writeln!(out, "  {}", describe(&rec, &tf))?;
            }
        }
        writeln!(out)?;
    }
    if o.symbols || o.lines {
        let names = pdb.names().map_err(err)?;
        for m in dbi.modules() {
            let Some(stream) = pdb.module_stream(m).map_err(err)? else {
                continue;
            };
            writeln!(out, "Module {} ({})", m.index, m.name_str())?;
            if o.symbols {
                let mut depth = 0usize;
                for rec in stream.symbols() {
                    if kind::closes_scope(rec.kind) {
                        depth = depth.saturating_sub(1);
                    }
                    // (Indented by depth up to a point: a hostile stream can
                    // open scope after scope, and the output would grow as
                    // its square.)
                    let indent = if depth <= MAX_INDENT {
                        "  ".repeat(depth)
                    } else {
                        format!("{}[depth {depth}] ", "  ".repeat(MAX_INDENT))
                    };
                    writeln!(out, "  {:08X} {indent}{}", rec.offset, describe(&rec, &tf))?;
                    if kind::opens_scope(rec.kind) {
                        depth += 1;
                    }
                }
            }
            if o.lines {
                for block in stream.line_blocks() {
                    let file = stream
                        .file_checksum(block.file)
                        .and_then(|c| names.get(c.name))
                        .map(s)
                        .unwrap_or_default();
                    writeln!(
                        out,
                        "  lines {:04X}:{:08X}+{:X} {file}",
                        block.segment, block.offset, block.code_size
                    )?;
                    for l in block.lines {
                        writeln!(
                            out,
                            "    {:08X} line {}",
                            // (Both from the file: shown as they add up.)
                            block.offset.wrapping_add(l.offset.get()),
                            l.line()
                        )?;
                    }
                }
            }
            writeln!(out)?;
        }
    }
    if o.types {
        writeln!(out, "Types")?;
        for (ti, rec) in types.iter() {
            writeln!(
                out,
                "  {:#x} {} {}",
                ti.0,
                leaf::name(rec.kind),
                describe_type(ti, &rec, &tf)
            )?;
        }
        writeln!(out)?;
    }
    if o.ids {
        writeln!(out, "Ids")?;
        let ids = pdb.ids().map_err(err)?;
        for (ti, rec) in ids.iter() {
            let name = rec.name().map(s).unwrap_or_default();
            writeln!(out, "  {:#x} {} {name}", ti.0, leaf::name(rec.kind))?;
        }
        writeln!(out)?;
    }
    for name in &o.find {
        writeln!(out, "Lookup {name}")?;
        for g in pdb.find_globals(name).map_err(err)? {
            writeln!(out, "  global: {}", describe(&g, &tf))?;
        }
        if let Some(p) = pdb.find_public(name).map_err(err)? {
            writeln!(out, "  public: {}", describe(&p, &tf))?;
        }
        if let Some(ti) = types.find_udt(name) {
            writeln!(out, "  type:   {:#x} {}", ti.0, tf.name(ti))?;
            if let Some(udt) = types.record(ti).and_then(|r| r.udt()) {
                writeln!(out, "          size {}", udt.size)?;
                if let Some(fl) = types.record(udt.field_list) {
                    for f in fl.fields() {
                        writeln!(out, "          {}", describe_field(&f, &tf))?;
                    }
                }
            }
        }
    }
    for &(sec, off) in &o.addr {
        writeln!(out, "Address {sec:04X}:{off:08X}")?;
        if let Some((p, delta)) = pdb.public_at(sec, off).map_err(err)? {
            writeln!(
                out,
                "  public: {}+{delta:#x}",
                p.name().map(s).unwrap_or_default()
            )?;
        }
        if let Some(l) = pdb.line_at(sec, off).map_err(err)? {
            writeln!(out, "  line:   {}({})", l.file, l.line)?;
        }
    }
    Ok(())
}

fn describe(rec: &hexcavator_codeview::SymbolRecord<'_>, tf: &TypeFormatter<'_>) -> String {
    let name = kind::name(rec.kind);
    match rec.parse() {
        Ok(Symbol::Public {
            flags,
            offset,
            segment,
            name: n,
        }) => format!(
            "{name} [{segment:04X}:{offset:08X}] flags {flags:X} {}",
            s(n)
        ),
        Ok(Symbol::Procedure {
            offset,
            segment,
            len,
            ty,
            name: n,
            ..
        }) => {
            format!(
                "{name} [{segment:04X}:{offset:08X}] len {len:X} {} type {}",
                s(n),
                type_name(ty, tf)
            )
        }
        Ok(Symbol::Data {
            offset,
            segment,
            ty,
            name: n,
            ..
        }) => {
            format!(
                "{name} [{segment:04X}:{offset:08X}] {} : {}",
                s(n),
                type_name(ty, tf)
            )
        }
        Ok(Symbol::Udt { ty, name: n }) => format!("{name} {} = {}", s(n), tf.name(ty)),
        Ok(Symbol::Constant { ty, value, name: n }) => {
            format!("{name} {} = {value} : {}", s(n), tf.name(ty))
        }
        Ok(Symbol::Reference {
            symbol_offset,
            module,
            name: n,
            ..
        }) => {
            format!(
                "{name} {} (module {module}, offset {symbol_offset:X})",
                s(n)
            )
        }
        Ok(Symbol::RegisterRelative {
            offset,
            ty,
            register,
            name: n,
        }) => {
            format!(
                "{name} {} : {} at reg {register}{offset:+#x}",
                s(n),
                tf.name(ty)
            )
        }
        Ok(Symbol::Local { ty, flags, name: n }) => {
            format!("{name} {} : {} flags {flags:X}", s(n), tf.name(ty))
        }
        Ok(Symbol::Block {
            offset,
            segment,
            len,
            ..
        }) => format!("{name} [{segment:04X}:{offset:08X}] len {len:X}"),
        Ok(Symbol::Label {
            offset,
            segment,
            name: n,
            ..
        }) => format!("{name} [{segment:04X}:{offset:08X}] {}", s(n)),
        Ok(Symbol::Thunk {
            offset,
            segment,
            len,
            name: n,
            ..
        }) => format!("{name} [{segment:04X}:{offset:08X}] len {len:X} {}", s(n)),
        Ok(Symbol::ObjName { name: n, .. }) => format!("{name} {}", s(n)),
        Ok(Symbol::Compile3 {
            machine,
            frontend,
            backend,
            version,
            flags,
        }) => format!(
            "{name} machine {machine:#x} lang {} fe {}.{}.{}.{} be {}.{}.{}.{} {}",
            flags & hexcavator_codeview::symbols::COMPILE3_LANGUAGE_MASK,
            frontend[0],
            frontend[1],
            frontend[2],
            frontend[3],
            backend[0],
            backend[1],
            backend[2],
            backend[3],
            s(version)
        ),
        Ok(Symbol::FrameProc {
            frame_size,
            callee_saved_size,
            flags,
            ..
        }) => {
            format!("{name} frame {frame_size:X} saved {callee_saved_size:X} flags {flags:X}")
        }
        Ok(Symbol::Section {
            section,
            rva,
            size,
            name: n,
            ..
        }) => format!("{name} {section} rva {rva:X} size {size:X} {}", s(n)),
        Ok(Symbol::CoffGroup {
            offset,
            segment,
            size,
            name: n,
            ..
        }) => {
            format!("{name} [{segment:04X}:{offset:08X}] size {size:X} {}", s(n))
        }
        Ok(Symbol::InlineSite { inlinee, .. }) => format!("{name} inlinee {:#x}", inlinee.0),
        Ok(Symbol::BuildInfo { id }) => format!("{name} {:#x}", id.0),
        Ok(Symbol::Register {
            ty,
            register,
            name: n,
        }) => format!("{name} {} : {} reg {register}", s(n), tf.name(ty)),
        Ok(Symbol::BpRelative {
            offset,
            ty,
            name: n,
        }) => format!("{name} {} : {} bp{offset:+#x}", s(n), tf.name(ty)),
        Ok(_) if name == "S_???" => format!("S_??? ({:#06x})", rec.kind),
        Ok(_) => name.to_string(),
        Err(e) => format!("{name} <{e}>"),
    }
}

fn type_name(ti: TypeIndex, tf: &TypeFormatter<'_>) -> String {
    tf.name(ti)
}

fn describe_type(
    ti: TypeIndex,
    rec: &hexcavator_codeview::TypeRecord<'_>,
    tf: &TypeFormatter<'_>,
) -> String {
    if let Some(u) = rec.udt() {
        let fwd = if u.is_forward_ref() { " (forward)" } else { "" };
        return format!("{} size {}{fwd}", s(u.name), u.size);
    }
    match rec.kind {
        leaf::LF_FIELDLIST => format!("{} fields", rec.fields().count()),
        leaf::LF_POINTER
        | leaf::LF_MODIFIER
        | leaf::LF_ARRAY
        | leaf::LF_PROCEDURE
        | leaf::LF_MFUNCTION
        | leaf::LF_ARGLIST
        | leaf::LF_BITFIELD => tf.name(ti),
        _ => String::new(),
    }
}

fn describe_field(f: &Field<'_>, tf: &TypeFormatter<'_>) -> String {
    match f {
        Field::BaseClass { ty, offset, .. } => format!("base {} at {offset}", tf.name(*ty)),
        Field::VirtualBaseClass { ty, .. } => format!("virtual base {}", tf.name(*ty)),
        Field::Member {
            ty, offset, name, ..
        } => format!("+{offset:#x} {} : {}", s(name), tf.name(*ty)),
        Field::StaticMember { ty, name, .. } => format!("static {} : {}", s(name), tf.name(*ty)),
        Field::Method { count, name, .. } => format!("method {} ({count} overloads)", s(name)),
        Field::OneMethod {
            name,
            vtable_offset,
            ..
        } => match vtable_offset {
            Some(v) => format!("method {} (vtable +{v:#x})", s(name)),
            None => format!("method {}", s(name)),
        },
        Field::NestedType { ty, name } => format!("nested {} = {}", s(name), tf.name(*ty)),
        Field::Enumerate { value, name, .. } => format!("{} = {value}", s(name)),
        Field::VFuncTab { ty } => format!("vftable {}", tf.name(*ty)),
        Field::Index { ty } => format!("continued in {:#x}", ty.0),
        Field::Unknown { kind } => format!("<field {kind:#x}>"),
    }
}

/// Prints the same lines as `tools/diadump`, for comparison with DIA.
fn dia_format(out: &mut dyn Write, pdb: &Pdb<'_>) -> io::Result<()> {
    let dbi = pdb.dbi().map_err(err)?;
    let sections = pdb.sections().map_err(err)?;
    let names = pdb.names().map_err(err)?;
    let rva = |sec: u16, off: u32| pdb.rva(&sections, sec, off);
    for m in dbi.modules() {
        writeln!(out, "MODULE {}", m.name_str())?;
        let Some(stream) = pdb.module_stream(m).map_err(err)? else {
            continue;
        };
        // A line extends to the next line of its block (which may be at the
        // same address); the last line of a block extends to the first line
        // of the next block of the subsection if that is higher, or to the
        // end of the subsection's code. (This is how DIA computes lengths.)
        let blocks = stream.line_blocks();
        let mut i = 0;
        while i < blocks.len() {
            let key = (blocks[i].segment, blocks[i].offset, blocks[i].code_size);
            let first = i;
            while i < blocks.len()
                && (blocks[i].segment, blocks[i].offset, blocks[i].code_size) == key
            {
                i += 1;
            }
            let group = &blocks[first..i];
            for (bi, b) in group.iter().enumerate() {
                let next_block = group
                    .get(bi + 1)
                    .and_then(|n| n.lines.first())
                    .map(|l| l.offset.get());
                let file = stream
                    .file_checksum(b.file)
                    .and_then(|c| names.get(c.name))
                    .map(s)
                    .unwrap_or_default();
                for (j, l) in b.lines.iter().enumerate() {
                    let start = l.offset.get();
                    let end = match b.lines.get(j + 1) {
                        Some(n) => n.offset.get(),
                        None => next_block.filter(|&o| o > start).unwrap_or(key.2),
                    };
                    if let Some(r) = rva(key.0, key.1 + start) {
                        writeln!(
                            out,
                            "LINE {r:X} {:X} {} {file}",
                            end.saturating_sub(start),
                            l.line()
                        )?;
                    }
                }
            }
        }
        for rec in stream.symbols() {
            if let Ok(Symbol::Procedure {
                offset,
                segment,
                len,
                name,
                ..
            }) = rec.parse()
                && let Some(r) = rva(segment, offset)
            {
                writeln!(out, "FUNC {r:X} {len:X} {}", s(name))?;
            }
        }
    }
    let records = pdb.symbol_records();
    for off in pdb.publics().map_err(err)?.address_map() {
        if let Some(Ok(Symbol::Public {
            offset,
            segment,
            name,
            ..
        })) = hexcavator_pdb::gsi::symbol_at(records, off.get()).map(|r| r.parse())
        {
            writeln!(out, "PUBLIC {segment:X}:{offset:X} {}", s(name))?;
        }
    }
    for h in pdb.globals().map_err(err)?.records() {
        if let Some(Ok(Symbol::Data {
            offset,
            segment,
            name,
            thread: false,
            ..
        })) =
            hexcavator_pdb::gsi::symbol_at(records, (h.offset.get() - 1) as u32).map(|r| r.parse())
            && let Some(r) = rva(segment, offset)
        {
            writeln!(out, "DATA {r:X} {}", s(name))?;
        }
    }
    // DIA lists each UDT name once, with the size of its definition (or 0
    // if there is only a forward reference).
    let types = pdb.types().map_err(err)?;
    type UdtKey<'a> = (&'a [u8], u32);
    let mut udts: std::collections::BTreeMap<UdtKey<'_>, (&[u8], u64)> =
        std::collections::BTreeMap::new();
    for (ti, rec) in types.iter() {
        if let Some(u) = rec.udt().filter(|u| u.kind != leaf::LF_ENUM) {
            // Anonymous types without a unique name are each distinct.
            let anonymous = u.name.starts_with(b"<");
            if anonymous && u.is_forward_ref() {
                continue;
            }
            let key = (
                u.unique_name.unwrap_or(u.name),
                if anonymous { ti.0 } else { 0 },
            );
            let e = udts.entry(key).or_insert((u.name, 0));
            if !u.is_forward_ref() {
                e.1 = u.size;
            }
        }
    }
    for (name, size) in udts.into_values() {
        writeln!(out, "UDT {size:X} {}", s(name))?;
    }
    Ok(())
}
