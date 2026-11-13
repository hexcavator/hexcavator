//! An image's symbols as a table to query (see `hexcavator_query`): one
//! row per symbol, with where it is and where it came from.

use std::borrow::Cow;

use hexcavator_query::{Column, Kind, Table, Value};

use crate::Model;
use crate::symbols::Symbol;

/// The columns, in order.
pub const COLUMNS: [Column; 13] = [
    Column {
        name: "name",
        kind: Kind::Str,
        summable: false,
        doc: "the symbol's name, demangled",
    },
    Column {
        name: "kind",
        kind: Kind::Str,
        summable: false,
        doc: "function, data, public, string, thunk, primary-block, separated-block, pdata, unwind, import-thunk, resource-data, ...",
    },
    Column {
        name: "file",
        kind: Kind::Int,
        summable: true,
        doc: "its size in the file (0 for a folded name)",
    },
    Column {
        name: "vm",
        kind: Kind::Int,
        summable: true,
        doc: "its size in memory",
    },
    Column {
        name: "rva",
        kind: Kind::Int,
        summable: false,
        doc: "its address, relative to the image",
    },
    Column {
        name: "section",
        kind: Kind::Str,
        summable: false,
        doc: "its section (.text, .rdata, ...)",
    },
    Column {
        name: "group",
        kind: Kind::Str,
        summable: false,
        doc: "its COFF group (.text$mn, .rdata$r, ...)",
    },
    Column {
        name: "compiland",
        kind: Kind::Str,
        summable: false,
        doc: "the object whose debug information holds it",
    },
    Column {
        name: "library",
        kind: Kind::Str,
        summable: false,
        doc: "the library that object came from",
    },
    Column {
        name: "folded",
        kind: Kind::Bool,
        summable: false,
        doc: "a name identical code folding merged into another",
    },
    Column {
        name: "static",
        kind: Kind::Bool,
        summable: false,
        doc: "a file-scope variable with internal linkage (a copy per compiland)",
    },
    Column {
        name: "source",
        kind: Kind::Str,
        summable: false,
        doc: "the source file its code starts in (from the line tables; code only)",
    },
    Column {
        name: "line",
        kind: Kind::Int,
        summable: false,
        doc: "the source line its code starts at",
    },
];

/// A name as a value: unknown if there is none, or it is empty.
fn text(name: Option<&str>) -> Value<'_> {
    match name {
        Some(n) if !n.is_empty() => Value::Str(Cow::Borrowed(n)),
        _ => Value::Null,
    }
}

/// An image's symbols, with the model they belong to and the debug
/// information's modules (which a symbol's compiland indexes).
pub struct SymbolTable<'a> {
    model: &'a Model,
    symbols: &'a [Symbol],
    modules: &'a [hexcavator_debuginfo::Compiland],
    /// Each symbol's section and group (indexes, or `u32::MAX`).
    places: Vec<(u32, u32)>,
    /// The line tables, if given.
    lines: Option<&'a hexcavator_debuginfo::SourceLines>,
}

impl<'a> SymbolTable<'a> {
    pub fn new(
        model: &'a Model,
        symbols: &'a [Symbol],
        modules: &'a [hexcavator_debuginfo::Compiland],
    ) -> Self {
        let find = |addr: u64, starts: &[(u64, u64)]| -> u32 {
            let i = starts.partition_point(|s| s.0 <= addr);
            match i.checked_sub(1) {
                Some(j) if addr < starts[j].1 => u32::try_from(j).unwrap_or(u32::MAX),
                _ => u32::MAX,
            }
        };
        let sections: Vec<(u64, u64)> = model
            .sections
            .iter()
            .map(|s| (s.addr, s.addr + s.size.vm.max(s.size.file)))
            .collect();
        let groups: Vec<(u64, u64)> = model
            .groups
            .iter()
            .map(|g| (g.addr, g.addr + g.extent()))
            .collect();
        let places = symbols
            .iter()
            .map(|s| (find(s.addr, &sections), find(s.addr, &groups)))
            .collect();
        SymbolTable {
            model,
            symbols,
            modules,
            places,
            lines: None,
        }
    }

    /// With the line tables, for the `file` and `line` columns.
    pub fn with_lines(mut self, lines: &'a hexcavator_debuginfo::SourceLines) -> Self {
        self.lines = Some(lines);
        self
    }

    /// The line span at `addr`.
    fn line_at(&self, addr: u64) -> Option<&'a hexcavator_debuginfo::LineSpan> {
        let spans = &self.lines?.spans;
        let i = spans.partition_point(|s| s.addr <= addr);
        spans[..i].last().filter(|s| addr < s.addr + s.size)
    }
}

impl Table for SymbolTable<'_> {
    fn columns(&self) -> &[Column] {
        &COLUMNS
    }

    fn rows(&self) -> usize {
        self.symbols.len()
    }

    fn cell(&self, row: usize, column: usize) -> Value<'_> {
        let s = &self.symbols[row];
        let (section, group) = self.places[row];
        let compiland = s.compiland.and_then(|c| self.modules.get(c as usize));
        match column {
            0 => Value::Str(Cow::Borrowed(&s.name)),
            1 => Value::Str(Cow::Borrowed(s.kind.label())),
            2 => Value::Int(s.size.file),
            3 => Value::Int(s.size.vm),
            4 => Value::Int(s.addr),
            5 => self
                .model
                .sections
                .get(section as usize)
                .map_or(Value::Null, |x| Value::Str(Cow::Borrowed(&x.name))),
            6 => self
                .model
                .groups
                .get(group as usize)
                .map_or(Value::Null, |x| Value::Str(Cow::Borrowed(&x.name))),
            7 => text(compiland.map(|c| c.name.as_str())),
            8 => text(compiland.map(|c| c.library.as_str())),
            9 => Value::Bool(s.folded),
            10 => Value::Bool(s.file_static),
            11 => text(
                self.line_at(s.addr)
                    .and_then(|l| self.lines?.files.get(l.file as usize))
                    .map(String::as_str),
            ),
            _ => self
                .line_at(s.addr)
                .map_or(Value::Null, |l| Value::Int(u64::from(l.line))),
        }
    }
}
