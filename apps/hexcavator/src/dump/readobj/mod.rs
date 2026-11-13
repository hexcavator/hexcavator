//! `hexc dump` of ELF, Mach-O, and WebAssembly files, as llvm-readobj
//! shows them (its LLVM style): file headers, sections, segments,
//! symbols, relocations, the dynamic table, notes, and the like, in its
//! layout and spelling, so that its output and ours can be compared line
//! for line.
//!
//! What each part shows is chosen as llvm-readobj's options choose it
//! (`--file-headers`, `--sections`, `--symbols`, ...); `-headers`,
//! `-symbols`, and `-all` choose the usual sets.

use std::fmt::Write as _;

pub mod elf;
pub mod macho;
pub mod wasm;

/// What to show.
#[derive(Clone, Copy, Debug, Default)]
pub struct Parts {
    pub file_headers: bool,
    pub sections: bool,
    pub program_headers: bool,
    pub symbols: bool,
    pub dyn_symbols: bool,
    pub relocations: bool,
    pub dynamic_table: bool,
    pub notes: bool,
    pub macho_segment: bool,
    pub macho_dysymtab: bool,
    pub macho_version_min: bool,
    pub needed_libs: bool,
}

impl Parts {
    /// Whether anything was asked for.
    pub fn any(&self) -> bool {
        self.file_headers
            || self.sections
            || self.program_headers
            || self.symbols
            || self.dyn_symbols
            || self.relocations
            || self.dynamic_table
            || self.notes
            || self.macho_segment
            || self.macho_dysymtab
            || self.macho_version_min
            || self.needed_libs
    }

    /// Everything.
    pub fn all() -> Self {
        Self {
            file_headers: true,
            sections: true,
            program_headers: true,
            symbols: true,
            dyn_symbols: true,
            relocations: true,
            dynamic_table: true,
            notes: true,
            macho_segment: true,
            macho_dysymtab: true,
            macho_version_min: true,
            needed_libs: true,
        }
    }

    /// Sets the part an llvm-readobj option names; false if none.
    pub fn set(&mut self, name: &str) -> bool {
        match name {
            "file-headers" | "file-header" | "h" => self.file_headers = true,
            "sections" | "section-headers" | "S" => self.sections = true,
            "program-headers" | "segments" | "l" => self.program_headers = true,
            "symbols" | "syms" => self.symbols = true,
            "dyn-symbols" | "dyn-syms" => self.dyn_symbols = true,
            "relocations" | "relocs" | "r" => self.relocations = true,
            "dynamic-table" | "dynamic" | "d" => self.dynamic_table = true,
            "notes" | "n" => self.notes = true,
            "macho-segment" => self.macho_segment = true,
            "macho-dysymtab" => self.macho_dysymtab = true,
            "macho-version-min" => self.macho_version_min = true,
            "needed-libs" => self.needed_libs = true,
            _ => return false,
        }
        true
    }
}

/// llvm-readobj's ScopedPrinter: lines indented two spaces a level.
pub struct Printer<'o> {
    pub out: &'o mut String,
    depth: usize,
}

impl<'o> Printer<'o> {
    pub fn new(out: &'o mut String) -> Self {
        Self { out, depth: 0 }
    }

    fn pad(&mut self) {
        for _ in 0..self.depth {
            self.out.push_str("  ");
        }
    }

    /// `Name: value`.
    pub fn line(&mut self, name: &str, value: impl std::fmt::Display) {
        self.pad();
        let _ = writeln!(self.out, "{name}: {value}");
    }

    /// A line as it is.
    pub fn raw(&mut self, text: impl std::fmt::Display) {
        self.pad();
        let _ = writeln!(self.out, "{text}");
    }

    /// `Name {` (or `Name [`), then the group's lines one level deeper.
    pub fn open(&mut self, head: &str) {
        self.pad();
        let _ = writeln!(self.out, "{head}");
        self.depth += 1;
    }

    /// The group's end: `}` or `]`.
    pub fn close(&mut self, end: &str) {
        self.depth = self.depth.saturating_sub(1);
        self.pad();
        let _ = writeln!(self.out, "{end}");
    }

    /// `Name: value (0xN)`, or the number alone if it has no name.
    pub fn enumerated(&mut self, name: &str, label: Option<&str>, v: u64) {
        match label {
            Some(l) => self.line(name, format_args!("{l} (0x{v:X})")),
            None => self.line(name, format_args!("0x{v:X}")),
        }
    }

    /// `Name [ (0xN)` and the flags set, by name (the bits without names,
    /// as numbers), then `]`.
    pub fn flags(&mut self, name: &str, v: u64, names: &[(&str, u64)]) {
        self.open(&format!("{name} [ (0x{v:X})"));
        let mut set: Vec<(&str, u64)> = names
            .iter()
            .copied()
            .filter(|&(_, b)| b != 0 && v & b == b)
            .collect();
        set.sort_by(|a, b| a.0.cmp(b.0));
        let mut named = 0u64;
        for (n, b) in &set {
            self.raw(format_args!("{n} (0x{b:X})"));
            named |= b;
        }
        let mut rest = v & !named;
        while rest != 0 {
            let bit = rest & rest.wrapping_neg();
            self.raw(format_args!("0x{bit:X}"));
            rest &= !bit;
        }
        self.close("]");
    }
}
