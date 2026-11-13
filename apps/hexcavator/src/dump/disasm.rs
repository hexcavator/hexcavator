//! `/disasm`: linear disassembly of code sections, matching dumpbin.
//!
//! x86, x64, and ARM64 code is supported. Hybrid images (ARM64EC, ARM64X,
//! and x86 CHPE) say in their code range map which ranges hold which kind
//! of code; like dumpbin, only those ranges are disassembled.

use std::io::{self, Write};

use hexcavator_core::Rva;
use hexcavator_pe::consts::{machine, section_characteristics as scn};
use hexcavator_pe::raw::SectionHeader;
use hexcavator_pe::{CodeKind, FileKind, PeFile};
use hexcavator_x86::{Mode, decode, format};

use crate::symbols::SymbolMap;

/// What to decode a range as.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Arch {
    X86(Mode),
    Arm64,
}

fn isa(file: &PeFile<'_>) -> Option<Arch> {
    match file.machine() {
        machine::AMD64 => Some(Arch::X86(Mode::Bits64)),
        machine::I386 | machine::CHPE_X86 => Some(Arch::X86(Mode::Bits32)),
        machine::ARM64 | machine::ARM64EC | machine::ARM64X => Some(Arch::Arm64),
        _ => None,
    }
}

/// Notes (once) that the file's machine cannot be disassembled yet.
pub fn check_machine(out: &mut dyn Write, file: &PeFile<'_>) -> io::Result<()> {
    if isa(file).is_none() {
        writeln!(
            out,
            "\n  (disassembly of {} code is not supported yet)",
            machine::name(file.machine()).unwrap_or("this machine's")
        )?;
    }
    Ok(())
}

/// The ranges of `section` to disassemble, and how: the whole section, or
/// for hybrid images the parts the code range map covers.
fn ranges(file: &PeFile<'_>, section: &SectionHeader) -> Vec<(Rva, u32, Arch)> {
    let start = section.virtual_address.get();
    let raw = section.size_of_raw_data.get();
    let size = match (file.kind(), section.virtual_size.get()) {
        (FileKind::Image, v) if v != 0 => v.min(raw),
        _ => raw,
    };
    let hybrid = (file.kind() == FileKind::Image)
        .then(|| file.load_config().and_then(|c| c.hybrid_metadata()))
        .flatten();
    let Some(hybrid) = hybrid else {
        return isa(file).map_or_else(Vec::new, |i| vec![(Rva(start), size, i)]);
    };
    let x86_mode = if hybrid.is_x86() {
        Mode::Bits32
    } else {
        Mode::Bits64
    };
    let end = start + size;
    hybrid
        .code_ranges()
        .filter_map(|r| {
            let lo = r.rva.get().max(start);
            let hi = r.rva.get().saturating_add(r.size).min(end);
            (lo < hi).then(|| {
                let isa = match r.kind {
                    CodeKind::X64 | CodeKind::X86 => Arch::X86(x86_mode),
                    CodeKind::Arm64 | CodeKind::Arm64ec => Arch::Arm64,
                };
                (Rva(lo), hi - lo, isa)
            })
        })
        .collect()
}

/// Disassembles `section`, if it holds code.
pub fn disassemble_section(
    out: &mut dyn Write,
    file: &PeFile<'_>,
    section: &SectionHeader,
    symbols: Option<&SymbolMap>,
) -> io::Result<()> {
    let flags = section.characteristics.get();
    if flags & (scn::CNT_CODE | scn::MEM_EXECUTE) == 0 {
        return Ok(());
    }
    let ranges = ranges(file, section);
    if ranges.is_empty() {
        return Ok(());
    }
    let base = file.optional_header().map_or(0, |o| o.image_base().get());
    let section_start = section.virtual_address.get();
    let raw_start = section.pointer_to_raw_data.get() as usize;
    writeln!(out)?;
    for (rva, size, isa) in ranges {
        let offset = raw_start + (rva.get() - section_start) as usize;
        let Some(bytes) = file
            .data()
            .get(offset..)
            .and_then(|d| d.get(..size as usize))
        else {
            continue;
        };
        let address = base + u64::from(rva.get());
        match isa {
            Arch::X86(mode) => listing(out, mode, address, bytes, symbols)?,
            Arch::Arm64 => arm64_listing(out, address, bytes, symbols)?,
        }
    }
    Ok(())
}

/// Writes a dumpbin-style listing of `bytes`, which start at `address`.
pub fn listing(
    out: &mut dyn Write,
    mode: Mode,
    address: u64,
    bytes: &[u8],
    symbols: Option<&SymbolMap>,
) -> io::Result<()> {
    let none = hexcavator_x86::format::NoSymbols;
    let names: &dyn hexcavator_x86::format::Symbols = match symbols {
        Some(s) => s,
        None => &none,
    };
    let width = if mode == Mode::Bits64 { 16 } else { 8 };
    let mut offset = 0usize;
    while offset < bytes.len() {
        let here = address + offset as u64;
        if let Some(label) = symbols.and_then(|s| s.at(here)) {
            writeln!(out, "{label}:")?;
        }
        // Bytes no object contributed are shown as data.
        if let Some(end) = symbols.and_then(|s| s.gap_end(here)) {
            let room = usize::try_from(end - here).unwrap_or(usize::MAX);
            let n = room.min(16).min(bytes.len() - offset);
            data_line(out, width, here, &bytes[offset..offset + n])?;
            offset += n;
            continue;
        }
        let (len, inst) = match decode(&bytes[offset..], mode, here) {
            Ok(inst) => (inst.len(), Some(inst)),
            Err(_) => (1, None),
        };
        let text = format::listing_with(
            mode,
            here,
            &bytes[offset..offset + len],
            inst.as_ref(),
            names,
        );
        out.write_all(text.as_bytes())?;
        offset += len;
    }
    Ok(())
}

impl hexcavator_arm64::Symbols for SymbolMap {
    fn name_at(&self, address: u64) -> Option<&str> {
        self.public_at(address)
    }
}

/// An ARM64 listing: one line per word, `address: word  instruction`.
fn arm64_listing(
    out: &mut dyn Write,
    address: u64,
    bytes: &[u8],
    symbols: Option<&SymbolMap>,
) -> io::Result<()> {
    let mut offset = 0usize;
    while offset + 4 <= bytes.len() {
        let here = address + offset as u64;
        if let Some(label) = symbols.and_then(|s| s.at(here)) {
            writeln!(out, "{label}:")?;
        }
        if let Some(end) = symbols.and_then(|s| s.gap_end(here)) {
            let room = usize::try_from(end - here).unwrap_or(usize::MAX);
            let n = room.min(16).min(bytes.len() - offset);
            data_line(out, 16, here, &bytes[offset..offset + n])?;
            offset += n;
            continue;
        }
        let word = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        let text =
            hexcavator_arm64::decode(word, here).map_or_else(String::new, |inst| match symbols {
                Some(s) => hexcavator_arm64::format_with(&inst, s),
                None => hexcavator_arm64::format(&inst),
            });
        let line = format!("  {here:016X}: {word:08X}  {text}");
        writeln!(out, "{}", line.trim_end())?;
        offset += 4;
    }
    Ok(())
}

/// A line of raw bytes: hex, then the bytes as text.
fn data_line(out: &mut dyn Write, width: usize, address: u64, bytes: &[u8]) -> io::Result<()> {
    let addr = if width == 16 {
        format!("{address:016X}")
    } else {
        format!("{:08X}", address & 0xFFFF_FFFF)
    };
    let hex: String = bytes.iter().map(|b| format!("{b:02X} ")).collect();
    let text: String = bytes.iter().map(|&b| shown_char(b)).collect();
    writeln!(out, "  {addr}: {hex:<48} {text}")
}

/// How dumpbin shows a byte as text. It reads the byte as Windows-1252 and
/// writes the console's code page (437): printable ASCII as itself;
/// characters code page 437 has as themselves (dumpbin writes their 437
/// bytes; hexc writes the characters); others as Windows' "best fit" ASCII
/// (`Ì` as `I`, `‘` as a backquote); anything else as a dot.
fn shown_char(b: u8) -> char {
    const IN_CP437: &str = "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥ƒáíóúñÑªº¿¬½¼¡«»ßµ±÷°·²§¶•¤";
    let c = match b {
        0x20..=0x7E | 0x09 => return char::from(b),
        0x80 => '€',
        0x82 => '‚',
        0x83 => 'ƒ',
        0x84 => '„',
        0x85 => '…',
        0x86 => '†',
        0x87 => '‡',
        0x88 => 'ˆ',
        0x89 => '‰',
        0x8A => 'Š',
        0x8B => '‹',
        0x8C => 'Œ',
        0x8E => 'Ž',
        0x91 => '‘',
        0x92 => '’',
        0x93 => '“',
        0x94 => '”',
        0x95 => '•',
        0x96 => '–',
        0x97 => '—',
        0x98 => '˜',
        0x99 => '™',
        0x9A => 'š',
        0x9B => '›',
        0x9C => 'œ',
        0x9E => 'ž',
        0x9F => 'Ÿ',
        0xA0..=0xFF => char::from(b),
        _ => return '.',
    };
    if IN_CP437.contains(c) {
        return c;
    }
    // Best fit.
    match c {
        'À'..='Ã' => 'A',
        'È' | 'Ê' | 'Ë' => 'E',
        'Ì'..='Ï' => 'I',
        'Ò'..='Õ' | 'Ø' => 'O',
        'Ù'..='Û' => 'U',
        'Ý' | 'Ÿ' => 'Y',
        'ã' => 'a',
        'õ' | 'ø' => 'o',
        'ý' => 'y',
        'Š' => 'S',
        'š' => 's',
        'Ž' => 'Z',
        'ž' => 'z',
        'Œ' => 'O',
        'œ' => 'o',
        '¯' => '_',
        '‘' => '`',
        '’' | '´' => '\'',
        '“' | '”' | '„' | '¨' => '"',
        '‚' | '¸' => ',',
        '‹' => '<',
        '‰' => '%',
        '†' | '‡' => '+',
        '›' => '>',
        '–' | '—' | '\u{AD}' => '-',
        'ˆ' => '^',
        '˜' => '~',
        '¦' => '|',
        '©' => 'c',
        '®' => 'r',
        '³' => '3',
        '¹' => '1',
        '×' => 'x',
        'Ð' => 'D',
        'ð' => 'd',
        _ => '.',
    }
}
