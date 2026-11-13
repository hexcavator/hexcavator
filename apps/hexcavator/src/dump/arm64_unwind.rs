//! ARM64 unwind data for `/unwindinfo`, as dumpbin shows it: each unwind
//! code as the instruction it describes, next to the instruction actually
//! at that address, with a note where the two differ; packed records as the
//! prolog and epilog they stand for; and the exception handler's data.

use std::io::{self, Write};

/// The most rows of an EH table printed: a hostile count (an unreadable
/// table prints a row for each, as dumpbin does) can't print billions.
const MAX_ROWS: u32 = 0x1_0000;

use hexcavator_core::Rva;
use hexcavator_pe::PeFile;
use hexcavator_pe::exception::{Arm64PackedUnwind, Arm64UnwindCode as Code, Arm64Xdata};

/// What dumpbin shows for one unwind code.
struct Op {
    text: String,
    /// The encodings that match the code, as (value, mask) (empty: not
    /// checked).
    expected: Vec<(u32, u32)>,
    /// Whether the code stands for an instruction (and so moves on to the
    /// next one); markers (`end_c`, custom codes) do not.
    instruction: bool,
}

impl Op {
    fn new(text: String, expected: Vec<u32>) -> Self {
        Self {
            text,
            expected: expected.into_iter().map(|e| (e, u32::MAX)).collect(),
            instruction: true,
        }
    }

    fn unchecked(text: &str) -> Self {
        Self::new(text.to_string(), Vec::new())
    }

    fn marker(text: String) -> Self {
        Self {
            text,
            expected: Vec::new(),
            instruction: false,
        }
    }
}

/// A mnemonic and its operands, in the unwind listing's columns.
fn asm(mnemonic: &str, operands: &str) -> String {
    format!("{mnemonic:<6}{operands}")
}

fn xreg(n: u32) -> String {
    match n {
        29 => "fp".into(),
        30 => "lr".into(),
        31 => "sp".into(),
        _ => format!("x{n}"),
    }
}

const SP: u32 = 31;

/// Load/store pair encodings: signed offset, pre-index, post-index.
#[derive(Clone, Copy)]
enum Class {
    X,
    D,
    Q,
}

impl Class {
    fn size(self) -> u32 {
        match self {
            Class::Q => 16,
            _ => 8,
        }
    }

    fn prefix(self) -> char {
        match self {
            Class::X => 'x',
            Class::D => 'd',
            Class::Q => 'q',
        }
    }

    fn name(self, n: u32) -> String {
        match self {
            Class::X => xreg(n),
            _ => format!("{}{n}", self.prefix()),
        }
    }

    /// `stp`/`ldp` base opcodes: (store offset, store pre-index, load
    /// offset, load post-index).
    fn pair_ops(self) -> [u32; 4] {
        match self {
            Class::X => [0xA900_0000, 0xA980_0000, 0xA940_0000, 0xA8C0_0000],
            Class::D => [0x6D00_0000, 0x6D80_0000, 0x6D40_0000, 0x6CC0_0000],
            Class::Q => [0xAD00_0000, 0xAD80_0000, 0xAD40_0000, 0xACC0_0000],
        }
    }

    /// `str`/`ldr`: (store unsigned offset, store pre-index, load unsigned
    /// offset, load post-index).
    fn single_ops(self) -> [u32; 4] {
        match self {
            Class::X => [0xF900_0000, 0xF800_0C00, 0xF940_0000, 0xF840_0400],
            Class::D => [0xFD00_0000, 0xFC00_0C00, 0xFD40_0000, 0xFC40_0400],
            Class::Q => [0x3D80_0000, 0x3C80_0C00, 0x3DC0_0000, 0x3CC0_0400],
        }
    }
}

/// A register save: `count` (1 or 2) registers of `class` from `reg`, at
/// `offset` from sp, or with `writeback`, at sp after moving it down by
/// `offset` (prolog) or up by it (epilog).
#[derive(Clone, Copy)]
struct Save {
    class: Class,
    reg: u32,
    /// The second register of a pair, when it is not `reg + 1` (`lr`).
    second: Option<u32>,
    pair: bool,
    offset: u32,
    writeback: bool,
}

impl Save {
    fn op(self, epilog: bool) -> Op {
        let c = self.class;
        let regs = if self.pair {
            let second = self.second.unwrap_or(self.reg + 1);
            format!("{},{}", c.name(self.reg), c.name(second))
        } else {
            c.name(self.reg)
        };
        let mnemonic = match (self.pair, epilog) {
            (true, false) => "stp",
            (true, true) => "ldp",
            (false, false) => "str",
            (false, true) => "ldr",
        };
        let addr = match (self.writeback, epilog) {
            (false, _) => format!("[sp,#0x{:X}]", self.offset),
            (true, false) => format!("[sp,#-0x{:X}]!", self.offset),
            (true, true) => format!("[sp],#0x{:X}", self.offset),
        };
        let rt = self.reg;
        let encoding = if self.pair {
            let rt2 = self.second.unwrap_or(rt + 1);
            let ops = c.pair_ops();
            let scale = c.size();
            let (base, imm) = match (self.writeback, epilog) {
                (false, false) => (ops[0], self.offset / scale),
                (true, false) => (ops[1], (self.offset / scale).wrapping_neg()),
                (false, true) => (ops[2], self.offset / scale),
                (true, true) => (ops[3], self.offset / scale),
            };
            base | (imm & 0x7F) << 15 | rt2 << 10 | SP << 5 | rt
        } else {
            let ops = c.single_ops();
            match (self.writeback, epilog) {
                (false, false) => ops[0] | (self.offset / c.size()) << 10 | SP << 5 | rt,
                (true, false) => ops[1] | (self.offset.wrapping_neg() & 0x1FF) << 12 | SP << 5 | rt,
                (false, true) => ops[2] | (self.offset / c.size()) << 10 | SP << 5 | rt,
                (true, true) => ops[3] | (self.offset & 0x1FF) << 12 | SP << 5 | rt,
            }
        };
        Op::new(asm(mnemonic, &format!("{regs},{addr}")), vec![encoding])
    }

    /// The save that a `save_next` after this one stands for.
    fn next(self, steps: u32) -> Self {
        let stride = 2 * self.class.size();
        Self {
            reg: self.reg + 2 * steps,
            offset: if self.writeback { 0 } else { self.offset } + stride * steps,
            writeback: false,
            ..self
        }
    }
}

fn save(class: Class, reg: u32, pair: bool, offset: u32, writeback: bool) -> Save {
    Save {
        class,
        reg,
        second: None,
        pair,
        offset,
        writeback,
    }
}

/// The register save a code stands for, if it is one.
fn as_save(code: &Code) -> Option<Save> {
    let reg = |r: u8| u32::from(r);
    Some(match *code {
        Code::SaveR19R20X { offset } => save(Class::X, 19, true, offset, true),
        Code::SaveFpLr { offset } => save(Class::X, 29, true, offset, false),
        Code::SaveFpLrX { offset } => save(Class::X, 29, true, offset, true),
        Code::SaveRegp { reg: r, offset } => save(Class::X, 19 + reg(r), true, offset, false),
        Code::SaveRegpX { reg: r, offset } => save(Class::X, 19 + reg(r), true, offset, true),
        Code::SaveReg { reg: r, offset } => save(Class::X, 19 + reg(r), false, offset, false),
        Code::SaveRegX { reg: r, offset } => save(Class::X, 19 + reg(r), false, offset, true),
        Code::SaveLrpair { reg: r, offset } => Save {
            second: Some(30),
            ..save(Class::X, 19 + 2 * reg(r), true, offset, false)
        },
        Code::SaveFregp { reg: r, offset } => save(Class::D, 8 + reg(r), true, offset, false),
        Code::SaveFregpX { reg: r, offset } => save(Class::D, 8 + reg(r), true, offset, true),
        Code::SaveFreg { reg: r, offset } => save(Class::D, 8 + reg(r), false, offset, false),
        Code::SaveFregX { reg: r, offset } => save(Class::D, 8 + reg(r), false, offset, true),
        Code::SaveAnyReg { raw } => {
            // 0pxrrrrr ffoooooo: pair, writeback, register; class, offset.
            let pair = raw & 0x4000 != 0;
            let writeback = raw & 0x2000 != 0;
            let reg = u32::from(raw >> 8 & 0x1F);
            let class = match raw >> 6 & 3 {
                0 => Class::X,
                1 => Class::D,
                2 => Class::Q,
                _ => return None,
            };
            let o = u32::from(raw & 0x3F);
            let offset = if writeback {
                (o + 1) * 16
            } else if pair || matches!(class, Class::Q) {
                o * 16
            } else {
                o * 8
            };
            save(class, reg, pair, offset, writeback)
        }
        _ => return None,
    })
}

/// `sub sp, sp, #size` (prolog) or `add sp, sp, #size` (epilog).
fn alloc(size: u32, epilog: bool, large: bool) -> Op {
    let text = if large {
        asm(
            if epilog { "add" } else { "sub" },
            &format!("sp,sp,Xm   ; Xm = 0x{size:X}"),
        )
    } else {
        asm(
            if epilog { "add" } else { "sub" },
            &format!("sp,sp,#0x{size:X}"),
        )
    };
    let expected = match (epilog, size < 0x1000) {
        // Small allocations may also be a `stp x0, x0, [sp, #-size]!`
        // (the GS cookie push).
        (false, true) => vec![
            0xD100_03FF | size << 10,
            0xA980_03E0 | ((size / 8).wrapping_neg() & 0x7F) << 15,
        ],
        (true, true) => vec![0x9100_03FF | size << 10],
        // dumpbin expects `add sp, sp, w0, uxtw #4`, not the
        // `add sp, sp, x15, lsl #4` compilers emit.
        (false, false) => vec![0xCB20_53FF],
        (true, false) => vec![0x8B20_53FF],
    };
    let mut op = Op::new(text, expected);
    if let Some(stp) = op.expected.get_mut(1) {
        // Any register pair will do.
        stp.1 = !(0x1F << 10 | 0x1F);
    }
    op
}

/// The ops of a code sequence (in code order). `save_next` codes continue
/// the nearest register save after them in code order (before them in the
/// prolog's execution order).
fn ops(codes: &[(usize, Code)], epilog: bool) -> Vec<(Op, Option<String>)> {
    let mut out = Vec::with_capacity(codes.len());
    for (i, (_, code)) in codes.iter().enumerate() {
        let mut error = None;
        let op = match *code {
            Code::AllocS { size } | Code::AllocM { size } => alloc(size, epilog, false),
            Code::AllocL { size } => alloc(size, epilog, true),
            Code::AllocZ { count } => {
                let n = u32::from(count);
                let imm = if epilog { n } else { n.wrapping_neg() };
                Op::new(
                    asm(
                        "addvl",
                        &if epilog {
                            format!("sp,sp,#0x{n:X}")
                        } else {
                            format!("sp,sp,#-0x{n:X}")
                        },
                    ),
                    vec![0x043F_501F | (imm & 0x3F) << 5],
                )
            }
            Code::SetFp => {
                if epilog {
                    Op::unchecked(&asm("mov", "sp,fp"))
                } else {
                    Op::new(asm("mov", "fp,sp"), vec![0x9100_03FD])
                }
            }
            Code::AddFp { offset } => {
                if epilog {
                    Op::unchecked(&asm("sub", &format!("fp,sp,#0x{offset:X}")))
                } else {
                    Op::new(
                        asm("add", &format!("fp,sp,#0x{offset:X}")),
                        vec![0x9100_03FD | offset << 10],
                    )
                }
            }
            Code::Nop => Op::unchecked("nop"),
            Code::End => Op::unchecked("end"),
            Code::EndC => Op::marker("end_c".into()),
            Code::PacSignLr => {
                if epilog {
                    Op::new("autibsp".into(), vec![0xD503_23FF])
                } else {
                    Op::new("pacibsp".into(), vec![0xD503_237F])
                }
            }
            Code::Custom { op } => Op::marker(format!("custom {op:02X}")),
            Code::Reserved { op } => Op::marker(format!("reserved ({op:02X})")),
            Code::SaveNext => {
                let mut steps = 1;
                let mut base = None;
                for (_, later) in &codes[i + 1..] {
                    if matches!(later, Code::SaveNext) {
                        steps += 1;
                        continue;
                    }
                    base = Some(later);
                    break;
                }
                match base.and_then(as_save).filter(|s| s.pair) {
                    Some(s) => {
                        let next = s.next(steps);
                        if next.reg + 1 > 30 {
                            error = Some(format!(
                                "**** too many save_next_pair opcodes; referencing register x{}",
                                next.reg + 1
                            ));
                        }
                        next.op(epilog)
                    }
                    None => {
                        error = Some(match base {
                            Some(_) => {
                                let byte = codes[i + steps as usize].0;
                                format!(
                                    "**** save_next_pair opcode can only follow save_r19r20_x or save_[f]regp[_x], not {byte:02X}"
                                )
                            }
                            None => "**** save_next_pair opcode can only follow saving of register pairs".into(),
                        });
                        Op::unchecked(&asm("stp", "?"))
                    }
                }
            }
            ref other => match as_save(other) {
                Some(s) => s.op(epilog),
                None => Op::marker(String::new()),
            },
        };
        out.push((op, error));
    }
    out
}

struct Listing<'a, 'data> {
    file: &'a PeFile<'data>,
    begin: u32,
    base: u64,
    symbols: Option<&'a crate::symbols::SymbolMap>,
}

impl Listing<'_, '_> {
    /// The instruction word at `offset` from the function start.
    fn word(&self, offset: u32) -> Option<u32> {
        let b = self
            .file
            .bytes_at_rva(Rva(self.begin.wrapping_add(offset)), 4)
            .ok()?;
        Some(u32::from_le_bytes(b.try_into().ok()?))
    }

    fn actual(&self, offset: u32) -> (Option<u32>, String) {
        let Some(word) = self.word(offset) else {
            return (None, String::new());
        };
        let address = self.base + u64::from(self.begin) + u64::from(offset);
        let text = hexcavator_arm64::decode(word, address).map_or_else(String::new, |i| match self
            .symbols
        {
            Some(s) => hexcavator_arm64::format_with(&i, s),
            None => hexcavator_arm64::format(&i),
        });
        (Some(word), text.trim_end().to_string())
    }

    /// Writes a code's line, and if the instruction there is not what the
    /// code describes, a note saying so.
    fn line(
        &self,
        out: &mut dyn Write,
        prefix: &str,
        offset: u32,
        op: &Op,
        active: bool,
        // For a 16-byte allocation: "push" (prolog) or "pop" (epilog), for
        // the GS cookie code that is likely there instead.
        cookie: Option<&str>,
    ) -> io::Result<()> {
        if !active || !op.instruction {
            return writeln!(out, "{prefix} +{offset:04X} {:<25}", op.text);
        }
        let (word, text) = self.actual(offset);
        writeln!(out, "{prefix} +{offset:04X} {:<25}; Actual={text}", op.text)?;
        // dumpbin does not check zero words.
        let Some(word) = word.filter(|&w| w != 0) else {
            return Ok(());
        };
        if op.expected.is_empty() || op.expected.iter().any(|&(e, m)| word & m == e & m) {
            return Ok(());
        }
        let expected = op
            .expected
            .iter()
            .map(|(e, _)| format!("{e:X}"))
            .collect::<Vec<_>>()
            .join(" or ");
        if let Some(which) = cookie {
            writeln!(
                out,
                "#### Mismatched opcode, but likely __security_{which}_cookie. Expected opcode {expected}, got {word:X}"
            )
        } else {
            writeln!(out, "**** Expected opcode {expected}, got {word:X}")
        }
    }
}

/// The code bytes column: the code's bytes, padded with dots.
fn code_bytes(codes: &[u8], index: usize, len: usize) -> String {
    let mut s: String = codes
        .get(index..index + len)
        .unwrap_or(&[])
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect();
    while s.len() < 8 {
        s.push('.');
    }
    s
}

/// The codes from `index` through the next `end`, with their lengths.
fn sequence(codes: &[u8], index: usize) -> Vec<(usize, Code, usize)> {
    let mut out = Vec::new();
    let mut i = index;
    while let Some((code, len)) = codes.get(i..).and_then(Code::decode) {
        out.push((i, code, len));
        i += len;
        if code == Code::End {
            break;
        }
    }
    out
}

pub fn unwind(
    out: &mut dyn Write,
    file: &PeFile<'_>,
    begin: Rva,
    word: u32,
    symbols: Option<&crate::symbols::SymbolMap>,
) -> io::Result<()> {
    let base = file.optional_header().map_or(0, |h| h.image_base().get());
    // dumpbin shows the low 32 bits of these VAs.
    let va = |rva: u32| base.wrapping_add(u64::from(rva)) & 0xFFFF_FFFF;
    let listing = Listing {
        file,
        begin: begin.get(),
        base,
        symbols,
    };
    if let Some(p) = Arm64PackedUnwind::decode(word) {
        writeln!(
            out,
            "   Start={:X}  Flag={}  FuncLen={:X}  RegF={}  RegI={}  H={}  CR={}  FrameSize=0x{:X}",
            va(begin.get()),
            p.flag,
            p.function_length,
            p.reg_f,
            p.reg_i,
            u8::from(p.h),
            p.cr,
            p.frame_size
        )?;
        writeln!(out, "      [RawPdata={:08X} {word:08X}]", begin.get())?;
        return packed(out, &listing, &p);
    }
    let Some(x) = Arm64Xdata::parse(file, Rva(word)) else {
        return Ok(());
    };
    writeln!(out, "   Start={:X}  Xdata={:X}", va(begin.get()), va(word))?;
    writeln!(out, "      [RawPdata={:08X} {word:08X}]", begin.get())?;
    writeln!(
        out,
        "   FuncLen={:X}  Vers={}  X={}  E={}  Epilogs={}  CodeWords={}",
        x.function_length,
        x.version,
        u8::from(x.x),
        u8::from(x.e),
        if x.e { 1 } else { x.epilog_count },
        x.code_words
    )?;

    // The prolog: the codes up to the first `end`, in reverse. Codes after
    // an `end_c` belong to the prolog of the function this fragment
    // continues, so they are not here.
    writeln!(out, "   Prolog unwind:")?;
    let seq: Vec<_> = sequence(x.codes, 0)
        .into_iter()
        .filter(|(_, c, _)| *c != Code::End)
        .collect();
    let list: Vec<(usize, Code)> = seq.iter().map(|&(i, c, _)| (i, c)).collect();
    let described = ops(&list, false);
    let end_c = seq.iter().position(|(_, c, _)| *c == Code::EndC);
    let mut offset = 0u32;
    for (k, &(index, code, len)) in seq.iter().enumerate().rev() {
        let (op, error) = &described[k];
        let active = end_c.is_none_or(|e| k < e);
        let prefix = format!("      {index:02X}: {}", code_bytes(x.codes, index, len));
        let cookie = (code == Code::AllocS { size: 16 }).then_some("push");
        listing.line(out, &prefix, offset, op, active, cookie)?;
        if let Some(e) = error {
            writeln!(out, "{e}")?;
        }
        if active && op.instruction {
            offset += 4;
        }
    }
    if !seq.is_empty() {
        writeln!(out, "                   +{offset:04X} (end sequence)")?;
    }

    // The epilogs: each from its first code through `end`.
    let scopes: Vec<(Option<u32>, usize)> = if x.e {
        vec![(None, usize::from(x.epilog_count))]
    } else {
        x.epilog_scopes()
            .map(|s| (Some(s.start_offset), usize::from(s.start_index)))
            .collect()
    };
    for (n, (start, index)) in scopes.into_iter().enumerate() {
        let seq = sequence(x.codes, index);
        let list: Vec<(usize, Code)> = seq.iter().map(|&(i, c, _)| (i, c)).collect();
        let described = ops(&list, true);
        let mut offset = match start {
            Some(o) => {
                writeln!(
                    out,
                    "   Epilog #{} unwind:  (Offset={o:X}  Index={index})",
                    n + 1
                )?;
                o
            }
            None => {
                writeln!(
                    out,
                    "   Epilog #{} unwind:  (Offset=auto  Index={index})",
                    n + 1
                )?;
                let count =
                    u32::try_from(described.iter().filter(|(op, _)| op.instruction).count())
                        .unwrap_or(0);
                x.function_length.wrapping_sub(4 * count)
            }
        };
        let mut active = true;
        for (k, &(i, code, len)) in seq.iter().enumerate() {
            let (op, error) = &described[k];
            if code == Code::EndC {
                active = false;
            }
            let prefix = format!("      {i:02X}: {}", code_bytes(x.codes, i, len));
            let cookie = (code == Code::AllocS { size: 16 }).then_some("pop");
            listing.line(out, &prefix, offset, op, active, cookie)?;
            if let Some(e) = error {
                writeln!(out, "{e}")?;
            }
            if active && op.instruction {
                offset += 4;
            }
        }
        // Codes that run out without an `end` have no end.
        if seq.last().is_some_and(|&(_, c, _)| c == Code::End) {
            writeln!(out, "                   +{:04X} (end sequence)", offset + 4)?;
        }
    }

    if let Some(h) = x.handler {
        writeln!(
            out,
            "   Exception Handler={:X}",
            base.wrapping_add(u64::from(h.get()))
        )?;
    }
    raw_xdata(out, file, word, x.size)?;
    if x.handler.is_some() {
        writeln!(out)?;
        handler_data(out, file, Rva(word + x.size), &va)?;
    }
    Ok(())
}

fn raw_xdata(out: &mut dyn Write, file: &PeFile<'_>, rva: u32, size: u32) -> io::Result<()> {
    let words: Vec<String> = file
        .bytes_at_rva(Rva(rva), size)
        .unwrap_or(&[])
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| format!("{:08X}", u32::from_le_bytes(*c)))
        .collect();
    for (i, chunk) in words.chunks(8).enumerate() {
        let lead = if i == 0 {
            "   [RawXdata="
        } else {
            "            ["
        };
        writeln!(out, "{lead}{}]", chunk.join(" "))?;
    }
    Ok(())
}

/// Reads handler data as dumpbin does: a word at a time, noting reads
/// outside every section (which give 0).
struct EhReader<'a, 'data> {
    file: &'a PeFile<'data>,
}

impl EhReader<'_, '_> {
    fn word(&self, out: &mut dyn Write, rva: u32) -> io::Result<u32> {
        let inside = self.file.sections().iter().any(|s| {
            let start = s.virtual_address.get();
            let size = match s.virtual_size.get() {
                0 => s.size_of_raw_data.get(),
                v => v,
            };
            rva >= start && rva - start < size
        });
        if !inside {
            writeln!(out, "Invalid RVA for EH Data")?;
            return Ok(0);
        }
        Ok(self
            .file
            .bytes_at_rva(Rva(rva), 4)
            .ok()
            .map_or(0, |b| u32::from_le_bytes(b.try_into().expect("4 bytes"))))
    }
}

/// The handler's data. dumpbin does not identify the handler; it goes by
/// what the data looks like: a negative word is a GS cookie offset (and the
/// next word is looked at too); then a small count starts an SEH scope
/// table, and an aligned value may be the RVA of C++ EH tables.
fn handler_data(
    out: &mut dyn Write,
    file: &PeFile<'_>,
    rva: Rva,
    va: &dyn Fn(u32) -> u64,
) -> io::Result<()> {
    let r = EhReader { file };
    let mut at = rva.get();
    let mut w = r.word(out, at)?;
    let mut gs = false;
    if (w as i32) < 0 {
        writeln!(out, "   --> GS Cookie Offset = {}", w as i32)?;
        at += 4;
        w = r.word(out, at)?;
        gs = true;
    }
    let shown = if w == 0 {
        false
    } else if w < 0x100 {
        seh_scopes(out, &r, at, w, va)?;
        true
    } else if w & 3 == 0 {
        cxx_eh(out, &r, w, va)?
    } else {
        false
    };
    if !shown && !gs {
        writeln!(out, "   --> Unknown exception data = {w:08X}")?;
    }
    Ok(())
}

fn va_or_null(va: &dyn Fn(u32) -> u64, rva: u32) -> String {
    if rva == 0 {
        "NULL".to_string()
    } else {
        format!("{:X}", va(rva))
    }
}

fn seh_scopes(
    out: &mut dyn Write,
    r: &EhReader<'_, '_>,
    at: u32,
    count: u32,
    va: &dyn Fn(u32) -> u64,
) -> io::Result<()> {
    writeln!(out, "   --> SEH Scopes={count}")?;
    for i in 0..count.min(MAX_ROWS) {
        let s = at + 4 + 16 * i;
        let begin = r.word(out, s)?;
        let end = r.word(out, s + 4)?;
        let handler = r.word(out, s + 8)?;
        let jump = r.word(out, s + 12)?;
        writeln!(
            out,
            "          Scope{i:3}: {:08X}-{:08X}      Handler={}      Jump={}",
            va(begin),
            va(end),
            va_or_null(va, handler),
            va_or_null(va, jump)
        )?;
    }
    Ok(())
}

/// `__CxxFrameHandler3` tables (`FuncInfo`), if `rva` holds them.
fn cxx_eh(
    out: &mut dyn Write,
    r: &EhReader<'_, '_>,
    rva: u32,
    va: &dyn Fn(u32) -> u64,
) -> io::Result<bool> {
    let magic = r.word(out, rva)?;
    if magic & 0x1FFF_FFFF != hexcavator_pe::eh::magic::VC8 {
        return Ok(false);
    }
    let mut f = [0u32; 10];
    for (i, v) in (0u32..).zip(f.iter_mut()).skip(1) {
        *v = r.word(out, rva + 4 * i)?;
    }
    let [
        _,
        max_state,
        unwind_map,
        tries,
        try_map,
        ip_entries,
        ip_map,
        unwind_help,
        es_types,
        flags,
    ] = f;
    writeln!(
        out,
        "   --> EH UnwindHelp={}, Flags={flags:X}",
        unwind_help as i32
    )?;
    writeln!(out, "       IPEntries={ip_entries}:")?;
    for i in 0..ip_entries.min(MAX_ROWS) {
        let ip = r.word(out, ip_map + 8 * i)?;
        let state = r.word(out, ip_map + 8 * i + 4)?;
        writeln!(
            out,
            "          IPMap{i:3}: {:08X} State={}",
            va(ip),
            state as i32
        )?;
    }
    writeln!(out, "       MaxState={}:", max_state as i32)?;
    for i in 0..max_state.min(MAX_ROWS) {
        let to_state = r.word(out, unwind_map + 8 * i)?;
        let action = r.word(out, unwind_map + 8 * i + 4)?;
        writeln!(
            out,
            "          UnwindMap{i:3}: ToState={:2} Action={}",
            to_state as i32,
            va_or_null(va, action)
        )?;
    }
    if tries != 0 {
        writeln!(out, "       TryBlocks={tries}:")?;
        for i in 0..tries.min(MAX_ROWS) {
            let e = try_map + 20 * i;
            let mut t = [0u32; 5];
            for (k, v) in (0u32..).zip(t.iter_mut()) {
                *v = r.word(out, e + 4 * k)?;
            }
            let [low, high, catch_high, catches, handlers] = t;
            writeln!(
                out,
                "          Try{i:3}:{:3}-{:2} CatchHigh={} Catches={}",
                low as i32, high as i32, catch_high as i32, catches as i32
            )?;
            for j in 0..catches.min(MAX_ROWS) {
                // dumpbin steps through the handler array a word at a
                // time, rather than a HandlerType (20 bytes) at a time.
                write!(out, "             Catch{j:3}: ")?;
                let h = r.word(out, handlers + 4 * j)?;
                writeln!(out, "Handler={}", va_or_null(va, h))?;
            }
        }
    }
    if es_types != 0 {
        let count = r.word(out, es_types)?;
        if count != 0 {
            writeln!(out, "       TypeList.Count={count}:")?;
            let array = r.word(out, es_types + 4)?;
            for i in 0..count.min(MAX_ROWS) {
                let e = array + 16 * i;
                let adjectives = r.word(out, e)?;
                let type_addr = r.word(out, e + 4)?;
                let catch_addr = r.word(out, e + 8)?;
                let handler = r.word(out, e + 12)?;
                writeln!(
                    out,
                    "             Type{i:3}: Adjectives={adjectives:08X} TypeAddr={type_addr:08X} CatchAddr={catch_addr:08X} Handler={}",
                    va_or_null(va, handler)
                )?;
            }
        }
    }
    Ok(true)
}
/// A packed record's prolog and epilog, rebuilt from its fields as
/// dumpbin does (its own spelling: two spaces after the mnemonic, and
/// local allocations without `0x`).
fn packed(out: &mut dyn Write, listing: &Listing<'_, '_>, p: &Arm64PackedUnwind) -> io::Result<()> {
    let (prolog, epilog) = packed_ops(p);
    let mut offset = 0;
    for text in &prolog {
        let (_, actual) = listing.actual(offset);
        writeln!(out, "      +{offset:04X} {text:<25}; Actual={actual}")?;
        offset += 4;
    }
    let start = p
        .function_length
        .wrapping_sub(4 * u32::try_from(epilog.len()).unwrap_or(0));
    writeln!(out, "   Epilog #1 unwind:  (Offset={start:X})")?;
    let mut offset = start;
    for text in &epilog {
        let (_, actual) = listing.actual(offset);
        writeln!(out, "      +{offset:04X} {text:<25}; Actual={actual}")?;
        offset += 4;
    }
    Ok(())
}

/// The canonical prolog and epilog of a packed record.
fn packed_ops(p: &Arm64PackedUnwind) -> (Vec<String>, Vec<String>) {
    let reg_i = u32::from(p.reg_i);
    let cr = p.cr;
    let fp_count = if p.reg_f > 0 {
        u32::from(p.reg_f) + 1
    } else {
        0
    };
    let int_size = reg_i * 8 + if cr == 1 { 8 } else { 0 };
    let fp_size = fp_count * 8;
    let save_size = (int_size + fp_size + if p.h { 64 } else { 0 } + 15) & !15;
    let local = p.frame_size.saturating_sub(save_size);
    let chained = cr == 2 || cr == 3;

    let mut prolog = Vec::new();
    let mut epilog = Vec::new();
    if cr == 2 {
        prolog.push("pacibsp".to_string());
    }
    // Integer registers (and lr, unchained).
    let mut first = true;
    if cr == 1 && reg_i == 1 {
        prolog.push(format!("sub  sp,sp,#{save_size:X}"));
        prolog.push("stp  x19,lr,[sp,#0x0]".into());
        epilog.push(format!("add  sp,sp,#0x{save_size:X}"));
        epilog.push("ldp  x19,lr,[sp]".into());
        first = false;
    } else {
        let mut i = 0;
        while i + 1 < reg_i {
            let (a, b) = (19 + i, 20 + i);
            if first {
                prolog.push(format!("stp  x{a},x{b},[sp,#-0x{save_size:X}]!"));
                epilog.push(format!("ldp  x{a},x{b},[sp],#0x{save_size:X}"));
            } else {
                prolog.push(format!("stp  x{a},x{b},[sp,#0x{:X}]", i * 8));
                epilog.push(format!("ldp  x{a},x{b},[sp,#0x{:X}]", i * 8));
            }
            first = false;
            i += 2;
        }
        let at = i * 8;
        if reg_i % 2 == 1 {
            let r = 19 + reg_i - 1;
            if cr == 1 {
                prolog.push(format!("stp  x{r},lr,[sp,#0x{at:X}]"));
                epilog.push(format!("ldp  x{r},lr,[sp,#0x{at:X}]"));
            } else if first {
                prolog.push(format!("str  x{r},[sp,#-0x{save_size:X}]!"));
                epilog.push(format!("ldr  x{r},[sp],#0x{save_size:X}"));
            } else {
                prolog.push(format!("str  x{r},[sp,#0x{at:X}]"));
                epilog.push(format!("ldr  x{r},[sp,#0x{at:X}]"));
            }
            first = false;
        } else if cr == 1 {
            if first {
                prolog.push(format!("str  lr,[sp,#-0x{save_size:X}]!"));
                epilog.push(format!("ldr  lr,[sp],#0x{save_size:X}"));
            } else {
                prolog.push(format!("str  lr,[sp,#0x{at:X}]"));
                epilog.push(format!("ldr  lr,[sp,#0x{at:X}]"));
            }
            first = false;
        }
    }
    // Floating-point registers, after the integer ones.
    let mut j = 0;
    while j + 1 < fp_count {
        let (a, b) = (8 + j, 9 + j);
        if first {
            prolog.push(format!("stp  d{a},d{b},[sp,#-0x{save_size:X}]!"));
            epilog.push(format!("ldp  d{a},d{b},[sp],#0x{save_size:X}"));
        } else {
            let at = int_size + j * 8;
            prolog.push(format!("stp  d{a},d{b},[sp,#0x{at:X}]"));
            epilog.push(format!("ldp  d{a},d{b},[sp,#0x{at:X}]"));
        }
        first = false;
        j += 2;
    }
    if fp_count % 2 == 1 {
        let at = int_size + j * 8;
        prolog.push(format!("str  d{},[sp,#0x{at:X}]", 8 + j));
        epilog.push(format!("ldr  d{},[sp,#0x{at:X}]", 8 + j));
    }
    // Homed arguments (not restored).
    if p.h {
        let at = int_size + fp_size;
        for (k, regs) in (0u32..).zip(["x0,x1", "x2,x3", "x4,x5", "x6,x7"]) {
            prolog.push(format!("stp  {regs},[sp,#0x{:X}]", at + 16 * k));
        }
    }
    // Locals (and fp/lr, chained).
    let mut tail_prolog = Vec::new();
    let mut tail_epilog = Vec::new();
    let sub = |n: u32, v: &mut Vec<String>, mnemonic: &str| {
        if n > 0xFFF {
            v.push(format!("{mnemonic}  sp,sp,#{:X}, LSL #12", n >> 12));
            if n & 0xFFF != 0 {
                v.push(format!("{mnemonic}  sp,sp,#{:X}", n & 0xFFF));
            }
        } else {
            v.push(format!("{mnemonic}  sp,sp,#{n:X}"));
        }
    };
    if chained {
        if local <= 512 {
            tail_prolog.push(format!("stp  fp,lr,[sp,#-0x{local:X}]!"));
            tail_epilog.push(format!("ldp  fp,lr,[sp],#0x{local:X}"));
        } else {
            sub(local, &mut tail_prolog, "sub");
            tail_prolog.push("stp  fp,lr,[sp]".into());
            tail_epilog.push("ldp  fp,lr,[sp]".into());
            let mut adds = Vec::new();
            sub(local, &mut adds, "add");
            adds.reverse();
            tail_epilog.extend(adds);
        }
        tail_prolog.push("mov  fp,sp".into());
    } else if local > 0 {
        sub(local, &mut tail_prolog, "sub");
        let mut adds = Vec::new();
        sub(local, &mut adds, "add");
        adds.reverse();
        tail_epilog.extend(adds);
    }
    prolog.extend(tail_prolog);
    epilog.reverse();
    let mut full_epilog = tail_epilog;
    full_epilog.extend(epilog);
    if cr == 2 {
        full_epilog.push("autibsp".into());
    }
    full_epilog.push("ret".into());
    (prolog, full_epilog)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packed(word: u32) -> (Vec<String>, Vec<String>) {
        packed_ops(&Arm64PackedUnwind::decode(word).unwrap())
    }

    // Expected listings from dumpbin.
    #[test]
    fn packed_lr_with_one_register() {
        let (prolog, epilog) = packed(0x00A1_0171);
        assert_eq!(prolog, ["sub  sp,sp,#10", "stp  x19,lr,[sp,#0x0]"]);
        assert_eq!(epilog, ["ldp  x19,lr,[sp]", "add  sp,sp,#0x10", "ret"]);
    }

    #[test]
    fn packed_chained_with_fp_registers() {
        let (prolog, epilog) = packed(0x0241_60C1);
        assert_eq!(
            prolog,
            [
                "pacibsp",
                "str  x19,[sp,#-0x30]!",
                "stp  d8,d9,[sp,#0x8]",
                "stp  d10,d11,[sp,#0x18]",
                "stp  fp,lr,[sp,#-0x10]!",
                "mov  fp,sp"
            ]
        );
        assert_eq!(
            epilog,
            [
                "ldp  fp,lr,[sp],#0x10",
                "ldp  d10,d11,[sp,#0x18]",
                "ldp  d8,d9,[sp,#0x8]",
                "ldr  x19,[sp],#0x30",
                "autibsp",
                "ret"
            ]
        );
    }

    #[test]
    fn packed_unchained_odd_registers_with_lr() {
        let (prolog, epilog) = packed(0x02A3_4099);
        assert_eq!(
            prolog,
            [
                "stp  x19,x20,[sp,#-0x40]!",
                "stp  x21,lr,[sp,#0x10]",
                "stp  d8,d9,[sp,#0x20]",
                "str  d10,[sp,#0x30]",
                "sub  sp,sp,#10"
            ]
        );
        assert_eq!(
            epilog,
            [
                "add  sp,sp,#10",
                "ldr  d10,[sp,#0x30]",
                "ldp  d8,d9,[sp,#0x20]",
                "ldp  x21,lr,[sp,#0x10]",
                "ldp  x19,x20,[sp],#0x40",
                "ret"
            ]
        );
    }

    #[test]
    fn save_next_continues_the_pair_before_it() {
        // stp q6,q7,[sp,#-0xA0]! then two save_next codes (prolog order is
        // the reverse of code order).
        let codes = [
            (0, Code::SaveNext),
            (1, Code::SaveNext),
            (2, Code::SaveAnyReg { raw: 0x6689 }),
        ];
        let texts: Vec<String> = ops(&codes, false)
            .into_iter()
            .map(|(o, _)| o.text)
            .collect();
        assert_eq!(
            texts,
            [
                "stp   q10,q11,[sp,#0x40]",
                "stp   q8,q9,[sp,#0x20]",
                "stp   q6,q7,[sp,#-0xA0]!"
            ]
        );
    }
}
