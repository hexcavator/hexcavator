//! What dyld writes into an image as it loads it: rebases (the image's own
//! addresses, moved with it) and binds (imports' addresses), from chained
//! fixups (`LC_DYLD_CHAINED_FIXUPS`, every pointer format of
//! `<mach-o/fixup-chains.h>`) or from the rebase and bind opcodes
//! (`LC_DYLD_INFO`); and the exports trie (`LC_DYLD_EXPORTS_TRIE`, or
//! `LC_DYLD_INFO`'s).
//!
//! Bounded: at most 2^24 fixups and exports, chains followed only within
//! their pages, a trie's nodes visited once. Damage ends a list.

use alloc::vec::Vec;

use hexcavator_core::Endian;

use crate::consts::*;
use crate::{MachO, Segment};

/// The most fixups or exports read.
const MAX_ENTRIES: usize = 1 << 24;
/// The most fixups an opcode table may describe, per byte of it: its
/// "times" opcodes repeat without reading more, so a few bytes could
/// otherwise ask for millions.
const ENTRIES_PER_BYTE: usize = 64;

/// How long `out` may grow while reading a table of `len` bytes.
fn entry_limit(so_far: usize, len: usize) -> usize {
    so_far
        .saturating_add(len.saturating_mul(ENTRIES_PER_BYTE).saturating_add(4096))
        .min(MAX_ENTRIES)
}

/// A value as an index (saturating: one past any data).
fn index(v: u64) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

/// What a fixup writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixupKind<'d> {
    /// An address in the image (its preferred address).
    Rebase { target: u64 },
    /// An import's address, plus `addend`: the symbol, and the library
    /// (`library` is the dylib ordinal: 1 and up for the image's
    /// `LC_LOAD_DYLIB`s, 0 the image itself, -1 the main executable, -2
    /// flat namespace, -3 weak lookup).
    Bind {
        symbol: &'d [u8],
        library: i32,
        addend: i64,
        weak: bool,
    },
}

/// One fixup: where (its address) and how wide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fixup<'d> {
    pub addr: u64,
    pub width: u8,
    pub kind: FixupKind<'d>,
}

/// An exported symbol: its name, flags (`EXPORT_SYMBOL_FLAGS_*`), and
/// address (preferred), or the library it's re-exported from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Export {
    pub name: Vec<u8>,
    pub flags: u64,
    /// Its address (for a stub and resolver: the stub's), unless it is
    /// re-exported.
    pub address: Option<u64>,
    /// A stub and resolver's resolver.
    pub resolver: Option<u64>,
    /// A re-export's library ordinal and name there (empty: the same).
    pub reexport: Option<(u64, Vec<u8>)>,
}

pub const EXPORT_SYMBOL_FLAGS_KIND_MASK: u64 = 0x03;
pub const EXPORT_SYMBOL_FLAGS_KIND_REGULAR: u64 = 0x00;
pub const EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL: u64 = 0x01;
pub const EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE: u64 = 0x02;
pub const EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION: u64 = 0x04;
pub const EXPORT_SYMBOL_FLAGS_REEXPORT: u64 = 0x08;
pub const EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER: u64 = 0x10;

/// Chained pointer formats.
pub const DYLD_CHAINED_PTR_ARM64E: u16 = 1;
pub const DYLD_CHAINED_PTR_64: u16 = 2;
pub const DYLD_CHAINED_PTR_32: u16 = 3;
pub const DYLD_CHAINED_PTR_32_CACHE: u16 = 4;
pub const DYLD_CHAINED_PTR_32_FIRMWARE: u16 = 5;
pub const DYLD_CHAINED_PTR_64_OFFSET: u16 = 6;
pub const DYLD_CHAINED_PTR_ARM64E_KERNEL: u16 = 7;
pub const DYLD_CHAINED_PTR_64_KERNEL_CACHE: u16 = 8;
pub const DYLD_CHAINED_PTR_ARM64E_USERLAND: u16 = 9;
pub const DYLD_CHAINED_PTR_ARM64E_FIRMWARE: u16 = 10;
pub const DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE: u16 = 11;
pub const DYLD_CHAINED_PTR_ARM64E_USERLAND24: u16 = 12;
pub const DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE: u16 = 13;
const DYLD_CHAINED_PTR_START_NONE: u16 = 0xFFFF;
const DYLD_CHAINED_PTR_START_MULTI: u16 = 0x8000;
const DYLD_CHAINED_PTR_START_LAST: u16 = 0x8000;
pub const DYLD_CHAINED_IMPORT: u32 = 1;
pub const DYLD_CHAINED_IMPORT_ADDEND: u32 = 2;
pub const DYLD_CHAINED_IMPORT_ADDEND64: u32 = 3;

/// A little cursor over bytes, for opcodes and tries.
struct Cursor<'d> {
    data: &'d [u8],
    pos: usize,
}

impl<'d> Cursor<'d> {
    fn u8(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    fn uleb(&mut self) -> Option<u64> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let b = self.u8()?;
            v |= u64::from(b & 0x7F) << shift;
            if b & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    }
    fn sleb(&mut self) -> Option<i64> {
        let mut v = 0i64;
        let mut shift = 0;
        loop {
            let b = self.u8()?;
            if shift < 64 {
                v |= i64::from(b & 0x7F) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 64 && b & 0x40 != 0 {
                    v |= -1i64 << shift;
                }
                return Some(v);
            }
            if shift > 70 {
                return None;
            }
        }
    }
    fn cstr(&mut self) -> Option<&'d [u8]> {
        let rest = self.data.get(self.pos..)?;
        let n = rest.iter().position(|&b| b == 0)?;
        self.pos += n + 1;
        Some(&rest[..n])
    }
}

/// An import of the chained fixups' table: its symbol, library, addend,
/// and whether weak.
#[derive(Clone, Copy)]
struct Import<'d> {
    symbol: &'d [u8],
    library: i32,
    addend: i64,
    weak: bool,
}

impl<'d> MachO<'d> {
    /// The preferred address of the image's start (its `__TEXT`), which
    /// offset-based fixups are relative to.
    fn base_address(segments: &[Segment<'_>]) -> u64 {
        segments
            .iter()
            .find(|s| s.fileoff == 0 && s.filesize > 0)
            .map_or(0, |s| s.vmaddr)
    }

    /// The file offset of the preferred address `addr`.
    fn file_offset(segments: &[Segment<'_>], addr: u64) -> Option<u64> {
        let s = segments
            .iter()
            .find(|s| addr >= s.vmaddr && addr - s.vmaddr < s.filesize)?;
        s.fileoff.checked_add(addr - s.vmaddr)
    }

    fn read_at(&self, offset: u64, width: u8) -> Option<u64> {
        let start = usize::try_from(offset).ok()?;
        let b = self
            .data()
            .get(start..start.checked_add(usize::from(width))?)?;
        Some(match self.endian() {
            Endian::Little => b.iter().rev().fold(0u64, |v, &x| (v << 8) | u64::from(x)),
            Endian::Big => b.iter().fold(0u64, |v, &x| (v << 8) | u64::from(x)),
        })
    }

    pub(crate) fn pointer_width(&self) -> u8 {
        if self.header().is64 { 8 } else { 4 }
    }

    /// The fixups dyld applies, by address: chained, or from opcodes.
    pub fn fixups(&self) -> Vec<Fixup<'d>> {
        let segments = self.segments();
        let mut out = Vec::new();
        for lc in self.load_commands() {
            match lc.cmd {
                LC_DYLD_CHAINED_FIXUPS => {
                    if let Some((off, size)) = self.linkedit_data(&lc) {
                        self.chained(&segments, off, size, &mut out);
                    }
                }
                LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                    if let Some(info) = self.dyld_info(&lc) {
                        self.rebase_opcodes(&segments, info.rebase, &mut out);
                        for (table, lazy) in [
                            (info.bind, false),
                            (info.weak_bind, false),
                            (info.lazy_bind, true),
                        ] {
                            self.bind_opcodes(&segments, table, lazy, &mut out);
                        }
                    }
                }
                _ => {}
            }
        }
        out.sort_by_key(|f| f.addr);
        out
    }

    fn table(&self, (off, size): (u32, u32)) -> &'d [u8] {
        let start = off as usize;
        self.data()
            .get(start..start.saturating_add(size as usize))
            .unwrap_or(&[])
    }

    fn chained(&self, segments: &[Segment<'d>], off: u32, size: u32, out: &mut Vec<Fixup<'d>>) {
        let blob = self.table((off, size));
        let e = self.endian();
        let u32_at = |at: usize| crate::u32_at(blob, at as u64, e);
        let (Some(starts), Some(imports_off), Some(symbols_off), Some(count), Some(format)) =
            (u32_at(4), u32_at(8), u32_at(12), u32_at(16), u32_at(20))
        else {
            return;
        };
        // The imports.
        let mut imports = Vec::new();
        let name = |offset: u64| -> &'d [u8] {
            let at = (symbols_off as usize).saturating_add(index(offset));
            blob.get(at..)
                .and_then(|r| r.split(|&b| b == 0).next())
                .unwrap_or(&[])
        };
        let signed8 = |v: u64| i32::from((v & 0xFF) as u8 as i8);
        for i in 0..(count as usize).min(MAX_ENTRIES) {
            let import = match format {
                DYLD_CHAINED_IMPORT => u32_at(imports_off as usize + i * 4).map(|v| {
                    let v = u64::from(v);
                    Import {
                        symbol: name(v >> 9),
                        library: signed8(v),
                        addend: 0,
                        weak: v >> 8 & 1 != 0,
                    }
                }),
                DYLD_CHAINED_IMPORT_ADDEND => {
                    let at = imports_off as usize + i * 8;
                    u32_at(at).zip(u32_at(at + 4)).map(|(v, a)| {
                        let v = u64::from(v);
                        Import {
                            symbol: name(v >> 9),
                            library: signed8(v),
                            addend: i64::from(a as i32),
                            weak: v >> 8 & 1 != 0,
                        }
                    })
                }
                DYLD_CHAINED_IMPORT_ADDEND64 => {
                    let at = imports_off as usize + i * 16;
                    let lo = crate::read(blob, at as u64, 8, e);
                    let hi = crate::read(blob, at as u64 + 8, 8, e);
                    lo.zip(hi).map(|(v, a)| Import {
                        symbol: name(v >> 32),
                        library: i32::from((v & 0xFFFF) as u16 as i16),
                        addend: a as i64,
                        weak: v >> 16 & 1 != 0,
                    })
                }
                _ => None,
            };
            let Some(import) = import else { break };
            imports.push(import);
        }
        // The starts of each segment's chains.
        let base = Self::base_address(segments);
        let starts = starts as usize;
        let Some(seg_count) = u32_at(starts) else {
            return;
        };
        for si in 0..(seg_count as usize).min(256) {
            let Some(seg_off) = u32_at(starts + 4 + si * 4).filter(|&o| o != 0) else {
                continue;
            };
            let s = starts + seg_off as usize;
            let u16_at = |at: usize| {
                let b = blob.get(at..at + 2)?;
                Some(match e {
                    Endian::Little => u16::from_le_bytes([b[0], b[1]]),
                    Endian::Big => u16::from_be_bytes([b[0], b[1]]),
                })
            };
            let (
                Some(page_size),
                Some(pointer_format),
                Some(segment_offset),
                Some(max_valid),
                Some(page_count),
            ) = (
                u16_at(s + 4),
                u16_at(s + 6),
                crate::read(blob, s as u64 + 8, 8, e),
                u32_at(s + 16),
                u16_at(s + 20),
            )
            else {
                continue;
            };
            let page_size = u64::from(page_size);
            if page_size == 0 {
                continue;
            }
            for page in 0..u64::from(page_count) {
                let Some(start) = u16_at(s + 22 + index(page) * 2) else {
                    break;
                };
                if start == DYLD_CHAINED_PTR_START_NONE {
                    continue;
                }
                let page_addr = base
                    .wrapping_add(segment_offset)
                    .wrapping_add(page * page_size);
                // (32-bit formats: a page can have several chains.)
                let mut chain_starts = Vec::new();
                if start & DYLD_CHAINED_PTR_START_MULTI != 0 && !self.header().is64 {
                    let mut j = usize::from(start & !DYLD_CHAINED_PTR_START_MULTI);
                    while let Some(v) = u16_at(s + 22 + j * 2) {
                        chain_starts.push(v & !DYLD_CHAINED_PTR_START_LAST);
                        if v & DYLD_CHAINED_PTR_START_LAST != 0 || chain_starts.len() > 4096 {
                            break;
                        }
                        j += 1;
                    }
                } else {
                    chain_starts.push(start);
                }
                for first in chain_starts {
                    self.chain(
                        segments,
                        &imports,
                        pointer_format,
                        max_valid,
                        page_addr,
                        page_size,
                        u64::from(first),
                        base,
                        out,
                    );
                    if out.len() >= MAX_ENTRIES {
                        return;
                    }
                }
            }
        }
    }

    /// One chain of fixups in a page, from `offset` into it.
    #[allow(clippy::too_many_arguments, reason = "a chain's state")]
    fn chain(
        &self,
        segments: &[Segment<'d>],
        imports: &[Import<'d>],
        format: u16,
        max_valid: u32,
        page: u64,
        page_size: u64,
        mut offset: u64,
        base: u64,
        out: &mut Vec<Fixup<'d>>,
    ) {
        let wide = !matches!(
            format,
            DYLD_CHAINED_PTR_32 | DYLD_CHAINED_PTR_32_CACHE | DYLD_CHAINED_PTR_32_FIRMWARE
        );
        let width: u8 = if wide { 8 } else { 4 };
        let stride: u64 = match format {
            DYLD_CHAINED_PTR_ARM64E
            | DYLD_CHAINED_PTR_ARM64E_USERLAND
            | DYLD_CHAINED_PTR_ARM64E_USERLAND24
            | DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE => 8,
            DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE => 1,
            _ => 4,
        };
        let bits = |v: u64, at: u32, n: u32| (v >> at) & ((1u64 << n) - 1);
        let bind = |ordinal: u64, addend: i64| -> FixupKind<'d> {
            match imports.get(index(ordinal)) {
                Some(i) => FixupKind::Bind {
                    symbol: i.symbol,
                    library: i.library,
                    addend: i.addend.wrapping_add(addend),
                    weak: i.weak,
                },
                None => FixupKind::Bind {
                    symbol: &[],
                    library: 0,
                    addend,
                    weak: false,
                },
            }
        };
        let sign = |v: u64, n: u32| -> i64 { ((v << (64 - n)) as i64) >> (64 - n) };
        while offset < page_size {
            let addr = page.wrapping_add(offset);
            let Some(v) = Self::file_offset(segments, addr).and_then(|o| self.read_at(o, width))
            else {
                return;
            };
            let (kind, next) = match format {
                DYLD_CHAINED_PTR_64 | DYLD_CHAINED_PTR_64_OFFSET => {
                    let next = bits(v, 51, 12);
                    if bits(v, 63, 1) == 1 {
                        (bind(bits(v, 0, 24), sign(bits(v, 24, 8), 8)), next)
                    } else {
                        let target = bits(v, 0, 36);
                        let target = if format == DYLD_CHAINED_PTR_64_OFFSET {
                            base.wrapping_add(target)
                        } else {
                            target
                        };
                        (FixupKind::Rebase { target }, next)
                    }
                }
                DYLD_CHAINED_PTR_ARM64E
                | DYLD_CHAINED_PTR_ARM64E_USERLAND
                | DYLD_CHAINED_PTR_ARM64E_USERLAND24
                | DYLD_CHAINED_PTR_ARM64E_KERNEL
                | DYLD_CHAINED_PTR_ARM64E_FIRMWARE
                | DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE => {
                    let next = bits(v, 51, 11);
                    let (is_bind, auth) = (bits(v, 62, 1) == 1, bits(v, 63, 1) == 1);
                    let wide_ordinal = format == DYLD_CHAINED_PTR_ARM64E_USERLAND24;
                    let ordinal = bits(v, 0, if wide_ordinal { 24 } else { 16 });
                    let kind = match (is_bind, auth) {
                        (true, true) => bind(ordinal, 0),
                        (true, false) => bind(ordinal, sign(bits(v, 32, 19), 19)),
                        // An authenticated rebase: an offset from the base.
                        (false, true) => FixupKind::Rebase {
                            target: base.wrapping_add(bits(v, 0, 32)),
                        },
                        (false, false) => {
                            let target = bits(v, 0, 43);
                            // Only the original format has addresses;
                            // the others, offsets.
                            let target = if format == DYLD_CHAINED_PTR_ARM64E {
                                target
                            } else {
                                base.wrapping_add(target)
                            };
                            FixupKind::Rebase { target }
                        }
                    };
                    (kind, next)
                }
                DYLD_CHAINED_PTR_64_KERNEL_CACHE | DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE => (
                    FixupKind::Rebase {
                        target: base.wrapping_add(bits(v, 0, 30)),
                    },
                    bits(v, 51, 12),
                ),
                DYLD_CHAINED_PTR_32 => {
                    let next = bits(v, 26, 5);
                    if bits(v, 31, 1) == 1 {
                        (bind(bits(v, 0, 20), sign(bits(v, 20, 6), 6)), next)
                    } else {
                        let target = bits(v, 0, 26);
                        // (Past the largest pointer: a non-pointer value.)
                        if target > u64::from(max_valid) && max_valid != 0 {
                            offset += next * stride;
                            if next == 0 {
                                return;
                            }
                            continue;
                        }
                        (FixupKind::Rebase { target }, next)
                    }
                }
                DYLD_CHAINED_PTR_32_CACHE => (
                    FixupKind::Rebase {
                        target: base.wrapping_add(bits(v, 0, 30)),
                    },
                    bits(v, 30, 2),
                ),
                DYLD_CHAINED_PTR_32_FIRMWARE => (
                    FixupKind::Rebase {
                        target: bits(v, 0, 26),
                    },
                    bits(v, 26, 6),
                ),
                _ => return,
            };
            out.push(Fixup { addr, width, kind });
            if next == 0 || out.len() >= MAX_ENTRIES {
                return;
            }
            offset += next * stride;
        }
    }

    fn rebase_opcodes(
        &self,
        segments: &[Segment<'d>],
        table: (u32, u32),
        out: &mut Vec<Fixup<'d>>,
    ) {
        let w = u64::from(self.pointer_width());
        let mut c = Cursor {
            data: self.table(table),
            pos: 0,
        };
        let limit = entry_limit(out.len(), c.data.len());
        let (mut kind, mut seg, mut offset) = (1u8, None::<usize>, 0u64);
        let push = |seg: Option<usize>, offset: u64, kind: u8, out: &mut Vec<Fixup<'d>>| {
            let Some(s) = seg.and_then(|i| segments.get(i)) else {
                return false;
            };
            let addr = s.vmaddr.wrapping_add(offset);
            let width = if kind == 1 { self.pointer_width() } else { 4 };
            let target = Self::file_offset(segments, addr)
                .and_then(|o| self.read_at(o, width))
                .unwrap_or(0);
            out.push(Fixup {
                addr,
                width,
                kind: FixupKind::Rebase { target },
            });
            out.len() < limit
        };
        while let Some(b) = c.u8() {
            let imm = b & 0x0F;
            let ok = match b & 0xF0 {
                0x00 => return,
                0x10 => {
                    kind = imm;
                    true
                }
                0x20 => {
                    seg = Some(usize::from(imm));
                    c.uleb().map(|o| offset = o).is_some()
                }
                0x30 => c.uleb().map(|o| offset = offset.wrapping_add(o)).is_some(),
                0x40 => {
                    offset = offset.wrapping_add(u64::from(imm) * w);
                    true
                }
                0x50 | 0x60 => {
                    let n = if b & 0xF0 == 0x50 {
                        Some(u64::from(imm))
                    } else {
                        c.uleb()
                    };
                    let Some(n) = n else { return };
                    for _ in 0..n.min(MAX_ENTRIES as u64) {
                        if !push(seg, offset, kind, out) {
                            return;
                        }
                        offset = offset.wrapping_add(w);
                    }
                    true
                }
                0x70 => {
                    let Some(skip) = c.uleb() else { return };
                    if !push(seg, offset, kind, out) {
                        return;
                    }
                    offset = offset.wrapping_add(skip).wrapping_add(w);
                    true
                }
                0x80 => {
                    let (Some(n), Some(skip)) = (c.uleb(), c.uleb()) else {
                        return;
                    };
                    for _ in 0..n.min(MAX_ENTRIES as u64) {
                        if !push(seg, offset, kind, out) {
                            return;
                        }
                        offset = offset.wrapping_add(skip).wrapping_add(w);
                    }
                    true
                }
                _ => false,
            };
            if !ok {
                return;
            }
        }
    }

    fn bind_opcodes(
        &self,
        segments: &[Segment<'d>],
        table: (u32, u32),
        lazy: bool,
        out: &mut Vec<Fixup<'d>>,
    ) {
        let w = u64::from(self.pointer_width());
        let mut c = Cursor {
            data: self.table(table),
            pos: 0,
        };
        let limit = entry_limit(out.len(), c.data.len());
        let mut library = 0i32;
        let mut symbol: &[u8] = &[];
        let mut weak = false;
        let mut addend = 0i64;
        let (mut seg, mut offset) = (None::<usize>, 0u64);
        let bind = |seg: Option<usize>,
                    offset: u64,
                    symbol: &'d [u8],
                    library: i32,
                    addend: i64,
                    weak: bool,
                    out: &mut Vec<Fixup<'d>>| {
            let Some(s) = seg.and_then(|i| segments.get(i)) else {
                return false;
            };
            out.push(Fixup {
                addr: s.vmaddr.wrapping_add(offset),
                width: self.pointer_width(),
                kind: FixupKind::Bind {
                    symbol,
                    library,
                    addend,
                    weak,
                },
            });
            out.len() < limit
        };
        while let Some(b) = c.u8() {
            let imm = b & 0x0F;
            match b & 0xF0 {
                // (A lazy binding table's entries each end with DONE.)
                0x00 if lazy => {}
                0x00 => return,
                0x10 => library = i32::from(imm),
                0x20 => {
                    let Some(v) = c.uleb() else { return };
                    library = i32::try_from(v).unwrap_or(i32::MAX);
                }
                0x30 => {
                    library = if imm == 0 {
                        0
                    } else {
                        i32::from((0xF0 | imm) as i8)
                    }
                }
                0x40 => {
                    weak = imm & 1 != 0;
                    let Some(s) = c.cstr() else { return };
                    symbol = s;
                }
                0x50 => {}
                0x60 => {
                    let Some(a) = c.sleb() else { return };
                    addend = a;
                }
                0x70 => {
                    seg = Some(usize::from(imm));
                    let Some(o) = c.uleb() else { return };
                    offset = o;
                }
                0x80 => {
                    let Some(o) = c.uleb() else { return };
                    offset = offset.wrapping_add(o);
                }
                0x90 => {
                    if !bind(seg, offset, symbol, library, addend, weak, out) {
                        return;
                    }
                    offset = offset.wrapping_add(w);
                }
                0xA0 => {
                    let Some(o) = c.uleb() else { return };
                    if !bind(seg, offset, symbol, library, addend, weak, out) {
                        return;
                    }
                    offset = offset.wrapping_add(o).wrapping_add(w);
                }
                0xB0 => {
                    if !bind(seg, offset, symbol, library, addend, weak, out) {
                        return;
                    }
                    offset = offset.wrapping_add(u64::from(imm) * w + w);
                }
                0xC0 => {
                    let (Some(n), Some(skip)) = (c.uleb(), c.uleb()) else {
                        return;
                    };
                    for _ in 0..n.min(MAX_ENTRIES as u64) {
                        if !bind(seg, offset, symbol, library, addend, weak, out) {
                            return;
                        }
                        offset = offset.wrapping_add(skip).wrapping_add(w);
                    }
                }
                // (Threaded binds, of arm64e's first ABI: not read.)
                _ => return,
            }
        }
    }

    /// The entry point (`LC_MAIN`'s, as a preferred address).
    pub fn entry(&self) -> Option<u64> {
        let lc = self
            .load_commands()
            .into_iter()
            .find(|c| c.cmd == LC_MAIN)?;
        let off = crate::read(lc.data, 8, 8, self.endian())?;
        Some(Self::base_address(&self.segments()).wrapping_add(off))
    }

    /// The exported symbols, from the exports trie.
    pub fn exports(&self) -> Vec<Export> {
        let mut trie: &[u8] = &[];
        for lc in self.load_commands() {
            match lc.cmd {
                LC_DYLD_EXPORTS_TRIE => {
                    if let Some(t) = self.linkedit_data(&lc) {
                        trie = self.table(t);
                    }
                }
                LC_DYLD_INFO | LC_DYLD_INFO_ONLY if trie.is_empty() => {
                    if let Some(info) = self.dyld_info(&lc) {
                        trie = self.table(info.export);
                    }
                }
                _ => {}
            }
        }
        let base = Self::base_address(&self.segments());
        let mut out = Vec::new();
        let mut seen = alloc::collections::BTreeSet::new();
        // The bytes of names made so far, bounded: each node's name is all
        // the edges' to it, so a long chain of exports (or many edges to
        // one node) could otherwise make far more than the trie holds.
        let mut name_bytes = 0usize;
        let name_budget = trie.len().saturating_mul(64).saturating_add(1 << 20);
        // (node offset, the name so far); each node queued once (a real
        // trie is a tree: a node reached twice is hostile).
        let mut queued = alloc::collections::BTreeSet::from([0usize]);
        let mut stack: Vec<(usize, Vec<u8>)> = alloc::vec![(0, Vec::new())];
        while let Some((at, prefix)) = stack.pop() {
            if trie.is_empty() || !seen.insert(at) || out.len() >= MAX_ENTRIES {
                continue;
            }
            name_bytes = name_bytes.saturating_add(prefix.len());
            if name_bytes > name_budget {
                break;
            }
            let mut c = Cursor {
                data: trie,
                pos: at,
            };
            let Some(info_len) = c.uleb() else { continue };
            let children = c.pos.saturating_add(index(info_len));
            if info_len > 0 {
                let Some(flags) = c.uleb() else { continue };
                let mut e = Export {
                    name: prefix.clone(),
                    flags,
                    address: None,
                    resolver: None,
                    reexport: None,
                };
                if flags & EXPORT_SYMBOL_FLAGS_REEXPORT != 0 {
                    let (Some(ordinal), Some(name)) = (c.uleb(), c.cstr()) else {
                        continue;
                    };
                    e.reexport = Some((ordinal, name.to_vec()));
                } else {
                    let Some(addr) = c.uleb() else { continue };
                    let absolute =
                        flags & EXPORT_SYMBOL_FLAGS_KIND_MASK == EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE;
                    e.address = Some(if absolute {
                        addr
                    } else {
                        base.wrapping_add(addr)
                    });
                    if flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER != 0 {
                        e.resolver = c.uleb().map(|r| base.wrapping_add(r));
                    }
                }
                out.push(e);
            }
            let mut c = Cursor {
                data: trie,
                pos: children,
            };
            let Some(count) = c.u8() else { continue };
            for _ in 0..count {
                let (Some(edge), Some(child)) = (c.cstr(), c.uleb()) else {
                    break;
                };
                if prefix.len() + edge.len() > 4096 || !queued.insert(index(child)) {
                    continue;
                }
                let mut name = prefix.clone();
                name.extend_from_slice(edge);
                stack.push((index(child), name));
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }
}
