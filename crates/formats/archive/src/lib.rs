//! `ar` archives: static libraries (`.lib` for COFF, `.a` for ELF and
//! Mach-O) and Microsoft import libraries.
//!
//! An archive is `!<arch>\n` followed by members, each a 60-byte header and
//! its data (padded to an even length). Three dialects name members and
//! index symbols differently:
//!
//! - **GNU** (and System V): names end with `/`; `//` holds long names,
//!   referred to as `/<offset>`; `/` (or `/SYM64/`) is a symbol table of
//!   big-endian member offsets.
//! - **Microsoft**: like GNU, but there are two symbol tables named `/`
//!   (the second, little-endian and sorted, indexes members by number), and
//!   an optional `/<ECSYMBOLS>/` for ARM64EC.
//! - **BSD** (and Darwin): names of the form `#1/<length>` are stored at
//!   the start of the member's data; `__.SYMDEF` (or `__.SYMDEF SORTED`,
//!   `__.SYMDEF_64`) is the symbol table.
//!
//! *Thin* archives (`!<thin>\n`) name their members' files instead of
//! holding their data.
//!
//! Everything is read lazily and bounds-checked: a damaged archive yields
//! fewer (or stranger) members, never a panic.

#![no_std]
#![warn(missing_docs)]

extern crate alloc;

use alloc::borrow::Cow;
use alloc::vec::Vec;

use hexcavator_core::{Error, ErrorKind, Result};

/// The signature of a regular archive.
pub const MAGIC: &[u8; 8] = b"!<arch>\n";
/// The signature of a thin archive.
pub const THIN_MAGIC: &[u8; 8] = b"!<thin>\n";
/// The size of a member header.
pub const HEADER_SIZE: u64 = 60;
const HEADER_LEN: usize = 60;

/// At most this many members are read.
const MAX_MEMBERS: usize = 1 << 22;

/// What a member is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MemberKind {
    /// A file in the archive (an object, an import object, ...).
    File,
    /// A symbol table (GNU `/` or `/SYM64/`, Microsoft's first or second
    /// linker member, BSD `__.SYMDEF*`).
    SymbolTable,
    /// Microsoft's ARM64EC symbol table (`/<ECSYMBOLS>/`).
    EcSymbolTable,
    /// The long-name table (`//`).
    LongNames,
}

/// One member of an archive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member<'data> {
    /// A file, or one of the archive's tables.
    pub kind: MemberKind,
    /// The member's name: the file name for files (long names resolved,
    /// the trailing `/` removed), or the table's raw name.
    pub name: Cow<'data, [u8]>,
    /// The header's offset in the archive.
    pub header_offset: u64,
    /// The data's offset in the archive (after a BSD name), and the data.
    /// For a thin archive's files, the data is not in the archive and is
    /// empty.
    pub data_offset: u64,
    /// Its data (empty for a thin archive's files).
    pub data: &'data [u8],
    /// The size the header gives (BSD names included).
    pub size: u64,
    /// The header's time stamp, owner, group, and mode fields, as text.
    pub date: &'data [u8],
    /// The owner's user ID field.
    pub uid: &'data [u8],
    /// The group ID field.
    pub gid: &'data [u8],
    /// The mode (octal) field.
    pub mode: &'data [u8],
}

impl Member<'_> {
    /// The offset just past the member, including its padding byte.
    pub fn end(&self) -> u64 {
        let end = self.data_offset + self.data.len() as u64;
        end + (end & 1)
    }
}

/// An archive.
#[derive(Clone, Copy, Debug)]
pub struct Archive<'data> {
    data: &'data [u8],
    thin: bool,
}

/// A symbol and the archive offset of the header of the member that
/// defines it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchiveSymbol<'data> {
    /// The symbol's name.
    pub name: &'data [u8],
    /// The archive offset of its member's header.
    pub member: u64,
}

fn trim(field: &[u8]) -> &[u8] {
    let end = field.iter().rposition(|&b| b != b' ').map_or(0, |p| p + 1);
    &field[..end]
}

fn decimal(field: &[u8]) -> Option<u64> {
    let t = trim(field);
    if t.is_empty() {
        return None;
    }
    t.iter().try_fold(0u64, |acc, &b| {
        if b.is_ascii_digit() {
            acc.checked_mul(10)?.checked_add(u64::from(b - b'0'))
        } else {
            None
        }
    })
}

impl<'data> Archive<'data> {
    /// Parses an archive (regular or thin).
    pub fn parse(data: &'data [u8]) -> Result<Self> {
        let thin = if data.starts_with(MAGIC) {
            false
        } else if data.starts_with(THIN_MAGIC) {
            true
        } else {
            return Err(Error::new(ErrorKind::BadMagic, 0, "archive signature"));
        };
        Ok(Self { data, thin })
    }

    /// Whether `data` starts like an archive.
    pub fn is_archive(data: &[u8]) -> bool {
        data.starts_with(MAGIC) || data.starts_with(THIN_MAGIC)
    }

    /// The archive's bytes.
    pub fn data(&self) -> &'data [u8] {
        self.data
    }

    /// Whether this is a thin archive.
    pub fn is_thin(&self) -> bool {
        self.thin
    }

    /// Every member, tables included, in order.
    pub fn members(&self) -> impl Iterator<Item = Member<'data>> + 'data {
        let archive = *self;
        let mut offset = MAGIC.len() as u64;
        let mut long_names: &'data [u8] = &[];
        let mut count = 0usize;
        core::iter::from_fn(move || {
            if count >= MAX_MEMBERS {
                return None;
            }
            let member = archive.member_at(offset, long_names)?;
            if member.kind == MemberKind::LongNames {
                long_names = member.data;
            }
            count += 1;
            // Thin archives' file members have no data here.
            let next = if archive.thin && member.kind == MemberKind::File {
                member.header_offset + HEADER_SIZE
            } else {
                member.end()
            };
            if next <= offset {
                return None;
            }
            offset = next;
            Some(member)
        })
    }

    /// The file members.
    pub fn files(&self) -> impl Iterator<Item = Member<'data>> + 'data {
        self.members().filter(|m| m.kind == MemberKind::File)
    }

    /// The member whose header is at `offset` (as symbol tables give).
    pub fn member_at_offset(&self, offset: u64) -> Option<Member<'data>> {
        self.members().find(|m| m.header_offset == offset)
    }

    fn member_at(&self, offset: u64, long_names: &'data [u8]) -> Option<Member<'data>> {
        let start = usize::try_from(offset).ok()?;
        let header = self.data.get(start..start.checked_add(HEADER_LEN)?)?;
        // The header ends with "`\n".
        if &header[58..60] != b"`\n" {
            return None;
        }
        let raw_name = &header[0..16];
        let date = trim(&header[16..28]);
        let uid = trim(&header[28..34]);
        let gid = trim(&header[34..40]);
        let mode = trim(&header[40..48]);
        let size = decimal(&header[48..58])?;
        let body_offset = offset + HEADER_SIZE;
        let name_field = trim(raw_name);
        let (kind, name, name_len) = match name_field {
            b"/" | b"/SYM64/" => (MemberKind::SymbolTable, Cow::Borrowed(name_field), 0),
            b"//" => (MemberKind::LongNames, Cow::Borrowed(name_field), 0),
            b"/<ECSYMBOLS>/" => (MemberKind::EcSymbolTable, Cow::Borrowed(name_field), 0),
            b"__.SYMDEF" | b"__.SYMDEF SORTED" | b"__.SYMDEF_64" | b"__.SYMDEF_64 SORTED" => {
                (MemberKind::SymbolTable, Cow::Borrowed(name_field), 0)
            }
            [b'#', b'1', b'/', digits @ ..] => {
                // BSD: the name is the first `len` bytes of the data.
                let len = decimal(digits)?;
                let s = usize::try_from(body_offset).ok()?;
                let n = self
                    .data
                    .get(s..s.checked_add(usize::try_from(len).ok()?)?)?;
                let n = &n[..n.iter().position(|&b| b == 0).unwrap_or(n.len())];
                let kind = if n.starts_with(b"__.SYMDEF") {
                    MemberKind::SymbolTable
                } else {
                    MemberKind::File
                };
                (kind, Cow::Borrowed(n), len)
            }
            [b'/', digits @ ..] if digits.iter().all(u8::is_ascii_digit) && !digits.is_empty() => {
                // GNU/Microsoft long name: an offset into `//`, ending with
                // "/\n" (GNU) or NUL (Microsoft).
                let at = usize::try_from(decimal(digits)?).ok()?;
                let rest = long_names.get(at..).unwrap_or(&[]);
                let end = rest
                    .iter()
                    .position(|&b| b == b'\n' || b == 0)
                    .unwrap_or(rest.len());
                let n = &rest[..end];
                let n = n.strip_suffix(b"/").unwrap_or(n);
                (MemberKind::File, Cow::Borrowed(n), 0)
            }
            _ => {
                let n = name_field.strip_suffix(b"/").unwrap_or(name_field);
                (MemberKind::File, Cow::Borrowed(n), 0)
            }
        };
        let data_offset = body_offset + name_len;
        let data_len = size.checked_sub(name_len)?;
        let data = if self.thin && kind == MemberKind::File {
            &[][..]
        } else {
            let s = usize::try_from(data_offset).ok()?;
            let l = usize::try_from(data_len).ok()?;
            // A truncated member keeps what the archive has.
            let avail = self.data.len().saturating_sub(s).min(l);
            self.data.get(s..s + avail)?
        };
        Some(Member {
            kind,
            name,
            header_offset: offset,
            data_offset,
            data,
            size,
            date,
            uid,
            gid,
            mode,
        })
    }

    /// The symbols of the archive's first symbol table, in its order, with
    /// the header offset of each one's member. Microsoft's second linker
    /// member, if present, is preferred (it indexes members by number).
    pub fn symbols(&self) -> Vec<ArchiveSymbol<'data>> {
        let tables: Vec<Member<'data>> = self
            .members()
            .take_while(|m| m.kind != MemberKind::File)
            .filter(|m| m.kind == MemberKind::SymbolTable)
            .collect();
        match tables.as_slice() {
            [] => Vec::new(),
            [first, second, ..] if &*first.name == b"/" && &*second.name == b"/" => {
                microsoft_second(second.data)
                    .unwrap_or_else(|| gnu(first.data, false).unwrap_or_default())
            }
            [t, ..] if &*t.name == b"/" => gnu(t.data, false).unwrap_or_default(),
            [t, ..] if &*t.name == b"/SYM64/" => gnu(t.data, true).unwrap_or_default(),
            [t, ..] => bsd(
                t.data,
                t.name.ends_with(b"_64") || t.name.ends_with(b"_64 SORTED"),
            )
            .unwrap_or_default(),
        }
    }
}

/// GNU (and Microsoft's first linker member): a big-endian count, that many
/// big-endian member offsets (4 or 8 bytes), then NUL-terminated names.
fn gnu(data: &[u8], wide: bool) -> Option<Vec<ArchiveSymbol<'_>>> {
    let w = if wide { 8 } else { 4 };
    let be = |b: &[u8]| -> u64 { b.iter().fold(0u64, |a, &x| (a << 8) | u64::from(x)) };
    let count = usize::try_from(be(data.get(..w)?)).ok()?;
    let offsets = data.get(w..w.checked_add(count.checked_mul(w)?)?)?;
    let mut names = &data[w + count * w..];
    let mut out = Vec::with_capacity(count.min(1 << 20));
    for o in offsets.chunks_exact(w) {
        let end = names.iter().position(|&b| b == 0)?;
        out.push(ArchiveSymbol {
            name: &names[..end],
            member: be(o),
        });
        names = &names[end + 1..];
    }
    Some(out)
}

/// Microsoft's second linker member: a little-endian member count, member
/// offsets, a symbol count, 1-based 16-bit member indexes, then names.
fn microsoft_second(data: &[u8]) -> Option<Vec<ArchiveSymbol<'_>>> {
    let le32 = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let member_count = usize::try_from(le32(data.get(..4)?)).ok()?;
    let offsets_end = 4usize.checked_add(member_count.checked_mul(4)?)?;
    let offsets = data.get(4..offsets_end)?;
    let symbol_count = usize::try_from(le32(data.get(offsets_end..offsets_end + 4)?)).ok()?;
    let indexes_start = offsets_end + 4;
    let indexes =
        data.get(indexes_start..indexes_start.checked_add(symbol_count.checked_mul(2)?)?)?;
    let mut names = &data[indexes_start + symbol_count * 2..];
    let mut out = Vec::with_capacity(symbol_count.min(1 << 20));
    for i in indexes.as_chunks::<2>().0 {
        let index = usize::from(u16::from_le_bytes([i[0], i[1]]));
        let end = names.iter().position(|&b| b == 0)?;
        let member = index
            .checked_sub(1)
            .and_then(|k| offsets.get(k * 4..k * 4 + 4))
            .map(|b| u64::from(le32(b)))?;
        out.push(ArchiveSymbol {
            name: &names[..end],
            member,
        });
        names = &names[end + 1..];
    }
    Some(out)
}

/// BSD `__.SYMDEF`: a byte count of `ranlib` entries (name offset, member
/// offset; 4 or 8 bytes each), the entries, a string-table byte count, and
/// the strings. Little-endian (as Darwin writes them).
fn bsd(data: &[u8], wide: bool) -> Option<Vec<ArchiveSymbol<'_>>> {
    let w = if wide { 8 } else { 4 };
    let le = |b: &[u8]| -> u64 { b.iter().rev().fold(0u64, |a, &x| (a << 8) | u64::from(x)) };
    let ranlib_bytes = usize::try_from(le(data.get(..w)?)).ok()?;
    let entries = data.get(w..w.checked_add(ranlib_bytes)?)?;
    let strings_start = w + ranlib_bytes;
    let strings_len = usize::try_from(le(data.get(strings_start..strings_start + w)?)).ok()?;
    let strings = data.get(strings_start + w..)?;
    let strings = &strings[..strings_len.min(strings.len())];
    let mut out = Vec::new();
    for e in entries.chunks_exact(2 * w) {
        let name_at = usize::try_from(le(&e[..w])).ok()?;
        let member = le(&e[w..]);
        let rest = strings.get(name_at..)?;
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        out.push(ArchiveSymbol {
            name: &rest[..end],
            member,
        });
    }
    Some(out)
}

#[cfg(test)]
mod tests;
