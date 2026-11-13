//! ELF files: executables, shared objects, and relocatable objects, of
//! either class (32- or 64-bit) and either byte order.
//!
//! [`ElfFile`] is a borrowed view: parsing reads the file header; segments
//! ([`ElfFile::segments`]), sections ([`ElfFile::sections`]), symbols, and
//! notes are read on demand and normalized to 64-bit fields. Extended
//! numbering (more than 0xFF00 sections, or 0xFFFF program headers) is
//! followed through section 0, as the gABI says.
//!
//! Everything is bounds-checked: a damaged file gives errors or fewer
//! entries, never a panic.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use hexcavator_core::{Endian, Error, ErrorKind, Result, bytes_at, cstr_at};

pub mod arm;
pub mod consts;
pub mod eh_frame;
#[allow(missing_docs, reason = "generated: each names a constant")]
pub mod spelling;
pub mod versions;

use consts::*;

/// 32- or 64-bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Class {
    Elf32,
    Elf64,
}

/// The instruction set of a machine (`e_machine`) in a file of `class`
/// (some machines name an architecture of either width).
pub const fn arch(machine: u16, class: Class) -> hexcavator_core::Arch {
    use hexcavator_core::Arch;
    let wide = matches!(class, Class::Elf64);
    match machine {
        EM_386 | EM_IAMCU => Arch::X86,
        // (The x32 ABI is ELF32 on x86-64: the instructions are x64's.)
        EM_X86_64 => Arch::X64,
        EM_ARM => Arch::Arm,
        EM_AARCH64 => Arch::Arm64,
        EM_MIPS | EM_MIPS_RS3_LE if wide => Arch::Mips64,
        EM_MIPS | EM_MIPS_RS3_LE => Arch::Mips,
        EM_PPC => Arch::PowerPc,
        EM_PPC64 => Arch::PowerPc64,
        EM_RISCV if wide => Arch::RiscV64,
        EM_RISCV => Arch::RiscV32,
        EM_LOONGARCH if wide => Arch::LoongArch64,
        EM_LOONGARCH => Arch::LoongArch32,
        // 31-bit ESA/390 has no architecture of its own here.
        EM_S390 if wide => Arch::S390x,
        EM_SPARC | EM_SPARC32PLUS => Arch::Sparc,
        EM_SPARCV9 => Arch::Sparc64,
        EM_IA_64 => Arch::Ia64,
        // Alpha under ELF is the 64-bit architecture.
        EM_ALPHA | EM_ALPHA_UNOFFICIAL => Arch::Alpha64,
        EM_SH => Arch::SuperH,
        EM_68K => Arch::M68k,
        _ => Arch::Unknown,
    }
}

/// The file header, normalized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub class: Class,
    pub endian: Endian,
    pub os_abi: u8,
    pub abi_version: u8,
    /// `ET_*`.
    pub kind: u16,
    /// `EM_*`.
    pub machine: u16,
    pub version: u32,
    pub entry: u64,
    pub phoff: u64,
    pub shoff: u64,
    pub flags: u32,
    pub ehsize: u16,
    pub phentsize: u16,
    /// The program header count (from section 0 if extended).
    pub phnum: u32,
    pub shentsize: u16,
    /// The section count (from section 0 if extended).
    pub shnum: u32,
    /// The section-name string table's index (from section 0 if extended).
    pub shstrndx: u32,
}

/// A program header (segment), normalized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    pub index: usize,
    /// `PT_*`.
    pub kind: u32,
    /// `PF_*`.
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

/// A section header, normalized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Section<'data> {
    pub index: usize,
    /// Resolved through the section-name string table (empty if it can't
    /// be).
    pub name: &'data [u8],
    pub name_offset: u32,
    /// `SHT_*`.
    pub kind: u32,
    /// `SHF_*`.
    pub flags: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub addralign: u64,
    pub entsize: u64,
}

impl Section<'_> {
    /// Whether the section occupies bytes in the file (`SHT_NOBITS`
    /// doesn't).
    pub fn has_file_data(&self) -> bool {
        self.kind != SHT_NOBITS && self.kind != SHT_NULL
    }

    /// Whether the section is loaded into memory.
    pub fn is_alloc(&self) -> bool {
        self.flags & SHF_ALLOC != 0
    }

    /// The bytes the section occupies in the file: its size, or none.
    pub fn file_size(&self) -> u64 {
        if self.has_file_data() { self.size } else { 0 }
    }
}

/// A symbol, normalized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Symbol<'data> {
    /// Its index in its table.
    pub index: usize,
    pub name: &'data [u8],
    /// Where the name starts in the linked string table.
    pub name_offset: u32,
    pub value: u64,
    pub size: u64,
    /// `STB_*`.
    pub bind: u8,
    /// `STT_*`.
    pub kind: u8,
    /// `STV_*` (the low bits of `st_other`).
    pub visibility: u8,
    /// The section index (`SHN_XINDEX` resolved through the extended
    /// index table), or a special index (`SHN_UNDEF`, `SHN_ABS`,
    /// `SHN_COMMON`).
    pub shndx: u32,
}

/// A note (`SHT_NOTE` section or `PT_NOTE` segment entry).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Note<'data> {
    pub name: &'data [u8],
    pub kind: u32,
    pub desc: &'data [u8],
}

/// A relocation entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Relocation {
    /// Where the entry lies in the file.
    pub file_offset: u64,
    pub size: u64,
    /// The offset (in an object, within the target section) or address it
    /// patches.
    pub offset: u64,
    /// Its type (`R_<machine>_*`; MIPS64's three types packed, the first
    /// in the low byte).
    pub kind: u32,
    /// The index of its symbol in the linked symbol table (0: none).
    pub symbol: u32,
    /// Its addend (`SHT_RELA`), or `None` (`SHT_REL`: the addend is the
    /// bytes it patches).
    pub addend: Option<i64>,
}

/// How a relocation that writes an address word gets the address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AddressRelocation {
    /// The load bias plus its addend (`R_*_RELATIVE`).
    Relative,
    /// A symbol's address plus its addend (absolute words, GOT entries,
    /// PLT slots).
    Symbol,
    /// What the function at its addend (a resolver) returns
    /// (`R_*_IRELATIVE`).
    IndirectFunction,
}

/// Whether a relocation of `kind` for `machine` writes an address word, and
/// how. (Relocations of code, and of words that hold offsets, don't.)
pub const fn address_relocation(machine: u16, kind: u32) -> Option<AddressRelocation> {
    use AddressRelocation::*;
    Some(match (machine, kind) {
        (EM_X86_64, R_X86_64_RELATIVE)
        | (EM_386, R_386_RELATIVE)
        | (EM_AARCH64, R_AARCH64_RELATIVE)
        | (EM_ARM, R_ARM_RELATIVE)
        | (EM_RISCV, R_RISCV_RELATIVE) => Relative,
        (EM_X86_64, R_X86_64_64 | R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT)
        | (EM_386, R_386_32 | R_386_GLOB_DAT | R_386_JMP_SLOT)
        | (EM_AARCH64, R_AARCH64_ABS64 | R_AARCH64_GLOB_DAT | R_AARCH64_JUMP_SLOT)
        | (EM_ARM, R_ARM_ABS32 | R_ARM_GLOB_DAT | R_ARM_JUMP_SLOT)
        | (EM_RISCV, R_RISCV_32 | R_RISCV_64 | R_RISCV_JUMP_SLOT) => Symbol,
        (EM_X86_64, R_X86_64_IRELATIVE)
        | (EM_386, R_386_IRELATIVE)
        | (EM_AARCH64, R_AARCH64_IRELATIVE)
        | (EM_ARM, R_ARM_IRELATIVE)
        | (EM_RISCV, R_RISCV_IRELATIVE) => IndirectFunction,
        _ => return None,
    })
}

/// A dynamic section entry (`Elf*_Dyn`): its tag (`DT_*`) and value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dynamic {
    pub tag: u64,
    pub value: u64,
}

/// A compressed section's header (`Elf*_Chdr`), and where its compressed
/// bytes start in the section.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Compression {
    /// `ELFCOMPRESS_*`.
    pub kind: u32,
    pub size: u64,
    pub align: u64,
    pub data_offset: u64,
}

/// A section group (`SHT_GROUP`): sections kept or dropped together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group<'data> {
    /// The group section's index.
    pub section: usize,
    /// `GRP_*`.
    pub flags: u32,
    /// Its signature: the name of the symbol that identifies it (for a
    /// COMDAT, the copies' shared name).
    pub signature: &'data [u8],
    /// The indexes of its member sections.
    pub members: Vec<u32>,
}

/// A link to a separate debug file (`.gnu_debuglink`): its file name and
/// the CRC-32 of its contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DebugLink<'data> {
    pub path: &'data [u8],
    pub crc: u32,
}

/// A link to a supplementary debug file shared by several (`dwz`'s
/// `.gnu_debugaltlink`): its path and build ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AltLink<'data> {
    pub path: &'data [u8],
    pub build_id: &'data [u8],
}

/// An ELF file.
#[derive(Clone, Copy, Debug)]
pub struct ElfFile<'data> {
    data: &'data [u8],
    header: Header,
}

/// At most this many entries are read from a table.
const MAX_ENTRIES: u64 = 1 << 24;
/// The most entries a compressed table (Android's packed relocations) may
/// expand to, per byte of it: real ones compress far less.
const ENTRIES_PER_BYTE: u64 = 64;

fn read<const N: usize>(data: &[u8], offset: u64) -> Option<[u8; N]> {
    bytes_at(data, offset, N as u64).ok()?.try_into().ok()
}

macro_rules! readers {
    ($($name:ident: $t:ty;)*) => {$(
        fn $name(data: &[u8], offset: u64, endian: Endian) -> Option<$t> {
            let b = read(data, offset)?;
            Some(match endian {
                Endian::Little => <$t>::from_le_bytes(b),
                Endian::Big => <$t>::from_be_bytes(b),
            })
        }
    )*};
}

readers! {
    read_u16: u16;
    read_u32: u32;
    read_u64: u64;
}

/// A class-sized word (`Elf32_Addr`/`Elf64_Addr`, `_Off`, `_Xword`...).
fn read_word(data: &[u8], offset: u64, class: Class, endian: Endian) -> Option<u64> {
    match class {
        Class::Elf32 => read_u32(data, offset, endian).map(u64::from),
        Class::Elf64 => read_u64(data, offset, endian),
    }
}

impl<'data> ElfFile<'data> {
    /// Whether `data` starts with the ELF magic.
    pub fn is_elf(data: &[u8]) -> bool {
        data.starts_with(b"\x7fELF")
    }

    pub fn parse(data: &'data [u8]) -> Result<Self> {
        if !Self::is_elf(data) {
            return Err(Error::new(ErrorKind::BadMagic, 0, "ELF magic"));
        }
        let ident = bytes_at(data, 0, 16)?;
        let class = match ident[4] {
            ELFCLASS32 => Class::Elf32,
            ELFCLASS64 => Class::Elf64,
            _ => return Err(Error::new(ErrorKind::Unsupported, 4, "ELF class")),
        };
        let endian = match ident[5] {
            ELFDATA2LSB => Endian::Little,
            ELFDATA2MSB => Endian::Big,
            _ => return Err(Error::new(ErrorKind::Unsupported, 5, "ELF data encoding")),
        };
        let truncated = |o: u64| Error::new(ErrorKind::Truncated, o, "ELF header");
        let h16 = |o: u64| read_u16(data, o, endian).ok_or(truncated(o));
        let h32 = |o: u64| read_u32(data, o, endian).ok_or(truncated(o));
        let hw = |o: u64| read_word(data, o, class, endian).ok_or(truncated(o));
        let w: u64 = match class {
            Class::Elf32 => 4,
            Class::Elf64 => 8,
        };
        let kind = h16(0x10)?;
        let machine = h16(0x12)?;
        let version = h32(0x14)?;
        let entry = hw(0x18)?;
        let phoff = hw(0x18 + w)?;
        let shoff = hw(0x18 + 2 * w)?;
        let rest = 0x18 + 3 * w;
        let flags = h32(rest)?;
        let ehsize = h16(rest + 4)?;
        let phentsize = h16(rest + 6)?;
        let phnum = u32::from(h16(rest + 8)?);
        let shentsize = h16(rest + 10)?;
        let shnum = u32::from(h16(rest + 12)?);
        let shstrndx = u32::from(h16(rest + 14)?);
        let mut header = Header {
            class,
            endian,
            os_abi: ident[7],
            abi_version: ident[8],
            kind,
            machine,
            version,
            entry,
            phoff,
            shoff,
            flags,
            ehsize,
            phentsize,
            phnum,
            shentsize,
            shnum,
            shstrndx,
        };
        let mut file = Self { data, header };
        // Extended numbering lives in section 0.
        if shoff != 0
            && (shnum == 0 || shstrndx == u32::from(SHN_XINDEX) || phnum == u32::from(PN_XNUM))
        {
            if let Some(s0) = file.raw_section(0) {
                if shnum == 0 {
                    header.shnum = u32::try_from(s0.size).unwrap_or(u32::MAX);
                }
                if shstrndx == u32::from(SHN_XINDEX) {
                    header.shstrndx = s0.link;
                }
                if phnum == u32::from(PN_XNUM) {
                    header.phnum = s0.info;
                }
            }
            file.header = header;
        }
        Ok(file)
    }

    pub fn data(&self) -> &'data [u8] {
        self.data
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn class(&self) -> Class {
        self.header.class
    }

    pub fn endian(&self) -> Endian {
        self.header.endian
    }

    /// The `u32` at `base + offset` (`None` past the file, or on
    /// overflow).
    fn u32_at(&self, base: u64, offset: u64) -> Option<u32> {
        read_u32(self.data, base.checked_add(offset)?, self.header.endian)
    }

    fn u16_at(&self, base: u64, offset: u64) -> Option<u16> {
        read_u16(self.data, base.checked_add(offset)?, self.header.endian)
    }

    /// The class-sized word at `base + offset`.
    fn word_at(&self, base: u64, offset: u64) -> Option<u64> {
        read_word(
            self.data,
            base.checked_add(offset)?,
            self.header.class,
            self.header.endian,
        )
    }

    fn byte_at(&self, base: u64, offset: u64) -> Option<u8> {
        read::<1>(self.data, base.checked_add(offset)?).map(|[b]| b)
    }

    /// Whether this is a relocatable object (`ET_REL`).
    pub fn is_object(&self) -> bool {
        self.header.kind == ET_REL
    }

    /// The file range of the file header.
    pub fn header_range(&self) -> (u64, u64) {
        let size = match self.header.class {
            Class::Elf32 => 52,
            Class::Elf64 => 64,
        };
        (
            0,
            u64::from(self.header.ehsize)
                .max(size)
                .min(self.data.len() as u64),
        )
    }

    /// The file range of the program header table.
    pub fn program_headers_range(&self) -> (u64, u64) {
        let size = u64::from(self.header.phnum).saturating_mul(u64::from(self.header.phentsize));
        (
            self.header.phoff,
            if self.header.phoff == 0 { 0 } else { size },
        )
    }

    /// The file range of the section header table.
    pub fn section_headers_range(&self) -> (u64, u64) {
        let size = u64::from(self.header.shnum).saturating_mul(u64::from(self.header.shentsize));
        (
            self.header.shoff,
            if self.header.shoff == 0 { 0 } else { size },
        )
    }

    fn raw_section(&self, index: u64) -> Option<Section<'data>> {
        let entsize = u64::from(self.header.shentsize);
        let min = match self.header.class {
            Class::Elf32 => 40,
            Class::Elf64 => 64,
        };
        if entsize < min || self.header.shoff == 0 {
            return None;
        }
        let at = self.header.shoff.checked_add(index.checked_mul(entsize)?)?;
        let u32_at = |o: u64| self.u32_at(at, o);
        let word_at = |o: u64| self.word_at(at, o);
        let (name_offset, kind) = (u32_at(0)?, u32_at(4)?);
        let (flags, addr, offset, size, link, info, addralign, entsize) = match self.header.class {
            Class::Elf32 => (
                word_at(8)?,
                word_at(12)?,
                word_at(16)?,
                word_at(20)?,
                u32_at(24)?,
                u32_at(28)?,
                word_at(32)?,
                word_at(36)?,
            ),
            Class::Elf64 => (
                word_at(8)?,
                word_at(16)?,
                word_at(24)?,
                word_at(32)?,
                u32_at(40)?,
                u32_at(44)?,
                word_at(48)?,
                word_at(56)?,
            ),
        };
        Some(Section {
            index: usize::try_from(index).ok()?,
            name: &[],
            name_offset,
            kind,
            flags,
            addr,
            offset,
            size,
            link,
            info,
            addralign,
            entsize,
        })
    }

    /// The section at `index`, its name resolved.
    pub fn section(&self, index: usize) -> Option<Section<'data>> {
        if index as u64 >= u64::from(self.header.shnum) {
            return None;
        }
        let mut s = self.raw_section(index as u64)?;
        let strtab = self.header.shstrndx;
        if strtab != 0
            && u64::from(strtab) < u64::from(self.header.shnum)
            && let Some(names) = self.raw_section(u64::from(strtab))
            && names.kind != SHT_NOBITS
            && u64::from(s.name_offset) < names.size
        {
            s.name = cstr_at(
                self.data,
                names.offset.saturating_add(u64::from(s.name_offset)),
            )
            .unwrap_or(&[]);
            // A name can't run past its table.
            let limit = names.size - u64::from(s.name_offset);
            if (s.name.len() as u64) > limit {
                s.name = &s.name[..usize::try_from(limit).unwrap_or(usize::MAX)];
            }
        }
        Some(s)
    }

    /// Every section, in order (section 0, `SHT_NULL`, included).
    pub fn sections(&self) -> impl Iterator<Item = Section<'data>> + '_ {
        let n = u64::from(self.header.shnum).min(MAX_ENTRIES) as usize;
        (0..n).map_while(|i| self.section(i))
    }

    /// The section named `name`.
    pub fn section_by_name(&self, name: &[u8]) -> Option<Section<'data>> {
        self.sections().find(|s| s.name == name)
    }

    /// The bytes of a section (empty for `SHT_NOBITS`, clamped to the file).
    pub fn section_data(&self, s: &Section<'_>) -> &'data [u8] {
        if !s.has_file_data() {
            return &[];
        }
        let start = s.offset.min(self.data.len() as u64);
        let len = s.size.min(self.data.len() as u64 - start);
        bytes_at(self.data, start, len).unwrap_or(&[])
    }

    /// The program header at `index`.
    pub fn segment(&self, index: usize) -> Option<Segment> {
        if index as u64 >= u64::from(self.header.phnum) || self.header.phoff == 0 {
            return None;
        }
        let entsize = u64::from(self.header.phentsize);
        let min = match self.header.class {
            Class::Elf32 => 32,
            Class::Elf64 => 56,
        };
        if entsize < min {
            return None;
        }
        let at = self
            .header
            .phoff
            .checked_add((index as u64).checked_mul(entsize)?)?;
        let u32_at = |o: u64| self.u32_at(at, o);
        let word_at = |o: u64| self.word_at(at, o);
        Some(match self.header.class {
            Class::Elf32 => Segment {
                index,
                kind: u32_at(0)?,
                offset: word_at(4)?,
                vaddr: word_at(8)?,
                paddr: word_at(12)?,
                filesz: word_at(16)?,
                memsz: word_at(20)?,
                flags: u32_at(24)?,
                align: word_at(28)?,
            },
            Class::Elf64 => Segment {
                index,
                kind: u32_at(0)?,
                flags: u32_at(4)?,
                offset: word_at(8)?,
                vaddr: word_at(16)?,
                paddr: word_at(24)?,
                filesz: word_at(32)?,
                memsz: word_at(40)?,
                align: word_at(48)?,
            },
        })
    }

    /// Every program header, in order.
    pub fn segments(&self) -> impl Iterator<Item = Segment> + '_ {
        let n = u64::from(self.header.phnum).min(MAX_ENTRIES) as usize;
        (0..n).map_while(|i| self.segment(i))
    }

    /// The symbols of a symbol table section (`SHT_SYMTAB` or
    /// `SHT_DYNSYM`), names from its linked string table, `SHN_XINDEX`
    /// resolved through the table's `SHT_SYMTAB_SHNDX` section.
    pub fn symbols(&self, table: &Section<'data>) -> Vec<Symbol<'data>> {
        let mut out = Vec::new();
        if table.kind != SHT_SYMTAB && table.kind != SHT_DYNSYM {
            return out;
        }
        let entsize = match self.header.class {
            Class::Elf32 => 16u64,
            Class::Elf64 => 24,
        };
        if table.entsize != 0 && table.entsize < entsize {
            return out;
        }
        let stride = if table.entsize == 0 {
            entsize
        } else {
            table.entsize
        };
        let strings = self.section(table.link as usize);
        let extended = self
            .sections()
            .find(|s| s.kind == SHT_SYMTAB_SHNDX && s.link as usize == table.index);
        let count = (table.size / stride).min(MAX_ENTRIES);
        for i in 0..count {
            let at = table.offset.saturating_add(i * stride);
            let read = || -> Option<(u32, u64, u64, u8, u8, u16)> {
                Some(match self.header.class {
                    Class::Elf32 => (
                        self.u32_at(at, 0)?,
                        self.word_at(at, 4)?,
                        self.word_at(at, 8)?,
                        self.byte_at(at, 12)?,
                        self.byte_at(at, 13)?,
                        self.u16_at(at, 14)?,
                    ),
                    Class::Elf64 => (
                        self.u32_at(at, 0)?,
                        self.word_at(at, 8)?,
                        self.word_at(at, 16)?,
                        self.byte_at(at, 4)?,
                        self.byte_at(at, 5)?,
                        self.u16_at(at, 6)?,
                    ),
                })
            };
            let Some((name_offset, value, size, info, other, shndx)) = read() else {
                break;
            };
            let name = strings
                .filter(|s| u64::from(name_offset) < s.size)
                .and_then(|s| {
                    cstr_at(self.data, s.offset.saturating_add(u64::from(name_offset))).ok()
                })
                .unwrap_or(&[]);
            let shndx = if shndx == SHN_XINDEX {
                extended
                    .and_then(|x| self.u32_at(x.offset, i * 4))
                    .unwrap_or(0)
            } else {
                u32::from(shndx)
            };
            out.push(Symbol {
                index: out.len(),
                name,
                name_offset,
                value,
                size,
                bind: info >> 4,
                kind: info & 0xF,
                visibility: other & 3,
                shndx,
            });
        }
        out
    }

    /// The symbols of `.symtab` (or, failing that, `.dynsym`).
    pub fn all_symbols(&self) -> Vec<Symbol<'data>> {
        let table = self
            .sections()
            .find(|s| s.kind == SHT_SYMTAB)
            .or_else(|| self.sections().find(|s| s.kind == SHT_DYNSYM));
        table.map(|t| self.symbols(&t)).unwrap_or_default()
    }

    /// The notes in `data` (a note section's or segment's bytes), each
    /// field 4-byte aligned (as GNU tools write 64-bit notes, too).
    pub fn notes(&self, data: &'data [u8]) -> Vec<Note<'data>> {
        let mut out = Vec::new();
        let mut at = 0u64;
        let len = data.len() as u64;
        while at + 12 <= len {
            let e = self.header.endian;
            let (Some(namesz), Some(descsz), Some(kind)) = (
                read_u32(data, at, e),
                read_u32(data, at + 4, e),
                read_u32(data, at + 8, e),
            ) else {
                break;
            };
            let (namesz, descsz) = (u64::from(namesz), u64::from(descsz));
            let name_at = at + 12;
            let desc_at = name_at + namesz.next_multiple_of(4);
            let next = desc_at.saturating_add(descsz.next_multiple_of(4));
            let (Ok(name), Ok(desc)) = (
                bytes_at(data, name_at, namesz),
                bytes_at(data, desc_at, descsz),
            ) else {
                break;
            };
            let name = name.split(|&b| b == 0).next().unwrap_or(&[]);
            out.push(Note { name, kind, desc });
            if next <= at {
                break;
            }
            at = next;
        }
        out
    }

    /// The GNU build ID (`NT_GNU_BUILD_ID`), from a note section or
    /// segment.
    pub fn build_id(&self) -> Option<&'data [u8]> {
        let from = |data: &'data [u8]| {
            self.notes(data)
                .into_iter()
                .find(|n| n.name == b"GNU" && n.kind == NT_GNU_BUILD_ID)
                .map(|n| n.desc)
        };
        self.sections()
            .filter(|s| s.kind == SHT_NOTE)
            .find_map(|s| from(self.section_data(&s)))
            .or_else(|| {
                self.segments()
                    .filter(|p| p.kind == PT_NOTE)
                    .find_map(|p| from(bytes_at(self.data, p.offset, p.filesz).ok()?))
            })
    }

    /// The section groups, in section order.
    pub fn groups(&self) -> Vec<Group<'data>> {
        let mut out = Vec::new();
        let mut tables: Vec<(u32, Vec<Symbol<'data>>)> = Vec::new();
        for g in self.sections().filter(|s| s.kind == SHT_GROUP) {
            let data = self.section_data(&g);
            let word = |i: usize| read_u32(data, (i * 4) as u64, self.header.endian);
            let Some(flags) = word(0) else { continue };
            let members = (1..data.len() / 4).filter_map(word).collect();
            if !tables.iter().any(|(t, _)| *t == g.link) {
                let symbols = self
                    .section(g.link as usize)
                    .map(|t| self.symbols(&t))
                    .unwrap_or_default();
                tables.push((g.link, symbols));
            }
            let signature = tables
                .iter()
                .find(|(t, _)| *t == g.link)
                .and_then(|(_, syms)| syms.get(g.info as usize))
                .map_or(&[][..], |s| s.name);
            out.push(Group {
                section: g.index,
                flags,
                signature,
                members,
            });
        }
        out
    }

    /// The link to this file's separate debug file, if it has one.
    pub fn debug_link(&self) -> Option<DebugLink<'data>> {
        let s = self.section_by_name(b".gnu_debuglink")?;
        let data = self.section_data(&s);
        let path = data.split(|&b| b == 0).next()?;
        // The name, its NUL, padding to 4 bytes, then the CRC.
        let at = (path.len() as u64 + 1).next_multiple_of(4);
        let crc = read_u32(data, at, self.header.endian)?;
        Some(DebugLink { path, crc })
    }

    /// The link to this file's supplementary debug file, if it has one.
    pub fn alt_link(&self) -> Option<AltLink<'data>> {
        let s = self.section_by_name(b".gnu_debugaltlink")?;
        let data = self.section_data(&s);
        let path = data.split(|&b| b == 0).next()?;
        let build_id = data.get(path.len() + 1..)?;
        Some(AltLink { path, build_id })
    }

    /// A compressed section's header (`SHF_COMPRESSED`).
    pub fn compression(&self, s: &Section<'_>) -> Option<Compression> {
        if s.flags & SHF_COMPRESSED == 0 || !s.has_file_data() {
            return None;
        }
        let o = s.offset;
        Some(match self.header.class {
            Class::Elf32 => Compression {
                kind: self.u32_at(o, 0)?,
                size: self.word_at(o, 4)?,
                align: self.word_at(o, 8)?,
                data_offset: 12,
            },
            Class::Elf64 => Compression {
                kind: self.u32_at(o, 0)?,
                size: self.word_at(o, 8)?,
                align: self.word_at(o, 16)?,
                data_offset: 24,
            },
        })
    }

    /// The entries of a relocation section (`SHT_REL` or `SHT_RELA`):
    /// where each lies in the file, and the offset it patches (`r_offset`).
    pub fn relocations(&self, s: &Section<'_>) -> Vec<Relocation> {
        let mut out = Vec::new();
        let (w, min) = match self.header.class {
            Class::Elf32 => (4u64, 8u64),
            Class::Elf64 => (8, 16),
        };
        let natural = match s.kind {
            SHT_REL => min,
            SHT_RELA => min + w,
            SHT_ANDROID_REL | SHT_ANDROID_RELA => return self.android_relocations(s),
            _ => return out,
        };
        let stride = if s.entsize == 0 { natural } else { s.entsize };
        if stride < natural {
            return out;
        }
        let count = (s.size / stride).min(MAX_ENTRIES);
        for i in 0..count {
            let at = s.offset.saturating_add(i * stride);
            let (Some(offset), Some(info)) = (self.word_at(at, 0), self.word_at(at, w)) else {
                break;
            };
            let (symbol, kind) = self.split_info(info);
            let addend = (s.kind == SHT_RELA)
                .then(|| self.word_at(at, 2 * w))
                .flatten()
                .map(|a| match self.header.class {
                    Class::Elf32 => i64::from(i32::from_le_bytes(
                        u32::try_from(a).unwrap_or(0).to_le_bytes(),
                    )),
                    Class::Elf64 => a as i64,
                });
            out.push(Relocation {
                file_offset: at,
                size: stride,
                offset,
                kind,
                symbol,
                addend,
            });
        }
        out
    }

    /// A relocation's `r_info` as (symbol, type).
    fn split_info(&self, info: u64) -> (u32, u32) {
        let mips64 = self.header.machine == EM_MIPS && self.header.class == Class::Elf64;
        match self.header.class {
            Class::Elf32 => (
                u32::try_from(info >> 8).unwrap_or(0),
                u32::try_from(info & 0xFF).unwrap_or(0),
            ),
            // MIPS64's r_info: a 32-bit symbol, then a special symbol
            // and three one-byte types, last first, as bytes in
            // memory (so its value depends on the byte order).
            Class::Elf64 if mips64 => {
                let b = match self.header.endian {
                    Endian::Little => info.to_le_bytes(),
                    Endian::Big => info.to_be_bytes(),
                };
                let sym = match self.header.endian {
                    Endian::Little => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
                    Endian::Big => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
                };
                (
                    sym,
                    u32::from(b[7]) | u32::from(b[6]) << 8 | u32::from(b[5]) << 16,
                )
            }
            Class::Elf64 => ((info >> 32) as u32, (info & 0xFFFF_FFFF) as u32),
        }
    }

    /// Android's packed relocations (`SHT_ANDROID_REL`, `SHT_ANDROID_RELA`:
    /// "APS2", then signed LEB128s: the count, the first offset, and groups
    /// of relocations that may share an offset delta, an `r_info`, and an
    /// addend). Their entries have no place of their own in the file: each
    /// has the section's offset and size 0.
    fn android_relocations(&self, s: &Section<'_>) -> Vec<Relocation> {
        const BY_INFO: i64 = 1;
        const BY_OFFSET: i64 = 2;
        const BY_ADDEND: i64 = 4;
        const HAS_ADDEND: i64 = 8;
        let mut out = Vec::new();
        let Some(data) = self.section_data(s).strip_prefix(b"APS2") else {
            return out;
        };
        let mut at = 0usize;
        let mut sleb = || -> Option<i64> {
            let mut v = 0i64;
            let mut shift = 0;
            loop {
                let b = *data.get(at)?;
                at += 1;
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
        };
        let rela = s.kind == SHT_ANDROID_RELA;
        let (Some(count), Some(first)) = (sleb(), sleb()) else {
            return out;
        };
        // (A group can repeat one offset delta and info without reading
        // more: bounded by the section's size too, a few bytes can't ask
        // for millions of relocations.)
        let count = u64::try_from(count)
            .unwrap_or(0)
            .min(MAX_ENTRIES)
            .min((data.len() as u64).saturating_mul(ENTRIES_PER_BYTE) + 4096);
        let mut offset = first as u64;
        let mut addend = 0i64;
        while (out.len() as u64) < count {
            let (Some(size), Some(flags)) = (sleb(), sleb()) else {
                break;
            };
            if size <= 0 {
                break;
            }
            let group_offset = if flags & BY_OFFSET != 0 {
                sleb()
            } else {
                Some(0)
            };
            let group_info = if flags & BY_INFO != 0 {
                sleb()
            } else {
                Some(0)
            };
            let (Some(group_offset), Some(group_info)) = (group_offset, group_info) else {
                break;
            };
            if flags & HAS_ADDEND != 0 && flags & BY_ADDEND != 0 {
                let Some(a) = sleb() else { break };
                addend = addend.wrapping_add(a);
            } else if flags & HAS_ADDEND == 0 {
                addend = 0;
            }
            for _ in 0..size {
                if out.len() as u64 >= count {
                    break;
                }
                let delta = if flags & BY_OFFSET != 0 {
                    Some(group_offset)
                } else {
                    sleb()
                };
                let info = if flags & BY_INFO != 0 {
                    Some(group_info)
                } else {
                    sleb()
                };
                let (Some(delta), Some(info)) = (delta, info) else {
                    return out;
                };
                offset = offset.wrapping_add(delta as u64);
                if flags & HAS_ADDEND != 0 && flags & BY_ADDEND == 0 {
                    let Some(a) = sleb() else { return out };
                    addend = addend.wrapping_add(a);
                }
                let (symbol, kind) = self.split_info(info as u64);
                out.push(Relocation {
                    file_offset: s.offset,
                    size: 0,
                    offset,
                    kind,
                    symbol,
                    addend: rela.then_some(addend),
                });
            }
        }
        out
    }

    /// The addresses a relative relocation section (`SHT_RELR`) patches:
    /// each an address word the loader adds the load bias to. Bounded: at
    /// most 2^24 entries are read.
    pub fn relr(&self, s: &Section<'_>) -> Vec<u64> {
        let mut out = Vec::new();
        if s.kind != SHT_RELR && s.kind != SHT_ANDROID_RELR {
            return out;
        }
        let w: u64 = match self.header.class {
            Class::Elf32 => 4,
            Class::Elf64 => 8,
        };
        let bits = w * 8;
        let count = (s.size / w).min(MAX_ENTRIES);
        let mut base = 0u64;
        for i in 0..count {
            let Some(entry) = self.word_at(s.offset, i * w) else {
                break;
            };
            if entry & 1 == 0 {
                // An address; the next bitmap starts after it.
                out.push(entry);
                base = entry.wrapping_add(w);
            } else {
                // A bitmap of the next (bits - 1) words.
                for bit in 1..bits {
                    if entry >> bit & 1 != 0 {
                        out.push(base.wrapping_add((bit - 1) * w));
                    }
                }
                base = base.wrapping_add((bits - 1) * w);
            }
            if out.len() as u64 > MAX_ENTRIES {
                break;
            }
        }
        out
    }

    /// The dynamic section's entries (`SHT_DYNAMIC`, else `PT_DYNAMIC`),
    /// through the first `DT_NULL`.
    pub fn dynamic(&self) -> Vec<Dynamic> {
        let w: u64 = match self.header.class {
            Class::Elf32 => 4,
            Class::Elf64 => 8,
        };
        let (offset, size) = match self.sections().find(|s| s.kind == SHT_DYNAMIC) {
            Some(s) if s.has_file_data() => (s.offset, s.size),
            _ => match self.segments().find(|p| p.kind == PT_DYNAMIC) {
                Some(p) => (p.offset, p.filesz),
                None => return Vec::new(),
            },
        };
        let mut out = Vec::new();
        let count = (size / (2 * w)).min(MAX_ENTRIES);
        for i in 0..count {
            let (Some(tag), Some(value)) = (
                self.word_at(offset, i * 2 * w),
                self.word_at(offset, i * 2 * w + w),
            ) else {
                break;
            };
            if tag == DT_NULL {
                break;
            }
            out.push(Dynamic { tag, value });
        }
        out
    }

    /// The word at virtual address `addr` (for indirect pointers).
    pub fn word_at_vaddr(&self, addr: u64) -> Option<u64> {
        self.word_at(self.vaddr_to_offset(addr)?, 0)
    }

    /// The FDEs of `.eh_frame` (if `s` is it), with the functions they
    /// describe.
    pub fn eh_frame(&self, s: &Section<'_>) -> Vec<eh_frame::Entry> {
        let deref = |a| self.word_at_vaddr(a);
        eh_frame::fdes(
            self.section_data(s),
            s.addr,
            self.header.class,
            self.header.endian,
            &deref,
        )
    }

    /// The search table entries of `.eh_frame_hdr` (if `s` is it), with
    /// the functions they index.
    pub fn eh_frame_hdr(&self, s: &Section<'_>) -> Vec<eh_frame::Entry> {
        let deref = |a| self.word_at_vaddr(a);
        eh_frame::hdr_entries(
            self.section_data(s),
            s.addr,
            self.header.class,
            self.header.endian,
            &deref,
        )
    }

    /// The file offset of virtual address `addr`, through the `PT_LOAD`
    /// segments.
    pub fn vaddr_to_offset(&self, addr: u64) -> Option<u64> {
        self.segments().find_map(|p| {
            (p.kind == PT_LOAD && addr >= p.vaddr && addr - p.vaddr < p.filesz)
                .then(|| p.offset + (addr - p.vaddr))
        })
    }
}

#[cfg(test)]
mod tests;
