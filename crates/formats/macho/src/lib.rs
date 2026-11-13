//! Mach-O files: executables, dylibs, bundles, and objects, 32- and
//! 64-bit, either byte order, and universal ("fat") files holding several.
//!
//! [`MachO`] is a borrowed view of one image: its header, its load
//! commands ([`MachO::load_commands`]), segments and their sections, the
//! symbol table, and the link-edit tables the load commands locate
//! (dyld rebase/bind/export info, chained fixups, function starts, code
//! signature, ...). [`fat_archs`] lists a universal file's images.
//! Everything is bounds-checked: damage gives errors or fewer entries,
//! never a panic.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use hexcavator_core::{Endian, Error, ErrorKind, Result};

pub mod consts;
pub mod debugmap;
pub mod fixups;
pub mod info;
pub mod objc;
pub mod unwind_info;

pub use fixups::{Export, Fixup, FixupKind};

use consts::*;

fn read(data: &[u8], at: u64, n: usize, endian: Endian) -> Option<u64> {
    let start = usize::try_from(at).ok()?;
    let b = data.get(start..start.checked_add(n)?)?;
    let mut v = 0u64;
    match endian {
        Endian::Little => {
            for &x in b.iter().rev() {
                v = (v << 8) | u64::from(x);
            }
        }
        Endian::Big => {
            for &x in b {
                v = (v << 8) | u64::from(x);
            }
        }
    }
    Some(v)
}

fn u32_at(data: &[u8], at: u64, endian: Endian) -> Option<u32> {
    read(data, at, 4, endian).and_then(|v| u32::try_from(v).ok())
}

/// A fixed-size name field (`segname`, `sectname`), without its padding.
fn name16(b: &[u8]) -> &[u8] {
    let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    &b[..n]
}

/// One image of a universal file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FatArch {
    pub cputype: u32,
    pub cpusubtype: u32,
    pub offset: u64,
    pub size: u64,
    pub align: u32,
}

/// Whether `data` is a universal file.
pub fn is_fat(data: &[u8]) -> bool {
    matches!(u32_at(data, 0, Endian::Big), Some(FAT_MAGIC | FAT_MAGIC_64))
        // Java class files share the magic; they have a version, not an
        // architecture count, in the next word (45 and up; universal files
        // hold a few architectures).
        && u32_at(data, 4, Endian::Big).is_some_and(|n| n <= 20)
}

/// The images of a universal file (`None` if it isn't one). The headers
/// are big-endian whatever the images are.
pub fn fat_archs(data: &[u8]) -> Option<Vec<FatArch>> {
    if !is_fat(data) {
        return None;
    }
    let wide = u32_at(data, 0, Endian::Big)? == FAT_MAGIC_64;
    let n = u32_at(data, 4, Endian::Big)?;
    let entry: u64 = if wide { 32 } else { 20 };
    let mut out = Vec::new();
    for i in 0..u64::from(n) {
        let at = 8 + i * entry;
        let be = |o: u64, w: usize| read(data, at + o, w, Endian::Big);
        let be32 = |o: u64| be(o, 4).and_then(|v| u32::try_from(v).ok());
        let one = || -> Option<FatArch> {
            Some(if wide {
                FatArch {
                    cputype: be32(0)?,
                    cpusubtype: be32(4)?,
                    offset: be(8, 8)?,
                    size: be(16, 8)?,
                    align: be32(24)?,
                }
            } else {
                FatArch {
                    cputype: be32(0)?,
                    cpusubtype: be32(4)?,
                    offset: be(8, 4)?,
                    size: be(12, 4)?,
                    align: be32(16)?,
                }
            })
        };
        // A truncated table gives the archs before the damage.
        let Some(a) = one() else { break };
        out.push(a);
    }
    Some(out)
}

/// The architectures [`arch_name`] names, for choosing one by name.
const NAMED: &[(u32, u32)] = &[
    (CPU_TYPE_X86_64, 3),
    (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_H),
    (CPU_TYPE_ARM64, 0),
    (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E),
    (CPU_TYPE_ARM64_32, 1),
    (CPU_TYPE_X86, 3),
    (CPU_TYPE_ARM, 6),
    (CPU_TYPE_ARM, 9),
    (CPU_TYPE_ARM, 10),
    (CPU_TYPE_ARM, 11),
    (CPU_TYPE_ARM, 12),
    (CPU_TYPE_ARM, 13),
    (CPU_TYPE_POWERPC, 0),
    (CPU_TYPE_POWERPC64, 0),
];

/// The architecture to use from universal files (see [`set_preferred_arch`]):
/// a CPU type and subtype, or 0 for the host's.
static PREFERRED_CPU: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static PREFERRED_SUB: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Chooses the image of universal files that [`preferred_slice`] gives,
/// by its name (`arm64`, `x86_64`, as [`arch_name`] names them; `None`:
/// the host's architecture, else the first). False if no architecture
/// has that name.
pub fn set_preferred_arch(name: Option<&str>) -> bool {
    use core::sync::atomic::Ordering::Relaxed;
    let Some(name) = name else {
        PREFERRED_CPU.store(0, Relaxed);
        return true;
    };
    match NAMED.iter().find(|&&(c, s)| arch_name(c, s) == name) {
        Some(&(c, s)) => {
            PREFERRED_CPU.store(c, Relaxed);
            PREFERRED_SUB.store(s, Relaxed);
            true
        }
        None => false,
    }
}

/// The choice [`set_preferred_arch`] made, as a number (0: the host's),
/// for keeping what is built from one image apart from another's.
pub fn preferred_arch_key() -> u64 {
    use core::sync::atomic::Ordering::Relaxed;
    u64::from(PREFERRED_CPU.load(Relaxed)) << 32 | u64::from(PREFERRED_SUB.load(Relaxed))
}

/// The names [`set_preferred_arch`] knows.
pub fn arch_names() -> impl Iterator<Item = alloc::string::String> {
    NAMED.iter().map(|&(c, s)| arch_name(c, s))
}

/// The image of the universal file `data` to use: the architecture
/// [`set_preferred_arch`] chose; else the host's (an `arm64` image on an
/// ARM64 host, `x86_64` on x64), else the first. `None` if `data` isn't a
/// universal file or holds no image whose bytes are all there.
pub fn preferred_slice(data: &[u8]) -> Option<(FatArch, &[u8])> {
    use core::sync::atomic::Ordering::Relaxed;
    let archs = fat_archs(data)?;
    let bytes = |a: &FatArch| {
        let start = usize::try_from(a.offset).ok()?;
        let end = start.checked_add(usize::try_from(a.size).ok()?)?;
        data.get(start..end)
    };
    let present: Vec<(FatArch, &[u8])> = archs
        .into_iter()
        .filter_map(|a| Some((a, bytes(&a)?)))
        .collect();
    let named = |c: u32, s: u32| {
        let want = arch_name(c, s);
        present
            .iter()
            .find(|(a, _)| arch_name(a.cputype, a.cpusubtype) == want)
            .copied()
    };
    let cpu = PREFERRED_CPU.load(Relaxed);
    if cpu != 0 {
        return named(cpu, PREFERRED_SUB.load(Relaxed));
    }
    let host = if cfg!(target_arch = "aarch64") {
        Some((CPU_TYPE_ARM64, 0))
    } else if cfg!(target_arch = "x86_64") {
        Some((CPU_TYPE_X86_64, 3))
    } else {
        None
    };
    host.and_then(|(c, s)| named(c, s))
        .or_else(|| present.first().copied())
}

/// The size of a universal file's headers.
pub fn fat_header_size(data: &[u8]) -> u64 {
    let wide = u32_at(data, 0, Endian::Big) == Some(FAT_MAGIC_64);
    8 + u64::from(u32_at(data, 4, Endian::Big).unwrap_or(0)) * if wide { 32 } else { 20 }
}

/// The instruction set of a CPU type.
pub const fn arch(cputype: u32) -> hexcavator_core::Arch {
    use hexcavator_core::Arch;
    match cputype {
        CPU_TYPE_X86 => Arch::X86,
        CPU_TYPE_X86_64 => Arch::X64,
        CPU_TYPE_ARM => Arch::Arm,
        // arm64_32 (watchOS) is A64 code with 32-bit pointers.
        CPU_TYPE_ARM64 | CPU_TYPE_ARM64_32 => Arch::Arm64,
        CPU_TYPE_POWERPC => Arch::PowerPc,
        CPU_TYPE_POWERPC64 => Arch::PowerPc64,
        CPU_TYPE_MC680X0 => Arch::M68k,
        CPU_TYPE_SPARC => Arch::Sparc,
        CPU_TYPE_MIPS => Arch::Mips,
        _ => Arch::Unknown,
    }
}

/// The name Apple's tools give an architecture (`arm64`, `x86_64`, ...).
pub fn arch_name(cputype: u32, cpusubtype: u32) -> alloc::string::String {
    use alloc::string::ToString;
    let sub = cpusubtype & !CPU_SUBTYPE_MASK;
    match cputype {
        CPU_TYPE_X86_64 if sub == CPU_SUBTYPE_X86_64_H => "x86_64h".to_string(),
        CPU_TYPE_X86_64 => "x86_64".to_string(),
        CPU_TYPE_ARM64 if sub == CPU_SUBTYPE_ARM64E => "arm64e".to_string(),
        CPU_TYPE_ARM64 => "arm64".to_string(),
        CPU_TYPE_ARM64_32 => "arm64_32".to_string(),
        CPU_TYPE_X86 => "i386".to_string(),
        CPU_TYPE_ARM => match sub {
            6 => "armv6",
            9 => "armv7",
            10 => "armv7f",
            11 => "armv7s",
            12 => "armv7k",
            13 => "armv8",
            _ => "arm",
        }
        .to_string(),
        CPU_TYPE_POWERPC => "ppc".to_string(),
        CPU_TYPE_POWERPC64 => "ppc64".to_string(),
        _ => alloc::format!("cpu_{cputype}"),
    }
}

/// The Mach header, normalized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub is64: bool,
    pub endian: Endian,
    pub cputype: u32,
    pub cpusubtype: u32,
    /// `MH_EXECUTE`, `MH_DYLIB`, `MH_OBJECT`, ...
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: u32,
    /// The header's own size (28 or 32 bytes).
    pub size: u64,
}

/// A load command: its type and where its bytes lie.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoadCommand<'d> {
    pub index: usize,
    pub cmd: u32,
    pub offset: u64,
    pub size: u32,
    pub data: &'d [u8],
}

/// A section, normalized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Section<'d> {
    /// Its index among all sections (sections are numbered from 1 in
    /// symbols' `n_sect`; this is that number less one).
    pub index: usize,
    pub sectname: &'d [u8],
    pub segname: &'d [u8],
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub align: u32,
    pub reloff: u32,
    pub nreloc: u32,
    pub flags: u32,
    pub reserved1: u32,
    pub reserved2: u32,
    pub reserved3: u32,
}

impl Section<'_> {
    /// `S_REGULAR`, `S_ZEROFILL`, ...
    pub fn kind(&self) -> u32 {
        self.flags & SECTION_TYPE
    }

    /// Whether the section occupies memory only (zero-fill).
    pub fn is_zerofill(&self) -> bool {
        matches!(
            self.kind(),
            S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL
        )
    }

    /// The bytes it occupies in the file.
    pub fn file_size(&self) -> u64 {
        if self.is_zerofill() { 0 } else { self.size }
    }
}

/// A segment (`LC_SEGMENT`/`LC_SEGMENT_64`) and its sections.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment<'d> {
    /// Its load command's index.
    pub command: usize,
    pub name: &'d [u8],
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: u32,
    pub initprot: u32,
    pub flags: u32,
    pub sections: Vec<Section<'d>>,
}

/// `LC_SYMTAB`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Symtab {
    pub symoff: u32,
    pub nsyms: u32,
    pub stroff: u32,
    pub strsize: u32,
}

/// `LC_DYSYMTAB`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Dysymtab {
    pub ilocalsym: u32,
    pub nlocalsym: u32,
    pub iextdefsym: u32,
    pub nextdefsym: u32,
    pub iundefsym: u32,
    pub nundefsym: u32,
    pub tocoff: u32,
    pub ntoc: u32,
    pub modtaboff: u32,
    pub nmodtab: u32,
    pub extrefsymoff: u32,
    pub nextrefsyms: u32,
    pub indirectsymoff: u32,
    pub nindirectsyms: u32,
    pub extreloff: u32,
    pub nextrel: u32,
    pub locreloff: u32,
    pub nlocrel: u32,
}

/// `LC_DYLD_INFO` / `LC_DYLD_INFO_ONLY`: (offset, size) of each table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DyldInfo {
    pub rebase: (u32, u32),
    pub bind: (u32, u32),
    pub weak_bind: (u32, u32),
    pub lazy_bind: (u32, u32),
    pub export: (u32, u32),
}

/// A symbol table entry, normalized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nlist<'d> {
    pub index: usize,
    pub name: &'d [u8],
    pub strx: u32,
    pub n_type: u8,
    pub n_sect: u8,
    pub n_desc: u16,
    pub n_value: u64,
}

impl Nlist<'_> {
    /// A debugger (STABS) entry.
    pub fn is_stab(&self) -> bool {
        self.n_type & N_STAB != 0
    }

    /// Defined in a section.
    pub fn is_section_defined(&self) -> bool {
        !self.is_stab() && self.n_type & N_TYPE == N_SECT
    }
}

/// One Mach-O image.
#[derive(Clone, Copy, Debug)]
pub struct MachO<'d> {
    data: &'d [u8],
    header: Header,
}

/// Whether `data` starts with a (thin) Mach-O magic, of either byte order.
pub fn is_macho(data: &[u8]) -> bool {
    matches!(
        u32_at(data, 0, Endian::Little),
        Some(MH_MAGIC | MH_MAGIC_64 | MH_CIGAM | MH_CIGAM_64)
    )
}

impl<'d> MachO<'d> {
    pub fn parse(data: &'d [u8]) -> Result<Self> {
        let magic = u32_at(data, 0, Endian::Little).ok_or(Error::new(
            ErrorKind::Truncated,
            0,
            "Mach-O magic",
        ))?;
        let (is64, endian) = match magic {
            MH_MAGIC => (false, Endian::Little),
            MH_MAGIC_64 => (true, Endian::Little),
            MH_CIGAM => (false, Endian::Big),
            MH_CIGAM_64 => (true, Endian::Big),
            _ => return Err(Error::new(ErrorKind::BadMagic, 0, "Mach-O magic")),
        };
        let truncated = Error::new(ErrorKind::Truncated, 0, "Mach-O header");
        let f = |o: u64| u32_at(data, o, endian).ok_or(truncated);
        let size = if is64 { 32 } else { 28 };
        if (data.len() as u64) < size {
            return Err(truncated);
        }
        let header = Header {
            is64,
            endian,
            cputype: f(4)?,
            cpusubtype: f(8)?,
            filetype: f(12)?,
            ncmds: f(16)?,
            sizeofcmds: f(20)?,
            flags: f(24)?,
            size,
        };
        Ok(Self { data, header })
    }

    pub fn data(&self) -> &'d [u8] {
        self.data
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn endian(&self) -> Endian {
        self.header.endian
    }

    pub fn is_object(&self) -> bool {
        self.header.filetype == MH_OBJECT
    }

    fn u32(&self, at: u64) -> Option<u32> {
        u32_at(self.data, at, self.header.endian)
    }

    fn word(&self, at: u64) -> Option<u64> {
        read(
            self.data,
            at,
            if self.header.is64 { 8 } else { 4 },
            self.header.endian,
        )
    }

    /// The load commands, in order. Iteration stops at a command whose
    /// size is too small or runs past the command area or file.
    pub fn load_commands(&self) -> Vec<LoadCommand<'d>> {
        let mut out = Vec::new();
        let mut at = self.header.size;
        let end =
            (self.header.size + u64::from(self.header.sizeofcmds)).min(self.data.len() as u64);
        for index in 0..self.header.ncmds as usize {
            let (Some(cmd), Some(size)) = (self.u32(at), self.u32(at + 4)) else {
                break;
            };
            if size < 8 || at + u64::from(size) > end {
                break;
            }
            let Ok(start) = usize::try_from(at) else {
                break;
            };
            out.push(LoadCommand {
                index,
                cmd,
                offset: at,
                size,
                data: &self.data[start..start + size as usize],
            });
            at += u64::from(size);
        }
        out
    }

    /// The segments and their sections, in load-command order.
    pub fn segments(&self) -> Vec<Segment<'d>> {
        let mut out = Vec::new();
        let mut section_index = 0;
        for lc in self.load_commands() {
            let wide = match lc.cmd {
                LC_SEGMENT_64 => true,
                LC_SEGMENT => false,
                _ => continue,
            };
            let Some(s) = self.segment(&lc, wide, &mut section_index) else {
                continue;
            };
            out.push(s);
        }
        out
    }

    fn segment(
        &self,
        lc: &LoadCommand<'d>,
        wide: bool,
        section_index: &mut usize,
    ) -> Option<Segment<'d>> {
        let at = lc.offset;
        let w: u64 = if wide { 8 } else { 4 };
        let wn = if wide { 8 } else { 4 };
        let word = |o: u64| read(self.data, at + o, wn, self.header.endian);
        let name = name16(lc.data.get(8..24)?);
        let vmaddr = word(24)?;
        let vmsize = word(24 + w)?;
        let fileoff = word(24 + 2 * w)?;
        let filesize = word(24 + 3 * w)?;
        let p = 24 + 4 * w;
        let (maxprot, initprot, nsects, flags) = (
            self.u32(at + p)?,
            self.u32(at + p + 4)?,
            self.u32(at + p + 8)?,
            self.u32(at + p + 12)?,
        );
        let first = p + 16;
        let entry = if wide { 80 } else { 68 };
        let fits = (u64::from(lc.size).saturating_sub(first)) / entry;
        let mut sections = Vec::new();
        for i in 0..u64::from(nsects).min(fits) {
            let s = at + first + i * entry;
            let b = self
                .data
                .get(usize::try_from(s).ok()?..usize::try_from(s + entry).ok()?)?;
            let sw = |o: u64| read(self.data, s + o, wn, self.header.endian);
            let rest = 32 + 2 * w;
            let f = |k: u64| self.u32(s + rest + 4 * k);
            sections.push(Section {
                index: *section_index,
                sectname: name16(&b[0..16]),
                segname: name16(&b[16..32]),
                addr: sw(32)?,
                size: sw(32 + w)?,
                offset: f(0)?,
                align: f(1)?,
                reloff: f(2)?,
                nreloc: f(3)?,
                flags: f(4)?,
                reserved1: f(5)?,
                reserved2: f(6)?,
                reserved3: if wide { f(7)? } else { 0 },
            });
            *section_index += 1;
        }
        Some(Segment {
            command: lc.index,
            name,
            vmaddr,
            vmsize,
            fileoff,
            filesize,
            maxprot,
            initprot,
            flags,
            sections,
        })
    }

    /// Every section, numbered as symbols' `n_sect` counts (less one).
    pub fn sections(&self) -> Vec<Section<'d>> {
        self.segments()
            .into_iter()
            .flat_map(|s| s.sections)
            .collect()
    }

    fn command(&self, cmd: u32) -> Option<LoadCommand<'d>> {
        self.load_commands().into_iter().find(|c| c.cmd == cmd)
    }

    fn fields<const N: usize>(&self, lc: &LoadCommand<'_>) -> Option<[u32; N]> {
        let mut out = [0u32; N];
        for (i, v) in out.iter_mut().enumerate() {
            if 8 + 4 * (i as u64 + 1) > u64::from(lc.size) {
                return None;
            }
            *v = self.u32(lc.offset + 8 + 4 * i as u64)?;
        }
        Some(out)
    }

    pub fn symtab(&self) -> Option<Symtab> {
        let [symoff, nsyms, stroff, strsize] = self.fields(&self.command(LC_SYMTAB)?)?;
        Some(Symtab {
            symoff,
            nsyms,
            stroff,
            strsize,
        })
    }

    pub fn dysymtab(&self) -> Option<Dysymtab> {
        let f: [u32; 18] = self.fields(&self.command(LC_DYSYMTAB)?)?;
        Some(Dysymtab {
            ilocalsym: f[0],
            nlocalsym: f[1],
            iextdefsym: f[2],
            nextdefsym: f[3],
            iundefsym: f[4],
            nundefsym: f[5],
            tocoff: f[6],
            ntoc: f[7],
            modtaboff: f[8],
            nmodtab: f[9],
            extrefsymoff: f[10],
            nextrefsyms: f[11],
            indirectsymoff: f[12],
            nindirectsyms: f[13],
            extreloff: f[14],
            nextrel: f[15],
            locreloff: f[16],
            nlocrel: f[17],
        })
    }

    /// The dyld info tables of a load command (`LC_DYLD_INFO`/`_ONLY`).
    pub fn dyld_info(&self, lc: &LoadCommand<'_>) -> Option<DyldInfo> {
        let f: [u32; 10] = self.fields(lc)?;
        Some(DyldInfo {
            rebase: (f[0], f[1]),
            bind: (f[2], f[3]),
            weak_bind: (f[4], f[5]),
            lazy_bind: (f[6], f[7]),
            export: (f[8], f[9]),
        })
    }

    /// A `linkedit_data_command`'s (offset, size).
    pub fn linkedit_data(&self, lc: &LoadCommand<'_>) -> Option<(u32, u32)> {
        let [off, size] = self.fields(lc)?;
        Some((off, size))
    }

    /// `LC_UUID`.
    pub fn uuid(&self) -> Option<[u8; 16]> {
        let lc = self.command(LC_UUID)?;
        lc.data.get(8..24)?.try_into().ok()
    }

    /// The size of one symbol table entry.
    pub fn nlist_size(&self) -> u64 {
        if self.header.is64 { 16 } else { 12 }
    }

    /// The symbol table's entries, names resolved through the string
    /// table (names past it are empty).
    pub fn symbols(&self) -> Vec<Nlist<'d>> {
        let mut out = Vec::new();
        let Some(st) = self.symtab() else {
            return out;
        };
        let n = self.nlist_size();
        let strtab = {
            let s = (st.stroff as usize).min(self.data.len());
            let e = s.saturating_add(st.strsize as usize).min(self.data.len());
            &self.data[s..e]
        };
        for i in 0..u64::from(st.nsyms) {
            let at = u64::from(st.symoff) + i * n;
            let (Some(strx), Some(b), Some(desc), Some(value)) = (
                self.u32(at),
                usize::try_from(at)
                    .ok()
                    .and_then(|a| self.data.get(a + 4..a + 6)),
                read(self.data, at + 6, 2, self.header.endian),
                self.word(at + 8),
            ) else {
                break;
            };
            let name = strtab.get(strx as usize..).map_or(&[][..], |r| {
                &r[..r.iter().position(|&c| c == 0).unwrap_or(r.len())]
            });
            out.push(Nlist {
                index: out.len(),
                name,
                strx,
                n_type: b[0],
                n_sect: b[1],
                n_desc: u16::try_from(desc).unwrap_or(0),
                n_value: value,
            });
        }
        out
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unwind_info_tests;
