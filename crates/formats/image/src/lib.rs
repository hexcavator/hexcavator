//! A format-independent view of executables and object files.
//!
//! [`Image`] wraps a format-specific reader (PE/COFF, ELF, Mach-O, or
//! WebAssembly) and presents what analyses that are not format-specific
//! need: the architecture, the sections and their file and memory extents,
//! and the identity of the debug information that goes with the file.
//! Format-specific details stay available through the wrapped reader (see
//! [`Image::pe`], [`Image::elf`], [`Image::macho`], [`Image::wasm`]).
//!
//! # Addresses
//!
//! Addresses are `u64`s in the file's own address space, in the form its
//! native tools use: RVAs (relative to the image base) for PE images,
//! virtual addresses for ELF and Mach-O, and offsets into the code
//! section's contents for WebAssembly (as DWARF has them). COFF and ELF
//! objects have no address space: their sections all have address 0.
//! Mach-O objects lay their sections out in one.
//!
//! A universal (fat) Mach-O file holds several images: [`Image::parse`]
//! reads the one `hexcavator_macho::preferred_slice` gives (the host's
//! architecture, unless another was chosen), and its offsets are within
//! that image.

#![no_std]
#![warn(missing_docs)]

extern crate alloc;

mod arch;
mod elf;
mod macho;
mod pe;
mod section;
mod wasm;

use alloc::vec::Vec;

use hexcavator_core::{Error, ErrorKind, Result};
use hexcavator_elf::ElfFile;
use hexcavator_macho::MachO;
use hexcavator_pe::PeFile;
use hexcavator_wasm::Module;

pub use arch::{Arch, Hybrid, coff_machine_name, is_known_coff_machine};
/// A COFF section's characteristics, as [`SectionFlags`].
pub use pe::flags as coff_section_flags;
pub use section::{Section, SectionFlags};

/// The container format of a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Format {
    /// A PE image (`.exe`, `.dll`, `.sys`, ...).
    Pe,
    /// A COFF object (`.obj`).
    Coff,
    /// An ELF file: executable, shared object, relocatable object, or core
    /// dump.
    Elf,
    /// A (thin) Mach-O file.
    MachO,
    /// A WebAssembly module.
    Wasm,
}

/// Whether a file is linked, or an input to linking.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Kind {
    /// A linked executable or shared library, with an address space.
    Linked,
    /// A relocatable object.
    Object,
    /// A process's memory, dumped (an ELF or Mach-O core file).
    Dump,
    /// Debug information only, its image's sections described but empty
    /// (a dSYM's DWARF file).
    Debug,
}

/// What identifies the debug information that matches a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DebugId<'data> {
    /// A PDB 7.0 file (CodeView `RSDS` record): its GUID and age, and the
    /// path the linker wrote it to.
    Pdb {
        /// The PDB's GUID.
        guid: [u8; 16],
        /// Its age (how many times it has been written).
        age: u32,
        /// The path the linker wrote it to.
        path: &'data [u8],
    },
    /// A PDB 2.0 file (CodeView `NB10` record): its signature (a time
    /// stamp) and age, and the path the linker wrote it to.
    Pdb20 {
        /// Its signature (a time stamp).
        signature: u32,
        /// Its age.
        age: u32,
        /// The path the linker wrote it to.
        path: &'data [u8],
    },
    /// A build ID (ELF's `NT_GNU_BUILD_ID` note, a WebAssembly `build_id`
    /// section), which the separate debug file has too; debuginfod and
    /// `.build-id/xx/yyyy.debug` directories find files by it.
    BuildId(&'data [u8]),
    /// A Mach-O image's `LC_UUID`, which its dSYM has too.
    Uuid([u8; 16]),
    /// The name of a separate debug file (ELF's `.gnu_debuglink`, with the
    /// file's CRC-32; WebAssembly's `external_debug_info`, without).
    DebugLink {
        /// The file's name (or path, for WebAssembly).
        path: &'data [u8],
        /// The CRC-32 of its contents.
        crc: Option<u32>,
    },
    /// A supplementary debug file shared by several (`dwz`'s
    /// `.gnu_debugaltlink`): its path and build ID.
    AltLink {
        /// The supplementary file's path.
        path: &'data [u8],
        /// Its build ID.
        build_id: &'data [u8],
    },
}

/// A word the loader writes an address into (a pointer the image holds):
/// where it is, how wide, and the address it holds, if the image says
/// (its address convention's: an RVA for PE). An address taken from
/// another module (an import's) isn't known.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PointerSlot {
    /// Where the slot is.
    pub addr: u64,
    /// Its width in bytes.
    pub width: u8,
    /// The address it holds, if known.
    pub target: Option<u64>,
}

/// An executable or object file, of any supported format.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Image<'data> {
    /// A PE image or COFF object.
    Pe(PeFile<'data>),
    /// An ELF file.
    Elf(ElfFile<'data>),
    /// A (thin) Mach-O file.
    MachO(MachO<'data>),
    /// A WebAssembly module.
    Wasm(Module<'data>),
}

impl<'data> Image<'data> {
    /// Parses `data`, detecting its format.
    pub fn parse(data: &'data [u8]) -> Result<Self> {
        if data.starts_with(b"MZ") {
            return PeFile::parse_image(data).map(Image::Pe);
        }
        if ElfFile::is_elf(data) {
            return ElfFile::parse(data).map(Image::Elf);
        }
        if hexcavator_macho::is_macho(data) {
            return MachO::parse(data).map(Image::MachO);
        }
        if hexcavator_macho::is_fat(data) {
            // One of its images: the one chosen (see
            // `hexcavator_macho::preferred_slice`).
            let Some((_, slice)) = hexcavator_macho::preferred_slice(data) else {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    0,
                    "a universal file without the architecture asked for",
                ));
            };
            return MachO::parse(slice).map(Image::MachO);
        }
        if hexcavator_wasm::is_wasm(data) {
            return Module::parse(data).map(Image::Wasm);
        }
        // A COFF object has no magic number, only a machine type. Accept
        // only machine types we know, so that arbitrary data is not taken
        // for an object.
        match data.get(..2) {
            Some(&[lo, hi]) if arch::is_known_coff_machine(u16::from_le_bytes([lo, hi])) => {
                PeFile::parse_object(data).map(Image::Pe)
            }
            Some(_) => Err(Error::new(ErrorKind::BadMagic, 0, "file format")),
            None => Err(Error::new(ErrorKind::Truncated, 0, "file format")),
        }
    }

    /// The underlying PE/COFF reader, if this is a PE image or COFF object.
    pub fn pe(&self) -> Option<&PeFile<'data>> {
        match self {
            Image::Pe(pe) => Some(pe),
            _ => None,
        }
    }

    /// The underlying ELF reader, if this is an ELF file.
    pub fn elf(&self) -> Option<&ElfFile<'data>> {
        match self {
            Image::Elf(elf) => Some(elf),
            _ => None,
        }
    }

    /// The underlying Mach-O reader, if this is a Mach-O file.
    pub fn macho(&self) -> Option<&MachO<'data>> {
        match self {
            Image::MachO(m) => Some(m),
            _ => None,
        }
    }

    /// The underlying WebAssembly reader, if this is a module.
    pub fn wasm(&self) -> Option<&Module<'data>> {
        match self {
            Image::Wasm(m) => Some(m),
            _ => None,
        }
    }

    /// The file's bytes.
    pub fn data(&self) -> &'data [u8] {
        match self {
            Image::Pe(pe) => pe.data(),
            Image::Elf(elf) => elf.data(),
            Image::MachO(m) => m.data(),
            Image::Wasm(m) => m.data(),
        }
    }

    /// Its container format.
    pub fn format(&self) -> Format {
        match self {
            Image::Pe(pe) => pe::format(pe),
            Image::Elf(_) => Format::Elf,
            Image::MachO(_) => Format::MachO,
            Image::Wasm(_) => Format::Wasm,
        }
    }

    /// Whether it is linked, an object, a dump, or debug information only.
    pub fn kind(&self) -> Kind {
        match self {
            Image::Pe(pe) => match pe.kind() {
                hexcavator_pe::FileKind::Image => Kind::Linked,
                hexcavator_pe::FileKind::Object => Kind::Object,
            },
            Image::Elf(elf) => elf::kind(elf),
            Image::MachO(m) => macho::kind(m),
            Image::Wasm(m) => wasm::kind(m),
        }
    }

    /// The byte order of its data.
    pub fn endian(&self) -> hexcavator_core::Endian {
        match self {
            Image::Elf(elf) => elf.endian(),
            Image::MachO(m) => m.endian(),
            Image::Pe(_) | Image::Wasm(_) => hexcavator_core::Endian::Little,
        }
    }

    /// The instruction set of its code (for a hybrid image, of its native
    /// code: see [`Image::hybrid`]).
    pub fn arch(&self) -> Arch {
        match self {
            Image::Pe(pe) => hexcavator_pe::consts::machine::arch(pe.machine()),
            Image::Elf(elf) => hexcavator_elf::arch(elf.header().machine, elf.class()),
            Image::MachO(m) => hexcavator_macho::arch(m.header().cputype),
            Image::Wasm(m) if m.is_memory64() => Arch::Wasm64,
            Image::Wasm(_) => Arch::Wasm32,
        }
    }

    /// How the image mixes code of several architectures, if it does.
    pub fn hybrid(&self) -> Option<Hybrid> {
        match self {
            Image::Pe(pe) => Hybrid::from_coff_machine(pe.machine()),
            _ => None,
        }
    }

    /// What addresses in this API are relative to: for PE images, the
    /// address the image prefers to be loaded at (its addresses are RVAs);
    /// 0 for everything else (their addresses are already virtual), and for
    /// objects. Add it to an address for the address the format's own
    /// tools show.
    pub fn image_base(&self) -> u64 {
        match self {
            Image::Pe(pe) => pe.optional_header().map_or(0, |h| h.image_base().get()),
            _ => 0,
        }
    }

    /// The sections, in file order.
    pub fn sections(&self) -> Vec<Section<'data>> {
        match self {
            Image::Pe(pe) => pe::sections(pe),
            Image::Elf(elf) => elf::sections(elf),
            Image::MachO(m) => macho::sections(m),
            Image::Wasm(m) => wasm::sections(m),
        }
    }

    /// The alignment of sections in memory, for linked images.
    pub fn section_alignment(&self) -> Option<u64> {
        match self {
            Image::Pe(pe) => pe
                .optional_header()
                .map(|h| u64::from(h.section_alignment())),
            _ => None,
        }
    }

    /// The alignment of section data in the file, for linked images.
    pub fn file_alignment(&self) -> Option<u64> {
        match self {
            Image::Pe(pe) => pe.optional_header().map(|h| u64::from(h.file_alignment())),
            _ => None,
        }
    }

    /// The identities of the debug information files for this image, in the
    /// order the image lists them.
    pub fn debug_ids(&self) -> Vec<DebugId<'data>> {
        match self {
            Image::Pe(pe) => pe::debug_ids(pe),
            Image::Elf(elf) => elf::debug_ids(elf),
            Image::MachO(m) => macho::debug_ids(m),
            Image::Wasm(m) => wasm::debug_ids(m),
        }
    }

    /// The words the loader writes addresses into, by address: PE's base
    /// relocations; ELF's dynamic relocations that write an address
    /// (relative, absolute, GOT and PLT entries, indirect functions) and
    /// its packed relative relocations (RELR); Mach-O's rebases and binds
    /// (chained fixups, or the older opcodes). Objects have none: their
    /// relocations are the linker's.
    pub fn pointer_slots(&self) -> Vec<PointerSlot> {
        let mut out = match self {
            Image::Pe(pe) => pe::pointer_slots(pe),
            Image::Elf(elf) => elf::pointer_slots(elf),
            Image::MachO(m) => macho::pointer_slots(m),
            Image::Wasm(_) => Vec::new(),
        };
        out.sort_unstable_by_key(|s| s.addr);
        out.dedup_by_key(|s| s.addr);
        out
    }

    /// `len` bytes of file data at `addr`. They must all be present in the
    /// file, in one section: memory-only (zero-fill) bytes have no file
    /// data, and objects have no addresses.
    pub fn bytes_at(&self, addr: u64, len: u64) -> Option<&'data [u8]> {
        match self {
            Image::Pe(pe) => pe::bytes_at(pe, addr, len),
            Image::Elf(elf) => elf::bytes_at(elf, addr, len),
            Image::MachO(m) => macho::bytes_at(m, addr, len),
            Image::Wasm(m) => wasm::bytes_at(m, addr, len),
        }
    }
}
