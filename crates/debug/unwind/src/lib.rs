//! Virtual stack unwinders.
//!
//! Each unwinder takes one frame's registers, the stack memory they point
//! into, and the unwind data of the image the frame's code is in, and
//! recovers the caller's registers, the way the target's own unwinder
//! would. They never execute anything: memory and image bytes come through
//! [`Memory`] and [`Image`], which can be backed by a dump, a file on disk,
//! or a live process.
//!
//! The interfaces here are deliberately small and provisional; the
//! debugger's frame model will be designed separately and built on them.
//!
//! - [`windows_x64`]: Windows x64 (`.pdata` / `UNWIND_INFO`), matching
//!   `RtlVirtualUnwind`.
//! - [`windows_x86`]: Windows x86, from PDB frame data (FrameData programs, FPO
//!   records) or the EBP chain, matching dbghelp's `StackWalk64`.
//! - [`windows_arm64`]: Windows ARM64 (`.pdata` packed unwind data / `.xdata`).
//! - [`windows_arm32`]: Windows ARM (Thumb-2; `.pdata` packed unwind data /
//!   `.xdata`).
//! - [`dwarf_cfi`]: DWARF call frame information (`.eh_frame`,
//!   `.debug_frame`), for any architecture.
//! - [`apple_compact`]: Darwin compact unwind encodings (`__unwind_info`), x86-64
//!   and ARM64.
//! - [`arm_ehabi`]: ARM EHABI (`.ARM.exidx`, `.ARM.extab`).

#![no_std]

extern crate alloc;

pub mod apple_compact;
pub mod arm_ehabi;
pub mod dwarf_cfi;
pub mod windows_arm32;
pub mod windows_arm64;
pub mod windows_x64;
pub mod windows_x86;

/// Memory the unwinder reads (the stack, and anything a frame's registers
/// point at).
pub trait Memory {
    /// Fills `buf` from `address`; false if any of it is unavailable.
    fn read(&self, address: u64, buf: &mut [u8]) -> bool;
}

/// An image's bytes, by RVA, as they are when it is loaded (code, unwind
/// data).
pub trait Image {
    /// `len` bytes at `rva`, or None if any of them is not in the image.
    fn bytes(&self, rva: u32, len: u32) -> Option<&[u8]>;
}

impl Image for hexcavator_pe::PeFile<'_> {
    fn bytes(&self, rva: u32, len: u32) -> Option<&[u8]> {
        self.bytes_at_rva(hexcavator_core::Rva(rva), len).ok()
    }
}

/// An image whose bytes are already laid out by RVA (mapped).
impl Image for [u8] {
    fn bytes(&self, rva: u32, len: u32) -> Option<&[u8]> {
        let start = usize::try_from(rva).ok()?;
        let end = start.checked_add(usize::try_from(len).ok()?)?;
        self.get(start..end)
    }
}

/// Why a frame could not be unwound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Memory the unwind needed is unavailable.
    Memory { address: u64 },
    /// The unwind data at this RVA is missing or malformed.
    UnwindData { rva: u32 },
    /// Chained unwind entries nest too deeply (or loop).
    ChainTooDeep,
    /// The unwind data at this RVA uses something not supported (such as
    /// SVE, whose frames depend on the vector length).
    Unsupported { rva: u32 },
    /// A register the unwind needs is unknown (by the unwinder's numbering).
    Register { register: u16 },
    /// A DWARF expression in the unwind data can't be evaluated.
    Expression,
    /// A compact unwind encoding is invalid.
    Encoding { encoding: u32 },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Error::Memory { address } => write!(f, "memory at {address:#x} is unavailable"),
            Error::UnwindData { rva } => write!(f, "bad unwind data at RVA {rva:#x}"),
            Error::ChainTooDeep => f.write_str("chained unwind entries nest too deeply"),
            Error::Unsupported { rva } => write!(f, "unsupported unwind data at RVA {rva:#x}"),
            Error::Register { register } => write!(f, "register {register} is unknown"),
            Error::Expression => f.write_str("an unwind expression can't be evaluated"),
            Error::Encoding { encoding } => {
                write!(f, "invalid compact unwind encoding {encoding:#010x}")
            }
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;

fn read_u64(memory: &dyn Memory, address: u64) -> Result<u64> {
    let mut b = [0u8; 8];
    if memory.read(address, &mut b) {
        Ok(u64::from_le_bytes(b))
    } else {
        Err(Error::Memory { address })
    }
}

fn read_u128(memory: &dyn Memory, address: u64) -> Result<u128> {
    let mut b = [0u8; 16];
    if memory.read(address, &mut b) {
        Ok(u128::from_le_bytes(b))
    } else {
        Err(Error::Memory { address })
    }
}
