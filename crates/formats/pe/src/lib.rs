//! PE/COFF images (`.exe`, `.dll`, `.sys`, `.efi`, ...) and COFF objects
//! (`.obj`).
//!
//! [`PeFile`] is a borrowed view over the file's bytes. Parsing it reads only
//! the fixed headers and the section table; everything else is located on
//! demand.

#![no_std]

extern crate alloc;

pub mod consts;
mod debug;
pub mod eh;
pub mod eh4;
pub mod exception;
pub mod exports;
pub mod extras;
mod file;
pub mod import_object;
pub mod imports;
pub mod load_config;
pub mod raw;
pub mod reloc;
pub mod resources;
mod symbols;
#[cfg(test)]
mod testutil;
pub mod tls;
pub mod version;

pub use debug::{CodeView, CoffGroup, DebugEntry, Pogo};
pub use file::{FileKind, OptionalHeader, PeFile};
pub use load_config::{
    CodeKind, CodeRange, EnclaveConfig, EnclaveImport, GuardEntry, GuardTable, HybridMetadata,
    LoadConfig, VolatileMetadata,
};
pub use symbols::{CoffSymbol, SectionDefinition, StringTable, SymbolTable, comdat_select};
