//! Mach-O constants (`<mach-o/loader.h>`'s and `<mach/machine.h>`'s names).

pub const MH_MAGIC: u32 = 0xFEED_FACE;
pub const MH_CIGAM: u32 = 0xCEFA_EDFE;
pub const MH_MAGIC_64: u32 = 0xFEED_FACF;
pub const MH_CIGAM_64: u32 = 0xCFFA_EDFE;
pub const FAT_MAGIC: u32 = 0xCAFE_BABE;
pub const FAT_MAGIC_64: u32 = 0xCAFE_BABF;

// File types.
pub const MH_OBJECT: u32 = 0x1;
pub const MH_EXECUTE: u32 = 0x2;
pub const MH_FVMLIB: u32 = 0x3;
pub const MH_CORE: u32 = 0x4;
pub const MH_PRELOAD: u32 = 0x5;
pub const MH_DYLIB: u32 = 0x6;
pub const MH_DYLINKER: u32 = 0x7;
pub const MH_BUNDLE: u32 = 0x8;
pub const MH_DYLIB_STUB: u32 = 0x9;
pub const MH_DSYM: u32 = 0xA;
pub const MH_KEXT_BUNDLE: u32 = 0xB;
pub const MH_FILESET: u32 = 0xC;
pub const MH_GPU_EXECUTE: u32 = 0xD;
pub const MH_GPU_DYLIB: u32 = 0xE;

// Header flags (those hardening reads).
pub const MH_NOUNDEFS: u32 = 0x1;
pub const MH_DYLDLINK: u32 = 0x4;
pub const MH_TWOLEVEL: u32 = 0x80;
pub const MH_ALLOW_STACK_EXECUTION: u32 = 0x2_0000;
pub const MH_PIE: u32 = 0x20_0000;
pub const MH_HAS_TLV_DESCRIPTORS: u32 = 0x80_0000;
pub const MH_NO_HEAP_EXECUTION: u32 = 0x100_0000;
pub const MH_APP_EXTENSION_SAFE: u32 = 0x200_0000;

// CPU types.
pub const CPU_ARCH_MASK: u32 = 0xFF00_0000;
pub const CPU_ARCH_ABI64: u32 = 0x0100_0000;
pub const CPU_ARCH_ABI64_32: u32 = 0x0200_0000;
pub const CPU_TYPE_VAX: u32 = 1;
pub const CPU_TYPE_ROMP: u32 = 2;
pub const CPU_TYPE_NS32032: u32 = 4;
pub const CPU_TYPE_NS32332: u32 = 5;
pub const CPU_TYPE_MC680X0: u32 = 6;
pub const CPU_TYPE_X86: u32 = 7;
pub const CPU_TYPE_X86_64: u32 = CPU_TYPE_X86 | CPU_ARCH_ABI64;
pub const CPU_TYPE_MIPS: u32 = 8;
pub const CPU_TYPE_NS32352: u32 = 9;
pub const CPU_TYPE_MC98000: u32 = 10;
pub const CPU_TYPE_HPPA: u32 = 11;
pub const CPU_TYPE_ARM: u32 = 12;
pub const CPU_TYPE_ARM64: u32 = CPU_TYPE_ARM | CPU_ARCH_ABI64;
pub const CPU_TYPE_ARM64_32: u32 = CPU_TYPE_ARM | CPU_ARCH_ABI64_32;
pub const CPU_TYPE_MC88000: u32 = 13;
pub const CPU_TYPE_SPARC: u32 = 14;
pub const CPU_TYPE_I860: u32 = 15;
pub const CPU_TYPE_I860_LITTLE: u32 = 16;
pub const CPU_TYPE_RS6000: u32 = 17;
pub const CPU_TYPE_POWERPC: u32 = 18;
pub const CPU_TYPE_POWERPC64: u32 = CPU_TYPE_POWERPC | CPU_ARCH_ABI64;
/// The capability bits of a CPU subtype.
pub const CPU_SUBTYPE_MASK: u32 = 0xFF00_0000;
/// The pointer authentication ABI's version, in an arm64e subtype.
pub const CPU_SUBTYPE_PTRAUTH_ABI: u32 = 0x8000_0000;
pub const CPU_SUBTYPE_X86_ALL: u32 = 3;
pub const CPU_SUBTYPE_X86_64_H: u32 = 8;
pub const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
pub const CPU_SUBTYPE_ARM64_V8: u32 = 1;
pub const CPU_SUBTYPE_ARM64E: u32 = 2;

// Load commands.
/// Set in the commands dyld must understand to load the image.
pub const LC_REQ_DYLD: u32 = 0x8000_0000;
pub const LC_SEGMENT: u32 = 0x1;
pub const LC_SYMTAB: u32 = 0x2;
pub const LC_SYMSEG: u32 = 0x3;
pub const LC_THREAD: u32 = 0x4;
pub const LC_UNIXTHREAD: u32 = 0x5;
pub const LC_LOADFVMLIB: u32 = 0x6;
pub const LC_IDFVMLIB: u32 = 0x7;
pub const LC_IDENT: u32 = 0x8;
pub const LC_FVMFILE: u32 = 0x9;
pub const LC_PREPAGE: u32 = 0xA;
pub const LC_DYSYMTAB: u32 = 0xB;
pub const LC_LOAD_DYLIB: u32 = 0xC;
pub const LC_ID_DYLIB: u32 = 0xD;
pub const LC_LOAD_DYLINKER: u32 = 0xE;
pub const LC_ID_DYLINKER: u32 = 0xF;
pub const LC_PREBOUND_DYLIB: u32 = 0x10;
pub const LC_ROUTINES: u32 = 0x11;
pub const LC_SUB_FRAMEWORK: u32 = 0x12;
pub const LC_SUB_UMBRELLA: u32 = 0x13;
pub const LC_SUB_CLIENT: u32 = 0x14;
pub const LC_SUB_LIBRARY: u32 = 0x15;
pub const LC_TWOLEVEL_HINTS: u32 = 0x16;
pub const LC_PREBIND_CKSUM: u32 = 0x17;
pub const LC_LOAD_WEAK_DYLIB: u32 = 0x18 | LC_REQ_DYLD;
pub const LC_SEGMENT_64: u32 = 0x19;
pub const LC_ROUTINES_64: u32 = 0x1A;
pub const LC_UUID: u32 = 0x1B;
pub const LC_RPATH: u32 = 0x1C | LC_REQ_DYLD;
pub const LC_CODE_SIGNATURE: u32 = 0x1D;
pub const LC_SEGMENT_SPLIT_INFO: u32 = 0x1E;
pub const LC_REEXPORT_DYLIB: u32 = 0x1F | LC_REQ_DYLD;
pub const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
pub const LC_ENCRYPTION_INFO: u32 = 0x21;
pub const LC_DYLD_INFO: u32 = 0x22;
pub const LC_DYLD_INFO_ONLY: u32 = 0x22 | LC_REQ_DYLD;
pub const LC_LOAD_UPWARD_DYLIB: u32 = 0x23 | LC_REQ_DYLD;
pub const LC_VERSION_MIN_MACOSX: u32 = 0x24;
pub const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
pub const LC_FUNCTION_STARTS: u32 = 0x26;
pub const LC_DYLD_ENVIRONMENT: u32 = 0x27;
pub const LC_MAIN: u32 = 0x28 | LC_REQ_DYLD;
pub const LC_DATA_IN_CODE: u32 = 0x29;
pub const LC_SOURCE_VERSION: u32 = 0x2A;
pub const LC_DYLIB_CODE_SIGN_DRS: u32 = 0x2B;
pub const LC_ENCRYPTION_INFO_64: u32 = 0x2C;
pub const LC_LINKER_OPTION: u32 = 0x2D;
pub const LC_LINKER_OPTIMIZATION_HINT: u32 = 0x2E;
pub const LC_VERSION_MIN_TVOS: u32 = 0x2F;
pub const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
pub const LC_NOTE: u32 = 0x31;
pub const LC_BUILD_VERSION: u32 = 0x32;
pub const LC_DYLD_EXPORTS_TRIE: u32 = 0x33 | LC_REQ_DYLD;
pub const LC_DYLD_CHAINED_FIXUPS: u32 = 0x34 | LC_REQ_DYLD;
pub const LC_FILESET_ENTRY: u32 = 0x35 | LC_REQ_DYLD;
pub const LC_ATOM_INFO: u32 = 0x36;
pub const LC_FUNCTION_VARIANTS: u32 = 0x37;
pub const LC_FUNCTION_VARIANT_FIXUPS: u32 = 0x38;
pub const LC_TARGET_TRIPLE: u32 = 0x39;

pub const VM_PROT_NONE: u32 = 0;
pub const VM_PROT_READ: u32 = 1;
pub const VM_PROT_WRITE: u32 = 2;
pub const VM_PROT_EXECUTE: u32 = 4;

// Section types (the low byte of a section's flags).
pub const SECTION_TYPE: u32 = 0xFF;
pub const S_REGULAR: u32 = 0x0;
pub const S_ZEROFILL: u32 = 0x1;
pub const S_CSTRING_LITERALS: u32 = 0x2;
pub const S_4BYTE_LITERALS: u32 = 0x3;
pub const S_8BYTE_LITERALS: u32 = 0x4;
pub const S_LITERAL_POINTERS: u32 = 0x5;
pub const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
pub const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;
pub const S_SYMBOL_STUBS: u32 = 0x8;
pub const S_MOD_INIT_FUNC_POINTERS: u32 = 0x9;
pub const S_MOD_TERM_FUNC_POINTERS: u32 = 0xA;
/// Duplicates the linker coalesces: one of several definitions is kept.
pub const S_COALESCED: u32 = 0xB;
pub const S_GB_ZEROFILL: u32 = 0xC;
pub const S_INTERPOSING: u32 = 0xD;
pub const S_16BYTE_LITERALS: u32 = 0xE;
pub const S_DTRACE_DOF: u32 = 0xF;
pub const S_LAZY_DYLIB_SYMBOL_POINTERS: u32 = 0x10;
pub const S_THREAD_LOCAL_REGULAR: u32 = 0x11;
pub const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;
pub const S_THREAD_LOCAL_VARIABLES: u32 = 0x13;
pub const S_THREAD_LOCAL_VARIABLE_POINTERS: u32 = 0x14;
pub const S_THREAD_LOCAL_INIT_FUNCTION_POINTERS: u32 = 0x15;
pub const S_INIT_FUNC_OFFSETS: u32 = 0x16;

// Section attributes (the high three bytes of a section's flags).
pub const SECTION_ATTRIBUTES: u32 = 0xFFFF_FF00;
/// Only instructions.
pub const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
pub const S_ATTR_NO_TOC: u32 = 0x4000_0000;
pub const S_ATTR_STRIP_STATIC_SYMS: u32 = 0x2000_0000;
pub const S_ATTR_NO_DEAD_STRIP: u32 = 0x1000_0000;
pub const S_ATTR_LIVE_SUPPORT: u32 = 0x0800_0000;
pub const S_ATTR_SELF_MODIFYING_CODE: u32 = 0x0400_0000;
/// Debug information (DWARF), not loaded.
pub const S_ATTR_DEBUG: u32 = 0x0200_0000;
/// Some instructions.
pub const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;
pub const S_ATTR_EXT_RELOC: u32 = 0x0000_0200;
pub const S_ATTR_LOC_RELOC: u32 = 0x0000_0100;

pub const N_STAB: u8 = 0xE0;
pub const N_PEXT: u8 = 0x10;
pub const N_TYPE: u8 = 0x0E;
pub const N_EXT: u8 = 0x01;
pub const N_UNDF: u8 = 0x0;
pub const N_ABS: u8 = 0x2;
pub const N_SECT: u8 = 0xE;

// Debugger (STABS) entries' types: the debug map a linker leaves in an
// image whose DWARF stays in its objects.
/// A global variable (its address, from ld64, is 0: the symbol's).
pub const N_GSYM: u8 = 0x20;
/// A function: its address, then (an entry with no name) its size.
pub const N_FUN: u8 = 0x24;
/// A static variable.
pub const N_STSYM: u8 = 0x26;
/// A static variable in zero-fill memory.
pub const N_LCSYM: u8 = 0x28;
/// A function's start (the entries up to `N_ENSYM` describe it).
pub const N_BNSYM: u8 = 0x2E;
/// A function's end.
pub const N_ENSYM: u8 = 0x4E;
/// A source file (an empty name ends the object's entries).
pub const N_SO: u8 = 0x64;
/// An object file: its path, and its modification time.
pub const N_OSO: u8 = 0x66;
