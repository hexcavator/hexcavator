//! ELF constants (the gABI's names).

pub const ELFCLASS32: u8 = 1;
pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;
pub const ELFDATA2MSB: u8 = 2;

pub const ET_NONE: u16 = 0;
pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const ET_CORE: u16 = 4;

// Machines (`e_machine`): the gABI's registry, and the values in use
// beyond it.
pub const EM_NONE: u16 = 0;
pub const EM_M32: u16 = 1;
pub const EM_SPARC: u16 = 2;
pub const EM_386: u16 = 3;
pub const EM_68K: u16 = 4;
pub const EM_88K: u16 = 5;
pub const EM_IAMCU: u16 = 6;
pub const EM_860: u16 = 7;
pub const EM_MIPS: u16 = 8;
pub const EM_S370: u16 = 9;
pub const EM_MIPS_RS3_LE: u16 = 10;
pub const EM_PARISC: u16 = 15;
pub const EM_VPP500: u16 = 17;
pub const EM_SPARC32PLUS: u16 = 18;
pub const EM_960: u16 = 19;
pub const EM_PPC: u16 = 20;
pub const EM_PPC64: u16 = 21;
pub const EM_S390: u16 = 22;
pub const EM_SPU: u16 = 23;
pub const EM_V800: u16 = 36;
pub const EM_FR20: u16 = 37;
pub const EM_RH32: u16 = 38;
pub const EM_RCE: u16 = 39;
pub const EM_ARM: u16 = 40;
/// Digital Alpha (the gABI's old number; see also [`EM_ALPHA_UNOFFICIAL`]).
pub const EM_ALPHA: u16 = 41;
pub const EM_SH: u16 = 42;
pub const EM_SPARCV9: u16 = 43;
pub const EM_TRICORE: u16 = 44;
pub const EM_ARC: u16 = 45;
pub const EM_H8_300: u16 = 46;
pub const EM_H8_300H: u16 = 47;
pub const EM_H8S: u16 = 48;
pub const EM_H8_500: u16 = 49;
pub const EM_IA_64: u16 = 50;
pub const EM_MIPS_X: u16 = 51;
pub const EM_COLDFIRE: u16 = 52;
pub const EM_68HC12: u16 = 53;
pub const EM_MMA: u16 = 54;
pub const EM_PCP: u16 = 55;
pub const EM_NCPU: u16 = 56;
pub const EM_NDR1: u16 = 57;
pub const EM_STARCORE: u16 = 58;
pub const EM_ME16: u16 = 59;
pub const EM_ST100: u16 = 60;
pub const EM_TINYJ: u16 = 61;
pub const EM_X86_64: u16 = 62;
pub const EM_PDSP: u16 = 63;
pub const EM_PDP10: u16 = 64;
pub const EM_PDP11: u16 = 65;
pub const EM_FX66: u16 = 66;
pub const EM_ST9PLUS: u16 = 67;
pub const EM_ST7: u16 = 68;
pub const EM_68HC16: u16 = 69;
pub const EM_68HC11: u16 = 70;
pub const EM_68HC08: u16 = 71;
pub const EM_68HC05: u16 = 72;
pub const EM_SVX: u16 = 73;
pub const EM_ST19: u16 = 74;
pub const EM_VAX: u16 = 75;
pub const EM_CRIS: u16 = 76;
pub const EM_JAVELIN: u16 = 77;
pub const EM_FIREPATH: u16 = 78;
pub const EM_ZSP: u16 = 79;
pub const EM_MMIX: u16 = 80;
pub const EM_HUANY: u16 = 81;
pub const EM_PRISM: u16 = 82;
pub const EM_AVR: u16 = 83;
pub const EM_FR30: u16 = 84;
pub const EM_D10V: u16 = 85;
pub const EM_D30V: u16 = 86;
pub const EM_V850: u16 = 87;
pub const EM_M32R: u16 = 88;
pub const EM_MN10300: u16 = 89;
pub const EM_MN10200: u16 = 90;
pub const EM_PJ: u16 = 91;
pub const EM_OPENRISC: u16 = 92;
pub const EM_ARC_COMPACT: u16 = 93;
pub const EM_XTENSA: u16 = 94;
pub const EM_VIDEOCORE: u16 = 95;
pub const EM_TMM_GPP: u16 = 96;
pub const EM_NS32K: u16 = 97;
pub const EM_TPC: u16 = 98;
pub const EM_SNP1K: u16 = 99;
pub const EM_ST200: u16 = 100;
pub const EM_IP2K: u16 = 101;
pub const EM_MAX: u16 = 102;
pub const EM_CR: u16 = 103;
pub const EM_F2MC16: u16 = 104;
pub const EM_MSP430: u16 = 105;
pub const EM_BLACKFIN: u16 = 106;
pub const EM_SE_C33: u16 = 107;
pub const EM_SEP: u16 = 108;
pub const EM_ARCA: u16 = 109;
pub const EM_UNICORE: u16 = 110;
pub const EM_ALTERA_NIOS2: u16 = 113;
pub const EM_CRX: u16 = 114;
pub const EM_M32C: u16 = 120;
pub const EM_MT: u16 = 129;
pub const EM_TI_C6000: u16 = 140;
pub const EM_MICROBLAZE: u16 = 189;
pub const EM_HEXAGON: u16 = 164;
pub const EM_NDS32: u16 = 167;
pub const EM_AARCH64: u16 = 183;
pub const EM_AVR32: u16 = 185;
pub const EM_CUDA: u16 = 190;
pub const EM_TILEGX: u16 = 191;
pub const EM_Z80: u16 = 220;
pub const EM_AMDGPU: u16 = 224;
pub const EM_RISCV: u16 = 243;
pub const EM_BPF: u16 = 247;
pub const EM_CSKY: u16 = 252;
pub const EM_LOONGARCH: u16 = 258;
/// Digital Alpha, as Linux and the GNU tools number it.
pub const EM_ALPHA_UNOFFICIAL: u16 = 0x9026;

pub const PN_XNUM: u16 = 0xFFFF;

pub const SHN_UNDEF: u16 = 0;
pub const SHN_LORESERVE: u16 = 0xFF00;
pub const SHN_ABS: u16 = 0xFFF1;
pub const SHN_COMMON: u16 = 0xFFF2;
pub const SHN_XINDEX: u16 = 0xFFFF;

pub const SHT_NULL: u32 = 0;
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_HASH: u32 = 5;
pub const SHT_DYNAMIC: u32 = 6;
pub const SHT_NOTE: u32 = 7;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_REL: u32 = 9;
pub const SHT_DYNSYM: u32 = 11;
pub const SHT_INIT_ARRAY: u32 = 14;
pub const SHT_FINI_ARRAY: u32 = 15;
pub const SHT_GROUP: u32 = 17;
pub const SHT_SYMTAB_SHNDX: u32 = 18;
pub const SHT_RELR: u32 = 19;

pub const SHF_WRITE: u64 = 0x1;
pub const SHF_ALLOC: u64 = 0x2;
pub const SHF_EXECINSTR: u64 = 0x4;
pub const SHF_MERGE: u64 = 0x10;
pub const SHF_STRINGS: u64 = 0x20;
pub const SHF_INFO_LINK: u64 = 0x40;
pub const SHF_GROUP: u64 = 0x200;
pub const SHF_TLS: u64 = 0x400;
pub const SHF_COMPRESSED: u64 = 0x800;
pub const SHF_LINK_ORDER: u64 = 0x80;
pub const SHF_OS_NONCONFORMING: u64 = 0x100;
/// Kept through garbage collection (GNU).
pub const SHF_GNU_RETAIN: u64 = 0x20_0000;
/// Left out of the linked image (it is for the linker).
pub const SHF_EXCLUDE: u64 = 0x8000_0000;

/// A section group's flag: its sections are a COMDAT, one of possibly
/// several copies the linker keeps one of.
pub const GRP_COMDAT: u32 = 0x1;

pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;
pub const PT_GNU_EH_FRAME: u32 = 0x6474_E550;
pub const PT_GNU_STACK: u32 = 0x6474_E551;
pub const PT_GNU_RELRO: u32 = 0x6474_E552;

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;

pub const STT_NOTYPE: u8 = 0;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
pub const STT_SECTION: u8 = 3;
pub const STT_FILE: u8 = 4;
pub const STT_COMMON: u8 = 5;
pub const STT_TLS: u8 = 6;

pub const NT_GNU_BUILD_ID: u32 = 3;

// Dynamic section tags (`DT_*`).
pub const DT_NULL: u64 = 0;
pub const DT_NEEDED: u64 = 1;
pub const DT_PLTRELSZ: u64 = 2;
pub const DT_PLTGOT: u64 = 3;
pub const DT_HASH: u64 = 4;
pub const DT_STRTAB: u64 = 5;
pub const DT_SYMTAB: u64 = 6;
pub const DT_RELA: u64 = 7;
pub const DT_RELASZ: u64 = 8;
pub const DT_RELAENT: u64 = 9;
pub const DT_STRSZ: u64 = 10;
pub const DT_SYMENT: u64 = 11;
pub const DT_INIT: u64 = 12;
pub const DT_FINI: u64 = 13;
pub const DT_SONAME: u64 = 14;
pub const DT_RPATH: u64 = 15;
pub const DT_SYMBOLIC: u64 = 16;
pub const DT_REL: u64 = 17;
pub const DT_RELSZ: u64 = 18;
pub const DT_RELENT: u64 = 19;
pub const DT_PLTREL: u64 = 20;
pub const DT_DEBUG: u64 = 21;
pub const DT_TEXTREL: u64 = 22;
pub const DT_JMPREL: u64 = 23;
pub const DT_BIND_NOW: u64 = 24;
pub const DT_INIT_ARRAY: u64 = 25;
pub const DT_FINI_ARRAY: u64 = 26;
pub const DT_INIT_ARRAYSZ: u64 = 27;
pub const DT_FINI_ARRAYSZ: u64 = 28;
pub const DT_RUNPATH: u64 = 29;
pub const DT_FLAGS: u64 = 30;
pub const DT_PREINIT_ARRAY: u64 = 32;
pub const DT_PREINIT_ARRAYSZ: u64 = 33;
pub const DT_SYMTAB_SHNDX: u64 = 34;
pub const DT_RELRSZ: u64 = 35;
pub const DT_RELR: u64 = 36;
pub const DT_RELRENT: u64 = 37;
pub const DT_GNU_HASH: u64 = 0x6FFF_FEF5;
pub const DT_VERSYM: u64 = 0x6FFF_FFF0;
pub const DT_RELACOUNT: u64 = 0x6FFF_FFF9;
pub const DT_RELCOUNT: u64 = 0x6FFF_FFFA;
pub const DT_FLAGS_1: u64 = 0x6FFF_FFFB;
pub const DT_VERDEF: u64 = 0x6FFF_FFFC;
pub const DT_VERDEFNUM: u64 = 0x6FFF_FFFD;
pub const DT_VERNEED: u64 = 0x6FFF_FFFE;
pub const DT_VERNEEDNUM: u64 = 0x6FFF_FFFF;

pub const SHT_PREINIT_ARRAY: u32 = 16;
/// Arm's exception index table, and its other processor-specific types.
pub const SHT_ARM_EXIDX: u32 = 0x7000_0001;
pub const SHT_ARM_PREEMPTMAP: u32 = 0x7000_0002;
pub const SHT_ARM_ATTRIBUTES: u32 = 0x7000_0003;
pub const SHT_GNU_HASH: u32 = 0x6FFF_FFF6;
pub const SHT_GNU_VERDEF: u32 = 0x6FFF_FFFD;
pub const SHT_GNU_VERNEED: u32 = 0x6FFF_FFFE;
pub const SHT_GNU_VERSYM: u32 = 0x6FFF_FFFF;
/// Android's packed relocations (APS2).
pub const SHT_ANDROID_REL: u32 = 0x6000_0001;
pub const SHT_ANDROID_RELA: u32 = 0x6000_0002;
pub const SHT_ANDROID_RELR: u32 = 0x6FFF_FF00;

// Relocation types that write an address word, by machine: absolute,
// relative, GOT entries, PLT slots, and indirect functions' resolutions.
pub const R_X86_64_64: u32 = 1;
pub const R_X86_64_GLOB_DAT: u32 = 6;
pub const R_X86_64_JUMP_SLOT: u32 = 7;
pub const R_X86_64_RELATIVE: u32 = 8;
pub const R_X86_64_IRELATIVE: u32 = 37;
pub const R_386_32: u32 = 1;
pub const R_386_GLOB_DAT: u32 = 6;
pub const R_386_JMP_SLOT: u32 = 7;
pub const R_386_RELATIVE: u32 = 8;
pub const R_386_IRELATIVE: u32 = 42;
pub const R_AARCH64_ABS64: u32 = 257;
pub const R_AARCH64_GLOB_DAT: u32 = 1025;
pub const R_AARCH64_JUMP_SLOT: u32 = 1026;
pub const R_AARCH64_RELATIVE: u32 = 1027;
pub const R_AARCH64_IRELATIVE: u32 = 1032;
pub const R_ARM_ABS32: u32 = 2;
pub const R_ARM_GLOB_DAT: u32 = 21;
pub const R_ARM_JUMP_SLOT: u32 = 22;
pub const R_ARM_RELATIVE: u32 = 23;
pub const R_ARM_IRELATIVE: u32 = 160;
pub const R_RISCV_32: u32 = 1;
pub const R_RISCV_64: u32 = 2;
pub const R_RISCV_RELATIVE: u32 = 3;
pub const R_RISCV_JUMP_SLOT: u32 = 5;
pub const R_RISCV_IRELATIVE: u32 = 58;

pub const ELFCOMPRESS_ZLIB: u32 = 1;
pub const ELFCOMPRESS_ZSTD: u32 = 2;
