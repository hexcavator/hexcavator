# bloaty as an oracle

`build.cmd` builds [bloaty](https://github.com/google/bloaty) (Apache-2.0) from
a local clone; it is a test oracle only, never a dependency. `compare.py`
then runs bloaty and `hexc size` on every ELF, Mach-O, and WebAssembly
fixture in `testdata`, report by report (`-d <source> -n 0`, CSV), and
lists the reports whose rows differ (`--show` prints the rows).

    python compare.py %BLOATY_BUILD%\bloaty.exe target\release\hexc.exe

The oracle is not the spec: where bloaty is wrong, hexc is not, and the
difference is classified in the size module's documentation
(`crates/analysis/size/src/{elf,macho,wasm,sourcemap}.rs`). On 2026-11-08, 284
reports were identical, 151 differed, and bloaty refused 93. The
differences examined (a sample in each category, not every row of all
151) were each one of these:

- **Relocations** (ELF): bloaty skips each table's first entry and all
  `SHT_REL` tables; hexc charges them.
- **DWARF** (`compileunits`): DWARF 5's per-unit tables (`.debug_addr`,
  `.debug_str_offsets`, `.debug_loclists`, ...) are charged to their units,
  and bloaty's unnamed-unit row doesn't appear.
- **`inlines`** (ELF): hexc charges the symbol tables, relocations, unwind
  entries, and referenced data to lines; bloaty means to, but labels every
  section first, so its pass finds nothing.
- **Referenced data** (Mach-O, ARM64): hexc charges string literals,
  constants, and jump tables to the code that refers to them on Mach-O and
  ARM64 too; bloaty does this for ELF x86-64 only. Referenced data runs to
  the next reference, symbol, or section end rather than to whatever range
  bloaty added next.
- **Mach-O symbols**: a symbol stops at its section's end (bloaty runs a
  zero-fill symbol on into the file), `__mh_execute_header`, outside every
  section, is left to `[Mach-O Headers]`, and a real name wins over an
  assembler label at the same address.
- **Mach-O objects**: sections are named by their own segment
  (`__TEXT,__text`; bloaty gives `,__text`).
- **Universal files**: the whole header table is `[Mach-O Headers]` (bloaty
  labels its first 8 bytes).
- **Where bloaty refuses** (not counted as differences): `armembers` on
  Mach-O and WebAssembly, DWARF sources on objects, `archs` on ELF, Mach-O
  static libraries, and source maps without `--source-map`.
