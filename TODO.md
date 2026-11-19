# To do

What's planned for Hexcavator, and what's waiting on something. Items
leave this list when they ship.

## Size analysis

- **Recorded compiler options.** Read the compiler's command line from the
  debug information (GCC's `DW_AT_producer`, Clang's
  `-frecord-command-line`): `-ffunction-sections`, `-Os`, LTO, exceptions,
  visibility. `hexc recommend` can't otherwise tell a build compiled
  without `-ffunction-sections` (where `--gc-sections` and `--icf` leave no
  trace) from one linked without them.
- **Apple ICF advice.** ld64 folds identical functions by default
  (`-no_deduplicate` turns it off); check, and stop recommending
  `ld64.lld --icf=all` for links that already folded them.
- **MCP `why` and `recommend` beyond PE.** They read only PE images with
  PDBs (`pe_only` in `apps/hexcavator/src/mcp.rs`); the command line reads
  ELF, Mach-O, and WebAssembly too.
- **Exported symbols.** What `-fvisibility=hidden` or a version script
  would save in an ELF shared library or a Mach-O dylib: the dynamic
  symbols, their names, hash entries, and PLT/GOT slots of those nothing
  imports (`hexc deps` knows who imports what).
- **Near-identical functions.** Families of functions that differ only in
  a constant, a type's size, or a callee (template instantiations ICF
  can't fold), with what a type-erased version would save.
- **Inlining.** A function's inlined copies weighed against what calls to
  one out-of-line copy would cost instead, and `noinline` (or `-Os`)
  recommended where the copies cost more.
- **Relocations.** A relocations view (each relocation, by type, by the
  symbol it's in and the one it refers to), and a recommendation for
  pointer-heavy data (vtables, tables of string pointers) that relative
  vtables or offset tables would make smaller.
- **Build paths and strings.** Absolute paths from `__FILE__` and
  `assert` (`-fmacro-prefix-map`), and string literals duplicated where
  the linker couldn't merge them.
- **Exception handling.** What unwind tables and landing pads cost each
  function, and the functions that can't throw but carry cleanups
  (`noexcept`); a list on the Size Reduction page.
- **Rust.** Sizes by crate, and what panic messages and formatting
  machinery cost (`panic=abort`, `-Zfmt-debug`).
- **GNU ld and lld link maps.** Read their `-Map` output, as MSVC's
  `/MAP` is read now (`crates/formats/linkmap`): sizes by object and
  archive member without debug information.

## Waiting

- **GCC, GNU ld, gold, and mold.** `hexc recommend` judges what an ELF
  link did (`--gc-sections`, ICF) from what lld leaves in the image, and
  is tested only with lld. Check it against the others, with test
  binaries from each in `testdata/linkopts`. Waiting on a Linux
  environment (WSL) to build them.

## Ideas

- **A size check for pull requests.** A GitHub Action that comments on a
  pull request with the size it adds and why (`-budget` and diffs exist).
- **Size history.** Sizes across many builds: when each regression came,
  and from which commit.
