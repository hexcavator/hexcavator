# To do

What's planned for Hexcavator, and what's waiting on something. Items
leave this list when they ship.

## Size analysis

- **GNU ld and lld link maps.** Read their `-Map` output, as MSVC's
  `/MAP` is read now (`crates/formats/linkmap`): sizes by object and
  archive member without debug information.

- **Mach-O exception handling.** Its compact unwind (`__unwind_info`) and
  LSDAs (`__gcc_except_tab`), for the exception handling costs and
  needless cleanups ELF and PE have.
- **Rust's Debug implementations on Windows.** Rust's PDB names say
  `impl$12::fmt`, not which trait: `-Zfmt-debug`'s saving is measured on
  ELF and Mach-O only.

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
