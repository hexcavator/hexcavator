# To do

What's planned for Hexcavator, and what's waiting on something. Items
leave this list when they ship.

## Size analysis

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
