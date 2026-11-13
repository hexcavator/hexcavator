# hexcavator-fuzz

Hexcavator's fuzzer: every parser and every `hexc` command, on mutated
inputs, looking for denial of service: panics, stack overflows, hangs, and
runaway allocation. (Rust rules out memory unsafety; these it doesn't.)
It is in-house and runs on stable Rust, with no dependencies.

    cargo run --release -p hexcavator-fuzz -- list
    cargo run --release -p hexcavator-fuzz -- selftest
    cargo run --release -p hexcavator-fuzz -- run all -seconds 600
    cargo run --release -p hexcavator-fuzz -- replay pdb fuzz-findings/pdb-0123456789abcdef.bin

Run it from the repository: its seeds are the files under `testdata`, each
seeding the targets that read its kind (PE images, COFF objects, archives,
ELF, Mach-O, WebAssembly, PDBs, text), and its findings go to
`fuzz-findings/`.

## How it works

A supervisor runs each target's inputs in a child process, in batches
(`-batch`), on several workers (`-jobs`). The child writes each input to a
file before it runs it, so that whatever happens, the supervisor has the
input:

- a **panic** or a **stack overflow** kills the child;
- an input that runs longer than `-timeout` seconds (default 20) is
  killed;
- a counting global allocator aborts the child when the live heap passes
  512 MB plus 64 times the input's size.

Each finding is saved as `fuzz-findings/<target>-<hash>.bin`, with a
`.txt` that says what happened. `replay` runs it again in a supervised
child (capped, and timed out after a minute); `replay-here` runs it in
this process, still under the cap, to debug. **Never run `hexc` itself on
a finding**: one, run unguarded, once grew to 71 GB.

`selftest` checks the supervisor catches each kind of failure, with a
target that fails on purpose.

## Coverage

Built with coverage, the fuzzer is guided: a child reads LLVM's profiling
counters (`-C instrument-coverage`; SanitizerCoverage doesn't work with
COFF on stable Rust) after each input, and keeps inputs that reach a
counter value it hasn't seen (by AFL's buckets) in its pool and in
`fuzz-corpus/<target>/`, which later runs start from.

    set RUSTFLAGS=-C instrument-coverage
    cargo build --release -p hexcavator-fuzz --features coverage --target-dir target/fuzz-cov
    target\fuzz-cov\release\hexcavator-fuzz run all -seconds 3600

Without it, mutation is blind (but much faster per input).

## Targets

| Target | What runs |
|---|---|
| `pe` | `hexc dump /all /nopdb`, `size` by sections, `info`, `batch` |
| `coff`, `archive` | `dump /all`, `size` by sections, symbols, members |
| `elf`, `macho`, `wasm` | `size` by every data source, `-disassemble` (text and JSON) |
| `pdb` | `pdb -all`, `types`, and every `DebugInfo` query: symbols, lines, inline sites, annotations, classes, variables, layouts, values |
| `etl` | the ETL reader: buffers, records, extended data, LZ77 decompression, the timestamp merge |
| `etl-import` | importing ETL into the trace model: kernel event decoding, stack matching |
| `hxtrace` | trace index files |
| `stacktags` | stack tag XML (WPA's format) and folding rules |
| `manifest` | instrumentation manifests (`WEVT_TEMPLATE`) and payloads decoded by them |
| `text` | link maps and linker logs |
| `demangle` | the MSVC, Itanium, and Rust demanglers |
| `x86` | the decoder and formatter in 16-, 32-, and 64-bit modes |
| `arm64` | the decoder, formatter, and explainer |
| `query` | the query language's parser |
| `sourcemap` | source maps (JSON) |
