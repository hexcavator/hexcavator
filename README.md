# Hexcavator

*Dig into your binaries.*

A fast, free toolkit for exploring executables and their debug information:
what a binary holds, how it was built, what its code refers to and why,
and where its bytes go.

- **Formats:** PE images, COFF objects, and libraries; ELF and Mach-O
  (thin and universal) files and archives; WebAssembly modules; and
  MS-DOS, NE, LE, and LX executables.
- **Debug information:** PDBs (CodeView symbols, types, and lines) and
  DWARF (in the file, beside it, in a dSYM, or from a symbol server or
  debuginfod).
- **Exploring:** headers and file-format dumps (as `dumpbin`,
  `llvm-readobj`, and `llvm-dwarfdump` show them), symbols, type layouts,
  source files and line tables, inlined functions, data values,
  disassembly (x86/x64, ARM64, ARM32, WebAssembly), demangled names
  (Microsoft C++, Itanium C++, Rust, Swift), code signatures checked on
  any platform, and exploit mitigations and the compiler options behind
  them.
- **Analysis:** cross-references (why each function and datum is in the
  image), function fingerprints that survive rebuilds, build-to-build
  diffs, queries over an image's symbols, and size reports with measured
  recommendations.

`hexc` does all of it on the command line, with JSON for scripts and CI,
and as an MCP server for AI agents. The VS Code extension
(`editors/vscode/hexcavator`) puts it in a sidebar of binaries and builds
compared.

## Principles

- **Few dependencies.** Every parser, decoder, demangler, and analysis is
  written here. Crates are used only for general-purpose utilities
  (regular expressions, decompression) and for cryptography.
- **Zero-copy.** Files are memory-mapped and parsers borrow from the mapped
  bytes. Parsing is lazy and keeps minimal state; decoded instructions are not
  cached long-term but re-decoded from the original bytes.
- **Host-independent.** Any target's binaries can be analyzed on any host.
  On-disk integers have an explicit byte order (`U32Le`, `U32Be`, or a
  runtime `Endian`), on-disk structures have alignment 1, and target-derived
  sizes are `u64` until checked against the host buffer. Host-specific code
  lives only in `hexcavator-mmap`.
- **Hostile input.** Parsers never panic on malformed data; they return
  errors or partial results.
- **Read view and edit model are separate.** Reading is a borrowed view; editing
  (rare) builds an owned copy-on-write model and serializes it.

## Layout

| Crate | Purpose |
|---|---|
| `crates/base/core` (`hexcavator-core`) | Endian types, `Pod` overlays, bounds-checked readers, typed addresses, a bump arena |
| `crates/base/mmap` (`hexcavator-mmap`) | Read-only file mapping (Win32 / POSIX `mmap`) |
| `crates/formats/archive` (`hexcavator-archive`) | `ar` archives (`.lib`, `.a`) in their GNU, Microsoft, and BSD forms, and thin archives: members, long names, symbol tables |
| `crates/formats/elf` (`hexcavator-elf`) | ELF files of either class and byte order: headers (extended numbering), segments, sections, symbols, notes and build IDs, relocations, `.eh_frame`/`.eh_frame_hdr` |
| `crates/formats/etl` (`hexcavator-etl`) | Reader for Windows event trace log (ETL) files |
| `crates/formats/image` (`hexcavator-image`) | A format-independent view of executables and objects: architecture, sections, debug identity |
| `crates/formats/linkerlog` (`hexcavator-linkerlog`) | The MSVC linker's `/VERBOSE` output: why each library member was linked, what `/OPT:REF` discarded and `/OPT:ICF` folded |
| `crates/formats/linkmap` (`hexcavator-linkmap`) | Linker maps (MSVC `/MAP` so far): COFF groups, and every symbol with its object and library |
| `crates/formats/lx` (`hexcavator-lx`) | LE and LX (linear executable) files: VxDs, DOS extenders, and 32-bit OS/2 modules |
| `crates/formats/macho` (`hexcavator-macho`) | Mach-O files of either width and byte order, and universal files: load commands, segments, sections, symbols, link-edit tables |
| `crates/formats/minidump` (`hexcavator-minidump`) | Minidumps (MDMP): Windows, Breakpad, and Crashpad crash dumps (threads, modules, memory, exception, system information) |
| `crates/formats/mz` (`hexcavator-mz`) | MS-DOS MZ headers; dispatch to PE/NE/LE/LX new headers |
| `crates/formats/ne` (`hexcavator-ne`) | 16-bit NE (New Executable) files: Windows 1.x-3.x and OS/2 1.x modules and fonts |
| `crates/formats/pe` (`hexcavator-pe`) | PE images and COFF objects: headers, sections, symbols, RVA mapping, debug directory, imports, exports, relocations, load config (Guard CF, DVRT, CHPE/ARM64EC metadata), exception and unwind data, C++ EH and SEH handler data, TLS |
| `crates/formats/signature` (`hexcavator-signature`) | Code signatures, verified the same on every platform: DER, X.509, CMS, Authenticode (nested signatures, RFC 3161 and PKCS #9 timestamps), and Apple code signing (code directories, page hashes, requirements, entitlements); the cryptography is RustCrypto's, trust a bundled set of roots |
| `crates/formats/wasm` (`hexcavator-wasm`) | WebAssembly modules: sections, the name section, imports, function bodies, data segments |
| `crates/symbols/codeview` (`hexcavator-codeview`) | CodeView records, as cvinfo.h defines them: symbols, types (with a C++-style formatter and type layouts), C13 line and checksum subsections, inline annotations, register numbers |
| `crates/symbols/debuginfo` (`hexcavator-debuginfo`) | A format-independent view of debug information: compilands, contributions, groups (PDB so far), and finding an image's PDB |
| `crates/symbols/demangle` (`hexcavator-demangle`) | Symbol demanglers: Microsoft C++ (a syntax tree of the name, for queries, printed exactly as `UnDecorateSymbolName` does), Itanium C++, Rust (v0 and legacy), and Swift |
| `crates/symbols/dwarf` (`hexcavator-dwarf`) | DWARF 2-5: units, abbreviations, DIEs and attributes, string and address indirection, range and location lists, aranges, name tables, each with where its bytes lie |
| `crates/symbols/pdb` (`hexcavator-pdb`) | The PDB container: MSF, info, DBI, TPI/IPI with their hash streams, publics and globals, module streams |
| `crates/symbols/symbolize` (`hexcavator-symbolize`) | Finding an image's symbols and the function at an address, for traces and dumps |
| `crates/isa/arm32` (`hexcavator-arm32`) | AArch32 (A32 and T32) instruction decoder |
| `crates/isa/arm64` (`hexcavator-arm64`) | AArch64 decoder (base, FP, AdvSIMD, SVE/SVE2, SME/SME2, ...) generated from Arm's AARCHMRS and LLVM's AArch64 target, with a dumpbin-style formatter |
| `crates/isa/wasm` (`hexcavator-wasm-isa`) | The WebAssembly instruction decoder (the whole instruction set, through GC, threads, and relaxed SIMD) with text output |
| `crates/isa/x86` (`hexcavator-x86`) | x86/x86-64 decoder (legacy, x87, SSE, AVX, AVX-512, AMX, ...) and dumpbin-style formatter |
| `crates/debug/unwind` (`hexcavator-unwind`) | Virtual stack unwinders: recover a caller's registers from a frame's registers, its stack, and the image's unwind data |
| `crates/analysis/code` (`hexcavator-code`) | Code independent of the instruction set: instructions' control flow, and functions' basic blocks |
| `crates/analysis/fingerprint` (`hexcavator-fingerprint`) | Fingerprints of functions and data that don't depend on where they are: instructions with addresses masked, then what they refer to, refined until stable (as linkers fold identical code), so builds compare and unfolded duplicates show |
| `crates/analysis/program` (`hexcavator-program`) | Loading a program once: an image, its debug information, its model and symbols, for every analysis and front end |
| `crates/analysis/query` (`hexcavator-query`) | A small query language over tables of an image's facts: filters, grouping with counts and summed sizes, sorting, limits; shared by `hexc query` and the MCP server |
| `crates/analysis/size` (`hexcavator-size`) | Size attribution: which sections, COFF groups, libraries, compilands, and symbols account for each byte (a SizeBench replacement), and bloaty-style reports by data source for images, objects, and libraries |
| `crates/analysis/xref` (`hexcavator-xref`) | Cross-references: a graph of what each function and datum refers to (calls, branches, addresses code uses, pointers in data), found by disassembly, and why each is reachable from the image's roots |
| `crates/trace/etw` (`hexcavator-etw`) | Decoders for Windows kernel and trace-control events in ETL files |
| `crates/trace/trace` (`hexcavator-trace`) | A platform-neutral model of performance traces, and importers that build it |
| `crates/trace/trace-analysis` (`hexcavator-trace-analysis`) | Queries over traces: stack trees, callers and callees, CPU and wait analysis |
| `apps/hexcavator` | `hexc`: the command line, the MCP server for agents, and the server the VS Code extension runs |
| `apps/fuzz` | The fuzzer: every parser and command, on mutated inputs, for crashes, hangs, and blowups |
| `apps/xtask` | Development tasks: `cargo xtask test` builds every test and runs them all at once |
| `editors/vscode/hexcavator` | The VS Code extension: a sidebar of binaries and builds compared, with their headers, symbols, types, sources, data, and disassembly, size treemaps, and why each thing is there |

## Building

```
cargo build
cargo xtask test
cargo run -- info C:\Windows\System32\kernel32.dll
cargo run -- dump /headers C:\Windows\System32\kernel32.dll
```

`hexc dump` mirrors `dumpbin`, and accepts options as `/name`, `-name`, or
`--name` (use the dash forms from Git Bash, which rewrites `/name` into a
path).

### Testing

`cargo xtask test` builds every test and runs all the test binaries at
once (`cargo test` runs them one after another): about five seconds once
built. Arguments go to `cargo test` (`-p hexcavator-x86`), and after
`--` to the test binaries (a name filter). Each crate's integration
tests are one binary, `tests/it`, a module per file.

The tests are hermetic: it reads nothing outside this repository (not
the system's files, not installed tools), so it gives the same answer on
every machine. The extended tests compare Hexcavator with outside tools
(dumpbin, LLVM, XED, SizeBench, swift-demangle, Windows' own unwinder) on
files outside the repository (system DLLs, Visual Studio's, large
binaries, traces); they are in a separate repository, `hexcavator-private`,
whose README lists what each needs. What they find is kept here as golden
files (`tests/data` beside each crate), which `cargo test` checks.

`python tools/fixtures.py` regenerates the test data the tools here build
(test programs from MSVC and LLVM, and the tools' views of them that the
tests compare with), every step at once, with the paths they record the
same on every machine.

The dumpbin comparison covers system images, the fixtures in `tools/fixtures`
(x86, x64, ARM64, ARM64EC), and Visual Studio's ARM64 and ARM64X DLLs. ARM64
`/unwindinfo` shows each unwind code next to the instruction at its address,
as dumpbin does, and decodes the handler data the way dumpbin does: by what
it looks like, not by which handler it belongs to.

### hexcavator-x86 testing

`hexcavator-x86`'s opcode tables (`crates/isa/x86/tables/*.txt`) are written in the
Intel SDM's operand notation and compiled by `build.rs`. They are checked
against `dumpbin /disasm` by enumerating whole opcode spaces (every opcode with
every ModRM byte under prefix, VEX, and EVEX field combinations: about 11
million encodings) and by disassembling system DLLs (about 4.5 million
instructions). Where dumpbin disagrees with the SDM, the test classifies the
case (`known_divergence` in `crates/isa/x86/tests/dumpbin.rs`) rather than
copying dumpbin. A sample of the agreed results is kept in
`crates/isa/x86/tests/data/golden.txt` so that `cargo test` covers the decoder on
every host. Not yet supported: AVX512-FP16, most of AVX10.2, APX (REX2 is
decoded; EVEX promotions are not), AMX-AVX512, and Xeon Phi extensions.

### hexcavator-arm64 testing

`hexcavator-arm64`'s tables (`crates/isa/arm64/tables/a64.txt`) are generated by
`tools/arm64/extract.py` from openly licensed sources only: Arm's Machine
Readable Specification (AARCHMRS) and LLVM's AArch64 target (neither is
needed to build). They hold every encoding's fixed bits, its
UNDEFINED and CONSTRAINED UNPREDICTABLE conditions, alias preferences, and
assembler template; `build.rs` compiles the conditions to Rust. The output
follows Microsoft's ARM64 syntax, and is checked against `dumpbin /disasm` on
millions of pseudo-random words, which cover the encoding space in proportion
to its size. The test classifies every disagreement: features and encodings
dumpbin does not decode (listed in `crates/isa/arm64/tests/support/mod.rs`),
encodings ARM reserves that dumpbin decodes anyway, and dumpbin's bugs (in
`crates/isa/arm64/tests/dumpbin.rs`). `crates/isa/arm64/tests/data/golden.txt` keeps up
to four agreed words of every encoding for the hermetic test.

### hexcavator-demangle testing

`hexcavator-demangle` parses a decorated name into a tree in an arena (so a
`Demangler` reused across names allocates nothing once warm), with limits
on nesting depth and on the work back-references can cause, since names
come from untrusted files. Its output was compared with `undname` (which
shares dumpbin's undecorator) over about 50,000 distinct names from the MSVC
libraries and C++ DLLs, under the complete, `NO_PTR64`, and `NAME_ONLY`
flags (`examples/compare`), C++/CLI and C++/CX names included. Where the
two disagree, undname is wrong: it spells a back-referenced anonymous
namespace by its tag (`A0x1234abcd::`), does not count a variable
template's own name as a back-reference, and cannot read names containing
`<lambda_...>` or `<unnamed-type-...>`.
`crates/symbols/demangle/tests/data/golden.txt` keeps a sample for the hermetic
test.

### hexcavator-size testing

`hexc size -sizebench <image>` prints the analysis in the form
`tools/sizebench-oracle` prints SizeBench's. `testdata/sizebench` holds
SizeBench's own test binaries (x86, x64, ARM32; MSVC, clang-cl/lld-link,
Rust, Zig, Fortran) and SizeBench's analysis of each; `cargo test` checks
that sections, COFF groups, libraries, compilands, every contributed byte
range, and every symbol (names included) agree, but for classified
divergences where SizeBench or DIA is wrong or arbitrary. An extended test
does the same for SizeBench's two large external binaries and for clang:
over a million symbols, none unexplained. Large real-world binaries for performance work
are built from LLVM with `tools/llvm/build-msvc.cmd`. `testdata/coff` holds
objects and libraries built by `tools/coff/build.cmd`.

ELF follows bloaty's `elf.cc` (labels, the segments base map, the
catch-all fallbacks, table entries charged to the symbols they describe),
with its bugs classified and not copied (see `crates/analysis/size/src/elf.rs`).
`testdata/elf` holds clang/ld.lld output for x86-64, i386, AArch64 (both
byte orders), and big-endian ARM, built by `tools/elf/build.cmd` with the
`llvm-readobj` dumps that `hexcavator-elf` is checked against field by field.

## Using hexc

`hexc help` lists the commands. `hexc info` identifies files, `hexc dump`,
`hexc pdb`, and `hexc dwarf` show their contents, and the commands below
analyze them. Most analyses take `-json` for scripts and CI, and the
tabular ones `-csv` or `-tsv` too.

### Size analysis

```
hexc size app.exe                          # sections, COFF groups, libraries, compilands (using the PDB)
hexc size -d sections,symbols app.exe      # bloaty-style: every byte, by data sources, a level each
hexc size -d compileunits -n 10 app.exe -- old\app.exe   # a diff against another build
hexc size -d armembers,symbols foo.lib     # objects, import objects, and libraries need no PDB
hexc size -d segments,symbols app.elf      # ELF executables, shared objects, objects, and .a archives too
hexc size -d archs,segments App.app/App    # Mach-O and universal files too
hexc size -d symbols app.wasm              # and WebAssembly modules
hexc size -disassemble main app.wasm      # one function's code (PE with its PDB, ELF, Mach-O, WebAssembly), calls named
hexc size -d compileunits -debug-file app.debug app  # DWARF in a separate file (a dSYM next to a Mach-O image is found)
hexc size -d compileunits,symbols app.elf  # ELF compile units from DWARF; symbols demangled (fullsymbols, rawsymbols)
hexc size -d symbols -source-filter '^std::' app  # only labels a regular expression matches
hexc size -c project.bloaty app             # bloaty config files: custom sources rewriting labels
hexc size -list-sources                    # sections, segments, groups, symbols, compileunits, ...
hexc size -findings app.exe                # what wastes space (duplicate data, template bloat), with advice
hexc size -map app.map app.exe             # no PDB? the linker's map attributes symbols to objects and libraries
hexc linkerlog link.log -image app.exe     # the largest library members, and why each was linked
hexc linkerlog link.log -why gshandler.obj # why one was (from `link ... /VERBOSE > link.log`)
hexc linkerlog new.log -- old.log          # members linked now and not before, and why
```

Reports print as bloaty prints them, or with `-csv`, `-tsv`, or `-json`.

### Queries

```
hexc query app.exe "kind=function file>4k sort by file desc limit 20"
hexc query app.exe "group by library"                       # count, file and memory bytes per library
hexc query app.exe "name~'^std::' group by compiland limit 10"
hexc query app.exe "static group by name sort by count desc" # file-scope variables copied into many objects
hexc query -columns                                         # name, kind, file, vm, rva, section, group, compiland, library, folded, static, source, line
```

A query is a filter (`column op value`, joined by `and` or a space, `or`,
`not`, and parentheses; `~` is a regular expression; numbers take `k`, `M`,
`G`), then any of `group by`, `sort by ... [desc]`, `select`, and `limit`.
Output is a table, `-csv`, or `-json`; the MCP server's `query` tool takes
the same language.

### Signatures

```
hexc signature app.exe                     # its company, product, and versions; Authenticode: signer, timestamp, chain, and whether it's unchanged and trusted
hexc signature -json App.app/Contents/MacOS/App   # Apple code signing: each architecture's pages, cdhashes, requirements, Developer ID
hexc signature -root my-ca.cer app.exe     # trust another root too (DER or PEM)
```

A Windows binary verifies on macOS or Linux, and a Mac binary on Windows:
the file's hash, the signer's signature, each certificate of the chain,
the timestamps, and what each certificate may be used for are checked here,
with RustCrypto's hashes, RSA, and ECDSA. Trust is a bundled list of roots
(Microsoft's, Apple's, and the public code-signing and timestamping
authorities; `tools/signature/roots.py` fetches and checks them), not the
machine's, so the answer is the same everywhere. Revocation isn't checked
(it needs the network), nor are signatures outside the file (a Windows
catalog's, a notarization ticket). `tools/signature/oracle.ps1` compares the
verdicts with Windows' own (`Get-AuthenticodeSignature`): 3,000 of 3,000
signed files agree. Before the signatures, it shows what the file says it
is, as `sigcheck` does: a PE image's version resource (company, description,
product, versions, copyright; U.S. English where there are several
languages), or a Mach-O image's versions and Info.plist.
`tools/signature/version-oracle.ps1` compares those with Windows'
`FileVersionInfo`: 1,984 of 1,985 agree (Windows takes a localized file's
strings from its `.mui` satellite, which has its own versions; hexc reads
the file's own, so those are skipped).

### Type layouts

```
hexc types app.exe                         # classes, structures, and unions by the bytes their padding wastes
hexc types -layout Widget app.exe          # one type: bases, vfptr, vbptr, members (bitfields by bit), holes
hexc types new.exe -- old.exe              # the types whose layout changed between builds
```

Layouts come from the PDB's type records (an image's, or a PDB given
directly). An empty base takes no space; virtual bases, whose offsets the
records don't give, are placed after the rest of the object, aligned, as
MSVC places them. A type with a member of a type that has no definition in
the PDB is marked incomplete rather than counted as padding. On clang's
1.45 GB PDB, 292,170 types are laid out in about 2.5 seconds.

### Inlining and source files

```
hexc inlines app.exe                       # functions inlined into the code, by their copies' bytes
hexc inlines -inlinee "Twine::Twine" app.exe   # one function's copies, by the function each is in
hexc sourcefiles app.exe                   # the code by source file (headers too)
hexc sourcefiles -file "DenseMap\.h$" app.exe  # one file's code, by line
```

Inline sites come from the PDB's `S_INLINESITE` records and their binary
annotations (`hexcavator-pdb`'s `annotations`), which give each inlined
copy's code ranges. A copy's bytes are its own: a site nested in another
claims its bytes first, and the copies of one function that identical code
folding merged count once. Source files come from the line tables; inlined
code counts where it was inlined. On clang: 4.4 million inline sites of
361,000 functions, 38.8 MB of its 82 MB of code, in about 5 seconds.

### Annotations, batches, and findings compared

```
hexc annotations app.exe                   # strings code attached to addresses (__annotation), with file:line
hexc batch -r -findings C:\build\bin > sizes.jsonl   # one JSON line per image: sections, libraries, compilands, findings
hexc size -findings new.exe -- old.exe     # each finding's change from a base build, item by item
```

### Recommendations

```
hexc recommend app.exe          # build changes that would make the image smaller, each with its saving
```

Each recommendation is measured from the image and its PDB, and what can't
be measured isn't made: compile an object with `/Gy` or `/Gw` (what
nothing reaches that the linker kept with the sections it shares, from the
cross-reference graph and the PDB's section contributions); link with
`/OPT:REF` or `/OPT:ICF` when the link didn't (from the linker's command
line in the PDB; by the unreferenced COMDATs, and by the functions it could
fold); define a duplicated variable once. Objects of the toolset's and the
SDK's own libraries are left out: they can't be rebuilt.

### Cross-references

```
hexc xref app.exe                          # references, roots, and what no root reaches
hexc xref -why "Square::area" app.exe      # the chain from a root: why a function or datum is in the image
hexc xref -refs "Square::\`vftable'" app.exe  # what refers to it, and what it refers to
hexc xref -unreachable -n 0 app.exe        # everything no root reaches, largest first
hexc xref -vtables app.exe                 # vtables no constructor or destructor stores, and what refers to them
hexc xref -identical app.exe               # functions /OPT:ICF could have folded but didn't
hexc xref app.exe -- old\app.exe           # functions unchanged, changed, renamed (by fingerprint), added, removed
```

Fingerprints (`hexcavator-fingerprint`) hash each function's instructions
with every address masked (a branch inside it counts by offset; anything
else it refers to is a reference, in order), then rehash each with its
references' hashes until the classes stop splitting, so two functions
alike but for their callees differ unless the callees are alike, and
recursion needs nothing special. Read-only data counts by its bytes,
variables by name, and imports by the import table's `dll!function`.
`-identical` counts only what the linker could fold (COMDAT code and
read-only COMDAT data by contents; anything else is only itself): none in
the test program, which is linked with `/OPT:ICF`. Comparing builds pairs
functions by name, then the rest by fingerprint (renamed); a function is
unchanged if its code is and it refers to the same things, or their
renamed pairs.

`hexc xref` builds a graph of a PE image (x64, x86, ARM64) from its PDB's
symbols, its code (direct calls and branches, RIP-relative and
image-relative operands, ARM64 `ADRP` pairs), its base relocations
(pointers in data, such as vtable slots), and its exception data (a
function owns its `.pdata`, unwind data, and EH tables, which name its
funclets). The roots are the entry point, the exports, what the loader
reads, and the CRT's initializer tables. A virtual function needs no
special case: its vtable points to it, and the constructors and
destructors that store the vtable refer to it, so the chain runs through
whoever constructs the object (or through the object itself, for one
initialized at compile time; on clang, all 278 vtables no code stores are
such objects'). Data holding pointers that has no symbol (a Rust trait
object's vtable) is split where code takes its address, so each such
object keeps only what it points to.

What no root reaches is code and data the linker kept anyway, and the PDB's
section contributions say why: its section was not a COMDAT (code compiled
without `/Gy`, data without `/Gw`), which the linker keeps whole when
anything in it is used; or it is a COMDAT that such a section refers to; or
it is a COMDAT kept for a reason the graph doesn't see (`/OPT:NOREF`,
`/INCLUDE`, a reference it misses). `testdata/xref` holds the test program
(`tools/xref`), built for x64 and ARM64, where every unreachable item is of
the first two kinds. On clang's 108 MB image (in about 2 seconds, with its
symbols indexed), 16 data items (562 bytes) and no code are unreached; the
reference patterns found by checking the rest against clang's object files'
relocations (MSVC's tables by image offset, scaled and with the base added
after, and across forward jumps) are in `crates/analysis/xref/src/scan.rs`.

`hexc mcp` serves the same analysis to LLM agents over the Model Context
Protocol (stdio), with tools `size_report`, `symbols`, `findings`, `why`, `recommend`,
`linker_log`, `query`, and `lookup`; the
first question about an image reads its PDB, and later ones reuse it. For
example, for Claude Code:

```
claude mcp add hexc -- C:\path\to\hexc.exe mcp
```

## License

Hexcavator is licensed under the [Apache License 2.0](LICENSE) (see also
[`NOTICE`](NOTICE)). Some parts are derived from others' work: code that
follows the LLVM Project's or is generated from it, the Swift demangler
(translated from the Swift Project's), the ARM instruction tables
(generated from Arm's machine-readable specification), and some x86
tables (generated from Intel XED's data). Those parts also carry their
sources' licenses, all permissive. The crate holding each part has its
source's license file (`LICENSE-LLVM`, `LICENSE-SWIFT`, `LICENSE-ARM`,
`NOTICE-XED`), and [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)
says what came from where. `hexc licenses` prints the notices of
everything the program includes. The licenses test keeps that list
current, checks each crate's `license` against its license files, and
allows only permissive licenses.
