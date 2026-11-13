# WebAssembly test data

- `module.wasm` (with `module.wasm.map`, a source map, and
  `llvm-readobj`/`llvm-objdump -t` listings): a small module with every
  standard section, named functions, locals, imports, and data, assembled
  by `tools/wasm/make.py`, for the module parser, the size reports, and
  `-disassemble`.
- `ops.wasm`: one function per instruction LLVM's WebAssembly target knows,
  each with sample immediates, written by `tools/wasm/all_ops.py` from
  `llvm-tblgen --dump-json` of `llvm/lib/Target/WebAssembly/WebAssembly.td`.
  It is for disassembly only and doesn't validate.
- `sample.wasm`: real compiler output, `tools/wasm/sample.rs` built as its
  header says (rustc for `wasm32-wasip1`, with SIMD, bulk memory, sign
  extension, and saturating conversions).
- `*.objdump.txt`: `llvm-objdump -d` of the module beside it (the
  `llvm-tools` rustup component's, which has the WebAssembly target), with
  every feature on:

      llvm-objdump -d --mattr=+simd128,+relaxed-simd,+atomics,+bulk-memory,+exception-handling,+tail-call,+reference-types,+multimemory,+fp16,+gc,+wide-arithmetic,+nontrapping-fptoint,+sign-ext,+multivalue,+extended-const,+call-indirect-overlong ops.wasm

  `tools/wasm/build.cmd` makes all of these. `crates/isa/wasm/tests/objdump.rs`
  checks hexc's decoder against these: each
  instruction's length and immediates. LLVM prints `<unknown>` for relaxed
  SIMD and half-precision instructions; those are checked against the
  specification by the unit tests instead.
