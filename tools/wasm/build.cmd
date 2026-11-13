@echo off
rem Builds Hexcavator's WebAssembly test input, testdata\wasm\module.wasm, with
rem make.py (no WebAssembly compiler at hand), and the llvm-readobj and
rem llvm-objdump views of it the tests compare with.
setlocal
if "%LLVM_BIN%"=="" (echo set LLVM_BIN to the bin directory of an LLVM build or release 1>&2 & exit /b 1)
if "%PYTHON%"=="" set PYTHON=python
set OUT=%~dp0..\..\testdata\wasm
"%PYTHON%" -I "%~dp0make.py" "%OUT%" || exit /b 1
cd /d "%OUT%" || exit /b 1
"%LLVM_BIN%\llvm-readobj.exe" --sections --symbols module.wasm > module.wasm.readobj.txt || exit /b 1
"%LLVM_BIN%\llvm-objdump.exe" -t module.wasm > module.wasm.syms.txt || exit /b 1
rem The disassembler's oracles: ops.wasm (every instruction LLVM knows, from
rem its WebAssembly target's TableGen records), sample.wasm (rustc's output),
rem and llvm-objdump's listings of them. That llvm-objdump must have the
rem WebAssembly target: rustup component add llvm-tools gives one.
if "%LLVM_SRC%"=="" (echo set LLVM_SRC to the llvm directory of an llvm-project checkout 1>&2 & exit /b 1)
if "%LLVM_TOOLS%"=="" for /f "delims=" %%s in ('rustc --print sysroot') do set LLVM_TOOLS=%%s\lib\rustlib\x86_64-pc-windows-msvc\bin
"%LLVM_BIN%\llvm-tblgen.exe" --dump-json -I "%LLVM_SRC%\include" -I "%LLVM_SRC%\lib\Target\WebAssembly" "%LLVM_SRC%\lib\Target\WebAssembly\WebAssembly.td" -o "%TEMP%\webassembly.json" || exit /b 1
"%PYTHON%" -I "%~dp0all_ops.py" "%TEMP%\webassembly.json" ops.wasm || exit /b 1
rustc --target wasm32-wasip1 --crate-type cdylib -C opt-level=2 -C panic=abort -C target-feature=+simd128,+bulk-memory,+nontrapping-fptoint,+sign-ext -C strip=none "%~dp0sample.rs" -o sample.wasm || exit /b 1
rem A module with DWARF (rustc -g), its paths neutral (the toolchain's as
rem /rust; the repository's as R:, where every fixture script runs), and
rem llvm-dwarfdump's view of it.
for /f "delims=" %%s in ('rustc --print sysroot') do set SYSROOT=%%s
rustc --target wasm32-wasip1 --crate-type cdylib -C opt-level=2 -C panic=abort -C debuginfo=2 -C strip=none "--remap-path-prefix=%SYSROOT%=/rust" "%~dp0sample.rs" -o sample-dwarf.wasm || exit /b 1
"%LLVM_BIN%\llvm-dwarfdump.exe" --debug-info sample-dwarf.wasm > sample-dwarf.wasm.dwarfdump.txt 2>nul || exit /b 1
rem A relocatable object (rustc --emit=obj): its linking section's symbols,
rem segment names, and relocations, as llvm-readobj shows them.
rustc --target wasm32-wasip1 --crate-type cdylib -C opt-level=2 -C panic=abort -C strip=none --emit=obj "%~dp0sample.rs" -o sample.o || exit /b 1
"%LLVM_BIN%\llvm-readobj.exe" --file-headers --sections --relocations --symbols sample.o > sample.o.readobj.txt || exit /b 1
set MATTR=+simd128,+relaxed-simd,+atomics,+bulk-memory,+exception-handling,+tail-call,+reference-types,+multimemory,+fp16,+gc,+wide-arithmetic,+nontrapping-fptoint,+sign-ext,+multivalue,+extended-const,+call-indirect-overlong
"%LLVM_TOOLS%\llvm-objdump.exe" -d --mattr=%MATTR% ops.wasm > ops.wasm.objdump.txt || exit /b 1
"%LLVM_TOOLS%\llvm-objdump.exe" -d --mattr=%MATTR% sample.wasm > sample.wasm.objdump.txt || exit /b 1
