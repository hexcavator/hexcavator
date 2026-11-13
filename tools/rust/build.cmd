@echo off
rem Builds the Rust demangler's test data: corpus.rs compiled with the v0
rem symbol mangling, its symbols (llvm-nm), and llvm-cxxfilt's demangling of
rem each, as "mangled<TAB>demangled" lines in
rem crates\symbols\demangle\tests\data\rust-v0.txt, and the corpus as
rem Linux objects (testdata\elf\rust-*.o) for the size tests. Needs rustc and an LLVM build
rem with llvm-nm and llvm-cxxfilt (LLVM_BIN names its bin
rem directory).
setlocal
rem (Run from R:, the repository mapped: see ..\neutral.cmd.)
if /i not "%~d0"=="R:" (call "%~dp0..\neutral.cmd" "%~f0" & exit /b)
if "%LLVM_BIN%"=="" (echo set LLVM_BIN to the bin directory of an LLVM build or release 1>&2 & exit /b 1)
if "%PYTHON%"=="" set PYTHON=python
set WORK=%~dp0..\..\target\fixtures\rust
rem (The standard library's sources are named as in Rust's own builds, not
rem as wherever rustup put them.)
for /f "delims=" %%s in ('rustc --print sysroot') do set "REMAP=--remap-path-prefix=%%s=/rustc --remap-path-prefix=%~dp0="
if not exist "%WORK%" mkdir "%WORK%"
rustc --edition 2021 -C symbol-mangling-version=v0 -C opt-level=1 --emit obj -o "%WORK%\corpus.o" "%~dp0corpus.rs" || exit /b 1
"%LLVM_BIN%\llvm-nm.exe" --just-symbol-name "%WORK%\corpus.o" > "%WORK%\names.txt" || exit /b 1
rem Real-world names too: Hexcavator itself and its dependencies, built with v0
rem (the standard library stays legacy), from the rlibs' objects.
set RUSTFLAGS=-C symbol-mangling-version=v0
cargo build --release -q -p hexcavator --manifest-path "%~dp0..\..\Cargo.toml" --target-dir "%WORK%\target" || exit /b 1
set RUSTFLAGS=
for %%f in ("%WORK%\target\release\deps\*.rlib") do (
  "%LLVM_BIN%\llvm-nm.exe" --just-symbol-name "%%f" >> "%WORK%\names.txt" 2>nul
)
rem The corpus as Linux objects, in both manglings, for the size tests
rem (legacy, no longer the default, needs unstable options).
rustc --edition 2021 --target x86_64-unknown-linux-gnu -C symbol-mangling-version=v0 -C opt-level=1 %REMAP% --emit obj -o "%~dp0..\..\testdata\elf\rust-v0.o" "%~dp0corpus.rs" || exit /b 1
set RUSTC_BOOTSTRAP=1
rustc --edition 2021 --target x86_64-unknown-linux-gnu -Z unstable-options -C symbol-mangling-version=legacy -C opt-level=1 %REMAP% --emit obj -o "%~dp0..\..\testdata\elf\rust-legacy.o" "%~dp0corpus.rs" || exit /b 1
set RUSTC_BOOTSTRAP=
"%PYTHON%" -I "%~dp0pairs.py" "%LLVM_BIN%\llvm-cxxfilt.exe" "%WORK%\names.txt" "%~dp0..\..\crates\symbols\demangle\tests\data\rust-v0.txt" || exit /b 1
