@echo off
rem Builds the source lines test program for ELF (lines-elf.cpp, lines.h)
rem with clang and ld.lld from LLVM (LLVM_BIN names its bin directory), for
rem x86-64 Linux, as testdata\lines\lines-x86_64-linux-gnu (DWARF 5), and
rem lines-split-x86_64-linux-gnu with its split DWARF (lines-split.dwo);
rem then llvm-symbolizer's answers for each byte of their code (the
rem symbolize test compares with them).
setlocal
if "%LLVM_BIN%"=="" (echo set LLVM_BIN to the bin directory of an LLVM build or release 1>&2 & exit /b 1)
set OUT=%~dp0..\..\testdata\lines
if not exist "%OUT%" mkdir "%OUT%"
cd /d "%OUT%" || exit /b 1
set CFLAGS=--target=x86_64-linux-gnu -O2 -g -fms-extensions -ffreestanding -fno-exceptions -fno-asynchronous-unwind-tables -fno-ident -ffile-prefix-map=%~dp0= -fdebug-compilation-dir=.
"%LLVM_BIN%\clang++.exe" %CFLAGS% -c "%~dp0lines-elf.cpp" -o lines-elf.o || exit /b 1
"%LLVM_BIN%\ld.lld.exe" -static --build-id=sha1 -e _start lines-elf.o -o lines-x86_64-linux-gnu || exit /b 1
del lines-elf.o
"%LLVM_BIN%\clang++.exe" %CFLAGS% -gsplit-dwarf -c "%~dp0lines-elf.cpp" -o lines-split.o || exit /b 1
"%LLVM_BIN%\ld.lld.exe" -static --build-id=sha1 -e _start lines-split.o -o lines-split-x86_64-linux-gnu || exit /b 1
del lines-split.o
for %%f in (lines-x86_64-linux-gnu lines-split-x86_64-linux-gnu) do (
  python "%~dp0symbolize-oracle.py" "%LLVM_BIN%\llvm-symbolizer.exe" %%f > %%f.symbolize.txt || exit /b 1
)
exit /b 0
