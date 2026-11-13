@echo off
rem Builds testdata\linkmap: one program, linked from main.c and lib.a (used.c,
rem which it needs, and unused.c, which it does not) with dead stripping,
rem by ld.lld (ELF) and ld64.lld (Mach-O), with their maps and why-logs:
rem   elf.map (-Map), elf.why (--why-extract), elf.log (--why-live and
rem   --print-gc-sections, on standard output); macho.map (-map) and
rem   macho.log (-why_load and -why_live). LLVM_BIN names an LLVM bin directory.
setlocal
if "%LLVM_BIN%"=="" (echo set LLVM_BIN to the bin directory of an LLVM build or release 1>&2 & exit /b 1)
set OUT=%~dp0..\..\testdata\linkmap
if not exist "%OUT%" mkdir "%OUT%"
cd /d "%OUT%" || exit /b 1
set CF=-O1 -g0 -ffreestanding -fno-stack-protector -fno-asynchronous-unwind-tables -fno-ident -ffunction-sections -fdata-sections
for %%c in (main used unused) do "%LLVM_BIN%\clang.exe" --target=x86_64-linux-gnu %CF% -c "%~dp0%%c.c" -o %%c.o || exit /b 1
del lib.a 2>nul
"%LLVM_BIN%\llvm-ar.exe" rcsD lib.a used.o unused.o || exit /b 1
"%LLVM_BIN%\ld.lld.exe" -static --gc-sections -e _start -Map=elf.map --why-extract=elf.why --print-gc-sections --why-live=used_helper --why-live=shared_table main.o lib.a -o program-elf > elf.log 2>&1 || exit /b 1
del main.o used.o unused.o lib.a
for %%c in (main used unused) do "%LLVM_BIN%\clang.exe" --target=arm64-apple-macos13 %CF% -c "%~dp0%%c.c" -o %%c.o || exit /b 1
"%LLVM_BIN%\llvm-ar.exe" rcsD lib.a used.o unused.o || exit /b 1
"%LLVM_BIN%\ld64.lld.exe" -arch arm64 -platform_version macos 13.0 13.0 -dead_strip -e __start -map macho.map -why_load -why_live _used_helper -why_live _shared_table main.o lib.a -o program-macho > macho.log 2>&1 || exit /b 1
del main.o used.o unused.o lib.a
