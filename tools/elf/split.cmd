@echo off
rem Builds split DWARF test inputs into testdata\elf (called by build.cmd):
rem for DWARF 4 (GNU's extension) and 5, the two compile units of program.c
rem and second.c split (skeletons in split-dwarf<v>, the rest in
rem sd<v>-program.dwo and sd<v>-second.dwo, named relative to the
rem compilation directory, .), the .dwo files packaged in split-dwarf<v>.dwp,
rem and the same program unsplit (split-dwarf<v>-plain), whose code is the
rem same.
setlocal enabledelayedexpansion
if "%LLVM_BIN%"=="" (echo set LLVM_BIN to the bin directory of an LLVM build or release 1>&2 & exit /b 1)
set OUT=%~dp0..\..\testdata\elf
cd /d "%OUT%" || exit /b 1
set CFLAGS=--target=x86_64-linux-gnu -O1 -g -ffreestanding -fno-stack-protector -fno-asynchronous-unwind-tables -fno-ident -ffile-prefix-map=%~dp0= -fdebug-compilation-dir=.
for %%v in (4 5) do (
  for %%s in (program second) do (
    "%LLVM_BIN%\clang.exe" %CFLAGS% -gdwarf-%%v -gsplit-dwarf -c "%~dp0%%s.c" -o sd%%v-%%s.o || exit /b 1
    "%LLVM_BIN%\clang.exe" %CFLAGS% -gdwarf-%%v -c "%~dp0%%s.c" -o sd%%v-%%s-plain.o || exit /b 1
  )
  "%LLVM_BIN%\ld.lld.exe" -static --build-id=sha1 -e _start sd%%v-program.o sd%%v-second.o -o split-dwarf%%v || exit /b 1
  "%LLVM_BIN%\ld.lld.exe" -static --build-id=sha1 -e _start sd%%v-program-plain.o sd%%v-second-plain.o -o split-dwarf%%v-plain || exit /b 1
  "%LLVM_BIN%\llvm-dwp.exe" -e split-dwarf%%v -o split-dwarf%%v.dwp || exit /b 1
  del sd%%v-program.o sd%%v-second.o sd%%v-program-plain.o sd%%v-second-plain.o
)
