@echo off
rem Builds Hexcavator's Mach-O test inputs into testdata\macho with clang and
rem ld64.lld from LLVM (LLVM_BIN names its bin directory):
rem for arm64 and x86_64, the objects (with DWARF), an executable, and a
rem dylib; a universal (fat) executable of both; and llvm-readobj's view.
setlocal enabledelayedexpansion
if "%LLVM_BIN%"=="" (echo set LLVM_BIN to the bin directory of an LLVM build or release 1>&2 & exit /b 1)
set OUT=%~dp0..\..\testdata\macho
if not exist "%OUT%" mkdir "%OUT%"
cd /d "%OUT%" || exit /b 1
set CFLAGS=-O1 -g -ffreestanding -fno-stack-protector -fno-ident -ffile-prefix-map=%~dp0= -fdebug-compilation-dir=.
for %%a in (arm64 x86_64) do (
  "%LLVM_BIN%\clang.exe" --target=%%a-apple-macos13 %CFLAGS% -c "%~dp0program.c" -o program-%%a.o || exit /b 1
  "%LLVM_BIN%\clang.exe" --target=%%a-apple-macos13 %CFLAGS% -c "%~dp0..\elf\second.c" -o second-%%a.o || exit /b 1
  "%LLVM_BIN%\ld64.lld.exe" -arch %%a -platform_version macos 13.0 13.0 -oso_prefix . -e _start program-%%a.o second-%%a.o -o program-%%a || exit /b 1
  "%LLVM_BIN%\ld64.lld.exe" -arch %%a -platform_version macos 13.0 13.0 -oso_prefix . -dylib -install_name @rpath/libsecond.dylib second-%%a.o -o libsecond-%%a.dylib || exit /b 1
)
rem Pointers: a dylib with rebases and a bind, linked with chained fixups and
rem with the older opcodes, and llvm-objdump's decoding of each.
for %%a in (arm64 x86_64) do (
  "%LLVM_BIN%\clang.exe" --target=%%a-apple-macos13 -O1 -ffreestanding -fno-stack-protector -fno-ident -c "%~dp0pointers.c" -o pointers-%%a.o || exit /b 1
  "%LLVM_BIN%\ld64.lld.exe" -arch %%a -platform_version macos 13.0 13.0 -dylib -undefined dynamic_lookup -install_name @rpath/libpointers.dylib pointers-%%a.o -o pointers-%%a.dylib || exit /b 1
  "%LLVM_BIN%\ld64.lld.exe" -arch %%a -platform_version macos 13.0 13.0 -dylib -undefined dynamic_lookup -no_fixup_chains -install_name @rpath/libpointers.dylib pointers-%%a.o -o pointers-%%a-opcodes.dylib || exit /b 1
  del pointers-%%a.o
  "%LLVM_BIN%\llvm-objdump.exe" --macho --dyld-info pointers-%%a.dylib > pointers-%%a.dylib.fixups.txt || exit /b 1
  "%LLVM_BIN%\llvm-objdump.exe" --macho --rebase --bind --lazy-bind --weak-bind pointers-%%a-opcodes.dylib > pointers-%%a-opcodes.dylib.fixups.txt || exit /b 1
)
rem Compact unwind: functions of several frame shapes, in a dylib, with
rem llvm-objdump's unwind info and function starts (and the programs').
for %%a in (arm64 x86_64) do (
  "%LLVM_BIN%\clang.exe" --target=%%a-apple-macos13 -O1 -fno-stack-protector -fno-ident -c "%~dp0unwind.c" -o unwind-%%a.o || exit /b 1
  "%LLVM_BIN%\ld64.lld.exe" -arch %%a -platform_version macos 13.0 13.0 -dylib -undefined dynamic_lookup -install_name @rpath/libunwind-test.dylib unwind-%%a.o -o unwind-%%a.dylib || exit /b 1
  del unwind-%%a.o
  for %%f in (unwind-%%a.dylib program-%%a) do "%LLVM_BIN%\llvm-objdump.exe" --macho --unwind-info --function-starts %%f > %%f.unwind.txt || exit /b 1
)
rem Objective-C metadata (objc.m: a root class of its own, so no SDK), in a
rem dylib linked with chained fixups and with the older opcodes, and
rem llvm-objdump's account of the latter (it reads chained pointers raw).
for %%a in (arm64 x86_64) do (
  "%LLVM_BIN%\clang.exe" --target=%%a-apple-macos13 -O1 -fno-stack-protector -fno-ident -fobjc-runtime=macosx-13.0 -c "%~dp0objc.m" -o objc-%%a.o || exit /b 1
  "%LLVM_BIN%\ld64.lld.exe" -arch %%a -platform_version macos 13.0 13.0 -dylib -undefined dynamic_lookup -install_name @rpath/libobjc-test.dylib objc-%%a.o -o objc-%%a.dylib || exit /b 1
  "%LLVM_BIN%\ld64.lld.exe" -arch %%a -platform_version macos 13.0 13.0 -dylib -undefined dynamic_lookup -no_fixup_chains -install_name @rpath/libobjc-test.dylib objc-%%a.o -o objc-%%a-opcodes.dylib || exit /b 1
  del objc-%%a.o
  "%LLVM_BIN%\llvm-objdump.exe" --macho --objc-meta-data objc-%%a-opcodes.dylib > objc-%%a-opcodes.dylib.objc.txt || exit /b 1
)
"%LLVM_BIN%\llvm-lipo.exe" -create program-arm64 program-x86_64 -output program-universal || exit /b 1
for %%f in (program-arm64 program-x86_64 program-arm64.o program-x86_64.o libsecond-arm64.dylib) do (
  "%LLVM_BIN%\llvm-readobj.exe" --file-headers --sections --symbols --macho-segment --macho-dysymtab --macho-version-min %%f > %%f.readobj.txt || exit /b 1
)
"%LLVM_BIN%\llvm-objdump.exe" --macho --private-headers program-arm64 > program-arm64.loadcmds.txt || exit /b 1
"%LLVM_BIN%\llvm-objdump.exe" --macho --universal-headers program-universal > program-universal.fat.txt || exit /b 1
rem The debug information of each executable, as dsymutil gathers it from
rem the objects into a dSYM (kept as the bare DWARF file).
for %%a in (arm64 x86_64) do (
  "%LLVM_BIN%\dsymutil.exe" program-%%a -o program-%%a.dSYM || exit /b 1
  copy /y program-%%a.dSYM\Contents\Resources\DWARF\program-%%a program-%%a.dwarf >nul || exit /b 1
  rmdir /s /q program-%%a.dSYM
)
rem Anonymous data only code refers to (see tools\elf\refs.c), -O2, and
rem llvm-objdump's disassembly, which names the targets.
for %%a in (arm64 x86_64) do (
  "%LLVM_BIN%\clang.exe" --target=%%a-apple-macos13 %CFLAGS% -O2 -c "%~dp0..\elf\refs.c" -o refs-%%a.o || exit /b 1
  "%LLVM_BIN%\ld64.lld.exe" -arch %%a -platform_version macos 13.0 13.0 -oso_prefix . -e __start refs-%%a.o -o refs-%%a || exit /b 1
  "%LLVM_BIN%\llvm-objdump.exe" -d --no-show-raw-insn refs-%%a > refs-%%a.objdump.txt || exit /b 1
  del refs-%%a.o
)
rem Static libraries (Darwin-format archives) of both objects, one per
rem architecture and a universal one, with llvm-ar's member listing.
for %%a in (arm64 x86_64) do (
  del libprogram-%%a.a 2>nul
  "%LLVM_BIN%\llvm-ar.exe" rcs --format=darwin libprogram-%%a.a program-%%a.o second-%%a.o || exit /b 1
)
"%LLVM_BIN%\llvm-lipo.exe" -create libprogram-arm64.a libprogram-x86_64.a -output libprogram-universal.a || exit /b 1
"%LLVM_BIN%\llvm-ar.exe" tv libprogram-arm64.a > libprogram-arm64.a.members.txt || exit /b 1
rem A debug map (no dSYM): in oso\, executables whose DWARF stays in their
rem objects, one object given whole and one a member of an archive, and
rem dsymutil's dSYM of each (as the bare DWARF file, named so that it isn't
rem found beside the image) for the tests to compare with.
if not exist oso mkdir oso
for %%a in (arm64 x86_64) do (
  copy /y program-%%a.o oso\program-%%a.o >nul || exit /b 1
  copy /y second-%%a.o oso\second-%%a.o >nul || exit /b 1
  pushd oso
  del libsecond-%%a.a 2>nul
  "%LLVM_BIN%\llvm-ar.exe" rcs --format=darwin libsecond-%%a.a second-%%a.o || exit /b 1
  del second-%%a.o
  "%LLVM_BIN%\ld64.lld.exe" -arch %%a -platform_version macos 13.0 13.0 -oso_prefix . -e _start program-%%a.o libsecond-%%a.a -o oso-%%a || exit /b 1
  "%LLVM_BIN%\dsymutil.exe" oso-%%a -o oso-%%a.dSYM || exit /b 1
  copy /y oso-%%a.dSYM\Contents\Resources\DWARF\oso-%%a oso-%%a.dsymutil >nul || exit /b 1
  rmdir /s /q oso-%%a.dSYM
  popd
)
del second-arm64.o second-x86_64.o
