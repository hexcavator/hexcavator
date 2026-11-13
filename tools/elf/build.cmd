@echo off
rem Builds Hexcavator's ELF test inputs into testdata\elf with clang and ld.lld
rem from LLVM (LLVM_BIN names its bin directory):
rem for each target, program-<t>.o (relocatable, -g) and program-<t>
rem (a static executable), plus a shared object and a stripped copy for
rem x86-64, and the llvm-readobj/llvm-nm output the tests compare with.
setlocal enabledelayedexpansion
if "%LLVM_BIN%"=="" (echo set LLVM_BIN to the bin directory of an LLVM build or release 1>&2 & exit /b 1)
set OUT=%~dp0..\..\testdata\elf
if not exist "%OUT%" mkdir "%OUT%"
cd /d "%OUT%" || exit /b 1
set CFLAGS=-O1 -g -ffreestanding -fno-stack-protector -fno-asynchronous-unwind-tables -fno-ident -ffile-prefix-map=%~dp0= -fdebug-compilation-dir=.
for %%t in (x86_64-linux-gnu i386-linux-gnu aarch64-linux-gnu aarch64_be-linux-gnu armeb-linux-gnueabi) do (
  set EXTRA=
  if %%t==armeb-linux-gnueabi set EXTRA=-march=armv7-a -mtp=cp15
  "%LLVM_BIN%\clang.exe" --target=%%t %CFLAGS% !EXTRA! -c "%~dp0program.c" -o program-%%t.o || exit /b 1
  "%LLVM_BIN%\ld.lld.exe" -static --build-id=sha1 -e _start program-%%t.o -o program-%%t || exit /b 1
)
rem 32-bit ARM, little-endian: A32 and Thumb, and llvm-objdump's listing
rem of each (decimal immediates, no bytes) for the disassembler's test.
for %%m in (arm thumb) do (
  "%LLVM_BIN%\clang.exe" --target=armv7a-linux-gnueabihf -m%%m -mtp=cp15 %CFLAGS% -c "%~dp0program.c" -o program-%%m-linux-gnueabihf.o || exit /b 1
  "%LLVM_BIN%\ld.lld.exe" -static --build-id=sha1 -e _start program-%%m-linux-gnueabihf.o -o program-%%m-linux-gnueabihf || exit /b 1
  "%LLVM_BIN%\llvm-objdump.exe" -d --no-print-imm-hex --no-show-raw-insn program-%%m-linux-gnueabihf > program-%%m-linux-gnueabihf.objdump.txt || exit /b 1
)
"%LLVM_BIN%\clang.exe" --target=x86_64-linux-gnu %CFLAGS% -fPIC -c "%~dp0program.c" -o program-pic.o || exit /b 1
"%LLVM_BIN%\ld.lld.exe" -shared --build-id=sha1 program-pic.o -o program.so || exit /b 1
del program-pic.o
rem Relative relocations, packed (RELR) and not (RELA), with the dynamic table.
"%LLVM_BIN%\clang.exe" --target=x86_64-linux-gnu -O1 -ffreestanding -fno-stack-protector -fno-asynchronous-unwind-tables -fno-ident -fPIC -c "%~dp0relr.c" -o relr.o || exit /b 1
"%LLVM_BIN%\ld.lld.exe" -shared --build-id=sha1 -z pack-relative-relocs relr.o -o relr.so || exit /b 1
"%LLVM_BIN%\ld.lld.exe" -shared --build-id=sha1 relr.o -o relr-rela.so || exit /b 1
rem Symbol versions: relr.o versioned by versions.map (both hash tables), and
rem consumer.c linked against it, needing those versions.
"%LLVM_BIN%\ld.lld.exe" -shared --build-id=sha1 --hash-style=both --version-script="%~dp0versions.map" -soname libversions.so relr.o -o libversions.so || exit /b 1
"%LLVM_BIN%\clang.exe" --target=x86_64-linux-gnu -O1 -ffreestanding -fno-stack-protector -fno-asynchronous-unwind-tables -fno-ident -fPIC -c "%~dp0consumer.c" -o consumer.o || exit /b 1
"%LLVM_BIN%\ld.lld.exe" -shared --build-id=sha1 --hash-style=both consumer.o libversions.so -o consumer.so || exit /b 1
del consumer.o
for %%f in (libversions.so consumer.so) do "%LLVM_BIN%\llvm-readobj.exe" --version-info --dyn-syms %%f > %%f.versions.txt || exit /b 1
del relr.o
rem Android's packed relocations (APS2), and the same unpacked.
"%LLVM_BIN%\clang.exe" --target=aarch64-linux-android29 -O1 -ffreestanding -fno-stack-protector -fno-ident -fPIC -c "%~dp0relr.c" -o relr-android.o || exit /b 1
"%LLVM_BIN%\ld.lld.exe" -shared --build-id=sha1 --pack-dyn-relocs=android relr-android.o -o relr-android.so || exit /b 1
"%LLVM_BIN%\ld.lld.exe" -shared --build-id=sha1 relr-android.o -o relr-android-rela.so || exit /b 1
del relr-android.o
for %%f in (relr-android.so relr-android-rela.so) do "%LLVM_BIN%\llvm-readobj.exe" --relocations %%f > %%f.readobj.txt || exit /b 1
for %%f in (relr.so relr-rela.so) do "%LLVM_BIN%\llvm-readobj.exe" --relocations --dynamic-table %%f > %%f.readobj.txt || exit /b 1
"%LLVM_BIN%\ld.lld.exe" -static -s --build-id=sha1 -e _start program-x86_64-linux-gnu.o -o program-stripped || exit /b 1
rem A stripped image and its separate debug file, as objcopy splits them
rem (the build ID kept in both).
"%LLVM_BIN%\llvm-objcopy.exe" --only-keep-debug program-x86_64-linux-gnu program-split.debug || exit /b 1
"%LLVM_BIN%\llvm-objcopy.exe" --strip-all program-x86_64-linux-gnu program-split || exit /b 1
rem Built with the mitigations checksec reads on: PIE, full RELRO, canaries,
rem and CET (x86-64) or BTI and PAC (AArch64).
set HFLAGS=-O1 -g0 -ffreestanding -fno-asynchronous-unwind-tables -fno-ident -fPIE -fstack-protector-all
"%LLVM_BIN%\clang.exe" --target=x86_64-linux-gnu %HFLAGS% -fcf-protection=full -c "%~dp0hardened.c" -o hardened.o || exit /b 1
"%LLVM_BIN%\ld.lld.exe" -pie -z now -z relro -z noexecstack --build-id=sha1 -e _start hardened.o -o hardened-x86_64-linux-gnu || exit /b 1
"%LLVM_BIN%\clang.exe" --target=aarch64-linux-gnu %HFLAGS% -mbranch-protection=standard -c "%~dp0hardened.c" -o hardened.o || exit /b 1
"%LLVM_BIN%\ld.lld.exe" -pie -z now -z relro --build-id=sha1 -e _start hardened.o -o hardened-aarch64-linux-gnu || exit /b 1
del hardened.o
rem The stripped image with its symbol table xz-compressed into
rem .gnu_debugdata (MiniDebugInfo), and xz streams for the decoder.
if "%PYTHON%"=="" set PYTHON=python
"%PYTHON%" -I "%~dp0minidebuginfo.py" "%LLVM_BIN%" program-x86_64-linux-gnu . || exit /b 1
rem The stripped image, linked to its debug file by name and CRC.
"%LLVM_BIN%\llvm-objcopy.exe" --add-gnu-debuglink=program-split.debug program-split program-linked || exit /b 1
rem C++ names (an object: no C++ runtime needed).
"%LLVM_BIN%\clang.exe" --target=x86_64-linux-gnu %CFLAGS% -fno-rtti -fno-exceptions -fno-inline -c "%~dp0names.cpp" -o names.o || exit /b 1
"%LLVM_BIN%\llvm-nm.exe" --defined-only names.o > names.o.nm.txt || exit /b 1
"%LLVM_BIN%\llvm-nm.exe" --defined-only --demangle names.o > names.o.nm-demangled.txt || exit /b 1
"%LLVM_BIN%\llvm-readobj.exe" --section-groups names.o > names.o.groups.txt || exit /b 1
rem Two compile units, DWARF 4 (with aranges) and 5, functions in their own
rem sections (so units have range lists), and llvm-dwarfdump's view.
for %%v in (4 5) do (
  for %%t in (x86_64-linux-gnu aarch64_be-linux-gnu) do (
    "%LLVM_BIN%\clang.exe" --target=%%t %CFLAGS% -gdwarf-%%v -gdwarf-aranges -ffunction-sections -fdata-sections -c "%~dp0program.c" -o dw-a.o || exit /b 1
    "%LLVM_BIN%\clang.exe" --target=%%t %CFLAGS% -gdwarf-%%v -gdwarf-aranges -ffunction-sections -fdata-sections -c "%~dp0second.c" -o dw-b.o || exit /b 1
    "%LLVM_BIN%\ld.lld.exe" -static -e _start dw-a.o dw-b.o -o dwarf%%v-%%t || exit /b 1
    "%LLVM_BIN%\llvm-dwarfdump.exe" --debug-info --debug-aranges dwarf%%v-%%t > dwarf%%v-%%t.dwarfdump.txt || exit /b 1
    "%LLVM_BIN%\llvm-dwarfdump.exe" --debug-line dwarf%%v-%%t > dwarf%%v-%%t.lines.txt || exit /b 1
    del dw-a.o dw-b.o
  )
)
rem Split DWARF (.dwo, .dwp).
call "%~dp0split.cmd" || exit /b 1
rem Its compressed-debug-section variants (zlib, zstd, GNU .zdebug).
if "%PYTHON%"=="" set PYTHON=python
"%PYTHON%" -I "%~dp0compress.py" dwarf5-x86_64-linux-gnu dwarf5-x86_64-linux-gnu || exit /b 1
rem An archive of two objects (deterministic: no dates, uids, or modes).
del program.a 2>nul
"%LLVM_BIN%\llvm-ar.exe" rcsD program.a program-x86_64-linux-gnu.o program-aarch64-linux-gnu.o || exit /b 1
rem With unwind tables (.eh_frame, .eh_frame_hdr) and relocations kept.
for %%t in (x86_64-linux-gnu aarch64_be-linux-gnu i386-linux-gnu) do (
  "%LLVM_BIN%\clang.exe" --target=%%t %CFLAGS:-fno-asynchronous-unwind-tables=% -funwind-tables -c "%~dp0program.c" -o unwind-%%t.o || exit /b 1
  "%LLVM_BIN%\ld.lld.exe" -static --eh-frame-hdr --emit-relocs -e _start unwind-%%t.o -o unwind-%%t || exit /b 1
  "%LLVM_BIN%\llvm-readobj.exe" --unwind --relocs unwind-%%t > unwind-%%t.unwind.txt || exit /b 1
  "%LLVM_BIN%\llvm-readobj.exe" --relocs unwind-%%t.o > unwind-%%t.o.relocs.txt || exit /b 1
)
rem Anonymous data only code refers to (-O2, for the lookup and jump
rem tables), and llvm-objdump's disassembly, which names the targets.
for %%t in (x86_64-linux-gnu aarch64-linux-gnu) do (
  "%LLVM_BIN%\clang.exe" --target=%%t %CFLAGS% -O2 -c "%~dp0refs.c" -o refs.o || exit /b 1
  "%LLVM_BIN%\ld.lld.exe" -static -e _start refs.o -o refs-%%t || exit /b 1
  "%LLVM_BIN%\llvm-objdump.exe" -d --no-show-raw-insn refs-%%t > refs-%%t.objdump.txt || exit /b 1
  del refs.o
)
for %%f in (program-*.o program-x86_64-linux-gnu program-i386-linux-gnu program-aarch64-linux-gnu program-aarch64_be-linux-gnu program-armeb-linux-gnueabi program.so program-stripped) do (
  "%LLVM_BIN%\llvm-readobj.exe" --file-headers --sections --program-headers --symbols --dyn-symbols --notes %%f > %%f.readobj.txt || exit /b 1
)
