@echo off
rem Builds the type layout test program (types.cpp) with clang and ld.lld
rem for x86-64 Linux, as testdata\types\types-x86_64-linux-gnu (and -v2:
rem Padded reordered, Grows grown), with DWARF 5: the same types as the
rem MSVC builds' PDBs (build.cmd), for comparing the two. There is no C
rem library: a one-line stdio.h declares printf, which stays unresolved.
rem LLVM_BIN names LLVM's bin directory.
setlocal
rem (Run from R:, the repository mapped: see ..\neutral.cmd.)
if /i not "%~d0"=="R:" (call "%~dp0..\neutral.cmd" "%~f0" & exit /b)
if "%LLVM_BIN%"=="" (echo set LLVM_BIN to the bin directory of an LLVM build or release 1>&2 & exit /b 1)
set OUT=%~dp0..\..\testdata\types
set WORK=%~dp0..\..\target\fixtures\types-dwarf
if exist "%WORK%" rmdir /s /q "%WORK%"
mkdir "%WORK%\include"
echo extern "C" int printf(const char *, ...); > "%WORK%\include\stdio.h"
cd /d "%WORK%" || exit /b 1
set FLAGS=--target=x86_64-linux-gnu -O1 -g -gdwarf-5 -nostdinc -isystem "%WORK%\include" -fno-exceptions -fno-asynchronous-unwind-tables -fno-ident -ffile-prefix-map=%~dp0= -ffile-prefix-map=%WORK%\= -fdebug-compilation-dir=.
call :build types-x86_64-linux-gnu "" || exit /b 1
call :build types-x86_64-linux-gnu-v2 -DV2 || exit /b 1
rem With a name index (.debug_names), and llvm-dwarfdump's view of it.
call :build types-x86_64-linux-gnu-names -gpubnames || exit /b 1
"%LLVM_BIN%\llvm-dwarfdump.exe" --debug-names "%OUT%\types-x86_64-linux-gnu-names" > "%OUT%\types-x86_64-linux-gnu-names.names.txt" || exit /b 1
rem Split (-gsplit-dwarf), with type units (-fdebug-types-section), DWARF 4
rem and 5: the image, its .dwo file, and its .dwp package; and the same
rem unsplit (-plain).
for %%v in (4 5) do (
  call :link types-split%%v "-gdwarf-%%v -gsplit-dwarf -fdebug-types-section" || exit /b 1
  copy /y types-split%%v.dwo "%OUT%" >nul || exit /b 1
  "%LLVM_BIN%\llvm-dwp.exe" -e "%OUT%\types-split%%v" -o "%OUT%\types-split%%v.dwp" || exit /b 1
  call :link types-split%%v-plain "-gdwarf-%%v -fdebug-types-section" || exit /b 1
)
exit /b 0

:build
call :link %1 %2 || exit /b 1
"%LLVM_BIN%\llvm-dwarfdump.exe" --debug-info "%OUT%\%1" > "%OUT%\%1.dwarfdump.txt" || exit /b 1
exit /b 0

:link
"%LLVM_BIN%\clang++.exe" %FLAGS% %~2 -c "%~dp0types.cpp" -o %1.o || exit /b 1
"%LLVM_BIN%\ld.lld.exe" -static --build-id=sha1 -e main --unresolved-symbols=ignore-all %1.o -o "%OUT%\%1" || exit /b 1
exit /b 0
