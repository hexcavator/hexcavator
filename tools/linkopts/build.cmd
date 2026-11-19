@echo off
rem Builds the link-option test inputs into testdata\linkopts with clang and
rem ld.lld from LLVM (LLVM_BIN names its bin directory): static x86-64
rem executables, with DWARF, linked with and without --gc-sections and
rem --icf=all, for what hexc recommend judges a link did from what it left.
rem
rem   funcs-<link>        funcs.c (-ffunction-sections -fdata-sections),
rem                       linked plain, -gc, -icf, -gc-icf; and
rem                       funcs-nosections-gc-icf, compiled without them.
rem   eh, eh-icf          eh.cpp twice (N=1, N=2) and eh-main.cpp, with
rem                       exceptions: work<N> has an LSDA, which ICF keeps.
rem   dup, dup-icf        dup.c three times (USE=use_a, use_b, use_c),
rem                       other.c, and dup-main.c: constants copied (a
rem                       header's, dup.c's), and variables alike.
setlocal
if "%LLVM_BIN%"=="" (echo set LLVM_BIN to the bin directory of an LLVM build or release 1>&2 & exit /b 1)
set OUT=%~dp0..\..\testdata\linkopts
if not exist "%OUT%" mkdir "%OUT%"
set WORK=%~dp0..\..\target\fixtures\linkopts
if exist "%WORK%" rmdir /s /q "%WORK%"
mkdir "%WORK%"
cd /d "%WORK%" || exit /b 1
set CC="%LLVM_BIN%\clang.exe" --target=x86_64-linux-gnu -O2 -g -ffreestanding -fno-stack-protector -fno-ident -ffile-prefix-map=%~dp0= -fdebug-compilation-dir=.
set SECTIONS=-ffunction-sections -fdata-sections
set LD="%LLVM_BIN%\ld.lld.exe" -static --build-id=sha1 -e _start
rem (eh.cpp's personality and unwinder aren't linked: nothing runs these.)
set EHLD=%LD% --unresolved-symbols=ignore-all

%CC% %SECTIONS% -fno-asynchronous-unwind-tables -c "%~dp0funcs.c" -o funcs.o || exit /b 1
%CC% -fno-asynchronous-unwind-tables -c "%~dp0funcs.c" -o funcs-nosections.o || exit /b 1
%LD% funcs.o -o "%OUT%\funcs-plain" || exit /b 1
%LD% --gc-sections funcs.o -o "%OUT%\funcs-gc" || exit /b 1
%LD% --icf=all funcs.o -o "%OUT%\funcs-icf" || exit /b 1
%LD% --gc-sections --icf=all funcs.o -o "%OUT%\funcs-gc-icf" || exit /b 1
%LD% --gc-sections --icf=all funcs-nosections.o -o "%OUT%\funcs-nosections-gc-icf" || exit /b 1

%CC% %SECTIONS% -DN=1 -c "%~dp0eh.cpp" -o eh1.o || exit /b 1
%CC% %SECTIONS% -DN=2 -c "%~dp0eh.cpp" -o eh2.o || exit /b 1
%CC% %SECTIONS% -c "%~dp0eh-main.cpp" -o eh-main.o || exit /b 1
%EHLD% --gc-sections eh1.o eh2.o eh-main.o -o "%OUT%\eh" || exit /b 1
%EHLD% --gc-sections --icf=all eh1.o eh2.o eh-main.o -o "%OUT%\eh-icf" || exit /b 1

for %%u in (use_a use_b use_c) do (
  %CC% %SECTIONS% -fno-asynchronous-unwind-tables -DUSE=%%u -c "%~dp0dup.c" -o %%u.o || exit /b 1
)
%CC% %SECTIONS% -fno-asynchronous-unwind-tables -c "%~dp0other.c" -o other.o || exit /b 1
%CC% %SECTIONS% -fno-asynchronous-unwind-tables -c "%~dp0dup-main.c" -o dup-main.o || exit /b 1
%LD% --gc-sections use_a.o use_b.o use_c.o other.o dup-main.o -o "%OUT%\dup" || exit /b 1
%LD% --gc-sections --icf=all use_a.o use_b.o use_c.o other.o dup-main.o -o "%OUT%\dup-icf" || exit /b 1
