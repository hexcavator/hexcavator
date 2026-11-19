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
rem   funcs-rec           funcs.c with its options recorded in DW_AT_producer
rem                       (as -grecord-command-line would), linked plain.
rem   funcs-rec-nosections-gc-icf
rem                       funcs.c without -ffunction-sections, its options
rem                       in .GCC.command.line (as -frecord-command-line).
rem   libexp.so, libexp-bsymbolic.so, libexp-hidden.so, exp-main
rem                       exp.cpp's exports (see below), and an importer.
rem   near                near.cpp: templates' instantiations alike but for
rem                       sizes (total<T>) or callees (apply<F>), and some
rem                       that differ (pick<T>).
rem   inline              inline.cpp: a function inlined where calls would
rem                       cost less (mix), and one where they wouldn't (get).
rem   libptrs.so          ptrs.cpp: a table of string pointers and a vtable,
rem                       their relocations RELA (not packed).
rem   strings             paths.c (__FILE__, absolute, by #line), strs-a.c and
rem                       strs-b.c (a literal in both, merged; arrays alike,
rem                       not).
rem (What's recorded is given to clang's cc1 as its driver would, so no
rem path of this machine's is: the driver would record its own.)
rem   macho-<link>        funcs.c for arm64 macOS (-O2 recorded), linked by
rem                       ld64.lld plain, -icf, -dead, -dead-icf; the debug
rem                       map names macho-funcs.o beside them.
rem   macho-ld, macho-ld-O1
rem                       linked plain (from macho-funcs.o, and from
rem                       macho-funcs-O1.o, -O1 recorded), then marked as
rem                       Apple's ld's (as-apple-ld.py), which folds
rem                       identical functions unless given -no_deduplicate
rem                       (as clang does when it links at -O0 or -O1).
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
%CC% %SECTIONS% -fno-asynchronous-unwind-tables -Xclang -dwarf-debug-flags -Xclang "clang -O2 -g -ffunction-sections -fdata-sections -c funcs.c" -c "%~dp0funcs.c" -o funcs-rec.o || exit /b 1
%CC% -fno-asynchronous-unwind-tables -Xclang -record-command-line -Xclang "clang -O2 -g -c funcs.c" -c "%~dp0funcs.c" -o funcs-rec-nosections.o || exit /b 1
%LD% funcs-rec.o -o "%OUT%\funcs-rec" || exit /b 1
%LD% --gc-sections --icf=all funcs-rec-nosections.o -o "%OUT%\funcs-rec-nosections-gc-icf" || exit /b 1

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

rem Mach-O: linked in testdata\linkopts, so the debug map's objects are
rem named beside the images.
cd /d "%OUT%" || exit /b 1
set MCC="%LLVM_BIN%\clang.exe" --target=arm64-apple-macos13 -g -ffreestanding -fno-stack-protector -fno-ident -ffile-prefix-map=%~dp0= -fdebug-compilation-dir=.
set MLD="%LLVM_BIN%\ld64.lld.exe" -arch arm64 -platform_version macos 13.0 13.0 -oso_prefix . -e __start
%MCC% -O2 -Xclang -dwarf-debug-flags -Xclang "clang -O2 -g -c funcs.c" -c "%~dp0funcs.c" -o macho-funcs.o || exit /b 1
%MCC% -O1 -Xclang -dwarf-debug-flags -Xclang "clang -O1 -g -c funcs.c" -c "%~dp0funcs.c" -o macho-funcs-O1.o || exit /b 1
%MLD% macho-funcs.o -o macho-plain || exit /b 1
%MLD% --icf=all macho-funcs.o -o macho-icf || exit /b 1
%MLD% -dead_strip macho-funcs.o -o macho-dead || exit /b 1
%MLD% -dead_strip --icf=all macho-funcs.o -o macho-dead-icf || exit /b 1
%MLD% macho-funcs.o -o macho-ld || exit /b 1
%MLD% macho-funcs-O1.o -o macho-ld-O1 || exit /b 1
python "%~dp0as-apple-ld.py" macho-ld || exit /b 1
python "%~dp0as-apple-ld.py" macho-ld-O1 || exit /b 1

rem Exports: libexp.so (exp.cpp: exported functions calling each other,
rem and template instantiations and inline functions exported with them),
rem plain, -Bsymbolic-functions, and -fvisibility=hidden (its API marked);
rem and exp-main, a PIE importing exp_used only. No debug information.
set XCC="%LLVM_BIN%\clang.exe" --target=x86_64-linux-gnu -O1 -fPIC -ffreestanding -fno-stack-protector -fno-exceptions -fno-rtti -fno-ident -fno-asynchronous-unwind-tables -fno-inline-functions -I"%~dp0."
set XLD="%LLVM_BIN%\ld.lld.exe" --hash-style=gnu --build-id=sha1
cd /d "%WORK%" || exit /b 1
%XCC% -c "%~dp0exp.cpp" -o exp.o || exit /b 1
%XCC% -fvisibility=hidden -c "%~dp0exp.cpp" -o exp-hidden.o || exit /b 1
%XCC% -c "%~dp0exp-main.cpp" -o exp-main.o || exit /b 1
%XLD% -shared -soname libexp.so exp.o -o "%OUT%\libexp.so" || exit /b 1
%XLD% -shared -soname libexp.so -Bsymbolic-functions exp.o -o "%OUT%\libexp-bsymbolic.so" || exit /b 1
%XLD% -shared -soname libexp.so exp-hidden.o -o "%OUT%\libexp-hidden.so" || exit /b 1
%XLD% -pie -e _start exp-main.o "%OUT%\libexp.so" -o "%OUT%\exp-main" || exit /b 1

rem Near-identical functions: near, with DWARF, linked with --gc-sections.
%CC% %SECTIONS% -fno-asynchronous-unwind-tables -fno-exceptions -c "%~dp0near.cpp" -o near.o || exit /b 1
%LD% --gc-sections near.o -o "%OUT%\near" || exit /b 1

rem Inlining: inline, with DWARF.
%CC% %SECTIONS% -fno-asynchronous-unwind-tables -fno-exceptions -c "%~dp0inline.cpp" -o inline.o || exit /b 1
%LD% --gc-sections inline.o -o "%OUT%/inline" || exit /b 1

rem Pointer tables: libptrs.so, with DWARF.
%CC% %SECTIONS% -fPIC -fvisibility=hidden -fno-asynchronous-unwind-tables -fno-exceptions -fno-rtti -c "%~dp0ptrs.cpp" -o ptrs.o || exit /b 1
"%LLVM_BIN%\ld.lld.exe" -shared --build-id=sha1 --hash-style=gnu -soname libptrs.so ptrs.o -o "%OUT%/libptrs.so" || exit /b 1

rem Strings: strings, with DWARF.
%CC% %SECTIONS% -fno-asynchronous-unwind-tables -c "%~dp0paths.c" -o paths.o || exit /b 1
%CC% %SECTIONS% -fno-asynchronous-unwind-tables -c "%~dp0strs-a.c" -o strs-a.o || exit /b 1
%CC% %SECTIONS% -fno-asynchronous-unwind-tables -c "%~dp0strs-b.c" -o strs-b.o || exit /b 1
%LD% --gc-sections paths.o strs-a.o strs-b.o -o "%OUT%/strings" || exit /b 1
