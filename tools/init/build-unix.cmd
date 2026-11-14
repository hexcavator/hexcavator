@echo off
rem Builds the initialization test program for ELF (init-unix.c) and Mach-O
rem (init-macho.c) with clang, lld, and dsymutil from LLVM (LLVM_BIN names
rem its bin directory): testdata\init\init-x86_64-linux-gnu (a position-
rem independent program: its lists' entries are the loader's relocations),
rem libinit-x86_64-linux-gnu.so, and init-arm64 with its dSYM.
setlocal
if "%LLVM_BIN%"=="" (echo set LLVM_BIN to the bin directory of an LLVM build or release 1>&2 & exit /b 1)
set OUT=%~dp0..\..\testdata\init
if not exist "%OUT%" mkdir "%OUT%"
set WORK=%~dp0..\..\target\fixtures\init-unix
if exist "%WORK%" rmdir /s /q "%WORK%"
mkdir "%WORK%"
cd /d "%WORK%" || exit /b 1
copy /y "%~dp0init-unix.c" . >nul && copy /y "%~dp0init-macho.c" . >nul || exit /b 1
set CC="%LLVM_BIN%\clang.exe" --target=x86_64-linux-gnu -O1 -g -fPIC -ffreestanding -fno-asynchronous-unwind-tables -fno-ident -fno-stack-protector -fdebug-compilation-dir=.
set LD="%LLVM_BIN%\ld.lld.exe" --build-id=sha1 -init=init_function
%CC% -c init-unix.c -o init.o || exit /b 1
%LD% -pie -dynamic-linker /lib64/ld-linux-x86-64.so.2 -e _start init.o -o "%OUT%\init-x86_64-linux-gnu" || exit /b 1
%CC% -DLIB -c init-unix.c -o libinit.o || exit /b 1
%LD% -shared -soname libinit.so libinit.o -o "%OUT%\libinit-x86_64-linux-gnu.so" || exit /b 1
rem Mach-O: against a stand-in for libSystem (its binder), not shipped.
echo int stub_binder(void) __asm__("dyld_stub_binder"); int stub_binder(void) { return 0; } > system.c
set MC="%LLVM_BIN%\clang.exe" --target=arm64-apple-macos11 -O1 -g -fno-ident -fdebug-compilation-dir=.
%MC% -c system.c -o system.o || exit /b 1
"%LLVM_BIN%\ld64.lld.exe" -arch arm64 -platform_version macos 11.0 11.0 -dylib -install_name /usr/lib/libSystem.B.dylib system.o -o libSystem.B.dylib || exit /b 1
%MC% -c init-macho.c -o init-macho.o || exit /b 1
"%LLVM_BIN%\ld64.lld.exe" -arch arm64 -platform_version macos 11.0 11.0 init-macho.o libSystem.B.dylib -o init-arm64 || exit /b 1
"%LLVM_BIN%\dsymutil.exe" init-arm64 -o init-arm64.dSYM || exit /b 1
copy /y init-arm64 "%OUT%\init-arm64" >nul || exit /b 1
if exist "%OUT%\init-arm64.dSYM" rmdir /s /q "%OUT%\init-arm64.dSYM"
xcopy /e /i /q init-arm64.dSYM "%OUT%\init-arm64.dSYM" >nul || exit /b 1
exit /b 0
