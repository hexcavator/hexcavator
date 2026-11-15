@echo off
rem Builds the dependency test's ELF and Mach-O images (testdata\deps\elf,
rem testdata\deps\macho) with clang and lld from LLVM (LLVM_BIN names its bin
rem directory). ELF: a program, its libraries (rpath, runpath, an inherited
rem rpath, ld.so.conf's, one for another architecture), and a system root
rem (an interpreter, libc with symbol versions, etc/ld.so.conf with an
rem include). Mach-O: a program, its libraries (@rpath, @loader_path, a
rem re-export, one that lost a symbol), and an empty system root.
setlocal
if "%LLVM_BIN%"=="" (echo set LLVM_BIN to the bin directory of an LLVM build or release 1>&2 & exit /b 1)
set SRC=%~dp0unix
set OUT=%~dp0..\..\testdata\deps
set WORK=%~dp0..\..\target\fixtures\deps-unix
if exist "%WORK%" rmdir /s /q "%WORK%"
mkdir "%WORK%" || exit /b 1
cd /d "%WORK%" || exit /b 1
for %%d in (elf macho) do if exist "%OUT%\%%d" rmdir /s /q "%OUT%\%%d"
set E=%OUT%\elf
for %%d in (app\lib app\libb sysroot\lib64 sysroot\lib\x86_64-linux-gnu sysroot\etc\ld.so.conf.d sysroot\opt\lib) do mkdir "%E%\%%d"
set CC="%LLVM_BIN%\clang.exe" --target=x86_64-linux-gnu -O1 -fPIC -ffreestanding -fno-asynchronous-unwind-tables -fno-ident -fno-stack-protector
set LD="%LLVM_BIN%\ld.lld.exe" --build-id=none --hash-style=both
for %%f in (app app-ok a b inh opt libc interp) do %CC% -c "%SRC%\%%f.c" -o %%f.o || exit /b 1
"%LLVM_BIN%\clang.exe" --target=aarch64-linux-gnu -O1 -fPIC -ffreestanding -fno-ident -c "%SRC%\wrong.c" -o wrong.o || exit /b 1
%LD% -shared -soname ld-linux-x86-64.so.2 interp.o -o "%E%\sysroot\lib64\ld-linux-x86-64.so.2" || exit /b 1
%LD% -shared -soname libc.so.6 --version-script="%SRC%\libc.map" libc.o -o "%E%\sysroot\lib\x86_64-linux-gnu\libc.so.6" || exit /b 1
%LD% -shared -soname libopt.so opt.o -o "%E%\sysroot\opt\lib\libopt.so" || exit /b 1
%LD% -shared -soname libinh.so inh.o -o "%E%\app\lib\libinh.so" || exit /b 1
%LD% -shared -soname libb.so b.o "%E%\app\lib\libinh.so" -o "%E%\app\libb\libb.so" || exit /b 1
%LD% -shared -soname liba.so --enable-new-dtags -rpath "$ORIGIN/../libb" a.o "%E%\app\libb\libb.so" "%E%\sysroot\opt\lib\libopt.so" -o "%E%\app\lib\liba.so" || exit /b 1
"%LLVM_BIN%\ld.lld.exe" --build-id=none -shared -soname libwrong.so wrong.o -o "%E%\app\lib\libwrong.so" || exit /b 1
rem (The program links against an x86-64 libwrong; the one shipped is AArch64.)
%CC% -c "%SRC%\wrong.c" -o wrong64.o || exit /b 1
%LD% -shared -soname libwrong.so wrong64.o -o libwrong.so || exit /b 1
%LD% --disable-new-dtags -rpath "$ORIGIN/lib" -dynamic-linker /lib64/ld-linux-x86-64.so.2 -e _start app.o "%E%\app\lib\liba.so" libwrong.so "%E%\sysroot\lib\x86_64-linux-gnu\libc.so.6" -o "%E%\app\app" || exit /b 1
rem The second program: linked against a newer libc (vers_fn at GLIBC_2.99).
%LD% -shared -soname libc.so.6 --version-script="%SRC%\libc-new.map" libc.o -o libc.so.6 || exit /b 1
%LD% --disable-new-dtags -rpath "$ORIGIN/lib" -dynamic-linker /lib64/ld-linux-x86-64.so.2 -e _start app-ok.o "%E%\app\lib\liba.so" libc.so.6 -o "%E%\app\app-ok" || exit /b 1
> "%E%\sysroot\etc\ld.so.conf" echo include /etc/ld.so.conf.d/*.conf
> "%E%\sysroot\etc\ld.so.conf.d\opt.conf" echo /opt/lib
set M=%OUT%\macho
for %%d in (app\lib sysroot) do mkdir "%M%\%%d"
rem (An empty system root: libSystem is the shared cache's.)
> "%M%\sysroot\README" echo The Mach-O dependency test's system root: libraries in /usr/lib are the dyld shared cache's.
set MC="%LLVM_BIN%\clang.exe" --target=arm64-apple-macos11 -O1 -fno-ident
set ML="%LLVM_BIN%\ld64.lld.exe" -arch arm64 -platform_version macos 11.0 11.0
for %%f in (main a b re weak system) do %MC% -c "%SRC%\macho-%%f.c" -o m-%%f.o || exit /b 1
%MC% -DOLD -c "%SRC%\macho-a.c" -o m-a-old.o || exit /b 1
%ML% -dylib -install_name /usr/lib/libSystem.B.dylib m-system.o -o libSystem.B.dylib || exit /b 1
%ML% -dylib -install_name @rpath/libb.dylib m-b.o libSystem.B.dylib -o "%M%\app\lib\libb.dylib" || exit /b 1
rem (libre by @loader_path: beside liba; a copy beside the liba linked
rem against, where the linker looks for it.)
%ML% -dylib -install_name @loader_path/libre.dylib m-re.o libSystem.B.dylib -o libre.dylib || exit /b 1
copy /y libre.dylib "%M%\app\lib\libre.dylib" >nul || exit /b 1
%ML% -dylib -install_name @rpath/libweak.dylib m-weak.o libSystem.B.dylib -o libweak.dylib || exit /b 1
for %%v in (a-old a) do (
  %ML% -dylib -install_name @rpath/liba.dylib -rpath @loader_path m-%%v.o "%M%\app\lib\libb.dylib" -reexport_library libre.dylib libSystem.B.dylib -o lib%%v.dylib || exit /b 1
)
copy /y liba.dylib "%M%\app\lib\liba.dylib" >nul || exit /b 1
%ML% -rpath @executable_path/lib m-main.o liba-old.dylib -weak_library libweak.dylib libSystem.B.dylib -o "%M%\app\main" || exit /b 1
exit /b 0
