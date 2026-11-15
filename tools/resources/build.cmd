@echo off
rem Builds the resource test images into testdata\resources:
rem   resources.exe: the test program (resources.c) with resources.rc's
rem     resources, built with MSVC (rc, mc) for x64; the images drawn by
rem     images.py.
rem   resources-x86_64-linux-gnu: an ELF program (unix.c) with an ABI tag
rem     note, a build ID, and package metadata (ld.lld's).
rem   resources-arm64: a Mach-O program with an Info.plist (__TEXT,
rem     __info_plist), its ad-hoc signature given entitlements (entitle.py).
rem LLVM_BIN names the bin directory of an LLVM build or release; PYTHON,
rem a Python (default: python).
setlocal
rem (Run from R:, the repository mapped: see ..\neutral.cmd.)
if /i not "%~d0"=="R:" (call "%~dp0..\neutral.cmd" "%~f0" & exit /b)
if "%LLVM_BIN%"=="" (echo set LLVM_BIN to the bin directory of an LLVM build or release 1>&2 & exit /b 1)
if "%PYTHON%"=="" set PYTHON=python
set OUT=%~dp0..\..\testdata\resources
if not exist "%OUT%" mkdir "%OUT%"
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do set VS=%%i
call "%VS%\VC\Auxiliary\Build\vcvarsall.bat" amd64 >nul 2>&1 || exit /b 1
set WORK=%~dp0..\..\target\fixtures\resources
if exist "%WORK%" rmdir /s /q "%WORK%"
mkdir "%WORK%"
cd /d "%WORK%" || exit /b 1
for %%f in (resources.rc app.manifest readme.html messages.mc) do copy /y "%~dp0%%f" . >nul || exit /b 1
"%PYTHON%" -I "%~dp0images.py" . || exit /b 1
mc messages.mc >nul || exit /b 1
rc /nologo /n resources.rc || exit /b 1
cl /nologo /c /O1 /GS- "%~dp0resources.c" || exit /b 1
link /nologo /ENTRY:main /SUBSYSTEM:WINDOWS /NODEFAULTLIB /INCREMENTAL:NO /Brepro resources.obj resources.res /OUT:resources.exe >nul || exit /b 1
copy /y resources.exe "%OUT%\resources.exe" >nul || exit /b 1
"%LLVM_BIN%\clang.exe" --target=x86_64-linux-gnu -O1 -ffreestanding -fno-asynchronous-unwind-tables -fno-ident -fno-stack-protector -c "%~dp0unix.c" -o unix.o || exit /b 1
"%LLVM_BIN%\ld.lld.exe" --build-id=sha1 "--package-metadata={\"type\":\"deb\",\"name\":\"resources\",\"version\":\"1.2.3\"}" -e _start unix.o -o "%OUT%\resources-x86_64-linux-gnu" || exit /b 1
echo int main(void) { return 0; } > macho.c
"%LLVM_BIN%\clang.exe" --target=arm64-apple-macos12 -O1 -fno-ident -c macho.c -o macho.o || exit /b 1
"%LLVM_BIN%\ld64.lld.exe" -arch arm64 -platform_version macos 12.0 14.0 -e _main -adhoc_codesign -sectcreate __TEXT __info_plist "%~dp0Info.plist" macho.o -o resources-arm64 || exit /b 1
"%PYTHON%" -I "%~dp0entitle.py" resources-arm64 "%~dp0entitlements.plist" || exit /b 1
copy /y resources-arm64 "%OUT%\resources-arm64" >nul || exit /b 1
exit /b 0
