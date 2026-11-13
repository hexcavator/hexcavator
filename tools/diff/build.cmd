@echo off
rem Builds two versions of diff.cpp with MSVC for x64, to compare:
rem testdata\diff\diff-v1.exe and diff-v2.exe (V2 defined), each with its
rem PDB. Between them a function is added, one removed, and one changed,
rem and data likewise (see diff.cpp). The C runtime is the DLL (/MD), to
rem keep the PDBs small.
setlocal
rem (Run from R:, the repository mapped: see ..\neutral.cmd.)
if /i not "%~d0"=="R:" (call "%~dp0..\neutral.cmd" "%~f0" & exit /b)
set OUT=%~dp0..\..\testdata\diff
if not exist "%OUT%" mkdir "%OUT%"
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do set VS=%%i
call "%VS%\VC\Auxiliary\Build\vcvarsall.bat" amd64 >nul 2>&1 || exit /b 1
call :build v1 || exit /b 1
call :build v2 /DV2 || exit /b 1
exit /b 0

:build
setlocal
set WORK=%~dp0..\..\target\fixtures\diff-%1
rem Fresh each time: the linker updates an existing PDB in place.
if exist "%WORK%" rmdir /s /q "%WORK%"
mkdir "%WORK%"
cd /d "%WORK%" || exit /b 1
cl /nologo /c /O1 /MD /Gy /EHsc /Zi /std:c++20 %2 /Fddiff.pdb "%~dp0diff.cpp" || exit /b 1
link /nologo /DEBUG:FULL /OPT:REF /OPT:ICF /INCREMENTAL:NO /Brepro /PDB:diff-%1.pdb diff.obj /OUT:diff-%1.exe >nul || exit /b 1
for %%f in (exe pdb) do copy /y diff-%1.%%f "%OUT%\diff-%1.%%f" >nul || exit /b 1
exit /b 0
