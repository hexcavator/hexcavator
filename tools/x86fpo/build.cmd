@echo off
rem SPDX-License-Identifier: Apache-2.0
rem
rem Builds frames.exe (x86, MSVC) twice, into OUT (default
rem testdata\x86fpo): frames-fpo (/O2, frame pointers omitted) and
rem frames-fp (/O2 /Oy-), both with the static CRT, so the CRT's own
rem frames are described by the program's PDB; then takes each one's
rem synchronous snapshots. The PDBs kept are stripped (/PDBSTRIPPED):
rem public symbols and the FPO and FrameData records, all that stack
rem walking reads; the full ones stay in target\x86fpo. (Built there,
rem not in %TEMP%: PDBs record where they were built, and a path under
rem the user's profile would name the user.)
setlocal
set HERE=%~dp0
set OUT=%~1
if "%OUT%"=="" set OUT=%HERE%..\..\testdata\x86fpo
if not exist "%OUT%" mkdir "%OUT%"
for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -property installationPath`) do set VS=%%i
call "%VS%\VC\Auxiliary\Build\vcvarsall.bat" x64_x86 >nul || exit /b 1
set TMPD=%HERE%..\..\target\x86fpo
if not exist "%TMPD%" mkdir "%TMPD%"
pushd "%TMPD%"
ml /nologo /c /Zi /Fofpo.obj "%HERE%fpo.asm" || exit /b 1
for %%f in (fpo fp) do call :build %%f || exit /b 1
popd
exit /b 0

:build
set FLAGS=/O2 /Oy
if "%1"=="fp" set FLAGS=/O2 /Oy-
cl /nologo /c /Zi /MT /GS /EHsc %FLAGS% /Fdframes-%1.pdb "%HERE%frames.c" "%HERE%frames_eh.cpp" || exit /b 1
link /nologo /DEBUG /INCREMENTAL:NO /OPT:REF /OPT:ICF /PDBALTPATH:%%_PDB%% /out:"%OUT%\frames-%1.exe" /pdb:"%TMPD%\frames-%1.pdb" /PDBSTRIPPED:"%OUT%\frames-%1.pdb" frames.obj frames_eh.obj fpo.obj || exit /b 1
"%OUT%\frames-%1.exe" sync "%OUT%\frames-%1.sync" || exit /b 1
exit /b 0
