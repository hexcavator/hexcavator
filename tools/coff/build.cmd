@echo off
rem Builds Hexcavator's COFF test inputs into testdata\coff: objects.obj (/Z7,
rem /Gy), objects-big.obj (/bigobj), objects.lib (both), and imports.lib
rem (an import library from imports.def).
setlocal
rem (Run from R:, the repository mapped: see ..\neutral.cmd.)
if /i not "%~d0"=="R:" (call "%~dp0..\neutral.cmd" "%~f0" & exit /b)
set OUT=%~dp0..\..\testdata\coff
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do set VS=%%i
call "%VS%\VC\Auxiliary\Build\vcvarsall.bat" amd64 >nul 2>&1 || exit /b 1
cd /d "%OUT%" || exit /b 1
cl /nologo /c /O1 /Gy /Z7 /GS- /Brepro "%~dp0objects.cpp" /Fo:objects.obj || exit /b 1
cl /nologo /c /O1 /Gy /Z7 /GS- /Brepro /bigobj "%~dp0objects.cpp" /Fo:objects-big.obj || exit /b 1
lib /nologo /Brepro /out:objects.lib objects.obj objects-big.obj || exit /b 1
lib /nologo /Brepro /machine:x64 /def:"%~dp0imports.def" /out:imports.lib || exit /b 1
del imports.exp
rem The tools' views of the libraries, which the archive tests compare with:
rem the members (lib /list) and the symbol index (dumpbin /linkermember:2).
for %%l in (objects imports) do (
  lib /nologo /list %%l.lib > %%l.lib.list.txt || exit /b 1
  dumpbin /nologo /linkermember:2 %%l.lib > %%l.lib.linkermember.txt || exit /b 1
)
