@echo off
rem Builds the source lines test program (lines.cpp, lines.h) with MSVC for
rem x64, as testdata\lines\lines.exe with its PDB.
setlocal
rem (Run from R:, the repository mapped: see ..\neutral.cmd.)
if /i not "%~d0"=="R:" (call "%~dp0..\neutral.cmd" "%~f0" & exit /b)
set OUT=%~dp0..\..\testdata\lines
if not exist "%OUT%" mkdir "%OUT%"
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do set VS=%%i
call "%VS%\VC\Auxiliary\Build\vcvarsall.bat" amd64 >nul 2>&1 || exit /b 1
set WORK=%~dp0..\..\target\fixtures\lines
rem Fresh each time: the linker updates an existing PDB in place.
if exist "%WORK%" rmdir /s /q "%WORK%"
mkdir "%WORK%"
cd /d "%WORK%" || exit /b 1
cl /nologo /c /O2 /MD /Gy /EHsc /Zi /Fdlines-c.pdb "%~dp0lines.cpp" || exit /b 1
link /nologo /DEBUG:FULL /OPT:REF /OPT:ICF /INCREMENTAL:NO /Brepro /PDB:lines.pdb lines.obj /OUT:lines.exe >nul || exit /b 1
for %%f in (exe pdb) do copy /y lines.%%f "%OUT%\lines.%%f" >nul || exit /b 1
exit /b 0
