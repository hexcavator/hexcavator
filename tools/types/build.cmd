@echo off
rem Builds the type layout test program (types.cpp) with MSVC for x64, as
rem testdata\types\types.exe and types-v2.exe (V2: Padded reordered, Grows
rem grown), each with its PDB.
setlocal
rem (Run from R:, the repository mapped: see ..\neutral.cmd.)
if /i not "%~d0"=="R:" (call "%~dp0..\neutral.cmd" "%~f0" & exit /b)
set OUT=%~dp0..\..\testdata\types
if not exist "%OUT%" mkdir "%OUT%"
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do set VS=%%i
call "%VS%\VC\Auxiliary\Build\vcvarsall.bat" amd64 >nul 2>&1 || exit /b 1
call :build types "" || exit /b 1
call :build types-v2 /DV2 || exit /b 1
exit /b 0

:build
setlocal
set WORK=%~dp0..\..\target\fixtures\%1
rem Fresh each time: the linker updates an existing PDB in place.
if exist "%WORK%" rmdir /s /q "%WORK%"
mkdir "%WORK%"
cd /d "%WORK%" || exit /b 1
cl /nologo /c /O1 /MD /Gy /EHsc /Zi %~2 /Fd%1-c.pdb /Fo%1.obj "%~dp0types.cpp" || exit /b 1
link /nologo /DEBUG:FULL /OPT:REF /OPT:ICF /INCREMENTAL:NO /Brepro /PDB:%1.pdb %1.obj /OUT:%1.exe >nul || exit /b 1
for %%f in (exe pdb) do copy /y %1.%%f "%OUT%\%1.%%f" >nul || exit /b 1
exit /b 0
