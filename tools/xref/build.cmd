@echo off
rem Builds the cross-reference test program (main.cpp, dead.cpp) with MSVC
rem for x64 and ARM64, as testdata\xref\xref-<arch>.exe with its PDB, map,
rem and the linker's /VERBOSE output (trimmed by ..\linkerlog\trim.py).
rem main.cpp is compiled with /Gy and dead.cpp without, so that /OPT:REF
rem keeps dead.cpp's unreferenced functions along with its live one.
rem The C runtime is the DLL (/MD), to keep the PDBs small.
setlocal
rem (Run from R:, the repository mapped: see ..\neutral.cmd.)
if /i not "%~d0"=="R:" (call "%~dp0..\neutral.cmd" "%~f0" & exit /b)
set OUT=%~dp0..\..\testdata\xref
if not exist "%OUT%" mkdir "%OUT%"
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do set VS=%%i
call :build x64 amd64 || exit /b 1
call :build arm64 amd64_arm64 || exit /b 1
call :renamed || exit /b 1
exit /b 0

rem xref-x64-renamed.exe (and PDB): the x64 build with `inner` renamed
rem (main.cpp, RENAMED), for comparing builds.
:renamed
setlocal
call "%VS%\VC\Auxiliary\Build\vcvarsall.bat" amd64 >nul 2>&1 || exit /b 1
set WORK=%~dp0..\..\target\fixtures\xref-renamed
if exist "%WORK%" rmdir /s /q "%WORK%"
mkdir "%WORK%"
cd /d "%WORK%" || exit /b 1
cl /nologo /c /O1 /MD /Gy /EHsc /Zi /std:c++20 /DRENAMED /Fdxref.pdb "%~dp0main.cpp" || exit /b 1
cl /nologo /c /O1 /MD /Gy- /EHsc /Zi /Fdxref.pdb "%~dp0dead.cpp" || exit /b 1
link /nologo /DEBUG:FULL /OPT:REF /OPT:ICF /INCREMENTAL:NO /Brepro /PDB:xref-x64-renamed.pdb main.obj dead.obj /OUT:xref-x64-renamed.exe >nul || exit /b 1
for %%f in (exe pdb) do copy /y xref-x64-renamed.%%f "%OUT%\xref-x64-renamed.%%f" >nul || exit /b 1
exit /b 0

:build
setlocal
call "%VS%\VC\Auxiliary\Build\vcvarsall.bat" %2 >nul 2>&1 || exit /b 1
set WORK=%~dp0..\..\target\fixtures\xref-%1
rem Fresh each time: the linker updates an existing PDB in place.
if exist "%WORK%" rmdir /s /q "%WORK%"
mkdir "%WORK%"
cd /d "%WORK%" || exit /b 1
cl /nologo /c /O1 /MD /Gy /EHsc /Zi /std:c++20 /Fdxref.pdb "%~dp0main.cpp" || exit /b 1
cl /nologo /c /O1 /MD /Gy- /EHsc /Zi /Fdxref.pdb "%~dp0dead.cpp" || exit /b 1
link /nologo /DEBUG:FULL /OPT:REF /OPT:ICF /INCREMENTAL:NO /Brepro /VERBOSE /MAP:xref-%1.map /PDB:xref-%1.pdb main.obj dead.obj /OUT:xref-%1.exe > verbose-full.txt 2>&1 || (type verbose-full.txt & exit /b 1)
for %%f in (exe pdb map) do copy /y xref-%1.%%f "%OUT%\xref-%1.%%f" >nul || exit /b 1
python "%~dp0..\linkerlog\trim.py" verbose-full.txt "%OUT%\xref-%1.verbose.txt" || exit /b 1
exit /b 0
