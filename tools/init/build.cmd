@echo off
rem Builds the initialization test program (init.cpp) with MSVC for x64, as
rem testdata\init\init.exe and init.dll (with DLL defined), with their PDBs:
rem a TLS callback, a C initializer, a global object's constructor, and main
rem or DllMain. The C runtime is the DLL (/MD), to keep the PDBs small.
setlocal
rem (Run from R:, the repository mapped: see ..\neutral.cmd.)
if /i not "%~d0"=="R:" (call "%~dp0..\neutral.cmd" "%~f0" & exit /b)
set OUT=%~dp0..\..\testdata\init
if not exist "%OUT%" mkdir "%OUT%"
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do set VS=%%i
call "%VS%\VC\Auxiliary\Build\vcvarsall.bat" amd64 >nul 2>&1 || exit /b 1
set WORK=%~dp0..\..\target\fixtures\init
if exist "%WORK%" rmdir /s /q "%WORK%"
mkdir "%WORK%"
cd /d "%WORK%" || exit /b 1
set CFLAGS=/nologo /c /O1 /MD /Gy /EHsc /Zi
set LFLAGS=/nologo /DEBUG:FULL /OPT:REF /OPT:ICF /INCREMENTAL:NO /Brepro
cl %CFLAGS% /Fdinit-c.pdb /Foinit.obj "%~dp0init.cpp" || exit /b 1
link %LFLAGS% /PDB:init.pdb init.obj /OUT:init.exe >nul || exit /b 1
cl %CFLAGS% /DDLL /Fdinitdll-c.pdb /Foinitdll.obj "%~dp0init.cpp" || exit /b 1
link %LFLAGS% /DLL /PDB:initdll.pdb initdll.obj /OUT:initdll.dll >nul || exit /b 1
for %%f in (init.exe init.pdb initdll.dll initdll.pdb) do copy /y %%f "%OUT%\%%f" >nul || exit /b 1
exit /b 0
