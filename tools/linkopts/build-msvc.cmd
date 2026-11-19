@echo off
rem Builds the MSVC link-option test inputs into testdata\linkopts with
rem Visual Studio's cl and link (found by vswhere): x64 images, without the
rem C runtime, without PDBs.
rem
rem   msvc-strs-nogf.exe  msvc-strs.c twice (say_a; say_b, MSVC_STRS_B) and
rem                       msvc-main.c, /GF-: each object's string literals
rem                       its own, which the linker doesn't merge.
rem   msvc-strs-gf.exe    the same, /GF: pooled, merged.
setlocal
if /i not "%~d0"=="R:" (call "%~dp0..\neutral.cmd" "%~f0" & exit /b)
set OUT=%~dp0..\..\testdata\linkopts
if not exist "%OUT%" mkdir "%OUT%"
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do set VS=%%i
call "%VS%\VC\Auxiliary\Build\vcvarsall.bat" amd64 >nul 2>&1 || exit /b 1
set WORK=%~dp0..\..\target\fixtures\linkopts-msvc
if exist "%WORK%" rmdir /s /q "%WORK%"
mkdir "%WORK%"
cd /d "%WORK%" || exit /b 1
set CL=/nologo /c /O1 /GS- /Brepro
set LINK=/nologo /NODEFAULTLIB /ENTRY:start /SUBSYSTEM:CONSOLE /DEBUG:NONE /Brepro
cl %CL% /GF- /Fonogf-a.obj "%~dp0msvc-strs.c" || exit /b 1
cl %CL% /GF- /DMSVC_STRS_B /Fonogf-b.obj "%~dp0msvc-strs.c" || exit /b 1
cl %CL% /GF /Fogf-a.obj "%~dp0msvc-strs.c" || exit /b 1
cl %CL% /GF /DMSVC_STRS_B /Fogf-b.obj "%~dp0msvc-strs.c" || exit /b 1
cl %CL% /Fomain.obj "%~dp0msvc-main.c" || exit /b 1
link %LINK% nogf-a.obj nogf-b.obj main.obj /OUT:"%OUT%\msvc-strs-nogf.exe" || exit /b 1
link %LINK% gf-a.obj gf-b.obj main.obj /OUT:"%OUT%\msvc-strs-gf.exe" || exit /b 1
