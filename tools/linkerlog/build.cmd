@echo off
rem Builds tools\linkerlog\main.cpp with MSVC (x64) and keeps the linker's
rem /VERBOSE output, trimmed, as testdata\linkerlog\verbose.txt: every line
rem but most of the thousands of "Discarded" lines from the C runtime. Also
rem keeps the image and its map (link /MAP) as main.exe and main.map.
setlocal
set OUT=%~dp0..\..\testdata\linkerlog
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do set VS=%%i
call "%VS%\VC\Auxiliary\Build\vcvarsall.bat" amd64 >nul 2>&1 || exit /b 1
set WORK=%TEMP%\hexcavator-linkerlog
if not exist "%WORK%" mkdir "%WORK%"
cd /d "%WORK%" || exit /b 1
cl /nologo /c /O1 /Gy /EHsc "%~dp0main.cpp" || exit /b 1
link /nologo /OPT:REF /OPT:ICF /Brepro /VERBOSE /MAP:main.map main.obj /OUT:main.exe > verbose-full.txt 2>&1 || exit /b 1
copy /y main.exe "%OUT%\main.exe" >nul || exit /b 1
copy /y main.map "%OUT%\main.map" >nul || exit /b 1
python "%~dp0trim.py" verbose-full.txt "%OUT%\verbose.txt" || exit /b 1
