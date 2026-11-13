@echo off
rem Builds tools\fixtures\test.cpp for every target into .\out.
rem Produces test-<arch>.exe and test-<arch>.pdb, optimized and debug.
setlocal
rem (Run from R:, the repository mapped: see ..\neutral.cmd.)
if /i not "%~d0"=="R:" (call "%~dp0..\neutral.cmd" "%~f0" & exit /b)
set OUT=%~dp0out
if not exist "%OUT%" mkdir "%OUT%"
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do set VS=%%i
set SRC=%~dp0test.cpp
cd /d "%OUT%"
call :build x64 amd64 ""
call :build x86 amd64_x86 ""
call :build arm64 amd64_arm64 ""
call :build arm64ec amd64_arm64 "/arm64EC"
exit /b 0

:build
setlocal
call "%VS%\VC\Auxiliary\Build\vcvarsall.bat" %2 >nul 2>&1
set EC=%~3
set LINKEC=
if not "%EC%"=="" set LINKEC=/MACHINE:ARM64EC
cl /nologo /EHsc /O2 /Zi /MD %EC% "%SRC%" /Fo:test-%1.obj /Fd:test-%1-c.pdb /Fe:test-%1.exe /link %LINKEC% /DEBUG:FULL /PDB:test-%1.pdb /INCREMENTAL:NO > build-%1.log 2>&1
cl /nologo /EHsc /Od /Zi /MDd %EC% "%SRC%" /Fo:test-%1-d.obj /Fd:test-%1-d-c.pdb /Fe:test-%1-d.exe /link %LINKEC% /DEBUG:FULL /PDB:test-%1-d.pdb /INCREMENTAL:NO > build-%1-d.log 2>&1
endlocal
exit /b 0
