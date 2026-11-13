@echo off
rem Builds etwdump.exe, the ETW oracle (see etwdump.cpp).
setlocal
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do set VS=%%i
call "%VS%\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "%~dp0"
cl /nologo /EHsc /O2 /std:c++17 /W4 etwdump.cpp /link ole32.lib || exit /b 1
del etwdump.obj
