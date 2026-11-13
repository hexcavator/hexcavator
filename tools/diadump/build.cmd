@echo off
rem Builds diadump.exe and copies msdia140.dll next to it.
setlocal
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do set VS=%%i
call "%VS%\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "%~dp0"
cl /nologo /EHsc /O2 /I "%VS%\DIA SDK\include" diadump.cpp /link "%VS%\DIA SDK\lib\amd64\diaguids.lib" ole32.lib oleaut32.lib || exit /b 1
copy /y "%VS%\DIA SDK\bin\amd64\msdia140.dll" . >nul
