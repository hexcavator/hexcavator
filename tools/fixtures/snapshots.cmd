@echo off
rem Refreshes the committed x64 fixture and the oracles' views of it, which
rem the hermetic tests compare with: crates\symbols\pdb\tests\data\test-x64.exe
rem and .pdb (from build.cmd's out), DIA's view of the PDB (tools\diadump), and
rem dumpbin's of the image (headers and the rest, /disasm with the PDB beside
rem it, /unwindinfo).
setlocal
rem (Run from R:, the repository mapped: see ..\neutral.cmd.)
if /i not "%~d0"=="R:" (call "%~dp0..\neutral.cmd" "%~f0" & exit /b)
set ROOT=%~dp0..\..
set DATA=%ROOT%\crates\symbols\pdb\tests\data
set SNAP=%ROOT%\apps\hexcavator\tests\data
call "%~dp0build.cmd" || exit /b 1
call "%~dp0..\diadump\build.cmd" || exit /b 1
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do set VS=%%i
set "PATH=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer;%PATH%"
call "%VS%\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
for %%f in (exe pdb) do copy /y "%~dp0out\test-x64.%%f" "%DATA%\test-x64.%%f" >nul || exit /b 1
cd /d "%DATA%" || exit /b 1
"%~dp0..\diadump\diadump.exe" test-x64.pdb > test-x64.dia.txt || exit /b 1
dumpbin /nologo /nopdb /headers /exports /imports /loadconfig /relocations /unwindinfo test-x64.exe > "%SNAP%\test-x64.dumpbin.txt" || exit /b 1
dumpbin /nologo /disasm test-x64.exe > "%SNAP%\test-x64.disasm.txt" || exit /b 1
dumpbin /nologo /unwindinfo test-x64.exe > "%SNAP%\test-x64.unwind.txt" || exit /b 1
exit /b 0
