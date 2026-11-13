@echo off
rem Runs a build script with the repository mapped to drive R: (subst), so
rem that the paths a build records (sources, objects, PDBs, the build
rem directory) are R:\..., the same on every machine, and name nobody's
rem directories. The fixture build scripts run themselves through this:
rem
rem   if /i not "%~d0"=="R:" (call "%~dp0..\neutral.cmd" "%~f0" & exit /b)
rem
rem Their work directories are under R:\target\fixtures.
setlocal
for %%r in ("%~dp0..") do set "ROOT=%%~fr"
set "SCRIPT=%~f1"
call set "REL=%%SCRIPT:%ROOT%\=%%"
if "%REL%"=="%SCRIPT%" (echo %SCRIPT% is not in %ROOT% 1>&2 & exit /b 2)
if exist R:\ (echo R: is in use: free it ^(subst R: /d^) for the build 1>&2 & exit /b 1)
subst R: "%ROOT%" || exit /b 1
call "R:\%REL%"
set CODE=%ERRORLEVEL%
subst R: /d
exit /b %CODE%
