@echo off
rem Builds bloaty, an oracle only (not a dependency), from a clone at
rem BLOATY_SRC (github.com/google/bloaty) into BLOATY_BUILD, with Visual
rem Studio's CMake and Ninja. Then: python compare.py <bloaty.exe> <hexc.exe>.
setlocal
if "%BLOATY_SRC%"=="" (echo set BLOATY_SRC to a clone of github.com/google/bloaty 1>&2 & exit /b 1)
if "%BLOATY_BUILD%"=="" (echo set BLOATY_BUILD to a build directory 1>&2 & exit /b 1)
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do set VS=%%i
call "%VS%\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
set PATH=%VS%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;%VS%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%PATH%
cd /d "%BLOATY_SRC%" || exit /b 1
git submodule update --init --recursive || exit /b 1
cmake -G Ninja -S "%BLOATY_SRC%" -B "%BLOATY_BUILD%" -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_VERSION_MINIMUM=3.5 || exit /b 1
ninja -C "%BLOATY_BUILD%" bloaty || exit /b 1
