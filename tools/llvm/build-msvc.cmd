@echo off
rem Builds clang and lld from an llvm-project checkout with MSVC, with full
rem PDBs, as large real-world test binaries for Hexcavator (clang.exe is ~100 MB
rem with a multi-GB PDB); and the LLVM tools that make Hexcavator's test data
rem and that its extended tests compare with (llvm-mc, llvm-objdump, ...).
rem
rem   build-msvc.cmd <llvm-project dir> <build dir> [x64|arm64]
rem
rem The architecture is x64 unless given.
rem Uses the CMake and Ninja that ship with Visual Studio.
setlocal
set SRC=%~1
if "%SRC%"=="" (echo usage: build-msvc.cmd ^<llvm-project dir^> ^<build dir^> [x64^|arm64] 1>&2 & exit /b 2)
set ARCH=%~3
if "%ARCH%"=="" set ARCH=x64
set OUT=%~2
if "%OUT%"=="" (echo usage: build-msvc.cmd ^<llvm-project dir^> ^<build dir^> [x64^|arm64] 1>&2 & exit /b 2)
set VCARCH=amd64
if /i "%ARCH%"=="arm64" set VCARCH=amd64_arm64

for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do set VS=%%i
call "%VS%\VC\Auxiliary\Build\vcvarsall.bat" %VCARCH% || exit /b 1
set PATH=%VS%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;%VS%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%PATH%

rem CMake needs Python 3. Set PYTHON to its full path if CMake can't find
rem it (the WindowsApps "python.exe" alias is not a real interpreter).
set PYARG=
if not "%PYTHON%"=="" set "PYARG=-DPython3_EXECUTABLE=%PYTHON%"

if not exist "%OUT%" mkdir "%OUT%"
cmake -G Ninja -S "%SRC%\llvm" -B "%OUT%" %PYARG% ^
  -DCMAKE_BUILD_TYPE=RelWithDebInfo ^
  -DLLVM_ENABLE_PROJECTS=clang;lld ^
  -DLLVM_TARGETS_TO_BUILD=X86;AArch64;ARM ^
  -DLLVM_ENABLE_ASSERTIONS=OFF ^
  -DLLVM_PARALLEL_LINK_JOBS=2 ^
  -DLLVM_INCLUDE_TESTS=OFF ^
  -DLLVM_INCLUDE_BENCHMARKS=OFF ^
  -DLLVM_INCLUDE_EXAMPLES=OFF ^
  "-DCMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO=/DEBUG:FULL /INCREMENTAL:NO /OPT:REF /OPT:ICF" ^
  "-DCMAKE_SHARED_LINKER_FLAGS_RELWITHDEBINFO=/DEBUG:FULL /INCREMENTAL:NO /OPT:REF /OPT:ICF" ^
  "-DCMAKE_MODULE_LINKER_FLAGS_RELWITHDEBINFO=/DEBUG:FULL /INCREMENTAL:NO /OPT:REF /OPT:ICF" || exit /b 1
rem (CMake's own per-configuration defaults, "/debug /INCREMENTAL", come
rem after CMAKE_EXE_LINKER_FLAGS and would win; replace them instead.)
rem (LLVMSupport and LLVMDemangle are what swift-demangle links with.)
ninja -C "%OUT%" clang lld llvm-mc llvm-objdump llvm-readobj llvm-dwarfdump llvm-dwp llvm-nm llvm-cxxfilt llvm-tblgen LLVMSupport LLVMDemangle || exit /b 1
