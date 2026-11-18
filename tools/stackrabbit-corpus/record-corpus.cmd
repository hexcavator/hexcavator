@echo off
rem Records Stackrabbit's trace corpus: small traces to iterate on quickly,
rem and large ones to measure speed. Run it from an elevated command prompt:
rem
rem   record-corpus.cmd [small|large|all]        (default: all)
rem
rem The traces go to c:\jm\dev-private\stackrabbit\corpus. They must never
rem leave this machine: they record every process, file and registry key
rem that was active while they ran.
rem
rem Traces that already exist are skipped, so a rerun records only what is
rem missing; delete a trace to record it again. The script cancels any WPR
rem recording in progress, and restores the sampling interval and heap
rem tracing settings it changes, even after an interrupted run.
rem
rem Small: about 3 minutes in all, a few MB to a few hundred MB each.
rem Large: four full builds of this repository, each traced; about 5 to 10
rem minutes per build, and several GB per trace.
setlocal EnableExtensions
set "MODE=%~1"
if "%MODE%"=="" set "MODE=all"
if /i not "%MODE%"=="small" if /i not "%MODE%"=="large" if /i not "%MODE%"=="all" (
    echo usage: %~nx0 [small^|large^|all] 1>&2
    exit /b 2
)
net session >nul 2>&1
if errorlevel 1 (
    echo %~nx0: run this from an elevated ^(administrator^) command prompt 1>&2
    exit /b 1
)

for %%r in ("%~dp0..\..") do set "REPO=%%~fr"
set "CORPUS=c:\jm\dev-private\stackrabbit\corpus"
set "WORK=%CORPUS%\work"
set "TMPREC=%CORPUS%\tmp"
set "XPERF=%ProgramFiles(x86)%\Windows Kits\10\Windows Performance Toolkit\xperf.exe"

for %%d in ("%CORPUS%" "%WORK%" "%TMPREC%") do if not exist %%d mkdir %%d
if not exist "%CORPUS%" (echo %~nx0: cannot create %CORPUS% 1>&2 & exit /b 1)
if not exist "%CORPUS%\README.txt" (
    echo PRIVATE. These traces were recorded on this machine and must never leave it.> "%CORPUS%\README.txt"
    echo Do not copy, upload, attach, share or commit them, or anything made from them.>> "%CORPUS%\README.txt"
    echo Recorded by tools\stackrabbit-corpus\record-corpus.cmd in the Stackrabbit repository.>> "%CORPUS%\README.txt"
)

if /i not "%MODE%"=="small" (
    where cargo >nul 2>&1
    if errorlevel 1 (
        echo %~nx0: cargo is not on PATH; the large traces build this repository 1>&2
        exit /b 1
    )
    rem Fetch dependencies now, so the traced builds need no network.
    pushd "%REPO%"
    cargo fetch --locked
    popd
)

echo Corpus: %CORPUS%
echo Workloads use the repository at %REPO%
call :cleanup
if /i not "%MODE%"=="large" call :small
if /i not "%MODE%"=="small" call :large
call :cleanup
if exist "%WORK%" rmdir /s /q "%WORK%"
if exist "%TMPREC%" rmdir /s /q "%TMPREC%"
echo.
echo Done. The corpus:
dir "%CORPUS%\*.etl"
exit /b 0

rem ---------------------------------------------------------------------
rem The traces.

:small
echo.
echo === Small traces, for iterating
call :record s01-cpu-idle             "-start CPU.light"                                  "idle 5"
call :record s02-cpu-spin             "-start CPU"                                        "spin 10 4"
call :record s03-cpu-spin-compressed  "-start CPU"                                        "spin 10 4" compress
call :record s04-general-filemode     "-start GeneralProfile -filemode"                   "mixed"
call :record s05-disk-file            "-start DiskIO -start FileIO -filemode"             "files"
call :record s06-registry             "-start Registry"                                   "registry"
call :record s07-dotnet               "-start DotNET -start CPU"                          "dotnet" pdbs
call :record s08-memory               "-start VirtualAllocation -start Pool -start CPU"   "memory"
call :record s09-power-idle           "-start Power"                                      "idle 10"
call :record s10-gpu-desktop          "-start GPU -start DesktopComposition"              "idle 10"
call :heap     s11-heap-findstr
call :highrate s12-cpu-8khz           "spin 5 4"
call :unmerged s13-kernel-unmerged
goto :eof

:large
echo.
echo === Large traces, for measuring speed
call :clean_build
call :record l01-build-cpu            "-start CPU -filemode"                              "build"
call :clean_build
call :record l02-build-everything     "-start GeneralProfile -start CPU -start DiskIO -start FileIO -filemode" "build"
call :clean_build
call :record l03-build-cpu-compressed "-start CPU -filemode"                              "build" compress
call :clean_build
call :highrate l04-build-cpu-8khz     "build"
goto :eof

rem ---------------------------------------------------------------------
rem Recording.

rem :record <name> "<wpr start arguments>" "<workload> [arguments]" [compress|pdbs]
:record
set "OUTFILE=%CORPUS%\%~1.etl"
if exist "%OUTFILE%" (
    echo %~1: already recorded, skipped
    goto :eof
)
set "STOPARGS=-skipPdbGen"
if /i "%~4"=="compress" set "STOPARGS=-skipPdbGen -compress"
if /i "%~4"=="pdbs" set "STOPARGS="
echo %~1: recording, workload: %~3
wpr %~2 -recordtempto "%TMPREC%"
if errorlevel 1 (
    echo %~1: wpr could not start the recording; skipped 1>&2
    wpr -cancel >nul 2>&1
    goto :eof
)
call :wl_%~3
wpr -stop "%OUTFILE%" "Stackrabbit corpus: %~1" %STOPARGS%
if errorlevel 1 (
    echo %~1: wpr could not stop the recording; discarded 1>&2
    wpr -cancel >nul 2>&1
    if exist "%OUTFILE%" del "%OUTFILE%"
    goto :eof
)
for %%f in ("%OUTFILE%") do echo %~1: %%~zf bytes
goto :eof

rem Heap tracing applies to processes started after it is enabled, by name.
:heap
if exist "%CORPUS%\%~1.etl" (
    echo %~1: already recorded, skipped
    goto :eof
)
wpr -heaptracingconfig findstr.exe enable >nul
if errorlevel 1 (
    echo %~1: could not enable heap tracing; skipped 1>&2
    goto :eof
)
call :record %~1 "-start Heap -start CPU" "heapwork"
wpr -heaptracingconfig findstr.exe disable >nul
goto :eof

rem CPU sampling at the fastest interval WPR allows: 1221 x 100 ns, about
rem 8 kHz instead of the default 1 kHz.
:highrate
if exist "%CORPUS%\%~1.etl" (
    echo %~1: already recorded, skipped
    goto :eof
)
wpr -setprofint 1221 >nul
if errorlevel 1 (
    echo %~1: could not set the sampling interval; skipped 1>&2
    goto :eof
)
call :record %~1 "-start CPU -filemode" "%~2"
wpr -resetprofint >nul
goto :eof

rem The raw kernel log as xperf writes it: not merged, so it has no image
rem identity or system configuration events. The reader must cope.
:unmerged
set "OUTFILE=%CORPUS%\%~1.etl"
if exist "%OUTFILE%" (
    echo %~1: already recorded, skipped
    goto :eof
)
if not exist "%XPERF%" (
    echo %~1: xperf is not installed; skipped
    goto :eof
)
echo %~1: recording with xperf, workload: spin 5 4
"%XPERF%" -on PROC_THREAD+LOADER+PROFILE+CSWITCH+DISPATCHER -stackwalk Profile+CSwitch+ReadyThread -BufferSize 1024 -MinBuffers 64 -f "%TMPREC%\kernel.etl"
if errorlevel 1 (
    echo %~1: xperf could not start; skipped 1>&2
    goto :eof
)
call :wl_spin 5 4
"%XPERF%" -stop
move /y "%TMPREC%\kernel.etl" "%OUTFILE%" >nul
for %%f in ("%OUTFILE%") do echo %~1: %%~zf bytes
goto :eof

rem Undoes what an interrupted run may have left behind.
:cleanup
wpr -cancel >nul 2>&1
wpr -resetprofint >nul 2>&1
wpr -heaptracingconfig findstr.exe disable >nul 2>&1
goto :eof

rem ---------------------------------------------------------------------
rem Workloads.

rem Nothing but the system's own background activity, for %1 seconds.
:wl_idle
powershell -NoProfile -Command "Start-Sleep -Seconds %1"
goto :eof

rem Busy loops for %1 seconds on %2 worker processes.
:wl_spin
powershell -NoProfile -Command "$end = (Get-Date).AddSeconds(%1); $jobs = 1..%2 | ForEach-Object { Start-Job -ScriptBlock { param($e) $x = 0; while ((Get-Date) -lt $e) { $x++ } } -ArgumentList $end }; $jobs | Wait-Job | Remove-Job"
goto :eof

:wl_mixed
call :wl_spin 5 2
call :wl_files
call :wl_registry
goto :eof

rem Copies the repository's sources with unbuffered I/O, so it reaches the
rem disk; writes 512 MB straight through; lists a system folder.
:wl_files
if exist "%WORK%\copy" rmdir /s /q "%WORK%\copy"
robocopy "%REPO%" "%WORK%\copy" /E /J /XD target .git /NFL /NDL /NJH /NJS /NP >nul
powershell -NoProfile -Command "$f = [IO.File]::Create('%WORK%\big.bin', 1MB, [IO.FileOptions]::WriteThrough); $b = New-Object byte[] 1MB; 1..512 | ForEach-Object { $f.Write($b, 0, $b.Length) }; $f.Dispose()"
dir /s "%SystemRoot%\System32\drivers" >nul 2>&1
rmdir /s /q "%WORK%\copy"
del "%WORK%\big.bin"
goto :eof

:wl_registry
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion" /s >nul 2>&1
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /s >nul 2>&1
goto :eof

rem PowerShell runs on .NET: assembly loading, JIT and garbage collection.
:wl_dotnet
powershell -NoProfile -Command "$s = 0; 1..300000 | ForEach-Object { $s += ([string]$_).Length }; Get-Command | Out-Null; [GC]::Collect(); Get-ChildItem -Recurse '%REPO%\crates' -Filter *.rs | Select-String -Pattern 'unsafe' | Measure-Object | Out-Null"
goto :eof

rem 1 GB allocated and released, then file activity.
:wl_memory
powershell -NoProfile -Command "$keep = New-Object System.Collections.ArrayList; 1..64 | ForEach-Object { [void]$keep.Add((New-Object byte[] (16MB))) }; Start-Sleep -Seconds 1; $keep.Clear(); [GC]::Collect(); Start-Sleep -Seconds 1"
call :wl_files
goto :eof

:wl_heapwork
findstr /s /i /m /c:"fn " "%REPO%\crates\*.rs" >nul
goto :eof

rem A full debug build of this repository's workspace from scratch: many
rem processes, every core, and plenty of file I/O.
:wl_build
pushd "%REPO%"
set "CARGO_TARGET_DIR=%WORK%\target"
cargo build --workspace --locked --offline
set "CARGO_TARGET_DIR="
popd
goto :eof

:clean_build
if exist "%WORK%\target" rmdir /s /q "%WORK%\target"
goto :eof
