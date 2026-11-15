@echo off
rem Builds the dependency test's PE images (testdata\deps\pe) with MSVC: an
rem application and its helper DLL (and a kernel32.dll planted beside them),
rem a Windows directory of stand-ins (kernel32, an API set's host, the API set
rem schema, Common Controls 5 in System32 and 6 in WinSxS, and SysWOW64's
rem kernel32), and a 32-bit application. Their exports are their .def files'.
setlocal
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do set VS=%%i
set OUT=%~dp0..\..\testdata\deps\pe
set WORK=%~dp0..\..\target\fixtures\deps
if exist "%WORK%" rmdir /s /q "%WORK%"
mkdir "%WORK%" || exit /b 1
if exist "%OUT%" rmdir /s /q "%OUT%"
set SXS=%OUT%\windows\WinSxS\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.1.0_none_test
for %%d in (app app32 windows\System32 windows\SysWOW64 "%SXS%") do mkdir "%OUT%\%%~d" 2>nul
mkdir "%SXS%" 2>nul
python "%~dp0schema.py" "%WORK%\schema.c" || exit /b 1
call :x64 || exit /b 1
call :x86 || exit /b 1
exit /b 0

:x64
setlocal
call "%VS%\VC\Auxiliary\Build\vcvarsall.bat" amd64 >nul 2>&1 || exit /b 1
cd /d "%WORK%" || exit /b 1
set CFLAGS=/nologo /c /O1 /GS- /Zl
set LFLAGS=/nologo /NODEFAULTLIB /INCREMENTAL:NO /Brepro /MACHINE:X64
cl %CFLAGS% "%~dp0stub.c" "%~dp0forwards.c" "%~dp0helper.c" "%~dp0app.c" "%WORK%\schema.c" || exit /b 1
rem The DLLs, each from stub.obj under its .def file's names.
link %LFLAGS% /DLL /ENTRY:_DllMainCRTStartup /DEF:"%~dp0kernel32.def" stub.obj forwards.obj /OUT:kernel32.dll || exit /b 1
for %%d in (kernel32-old planted apihost apiset comctl5 comctl6 gone missing) do (
  link %LFLAGS% /DLL /ENTRY:_DllMainCRTStartup /DEF:"%~dp0%%d.def" stub.obj /OUT:%%d.dll || exit /b 1
)
link %LFLAGS% /DLL /ENTRY:_DllMainCRTStartup /DEF:"%~dp0helper.def" helper.obj kernel32-old.lib gone.lib /OUT:helper.dll || exit /b 1
link %LFLAGS% /DLL /NOENTRY /OPT:NOREF schema.obj /OUT:apisetschema.dll || exit /b 1
set DEP=/MANIFESTDEPENDENCY:"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'"
link %LFLAGS% /ENTRY:mainCRTStartup /SUBSYSTEM:CONSOLE /MANIFEST:EMBED %DEP% app.obj kernel32.lib helper.lib apiset.lib comctl6.lib missing.lib /DELAYLOAD:missing.dll /OUT:app.exe || exit /b 1
copy /y app.exe "%OUT%\app" >nul && copy /y helper.dll "%OUT%\app" >nul && copy /y planted.dll "%OUT%\app\kernel32.dll" >nul || exit /b 1
copy /y kernel32.dll "%OUT%\windows\System32" >nul && copy /y apihost.dll "%OUT%\windows\System32" >nul && copy /y apisetschema.dll "%OUT%\windows\System32" >nul || exit /b 1
copy /y comctl5.dll "%OUT%\windows\System32\comctl32.dll" >nul && copy /y comctl6.dll "%SXS%\comctl32.dll" >nul || exit /b 1
exit /b 0

:x86
setlocal
call "%VS%\VC\Auxiliary\Build\vcvarsall.bat" x86 >nul 2>&1 || exit /b 1
mkdir "%WORK%\x86" 2>nul
cd /d "%WORK%\x86" || exit /b 1
cl /nologo /c /O1 /GS- /Zl "%~dp0stub.c" "%~dp0forwards.c" "%~dp0app32.c" || exit /b 1
link /nologo /NODEFAULTLIB /INCREMENTAL:NO /Brepro /MACHINE:X86 /DLL /ENTRY:_DllMainCRTStartup@12 /DEF:"%~dp0kernel32.def" stub.obj forwards.obj /OUT:kernel32.dll || exit /b 1
link /nologo /NODEFAULTLIB /INCREMENTAL:NO /Brepro /MACHINE:X86 /ENTRY:mainCRTStartup /SUBSYSTEM:CONSOLE app32.obj kernel32.lib /OUT:app32.exe || exit /b 1
copy /y kernel32.dll "%OUT%\windows\SysWOW64" >nul && copy /y app32.exe "%OUT%\app32" >nul || exit /b 1
exit /b 0
