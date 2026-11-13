# Runs test/integration/index.js in a separate VS Code (its own user data
# and extensions), against the repository's test binaries:
#   powershell -File test\integration\run.ps1 <hexc.exe>
# (VS Code won't start while an update of it is pending: restart it first.)
param([Parameter(Mandatory)] [string] $Hexc)
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$ext = Resolve-Path "$here\..\.."
$repo = Resolve-Path "$ext\..\.."
$tmp = Join-Path ([IO.Path]::GetTempPath()) "hexc-vscode-smoke"
New-Item -ItemType Directory -Force "$tmp\ud\User" | Out-Null
@{ "hexcavator.path" = (Resolve-Path $Hexc).Path; "workbench.startupEditor" = "none"; "security.workspace.trust.enabled" = $false } |
  ConvertTo-Json | Out-File -Encoding utf8 "$tmp\ud\User\settings.json"
Remove-Item "$tmp\out.txt" -ErrorAction SilentlyContinue
$env:HEXC_SMOKE_OUT = "$tmp\out.txt"
$env:HEXC_SMOKE_IMAGE = "$repo\testdata\xref\xref-x64.exe"
$env:HEXC_SMOKE_BASE = "$repo\testdata\xref\xref-x64-renamed.exe"
$env:HEXC_SMOKE_OTHERS = "$repo\testdata\types\types-x86_64-linux-gnu;$repo\testdata\macho\program-arm64"
Remove-Item Env:ELECTRON_RUN_AS_NODE -ErrorAction SilentlyContinue
$code = "$env:LOCALAPPDATA\Programs\Microsoft VS Code\Code.exe"
$p = Start-Process -FilePath $code -PassThru -ArgumentList @("--user-data-dir=$tmp\ud", "--extensions-dir=$tmp\ext",
  "--extensionDevelopmentPath=$ext", "--extensionTestsPath=$here\index.js", "--disable-updates", "$repo\testdata")
$p.WaitForExit(120000) | Out-Null
if (-not (Test-Path "$tmp\out.txt")) { Write-Error "VS Code wrote nothing (is an update of it pending?)"; exit 1 }
Get-Content "$tmp\out.txt"
if (Select-String -Quiet -Path "$tmp\out.txt" -Pattern "^FAIL") { exit 1 }
