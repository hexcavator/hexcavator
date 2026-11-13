# Compares hexc signature with Windows' own verifier (Get-AuthenticodeSignature)
# on the PE files under the given directories that carry an embedded signature
# (catalog-signed files are skipped: their signature isn't in the file).
#
#   powershell -File tools/signature/oracle.ps1 <hexc.exe> <dir>... [-Max 500]
param(
  [Parameter(Mandatory = $true, Position = 0)] [string] $Hexc,
  [Parameter(Mandatory = $true, Position = 1)] [string[]] $Dirs,
  [int] $Max = 500
)
$files = foreach ($d in $Dirs) {
  Get-ChildItem -Path $d -Recurse -File -Include *.exe, *.dll, *.sys -ErrorAction SilentlyContinue
}
$files = $files | Select-Object -First ($Max * 4)
$same = 0; $differ = @(); $n = 0
foreach ($f in $files) {
  if ($n -ge $Max) { break }
  $sig = Get-AuthenticodeSignature -LiteralPath $f.FullName -ErrorAction SilentlyContinue
  if (-not $sig -or $sig.SignatureType -ne 'Authenticode') { continue }
  $n++
  $out = & $Hexc signature -json $f.FullName 2>$null | ConvertFrom-Json
  $ours = if ($out) { $out.status } else { 'error' }
  # Windows: Valid (trusted, unchanged), HashMismatch, NotTrusted, UnknownError.
  $theirs = "$($sig.Status)"
  $agree = switch ($theirs) {
    'Valid' { $ours -eq 'pass' -or $ours -eq 'warn' }
    'HashMismatch' { $ours -eq 'fail' }
    'NotSigned' { $ours -eq 'unsigned' -or $ours -eq 'fail' }
    default { $ours -ne 'pass' }
  }
  if ($agree) { $same++ } else { $differ += "$theirs vs $ours`t$($f.FullName)" }
}
"$same of $n agree"
$differ
