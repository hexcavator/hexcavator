# Compares hexc signature's version details (a PE image's version resource)
# with Windows' own reader (FileVersionInfo) on the PE files under the given
# directories: company, description, product, versions, copyright, original
# name, and the binary versions. Files whose strings Windows takes from a .mui
# satellite are skipped (hexc reads the file's own).
#
#   & tools/signature/version-oracle.ps1 <hexc.exe> @(<dir>, ...) [-Max 500]
param(
  [Parameter(Mandatory = $true, Position = 0)] [string] $Hexc,
  [Parameter(Mandatory = $true, Position = 1)] [string[]] $Dirs,
  [int] $Max = 500
)
$pairs = @(
  @('Company', 'CompanyName'), @('Description', 'FileDescription'), @('Product', 'ProductName'),
  @('Product version', 'ProductVersion'), @('File version', 'FileVersion'), @('Copyright', 'LegalCopyright'),
  @('Original file name', 'OriginalFilename'), @('Internal name', 'InternalName')
)
$files = foreach ($d in $Dirs) { Get-ChildItem -Path $d -Recurse -File -Include *.exe, *.dll -ErrorAction SilentlyContinue }
$n = 0; $same = 0; $differ = @()
foreach ($f in ($files | Select-Object -First $Max)) {
  $v = $f.VersionInfo
  # (Windows reads a localized file's strings from its .mui satellite, which
  # has its own versions: hexc reads the file's own. Not compared.)
  if ("$($v.OriginalFilename)" -like '*.mui' -or (Test-Path (Join-Path $f.DirectoryName "en-US\$($f.Name).mui"))) { continue }
  $out = & $Hexc signature -json $f.FullName 2>$null | ConvertFrom-Json
  if (-not $out) { continue }
  $n++
  $ours = @{}
  foreach ($x in $out.info) { $ours[$x.name] = $x.value }
  $bad = @()
  foreach ($p in $pairs) {
    $theirs = "$($v.($p[1]))".Trim()
    $mine = "$($ours[$p[0]])"
    if ($theirs -ne $mine) { $bad += "$($p[0]): '$mine' vs '$theirs'" }
  }
  if ($v.FileMajorPart -or $v.FileMinorPart -or $v.FileBuildPart -or $v.FilePrivatePart) {
    $bin = "$($v.FileMajorPart).$($v.FileMinorPart).$($v.FileBuildPart).$($v.FilePrivatePart)"
    if ($ours['File version (binary)'] -ne $bin) { $bad += "binary: '$($ours['File version (binary)'])' vs '$bin'" }
  }
  if ($bad.Count -eq 0) { $same++ } else { $differ += "$($f.FullName)`n    $($bad -join "`n    ")" }
}
"$same of $n agree"
$differ | Select-Object -First 20
