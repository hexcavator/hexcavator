# Makes testdata/signature: copies of testdata/types/types.exe signed by a
# throwaway test CA ("Hexcavator Test Root"; only its certificate is kept,
# as test-root.cer): signed.exe (SHA-1, with a SHA-256 signature nested in it)
# and signed-ecdsa.exe (ECDSA P-256, SHA-256). No timestamps (they'd need a
# timestamp server). The keys exist only in the user's store while signing.
#
#   powershell -File tools/signature/fixtures.ps1
$root = Join-Path $PSScriptRoot "..\.."
$out = Join-Path $root "testdata\signature"
$st = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe |
  Where-Object { $_.FullName -match '\\x64\\' } | Select-Object -Last 1 -ExpandProperty FullName
New-Item -ItemType Directory -Force $out | Out-Null
$ca = New-SelfSignedCertificate -Subject "CN=Hexcavator Test Root" -KeyUsage CertSign, CRLSign -KeyAlgorithm RSA -KeyLength 2048 `
  -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date "2045-01-01") -TextExtension @("2.5.29.19={critical}{text}ca=1")
$leaf = New-SelfSignedCertificate -Subject "CN=Hexcavator Test Signer" -Type CodeSigningCert -KeyAlgorithm RSA -KeyLength 2048 `
  -Signer $ca -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date "2044-01-01")
$ecc = New-SelfSignedCertificate -Subject "CN=Hexcavator Test ECDSA Signer" -Type CodeSigningCert -KeyAlgorithm ECDSA_nistP256 `
  -CurveExport CurveName -Signer $ca -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date "2044-01-01")
try {
  Export-Certificate -Cert $ca -FilePath "$out\test-root.cer" | Out-Null
  Copy-Item "$root\testdata\types\types.exe" "$out\signed.exe"
  & $st sign /q /fd sha1 /sha1 $leaf.Thumbprint "$out\signed.exe"
  & $st sign /q /as /fd sha256 /sha1 $leaf.Thumbprint "$out\signed.exe"
  Copy-Item "$root\testdata\types\types.exe" "$out\signed-ecdsa.exe"
  & $st sign /q /fd sha256 /sha1 $ecc.Thumbprint "$out\signed-ecdsa.exe"
} finally {
  foreach ($c in $leaf, $ecc, $ca) { Remove-Item "Cert:\CurrentUser\My\$($c.Thumbprint)" }
}
