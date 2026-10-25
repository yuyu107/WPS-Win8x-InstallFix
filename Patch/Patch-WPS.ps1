# WPS Win8.x offline compatibility research - supported x64 builds only
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$cases = @(
 @{Ver='29162';InputName='WPSOffice.exe';OuterSHA='937aa8ed95a1a7bb6c9daaf0ee3948d4bd8c8e47bbce9969dce08bc03bdfd4dc';Offset=294030;Header=2519683697;InnerSize=376488984;InnerSHA='ff81929317739a7ef13d489c575ed6a521eee931e063fe61c4e98ba247da055b';OutputSHA='e05e1667a0d212f26f02345b857f174da534ad7b0cae65439ef9c5c668bc5b73'},
 @{Ver='29158';InputName='WPS_Setup_x64_29158.exe';OuterSHA='1dd9f29797fa6d0a17a7f9ccc7ffef052f8a89327669570b77455a56fb9c4e3f';Offset=294017;Header=2521217603;InnerSize=378021584;InnerSHA='344962d031570139c87f3e7a3a64033e89e4eac015cf378da9ee285c1a454a8c';OutputSHA='9d174eb69d71e91768aed8d7b4b3e333ace32bba30b5f138c06d349f96ba6e14'}
)
function Sha256File([string]$Path) {
 $s=[System.IO.File]::OpenRead($Path); $h=[System.Security.Cryptography.SHA256]::Create()
 try { [System.BitConverter]::ToString($h.ComputeHash($s)).Replace('-','').ToLowerInvariant() }
 finally { $s.Dispose(); $h.Dispose() }
}
function ExtractInner($c,[string]$outer,[string]$inner) {
 $source=[System.IO.File]::OpenRead($outer)
 try {
  [void]$source.Seek([long]$c.Offset,[System.IO.SeekOrigin]::Begin)
  $reader=New-Object System.IO.BinaryReader($source)
  if($reader.ReadUInt32() -ne [uint32]$c.Header) { throw 'NSIS stream header mismatch.' }
  $deflate=New-Object System.IO.Compression.DeflateStream($source,[System.IO.Compression.CompressionMode]::Decompress,$true)
  try { $target=[System.IO.File]::Create($inner); try { $deflate.CopyTo($target) } finally { $target.Dispose() } }
  finally { $deflate.Dispose() }
 } finally { $source.Dispose() }
}
$found=0; $failed=$false
foreach ($c in $cases) {
 $outer=Join-Path $root $c.InputName
 if(-not [System.IO.File]::Exists($outer)) { continue }
 $found++
 $inner=Join-Path $root ('WPS_'+$c.Ver+'_original_inner.exe')
 $output=Join-Path $root ('WPS_'+$c.Ver+'_x64_Win8x_Patched.exe')
 try {
  Write-Host ('Verifying original '+$c.Ver+' ...')
  if((Sha256File $outer) -ne $c.OuterSHA) { throw 'Original SHA-256 mismatch. Unsupported or modified installer.' }
  if(-not [System.IO.File]::Exists($inner)) {
   try { ExtractInner $c $outer $inner }
   catch { Remove-Item -LiteralPath $inner -ErrorAction SilentlyContinue; throw }
  }
  if((Get-Item -LiteralPath $inner).Length -ne [long]$c.InnerSize -or (Sha256File $inner) -ne $c.InnerSHA) { throw 'Inner installer integrity check failed.' }
  if([System.IO.File]::Exists($output)) {
   if((Sha256File $output) -ne $c.OutputSHA) { throw 'Output file already exists with unexpected content.' }
   Write-Host ('Already patched: '+$output) -ForegroundColor Green
   continue
  }
  [System.IO.File]::Copy($inner,$output,$false)
  try {
   $f=[System.IO.File]::Open($output,[System.IO.FileMode]::Open,[System.IO.FileAccess]::ReadWrite,[System.IO.FileShare]::None)
   try {
    [byte[]]$before=@(0x40,0x53,0x48,0x83,0xEC,0x20)
    [byte[]]$after=@(0xB8,0x01,0x00,0x00,0x00,0xC3)
    [void]$f.Seek([long]0xC2680,[System.IO.SeekOrigin]::Begin)
    [byte[]]$actual=New-Object byte[] 6
    if($f.Read($actual,0,6) -ne 6) { throw 'Short read at patch site.' }
    for($i=0;$i -lt 6;$i++) { if($actual[$i] -ne $before[$i]) { throw 'Unexpected bytes at patch site.' } }
    [void]$f.Seek([long]0xC2680,[System.IO.SeekOrigin]::Begin)
    $f.Write($after,0,6)
   } finally { $f.Dispose() }
   if((Sha256File $output) -ne $c.OutputSHA) { throw 'Output integrity check failed.' }
  } catch { Remove-Item -LiteralPath $output -ErrorAction SilentlyContinue; throw }
  Write-Host ('SUCCESS: '+$output) -ForegroundColor Green
  Write-Host 'The modified installer no longer has a valid vendor signature.'
 } catch { $failed=$true; Write-Host ('FAILED: '+$_.Exception.Message) -ForegroundColor Red }
}
if($found -eq 0) { Write-Host 'Place WPSOffice.exe (29162) or WPS_Setup_x64_29158.exe (29158) beside the script.'; exit 2 }
if($failed) { exit 1 }
exit 0
