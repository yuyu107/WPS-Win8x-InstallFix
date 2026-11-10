$ErrorActionPreference='Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'Patch/WPSStandard.Core.ps1')
function S16([byte[]]$b,[int]$o,[uint16]$v) { [BitConverter]::GetBytes($v).CopyTo($b,$o) }
function S32([byte[]]$b,[int]$o,[uint32]$v) { [BitConverter]::GetBytes($v).CopyTo($b,$o) }
function S64([byte[]]$b,[int]$o,[uint64]$v) { [BitConverter]::GetBytes($v).CopyTo($b,$o) }
function Standard-Fixture([int]$Offset=0x600) {
 [byte[]]$b=New-Object byte[] 8192
 S16 $b 0 0x5A4D; S32 $b 60 0x80; S32 $b 0x80 0x4550
 S16 $b 0x84 0x8664; S16 $b 0x86 4; S16 $b 0x94 240
 $opt=0x98; S16 $b $opt 0x20B; S64 $b ($opt+24) 5368709120
 S32 $b ($opt+108) 16
 S32 $b ($opt+136) 0x4000; S32 $b ($opt+140) 12
 S32 $b ($opt+152) 0x5000; S32 $b ($opt+156) 12
 $section=$opt+240
 foreach ($spec in @(@(0x1000,0x400,0x1000,0x60000020),@(0x3000,0x1400,0x400,0x40000040),@(0x4000,0x1800,0x200,0x40000040),@(0x5000,0x1A00,0x200,0x40000040))) {
  S32 $b ($section+8) $spec[2]; S32 $b ($section+12) $spec[0]
  S32 $b ($section+16) $spec[2]; S32 $b ($section+20) $spec[1]
  S32 $b ($section+36) $spec[3]; $section+=40
 }
 $rva=0x1000+$Offset-0x400; $i=0
 foreach ($t in ($WPSStandardPattern -split ' ')) { if ($t -ne '??') { $b[$Offset+$i]=[Convert]::ToByte($t,16) }; $i++ }
 [BitConverter]::GetBytes([int](0x3000-$rva-16)).CopyTo($b,$Offset+12)
 [BitConverter]::GetBytes([int](0x3020-$rva-23)).CopyTo($b,$Offset+19)
 [Text.Encoding]::ASCII.GetBytes('support').CopyTo($b,0x1400)
 [Text.Encoding]::ASCII.GetBytes('InstallOnServer2008').CopyTo($b,0x1420)
 foreach ($at in @(23,34,51,65,73,81,143,160)) {
  [BitConverter]::GetBytes([int](0x1E00-$rva-$at-5)).CopyTo($b,$Offset+$at+1)
 }
 foreach ($at in @(0x450,0x470,0x490)) {
  $b[$at]=0xE8
  [BitConverter]::GetBytes([int]($rva-(0x1000+$at-0x400)-5)).CopyTo($b,$at+1)
 }
 $b[0x490]=0xE9; S64 $b 0x1500 5368713360
 S32 $b 0x1800 $rva; S32 $b 0x1804 ($rva+60); S32 $b 0x1808 0x3080
 S32 $b 0x1A00 0x1000; S32 $b 0x1A04 12
 return ,$b
}
function Reject-Standard([byte[]]$b,[string]$name) {
 $fastRejected=$false; try { $null=[WpsOnlinePredicate]::Analyze($b,$WPSStandardPattern) } catch { $fastRejected=$true }; if (-not $fastRejected) { throw ('Fast detector accepted: '+$name) }
 $ok=$false; try { $null=Find-WPSStandardPatch $b } catch { $ok=$true }
 if (-not $ok) { throw ('Expected refusal: '+$name) }; Write-Host ('PASS refusal: '+$name)
}
function Wrap-NSIS([byte[]]$Inner,[int]$Padding=0x2000,[switch]$Duplicate,[switch]$Raw) {
 $stub=Standard-Fixture
 S16 $stub 0x84 0x14C; S16 $stub 0x98 0x10B; S32 $stub (0x98+28) 0x400000; S32 $stub (0x98+92) 16
 $packed=$Inner
 if (-not $Raw) {
  $m=New-Object IO.MemoryStream
  $d=New-Object IO.Compression.DeflateStream -ArgumentList $m,([IO.Compression.CompressionMode]::Compress),$true
  try { $d.Write($Inner,0,$Inner.Length) } finally { $d.Dispose() }
  $packed=$m.ToArray(); $m.Dispose()
 }
 $count=1; if ($Duplicate) { $count=2 }
 $total=28+4+64+$count*(4+$packed.Length)+4
 [byte[]]$b=New-Object byte[] ($Padding+$total+128)
 [Array]::Copy($stub,0,$b,0,$stub.Length)
 [byte[]]$magic=0xEF,0xBE,0xAD,0xDE,0x4E,0x75,0x6C,0x6C,0x73,0x6F,0x66,0x74,0x49,0x6E,0x73,0x74
 $magic.CopyTo($b,$Padding+4); S32 $b ($Padding+20) 64; S32 $b ($Padding+24) $total
 $p=$Padding+28; S32 $b $p 64; $p+=68
 for ($i=0;$i -lt $count;$i++) {
  $v=[long]$packed.Length; if (-not $Raw) { $v+=2147483648L }
  S32 $b $p ([uint32]$v); $packed.CopyTo($b,$p+4); $p+=4+$packed.Length
 }
 return ,$b
}
# Regression: a large installer overlay must not enter PowerShell's array binder.
Add-Type -Path @((Join-Path (Split-Path -Parent $PSScriptRoot) 'Patch/Online/OnlineDebugNative.cs'),(Join-Path (Split-Path -Parent $PSScriptRoot) 'Patch/Online/OnlinePredicate.cs'))
$overlayFile=Join-Path $env:TEMP ('wps-overlay-'+[Guid]::NewGuid().ToString('N')+'.exe')
try {
 $fixture=Standard-Fixture
 # Realistic code-section size for the suspended-child performance regression.
 [byte[]]$large=New-Object byte[] 7517696
 [Array]::Copy($fixture,$large,$fixture.Length)
 S16 $large 0x86 5
 $paddingSection=0x98+240+4*40
 S32 $large ($paddingSection+8) 0x500000
 S32 $large ($paddingSection+12) 0x6000
 S32 $large ($paddingSection+16) 0x500000
 S32 $large ($paddingSection+20) 0x2000
 S32 $large ($paddingSection+36) 0x60000020
 $scanTimer=[Diagnostics.Stopwatch]::StartNew()
 $largePlan=[WpsOnlinePredicate]::Analyze($large,$WPSStandardPattern)
 if ($largePlan.Offset -ne 0x600 -or $scanTimer.Elapsed.TotalSeconds -gt 10) { throw 'Compiled detector performance regression.' }
 Write-Host ('PASS compiled 7.5MB image / 5MB executable-section detection: '+$scanTimer.Elapsed.TotalMilliseconds+' ms')
 [IO.File]::WriteAllBytes($overlayFile,$fixture)
 $stream=[IO.File]::OpenWrite($overlayFile)
 try { $stream.SetLength(380000000) } finally { $stream.Dispose() }
 $timer=[Diagnostics.Stopwatch]::StartNew()
 $bounded=[WpsOnlineNative]::ReadImageSections($overlayFile)
 if ($bounded.Length -ne 0x1C00) { throw 'Archive overlay was read into memory.' }
 $boundedPlan=[WpsOnlinePredicate]::AnalyzeFile($overlayFile,$WPSStandardPattern)
 if ($boundedPlan.Offset -ne 0x600) { throw 'Bounded image lost the predicate or structural checks.' }
 Write-Host ('PASS large-overlay bounded read and full predicate validation: '+$timer.Elapsed.TotalSeconds+' seconds.')
 # Truncated section bytes must fail before detector invocation.
 $stream=[IO.File]::OpenWrite($overlayFile)
 try { $stream.SetLength(0x1900) } finally { $stream.Dispose() }
 $rejected=$false
 try { $null=[WpsOnlineNative]::ReadImageSections($overlayFile) } catch { $rejected=$true }
 if (-not $rejected) { throw 'Truncated sections accepted.' }
} finally { Remove-Item -LiteralPath $overlayFile -Force -ErrorAction SilentlyContinue }
foreach ($offset in @(0x600,0x850)) {
 $fastFixture=Standard-Fixture $offset
 $fastPlan=[WpsOnlinePredicate]::Analyze($fastFixture,$WPSStandardPattern)
 if ($fastPlan.Offset -ne $offset) { throw 'Fast detector did not follow moved predicate.' }

 $b=Standard-Fixture $offset; $p=Find-WPSStandardPatch $b
 if ($p.Offset -ne $offset) { throw 'Moved function not detected.' }
 Write-Host ('PASS AMD64 detection at '+$offset)
}
$b=Standard-Fixture; $b[0x1420]=0; Reject-Standard $b 'wrong config anchor'
$b=Standard-Fixture; $b[0x600+87]=0x90; Reject-Standard $b 'changed version comparison'
$b=Standard-Fixture; S32 $b 0x1800 0; Reject-Standard $b 'missing function metadata'
$b=Standard-Fixture; S16 $b 0x1A08 0xA200; Reject-Standard $b 'DIR64 relocation overlaps entry'
$b=Standard-Fixture; $b[0x450]=0; Reject-Standard $b 'missing backend call'
$b=Standard-Fixture; S64 $b 0x1500 0; Reject-Standard $b 'missing interface pointer'
$b=Standard-Fixture; $b[0x600]=0xB8; Reject-Standard $b 'already patched'
$b=Standard-Fixture; [byte[]]$cut=$b[0..600]; Reject-Standard $cut 'truncated file'
$dir=Join-Path $env:TEMP ('wps-standard-test-'+[Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($dir)
try {
 $cli=Join-Path (Split-Path -Parent $PSScriptRoot) 'Patch/Patch-WPS.ps1'
 $engine=Join-Path $PSHOME 'powershell.exe'
 foreach ($spec in @(@(0x2000,$false),@(0x2500,$true))) {
  $source=Join-Path $dir ('outer '+$spec[0]+'.exe')
  $inner=Standard-Fixture 0x850
  $wrapped=Wrap-NSIS $inner $spec[0] -Raw:$spec[1]
  [IO.File]::WriteAllBytes($source,$wrapped)
  $blocks=Get-NSISBlocks $source
  if ($blocks.Count -ne 2 -or $blocks[1].Offset -ne $spec[0]+100) { throw 'Dynamic block offset failed.' }
  $before=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
  & $engine -NoProfile -ExecutionPolicy Bypass -File $cli -Installer $source -AnalyzeOnly
  if ($LASTEXITCODE -ne 0 -or (Test-Path -LiteralPath ($source.Replace('.exe','_x64_Win8x_Patched.exe')))) { throw 'NSIS AnalyzeOnly failed.' }
  & $engine -NoProfile -ExecutionPolicy Bypass -File $cli -Installer $source
  if ($LASTEXITCODE -ne 0) { throw 'NSIS patch CLI failed.' }
  $output=$source.Replace('.exe','_x64_Win8x_Patched.exe')
  $actual=[IO.File]::ReadAllBytes($output); $expected=[byte[]]$inner.Clone()
  [byte[]]$patch=0xB8,1,0,0,0,0xC3; $patch.CopyTo($expected,0x850)
  if ([BitConverter]::ToString($actual) -ne [BitConverter]::ToString($expected)) { throw 'Inner output differs outside six bytes.' }
  if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne $before) { throw 'Original NSIS package was modified.' }
  $report=Get-Content -LiteralPath ($output+'.patch.json') -Raw | ConvertFrom-Json
  if ($report.ReferenceBuild -ne $false -or $report.Route -ne 'nsis-nonsolid-blocks') { throw 'Incorrect build/route report.' }
  & $engine -NoProfile -ExecutionPolicy Bypass -File $cli -Installer $source
  if ($LASTEXITCODE -ne 1) { throw 'Existing output not protected.' }
  Write-Host ('PASS NSIS extraction and CLI: offset '+$spec[0]+' raw='+$spec[1])
 }
 $source=Join-Path $dir 'ambiguous.exe'
 [IO.File]::WriteAllBytes($source,(Wrap-NSIS (Standard-Fixture) -Duplicate))
 & $engine -NoProfile -ExecutionPolicy Bypass -File $cli -Installer $source
 if ($LASTEXITCODE -ne 1 -or (Test-Path -LiteralPath ($source.Replace('.exe','_x64_Win8x_Patched.exe')))) { throw 'Multiple valid inner installers were not refused.' }
 $source=Join-Path $dir 'broken.exe'; $b=Wrap-NSIS (Standard-Fixture)
 S32 $b (0x2000+28) 0x7FFFFFFF; [IO.File]::WriteAllBytes($source,$b)
 $refused=$false; try { $null=Get-NSISBlocks $source } catch { $refused=$true }
 if (-not $refused) { throw 'Invalid NSIS chunk size accepted.' }
 Write-Host 'PASS ambiguous installer and malformed NSIS block refusal'
} finally { Remove-Item -LiteralPath $dir -Recurse -Force }
Write-Host 'All ordinary/international detector tests passed.'
exit 0
