$ErrorActionPreference='Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'Patch/InstallerPattern.ps1')
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
 $ok=$false; try { $null=[WpsOnlinePredicate]::Analyze($b,$WPSStandardPattern) } catch { $ok=$true }
 if (-not $ok) { throw ('Expected refusal: '+$name) }; Write-Host ('PASS refusal: '+$name)
}
# Regression: a large installer overlay must not enter PowerShell's array binder.
Add-Type -Path @((Join-Path (Split-Path -Parent $PSScriptRoot) 'Patch/OnlineDebugNative.cs'),(Join-Path (Split-Path -Parent $PSScriptRoot) 'Patch/OnlinePredicate.cs'))
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
 $b=Standard-Fixture $offset
 $p=[WpsOnlinePredicate]::Analyze($b,$WPSStandardPattern)
 if ($p.Offset -ne $offset) { throw 'Moved predicate not detected.' }
}
$b=Standard-Fixture; $b[0x1420]=0; Reject-Standard $b 'wrong config anchor'
$b=Standard-Fixture; $b[0x600+87]=0x90; Reject-Standard $b 'changed version comparison'
$b=Standard-Fixture; S32 $b 0x1800 0; Reject-Standard $b 'missing function metadata'
$b=Standard-Fixture; S16 $b 0x1A08 0xA200; Reject-Standard $b 'DIR64 relocation overlaps entry'
$b=Standard-Fixture; $b[0x450]=0; Reject-Standard $b 'missing backend call'
$b=Standard-Fixture; S64 $b 0x1500 0; Reject-Standard $b 'missing interface pointer'
$b=Standard-Fixture; $b[0x600]=0xB8; Reject-Standard $b 'already patched'
$b=Standard-Fixture; [byte[]]$cut=$b[0..600]; Reject-Standard $cut 'truncated file'
Write-Host 'All international online predicate tests passed.'
