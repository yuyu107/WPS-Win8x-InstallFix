param([string]$Installer,[switch]$AnalyzeOnly)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'WPSStandard.Core.ps1')
$known=@(
 @{Version='29158'; Name='WPS_Setup_x64_29158.exe'; Outer='1DD9F29797FA6D0A17A7F9CCC7FFEF052F8A89327669570B77455A56FB9C4E3F'; Inner='344962D031570139C87F3E7A3A64033E89E4EAC015CF378DA9EE285C1A454A8C'; Output='9D174EB69D71E91768AED8D7B4B3E333ACE32BBA30B5F138C06D349F96BA6E14'}
)
$inputs=@()
if ($Installer) { $inputs+=$Installer } else {
 foreach ($c in $known) { $p=Join-Path $PSScriptRoot $c.Name; if (Test-Path -LiteralPath $p) { $inputs+=$p } }
}
if ($inputs.Count -eq 0) { Write-Host 'Drag an original Standard installer onto 01-Apply-Patch.cmd, or use -Installer PATH.'; exit 2 }
$failed=$false
foreach ($inputPath in $inputs) {
 $work=$null; $created=$false; $output=$null
 try {
  $path=(Resolve-Path -LiteralPath $inputPath).Path
  $file=Get-Item -LiteralPath $path
  $outerHash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
  $reference=@($known | Where-Object { $_.Outer -eq $outerHash -or $_.Inner -eq $outerHash })
  $work=Join-Path ([IO.Path]::GetTempPath()) ('wps-patch-'+[Guid]::NewGuid().ToString('N'))
  [void][IO.Directory]::CreateDirectory($work)
  $probeStream=[IO.File]::OpenRead($path)
  try {
   [byte[]]$prefix=New-Object byte[] 4096
   $read=$probeStream.Read($prefix,0,$prefix.Length)
   $peOffset=Std-U32 $prefix 60
   $direct=$peOffset+6 -le $read -and (Std-U32 $prefix $peOffset) -eq 0x4550 -and (Std-U16 $prefix ($peOffset+4)) -eq 0x8664
  } finally { $probeStream.Dispose() }
  $matches=@(); $route='direct-amd64'
  if ($direct) {
   $b=[IO.File]::ReadAllBytes($path)
   $plan=Find-WPSStandardPatch $b
   $matches += [pscustomobject]@{Path=$path; Plan=$plan; Block=$null}
   $b=$null
  } else {
   $route='nsis-nonsolid-blocks'
   Write-Host 'Reading NSIS block boundaries (no fixed extraction offset)...'
   $blocks=Get-NSISBlocks $path
   $number=0; $lastFailure='No AMD64 PE block found.'
   foreach ($block in $blocks) {
    $isPE=$false
    try { $isPE=Read-NSISBlock $path $block -Probe } catch { continue }
    if (-not $isPE) { continue }
    $number++
    $inner=Join-Path $work ('inner-'+$number+'.exe')
    try {
     Write-Host ('Checking AMD64 candidate '+$number+' ...')
     Read-NSISBlock $path $block $inner
     $b=[IO.File]::ReadAllBytes($inner)
     $plan=Find-WPSStandardPatch $b
     $matches += [pscustomobject]@{Path=$inner; Plan=$plan; Block=$block.Offset}
    } catch { $lastFailure=$_.Exception.Message; Remove-Item -LiteralPath $inner -Force -ErrorAction SilentlyContinue }
    finally { $b=$null; [GC]::Collect() }
   }
   if ($matches.Count -eq 0) { throw ('No supported inner installer: '+$lastFailure) }
  }
  if ($matches.Count -ne 1) { throw ('Ambiguous inner installers: '+$matches.Count) }
  $selected=$matches[0]; $plan=$selected.Plan
  $innerHash=(Get-FileHash -LiteralPath $selected.Path -Algorithm SHA256).Hash
  if ($reference.Count -eq 1 -and $innerHash -ne $reference[0].Inner) { throw 'Known package inner hash mismatch.' }
  $report=[ordered]@{InputSHA256=$outerHash; InnerSHA256=$innerHash; Route=$route; StreamOffset=$selected.Block; Profile=$plan.Profile; FileOffset=('0x{0:X}' -f $plan.Offset); Rva=('0x{0:X}' -f $plan.Rva); Before=$plan.Before; After=$plan.After; ReferenceBuild=($reference.Count -eq 1)}
  $report | ConvertTo-Json | Write-Host
  if ($reference.Count -eq 0) { Write-Host 'Recognized code family; this build has not been tested for installation.' -ForegroundColor Yellow }
  if ($AnalyzeOnly) { continue }
  $name=$file.BaseName+'_x64_Win8x_Patched.exe'
  if ($reference.Count -eq 1) { $name='WPS_'+$reference[0].Version+'_x64_Win8x_Patched.exe' }
  $output=Join-Path $file.DirectoryName $name
  if (Test-Path -LiteralPath $output) { throw ('Output already exists: '+$output) }
  [IO.File]::Copy($selected.Path,$output,$false); $created=$true
  if ((Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash -ne $innerHash) { throw 'Inner installer changed while copying.' }
  $s=[IO.File]::Open($output,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
  try {
   $s.Position=$plan.Offset; [byte[]]$before=New-Object byte[] 6
   if ($s.Read($before,0,6) -ne 6 -or [BitConverter]::ToString($before) -ne '40-53-48-83-EC-20') { throw 'Patch preimage mismatch.' }
   $s.Position=$plan.Offset; [byte[]]$after=0xB8,0x01,0,0,0,0xC3
   $s.Write($after,0,6); $s.Flush()
  } finally { $s.Dispose() }
  $outputHash=(Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash
  if ($reference.Count -eq 1 -and $outputHash -ne $reference[0].Output) { throw 'Known output SHA256 mismatch.' }
  if ((Get-Item -LiteralPath $output).Length -ne (Get-Item -LiteralPath $selected.Path).Length) { throw 'Output length changed.' }
  $report.OutputSHA256=$outputHash; $report.OutputFile=$name
  $report | ConvertTo-Json | Set-Content -LiteralPath ($output+'.patch.json') -Encoding UTF8
  Write-Host ('SUCCESS: '+$output) -ForegroundColor Green
  Write-Host 'The output is the official inner installer with six bytes changed; its vendor signature is invalid.'
 } catch {
  if ($created -and $output) { Remove-Item -LiteralPath $output -Force -ErrorAction SilentlyContinue }
  Write-Host ('FAILED: '+$_.Exception.Message) -ForegroundColor Red
  $failed=$true
 } finally {
  if ($work) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
 }
}
if ($failed) { exit 1 }
exit 0
