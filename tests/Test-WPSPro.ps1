$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'Patch/WPSPro.Core.ps1')
function Put16([byte[]]$b,[int]$o,[uint16]$v) { [BitConverter]::GetBytes($v).CopyTo($b,$o) }
function Put32([byte[]]$b,[int]$o,[uint32]$v) { [BitConverter]::GetBytes($v).CopyTo($b,$o) }
function Make-Fixture([int]$FunctionOffset=0x400) {
    [byte[]]$b = New-Object byte[] 8192
    Put16 $b 0 0x5A4D; Put32 $b 0x3C 0x80
    Put32 $b 0x80 0x4550; Put16 $b 0x84 0x14C; Put16 $b 0x86 3; Put16 $b 0x94 224
    $opt=0x98
    Put16 $b $opt 0x10B; Put32 $b ($opt+28) 0x400000
    Put32 $b ($opt+92) 16; Put32 $b ($opt+136) 0x4000; Put32 $b ($opt+140) 12
    $section=$opt+224
    foreach ($spec in @(@(0x1000,0x200,0x1000,0x60000020),@(0x3000,0x1200,0x400,0x40000040),@(0x4000,0x1600,0x200,0x40000040))) {
        Put32 $b ($section+8) $spec[2]; Put32 $b ($section+12) $spec[0]
        Put32 $b ($section+16) $spec[2]; Put32 $b ($section+20) $spec[1]
        Put32 $b ($section+36) $spec[3]; $section+=40
    }
    $o=$FunctionOffset; $rva=0x1000+$o-0x200
    $i=0
    foreach ($token in ($WPSProPattern -split ' ')) {
        if ($token -ne '??') { $b[$o+$i]=[Convert]::ToByte($token,16) }; $i++
    }
    Put32 $b ($o+3) 0x403000; Put32 $b ($o+8) 0x403020
    [Text.Encoding]::ASCII.GetBytes('support').CopyTo($b,0x1200)
    [Text.Encoding]::ASCII.GetBytes('InstallOnServer2008').CopyTo($b,0x1220)
    foreach ($at in @(12,27,43,56,63,70)) {
        [BitConverter]::GetBytes([int](0x1E00-$rva-$at-5)).CopyTo($b,$o+$at+1)
    }
    foreach ($at in @(0x250,0x270,0x290)) {
        $b[$at]=0xE8
        [BitConverter]::GetBytes([int]($rva-(0x1000+$at-0x200)-5)).CopyTo($b,$at+1)
    }
    $b[0x290]=0xE9; Put32 $b 0x1300 0x401090
    Put32 $b 0x1600 0x1000; Put32 $b 0x1604 12
    Put16 $b 0x1608 ([uint16](0x3000+($rva -band 0xFFF)+3))
    Put16 $b 0x160A ([uint16](0x3000+($rva -band 0xFFF)+8))
    return ,$b
}
function Expect-Reject([byte[]]$b,[string]$name) {
    $rejected=$false
    try { $null=Find-WPSProPatch $b } catch { $rejected=$true }
    if (-not $rejected) { throw ('Expected rejection: '+$name) }
    Write-Host ('PASS refusal: '+$name)
}
foreach ($offset in @(0x400,0x650)) {
    $b=Make-Fixture $offset
    $plan=Find-WPSProPatch $b
    if ($plan.Offset -ne $offset) { throw 'Relocated function not detected.' }
    foreach ($base in @(0x400000,0x120000,0x10000000)) {
        [byte[]]$entry=$b[$offset..($offset+115)]
        $entry[0]=0x56; $entry[1]=0xEB; $entry[2]=0x6A
        foreach ($at in @(3,8)) {
            $v=([long][BitConverter]::ToUInt32($entry,$at)+$base-0x400000) -band 4294967295L
            Put32 $entry $at ([uint32]$v)
        }
        if ([BitConverter]::ToString($entry,0,3) -ne '56-EB-6A' -or [BitConverter]::ToString($entry,109,7) -ne 'B8-01-00-00-00-5E-C3') { throw 'ASLR corrupts patch.' }
    }
    Write-Host ('PASS detection and ASLR: offset '+$offset)
}
$b=Make-Fixture; $b[0]=0; Expect-Reject $b 'invalid PE'
$b=Make-Fixture; Put16 $b 0x84 0x8664; Expect-Reject $b 'wrong architecture'
$b=Make-Fixture; $b[0x1220]=0x58; Expect-Reject $b 'wrong semantic anchor'
$b=Make-Fixture; $b[0x400+75]=0x90; Expect-Reject $b 'changed OS comparison'
$b=Make-Fixture; Put16 $b 0x1608 0x3201; Expect-Reject $b 'unsafe relocation layout'
$b=Make-Fixture; Put32 $b 0x1604 0; Expect-Reject $b 'invalid relocation block'
$b=Make-Fixture; $b[0x250]=0x90; $b[0x270]=0x90; Expect-Reject $b 'missing backend callers'
$b=Make-Fixture; Put32 $b 0x1300 0; Expect-Reject $b 'missing interface pointer'
$b=Make-Fixture; $b[0x400]=0x56; $b[0x401]=0xEB; $b[0x402]=0x6A; Expect-Reject $b 'already patched'
$b=Make-Fixture; [byte[]]$short=$b[0..511]; Expect-Reject $short 'truncated sections'
$b=Make-Fixture
[Array]::Copy($b,0x400,$b,0x650,116)
foreach ($at in @(12,27,43,56,63,70)) {
    [BitConverter]::GetBytes([int](0x1E00-0x1450-$at-5)).CopyTo($b,0x650+$at+1)
}
Put32 $b (0x98+140) 16; Put32 $b 0x1604 16
Put16 $b 0x160C 0x3453; Put16 $b 0x160E 0x3458
$reason=''
try { $null=Find-WPSProPatch $b } catch { $reason=$_.Exception.Message }
if ($reason -notmatch 'found 2') { throw ('Ambiguous-candidate check failed: '+$reason) }
Write-Host 'PASS refusal: two fully validated candidates'

# Exercise the actual CLI, copy/write path, report and no-overwrite contract.
$dir=Join-Path $env:TEMP ('wps-detector-test-'+[Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($dir)
try {
    $source=Join-Path $dir 'fixture installer.exe'
    $b=Make-Fixture
    [IO.File]::WriteAllBytes($source,$b)
    $before=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    $cli=Join-Path (Split-Path -Parent $PSScriptRoot) 'Patch/Patch-WPSPro.ps1'
    $engine=Join-Path $PSHOME 'powershell.exe'
    & $engine -NoProfile -ExecutionPolicy Bypass -File $cli -Installer $source -AnalyzeOnly
    if ($LASTEXITCODE -ne 0 -or @(Get-ChildItem -LiteralPath $dir).Count -ne 1) { throw 'AnalyzeOnly modified files or failed.' }
    & $engine -NoProfile -ExecutionPolicy Bypass -File $cli -Installer $source
    if ($LASTEXITCODE -ne 0) { throw 'Patch CLI failed.' }
    $output=Join-Path $dir 'fixture installer_Win8x_Patched.exe'
    $actual=[IO.File]::ReadAllBytes($output)
    $expected=[byte[]]$b.Clone()
    $expected[0x400]=0x56; $expected[0x401]=0xEB; $expected[0x402]=0x6A
    if ([BitConverter]::ToString($actual) -ne [BitConverter]::ToString($expected)) { throw 'Output bytes differ outside the patch.' }
    if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne $before) { throw 'Original was modified.' }
    $report=Get-Content -LiteralPath ($output+'.patch.json') -Raw | ConvertFrom-Json
    if ($report.InstallationVerified -ne $false -or $report.OutputSHA256 -ne (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash) { throw 'Report hash or verification status is incorrect.' }
    $saved=(Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash
    & $engine -NoProfile -ExecutionPolicy Bypass -File $cli -Installer $source
    if ($LASTEXITCODE -ne 1 -or (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash -ne $saved) { throw 'Existing output was not protected.' }
    Write-Host 'PASS CLI analysis, write, report, source preservation and existing output'
} finally { Remove-Item -LiteralPath $dir -Recurse -Force }
Write-Host 'All detector tests passed.'
exit 0
