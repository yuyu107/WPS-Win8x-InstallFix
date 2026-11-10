param([string]$Installer,[switch]$AnalyzeOnly)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'WPSPro.Core.ps1')
try {
    if (-not $Installer) { $Installer = Join-Path $PSScriptRoot 'WPSPro_12.1.0.29161.exe' }
    $Installer = (Resolve-Path -LiteralPath $Installer).Path
    $info = Get-Item -LiteralPath $Installer
    Write-Host 'Checking KPacket function structure and relocations...'
    $hash = (Get-FileHash -LiteralPath $Installer -Algorithm SHA256).Hash
    $bytes = [IO.File]::ReadAllBytes($Installer)
    $plan = Find-WPSProPatch $bytes
    $known = $hash -eq 'FEB097C7A40803DDC3BAE21162C971ED40F4506698E17EDA3A6FD461CFC59870'
    $report = [ordered]@{InputSHA256=$hash; Profile=$plan.Profile; FileOffset=('0x{0:X}' -f $plan.Offset); Rva=('0x{0:X}' -f $plan.Rva); Before=$plan.Original; After=$plan.Patch; InstallationVerified=$known}
    $report | ConvertTo-Json | Write-Host
    if (-not $known) { Write-Host 'Recognized code family; this build has NOT been tested for installation.' -ForegroundColor Yellow }
    if ($AnalyzeOnly) { exit 0 }
    $output = Join-Path $info.DirectoryName ($info.BaseName+'_Win8x_Patched.exe')
    if (Test-Path -LiteralPath $output) { throw ('Output already exists: '+$output) }
    # Release the input buffer before copying the large package.
    $bytes = $null
    [GC]::Collect()
    [IO.File]::Copy($Installer,$output,$false)
    try {
        if ((Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash -ne $hash) { throw 'Input changed while copying.' }
        $s = [IO.File]::Open($output,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        try {
            $s.Position = $plan.Offset
            [byte[]]$original = New-Object byte[] 3
            if ($s.Read($original,0,3) -ne 3 -or [BitConverter]::ToString($original) -ne '6A-00-68') { throw 'Patch preimage changed.' }
            $s.Position = $plan.Offset
            [byte[]]$replacement = 0x56,0xEB,0x6A
            $s.Write($replacement,0,3)
            $s.Flush()
        } finally { $s.Dispose() }
        $after = (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash
        if ($known -and $after -ne 'E6604FB5A8E2D1625A41EB9829DB13D0B76BBA4EC8F27813374407F5D8A631D1') { throw 'Known-build output hash mismatch.' }
        if ((Get-Item -LiteralPath $output).Length -ne $info.Length) { throw 'Output size mismatch.' }
        $report.OutputSHA256 = $after
        $report.OutputFile = [IO.Path]::GetFileName($output)
        $report | ConvertTo-Json | Set-Content -LiteralPath ($output+'.patch.json') -Encoding UTF8
        Write-Host ('SUCCESS: '+$output) -ForegroundColor Green
        Write-Host 'The output vendor digital signature is no longer valid.'
    } catch { Remove-Item -LiteralPath $output -Force -ErrorAction SilentlyContinue; throw }
    exit 0
} catch {
    Write-Host ('FAILED: '+$_.Exception.Message) -ForegroundColor Red
    exit 1
}
