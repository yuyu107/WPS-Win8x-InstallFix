param([string]$Installer,[int]$TimeoutMinutes=30)
$ErrorActionPreference='Stop'
$log=Join-Path $PSScriptRoot 'Online_Test4_Result.txt'
function Log([string]$s) {
 $line=(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')+' '+$s
 Write-Host $line
 Add-Content -LiteralPath $log -Value $line -Encoding UTF8
}
$active=@{}; $breaks=@{}; $pending=$null; $info=$null
$rootPatched=$false; $payloadPatched=0
try {
 if ([IntPtr]::Size -ne 8) { throw 'Use 64-bit Windows PowerShell on the 64-bit test system.' }
 if ($TimeoutMinutes -lt 1 -or $TimeoutMinutes -gt 120) { throw 'TimeoutMinutes must be between 1 and 120.' }
 if (-not $Installer) { $Installer=Join-Path $PSScriptRoot 'Original\wps_wid.cid-424762483.1792948203(1).exe' }
 $Installer=(Resolve-Path -LiteralPath $Installer).Path
 $rootHash=(Get-FileHash -LiteralPath $Installer -Algorithm SHA256).Hash
 if ($rootHash -ne '27D27759AD6D159A908AC7EC6CE3EBA5623ACAFA117A64644138673A6CBD2A31') { throw 'This test requires the original, unmodified online bootstrapper.' }
 . (Join-Path $PSScriptRoot 'InstallerPattern.ps1')
 Add-Type -Path @((Join-Path $PSScriptRoot 'OnlineDebugNative.cs'),(Join-Path $PSScriptRoot 'OnlinePredicate.cs'))
 Set-Content -LiteralPath $log -Value 'WPS international online compatibility Test4' -Encoding UTF8
 Log 'Launching the original online installer. Disk EXE files will not be patched.'
 $info=[WpsOnlineNative]::Start($Installer)
 $deadline=(Get-Date).AddMinutes($TimeoutMinutes)
 while ((Get-Date) -lt $deadline) {
  $event=[WpsOnlineNative]::Next(1000)
  if ($null -eq $event) { continue }
  $pending=$event; $handled=$true
  try {
   switch ($event.code) {
    3 {
     $active[[string]$event.pid]=$true
     $path=[WpsOnlineNative]::ImagePath($event.process)
     Log ('Process '+$event.pid+' '+$path)
     if ($event.pid -eq $info.pid) {
      [byte[]]$before=0x55,0x8B,0xEC,0x81,0xEC,0x20
      [byte[]]$after=0xB8,1,0,0,0,0xC3
      $address=New-Object IntPtr ($event.imageBase.ToInt64()+0x67500)
      [WpsOnlineNative]::Patch($event.process,$address,$before,$after)
      $rootPatched=$true
      Log 'Bootstrapper OS predicate patched in memory.'
     } elseif ($path -match '(?i)(wps|office|kpacket|setup)' -and (Get-Item -LiteralPath $path).Length -gt 33554432) {
      $b=$null; $plan=$null
      try {
       Log 'Reading bounded PE sections (archive overlay excluded).'
       $timer=[Diagnostics.Stopwatch]::StartNew()
       $plan=[WpsOnlinePredicate]::AnalyzeFile($path,$WPSStandardPattern)
       Log ('Predicate validation finished in '+$timer.Elapsed.TotalSeconds.ToString('F1')+' seconds.')
      } catch { Log ('VALIDATION FAILED: '+$_.Exception.Message); Log ($_.ScriptStackTrace | Out-String); throw }
      finally { $b=$null; [GC]::Collect() }
      if ($plan) {
       [byte[]]$before=0x40,0x53,0x48,0x83,0xEC,0x20
       [byte[]]$after=0xB8,1,0,0,0,0xC3
       $address=New-Object IntPtr ($event.imageBase.ToInt64()+$plan.Rva)
       [WpsOnlineNative]::Patch($event.process,$address,$before,$after)
       $payloadPatched++
       Log ('Installer predicate patched in memory: PID='+$event.pid+' RVA=0x'+$plan.Rva.ToString('X')+' Profile='+$plan.Profile)
      }
     }
    }
    1 {
     $handled=$false
     # Loader breakpoints for native and WOW64 process initialization.
     $breakKey=[string]$event.pid+':'+[string]$event.exceptionCode
     if (($event.exceptionCode -eq 2147483651 -or $event.exceptionCode -eq 1073741855) -and -not $breaks.ContainsKey($breakKey)) {
      $breaks[$breakKey]=$true; $handled=$true
     }
     if (-not $handled -and $event.firstChance -eq 0) { Log ('Unhandled exception PID='+$event.pid+' code=0x'+$event.exceptionCode.ToString('X')) }
    }
    5 { $active.Remove([string]$event.pid); Log ('Process exited: '+$event.pid) }
   }
  } finally {
   if (($event.code -eq 3 -or $event.code -eq 6) -and $event.file -ne [IntPtr]::Zero) { [void][WpsOnlineNative]::CloseHandle($event.file) }
   # CREATE_PROCESS/CREATE_THREAD event process/thread handles are closed
   # by Windows when the matching exit event is continued.
   [WpsOnlineNative]::Continue($event,$handled)
   $pending=$null
  }
  if ($active.Count -eq 0) { break }
 }
 Log ('Session ended. Bootstrapper patched='+$rootPatched+'; validated installer processes patched='+$payloadPatched)
 Log 'These counts do not by themselves confirm successful installation. Check the official installer result.'
 if (-not $rootPatched -or $payloadPatched -eq 0) { exit 2 }
 exit 0
} catch {
 Log ('FAILED: '+$_.Exception.Message)
 Log 'If process creation requires elevation, right-click Start_Online_Test4.cmd and run as administrator.'
 exit 1
} finally {
 if ($pending) { try { [WpsOnlineNative]::Continue($pending,$pending.code -ne 1) } catch {} }
 foreach ($processId in @($active.Keys)) { [WpsOnlineNative]::Detach([uint32]$processId) }
 if ($info) {
  if ($info.thread -ne [IntPtr]::Zero) { [void][WpsOnlineNative]::CloseHandle($info.thread) }
  if ($info.process -ne [IntPtr]::Zero) { [void][WpsOnlineNative]::CloseHandle($info.process) }
 }
}
