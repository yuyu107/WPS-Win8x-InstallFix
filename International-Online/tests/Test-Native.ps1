$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
Add-Type -Path (Join-Path $root 'Patch/OnlineDebugNative.cs')
if ([IntPtr]::Size -ne 8) { throw 'Native debugger test requires an x64 host.' }
if ([Runtime.InteropServices.Marshal]::SizeOf([type][WpsOnlineNative+DebugEvent]) -ne 176) { throw 'Wrong DEBUG_EVENT layout.' }
if ([Runtime.InteropServices.Marshal]::SizeOf([type][WpsOnlineNative+StartupInfo]) -ne 104) { throw 'Wrong STARTUPINFO layout.' }
if ([Runtime.InteropServices.Marshal]::OffsetOf([type][WpsOnlineNative+DebugEvent],'imageBase').ToInt32() -ne 40) { throw 'Wrong image-base offset.' }
$work=Join-Path $env:TEMP ('wps-online-native-'+[Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($work)
$pi=$null; $pending=$null; $seen=@{}; $active=@{}
try {
 $result=Join-Path $work 'result.txt'; $program=Join-Path $work 'test x86 parent.exe'
 $worker=Join-Path $work 'test x64 child.exe'
 $escaped=$result.Replace('"','""')
 $source='using System.IO; public class WpsChild { public static void Main() { File.WriteAllText(@"'+$escaped+'", "ran"); } }'
 Add-Type -TypeDefinition $source -OutputAssembly $worker -OutputType WindowsApplication
 $workerEscaped=$worker.Replace('"','""')
 $parentSource='using System.Diagnostics; public class WpsRoot { public static void Main() { Process p=Process.Start(@"'+$workerEscaped+'"); p.WaitForExit(); } }'
 $provider=New-Object Microsoft.CSharp.CSharpCodeProvider
 $parameters=New-Object CodeDom.Compiler.CompilerParameters
 $parameters.GenerateExecutable=$true; $parameters.OutputAssembly=$program
 $parameters.CompilerOptions='/platform:x86 /target:winexe'
 [void]$parameters.ReferencedAssemblies.Add('System.dll')
 try {
  $compiled=$provider.CompileAssemblyFromSource($parameters,$parentSource)
  if ($compiled.Errors.HasErrors) { throw ($compiled.Errors | Out-String) }
 } finally { $provider.Dispose() }
 $pi=[WpsOnlineNative]::Start($program)
 $started=$false; $patched=$false; $workerSeen=$false; $exited=$false; $deadline=(Get-Date).AddSeconds(45)
 while ((Get-Date) -lt $deadline -and -not $exited) {
  $e=[WpsOnlineNative]::Next(1000)
  if ($null -eq $e) { continue }
  $pending=$e; $handled=$true
  if ($e.code -eq 3) {
   $active[[string]$e.pid]=$true
   if ($e.pid -eq $pi.pid) {
    $path=[WpsOnlineNative]::ImagePath($e.process)
    if ($path -ne $program) { throw 'Unexpected debuggee path.' }
    [byte[]]$mz=0x4D,0x5A
    [WpsOnlineNative]::Patch($e.process,$e.imageBase,$mz,$mz)
    $started=$true; $patched=$true
   } else {
    if ([WpsOnlineNative]::ImagePath($e.process) -eq $worker) {
     [byte[]]$mz=0x4D,0x5A
     [WpsOnlineNative]::Patch($e.process,$e.imageBase,$mz,$mz)
     $workerSeen=$true
    }
   }
  } elseif ($e.code -eq 1) {
   $handled=$false; $key=[string]$e.pid+':'+[string]$e.exceptionCode
   if (($e.exceptionCode -eq 2147483651 -or $e.exceptionCode -eq 1073741855) -and -not $seen.ContainsKey($key)) { $seen[$key]=$true; $handled=$true }
  } elseif ($e.code -eq 5) {
   $active.Remove([string]$e.pid)
   if ($e.pid -eq $pi.pid) { $exited=$true }
  }
  if (($e.code -eq 3 -or $e.code -eq 6) -and $e.file -ne [IntPtr]::Zero) { [void][WpsOnlineNative]::CloseHandle($e.file) }
  [WpsOnlineNative]::Continue($e,$handled); $pending=$null
 }
 if (-not $started -or -not $patched -or -not $workerSeen -or -not $exited -or -not (Test-Path -LiteralPath $result)) { throw 'Debug event/patch/continue session did not finish.' }
 if ((Get-Content -LiteralPath $result -Raw) -ne 'ran') { throw 'Debuggee did not run normally.' }
 Write-Host 'PASS native layouts, WOW64 parent/AMD64 child debug propagation, memory preimage/write/read-back, continue and normal exit.'
} finally {
 if ($pending) { try { [WpsOnlineNative]::Continue($pending,$pending.code -ne 1) } catch {} }
 foreach ($id in $active.Keys) { [WpsOnlineNative]::Detach([uint32]$id) }
 if ($pi) { [void][WpsOnlineNative]::CloseHandle($pi.thread); [void][WpsOnlineNative]::CloseHandle($pi.process) }
 Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
exit 0
