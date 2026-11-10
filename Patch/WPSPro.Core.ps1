# Native KPacket PE32 family detector. Compatible with Windows PowerShell 4.
$WPSProPattern = '6A 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 0C 84 C0 74 5C 56 6A 00 E8 ?? ?? ?? ?? 83 C4 04 85 C0 75 46 50 50 6A 0A E8 ?? ?? ?? ?? 83 C4 0C 84 C0 75 36 57 E8 ?? ?? ?? ?? 8B F0 E8 ?? ?? ?? ?? 8B F8 E8 ?? ?? ?? ?? 83 FE 06 75 09 83 FF 01 76 04 B1 01 EB 02 32 C9 5F 84 C0 74 09 84 C9 75 09 83 FE 0A 73 04 33 C0 5E C3 B8 01 00 00 00 5E C3'

function Assert-Range([byte[]]$Bytes,[long]$Offset,[long]$Count) {
    if ($Offset -lt 0 -or $Count -lt 0 -or $Offset -gt $Bytes.LongLength - $Count) { throw 'Invalid or truncated PE range.' }
}
function Read-U16([byte[]]$Bytes,[long]$Offset) {
    Assert-Range $Bytes $Offset 2
    return [BitConverter]::ToUInt16($Bytes,[int]$Offset)
}
function Read-U32([byte[]]$Bytes,[long]$Offset) {
    Assert-Range $Bytes $Offset 4
    return [long][BitConverter]::ToUInt32($Bytes,[int]$Offset)
}
function Get-PE32([byte[]]$Bytes) {
    if ((Read-U16 $Bytes 0) -ne 0x5A4D) { throw 'Not a PE executable.' }
    $p = Read-U32 $Bytes 0x3C
    if ((Read-U32 $Bytes $p) -ne 0x4550 -or (Read-U16 $Bytes ($p+4)) -ne 0x14C) { throw 'Only native PE32 i386 KPacket installers are supported.' }
    $n = Read-U16 $Bytes ($p+6)
    $optSize = Read-U16 $Bytes ($p+20)
    $opt = $p+24
    Assert-Range $Bytes $opt $optSize
    if ($optSize -lt 144 -or (Read-U16 $Bytes $opt) -ne 0x10B -or $n -lt 1 -or $n -gt 96) { throw 'Invalid PE32 headers.' }
    if ((Read-U32 $Bytes ($opt+92)) -lt 6) { throw 'Missing PE relocation directory.' }
    $sections = @()
    for ($i=0; $i -lt $n; $i++) {
        $s = $opt+$optSize+$i*40
        Assert-Range $Bytes $s 40
        $raw = Read-U32 $Bytes ($s+20)
        $size = Read-U32 $Bytes ($s+16)
        Assert-Range $Bytes $raw $size
        $sections += [pscustomobject]@{Rva=(Read-U32 $Bytes ($s+12)); Raw=$raw; Size=$size; Flags=(Read-U32 $Bytes ($s+36))}
    }
    return [pscustomobject]@{Base=(Read-U32 $Bytes ($opt+28)); Sections=$sections; RelocRva=(Read-U32 $Bytes ($opt+136)); RelocSize=(Read-U32 $Bytes ($opt+140))}
}
function Convert-RvaToRaw($PE,[long]$Rva,[long]$Size=1) {
    $matches = @($PE.Sections | Where-Object { $Rva -ge $_.Rva -and $Size -ge 0 -and $Rva+$Size -le $_.Rva+$_.Size })
    if ($matches.Count -ne 1) { throw 'RVA is not uniquely mapped to file bytes.' }
    return [long]($matches[0].Raw+$Rva-$matches[0].Rva)
}
function Test-CodeRva($PE,[long]$Rva) {
    return @($PE.Sections | Where-Object { ($_.Flags -band 0x20000000) -ne 0 -and $Rva -ge $_.Rva -and $Rva -lt $_.Rva+$_.Size }).Count -eq 1
}
function Get-AsciiAtVA([byte[]]$Bytes,$PE,[long]$VA,[int]$Length) {
    $o = Convert-RvaToRaw $PE ($VA-$PE.Base) ($Length+1)
    if ($Bytes[$o+$Length] -ne 0) { return '' }
    return [Text.Encoding]::ASCII.GetString($Bytes,[int]$o,$Length)
}
function Get-Relocations([byte[]]$Bytes,$PE) {
    if ($PE.RelocRva -eq 0 -or $PE.RelocSize -lt 8) { throw 'Missing relocation information; family validation cannot complete.' }
    $p = Convert-RvaToRaw $PE $PE.RelocRva $PE.RelocSize
    $end = $p+$PE.RelocSize
    $entries = New-Object 'System.Collections.Generic.List[long]'
    while ($p -lt $end) {
        if ($end-$p -lt 8) { throw 'Truncated relocation block.' }
        $page = Read-U32 $Bytes $p
        $size = Read-U32 $Bytes ($p+4)
        if ($size -lt 8 -or ($size % 2) -ne 0 -or $p+$size -gt $end) { throw 'Invalid relocation block size.' }
        for ($q=$p+8; $q -lt $p+$size; $q+=2) {
            $v = [BitConverter]::ToUInt16($Bytes,[int]$q)
            $type = $v -shr 12
            if ($type -ne 0) { $entries.Add([long]$type*4294967296L+$page+($v -band 0xFFF)) }
        }
        $p += $size
    }
    return ,$entries.ToArray()
}
function Find-WPSProPatch([byte[]]$Bytes) {
    $pe = Get-PE32 $Bytes
    $relocs = Get-Relocations $Bytes $pe
    $latin = [Text.Encoding]::GetEncoding(28591)
    $parts = foreach ($token in ($WPSProPattern -split ' ')) {
        if ($token -eq '??') { '.' } else { '\x'+$token }
    }
    $rx = New-Object -TypeName Text.RegularExpressions.Regex -ArgumentList ($parts -join ''), ([Text.RegularExpressions.RegexOptions]::Singleline)
    $candidates = @()
    foreach ($section in $pe.Sections) {
        if (($section.Flags -band 0x20000000) -eq 0) { continue }
        $code = $latin.GetString($Bytes,[int]$section.Raw,[int]$section.Size)
        foreach ($match in $rx.Matches($code)) {
            $o = [long]($section.Raw+$match.Index)
            $rva = [long]($section.Rva+$match.Index)
            # Two semantic anchors identify this OS support predicate.
            if ((Get-AsciiAtVA $Bytes $pe (Read-U32 $Bytes ($o+3)) 7) -ne 'support') { continue }
            if ((Get-AsciiAtVA $Bytes $pe (Read-U32 $Bytes ($o+8)) 19) -ne 'InstallOnServer2008') { continue }
            foreach ($call in @(12,27,43,56,63,70)) {
                $target = $rva+$call+5+[BitConverter]::ToInt32($Bytes,[int]($o+$call+1))
                if (-not (Test-CodeRva $pe $target)) { throw 'Predicate helper call points outside executable code.' }
            }
            # Compact relocation records avoid a large PSObject allocation per entry.
            $operand3 = 0; $operand8 = 0
            foreach ($entry in $relocs) {
                $entryRva = $entry -band 4294967295L
                $entryType = $entry -shr 32
                if ($entryType -eq 3 -and $entryRva -eq $rva+3) { $operand3++ }
                if ($entryType -eq 3 -and $entryRva -eq $rva+8) { $operand8++ }
                $width = 8
                if ($entryType -eq 3) { $width = 4 }
                if ($entryRva -lt $rva+3 -and $entryRva+$width -gt $rva) { throw 'Relocation overlaps patch bytes.' }
                if ($entryRva -lt $rva+116 -and $entryRva+$width -gt $rva+109) { throw 'Relocation overlaps success return.' }
            }
            if ($operand3 -ne 1 -or $operand8 -ne 1) { throw 'Predicate relocation layout changed.' }
            $candidates += [pscustomobject]@{Offset=$o; Rva=$rva; Base=$pe.Base; SuccessRva=($rva+109); Original='6A0068'; Patch='56EB6A'; Profile='kpacket-pe32-osgate-v1'}
        }
    }
    if ($candidates.Count -ne 1) { throw ('Expected one OS predicate, found '+$candidates.Count+'. Unsupported, already patched, or ambiguous file.') }
    $candidate = $candidates[0]
    $calls = 0; $thunks = @()
    foreach ($section in $pe.Sections) {
        if (($section.Flags -band 0x20000000) -eq 0) { continue }
        $code = $latin.GetString($Bytes,[int]$section.Raw,[int]$section.Size)
        foreach ($match in [regex]::Matches($code,'[\xE8\xE9]....',[Text.RegularExpressions.RegexOptions]::Singleline)) {
            $raw = $section.Raw+$match.Index
            $target = $section.Rva+$match.Index+5+[BitConverter]::ToInt32($Bytes,[int]($raw+1))
            if ($target -eq $candidate.Rva) {
                if ($Bytes[$raw] -eq 0xE8) { $calls++ } else { $thunks += ($pe.Base+$section.Rva+$match.Index) }
            }
        }
    }
    if ($calls -lt 2 -or $thunks.Count -lt 1) { throw 'Missing shared backend calls or interface thunk.' }
    # Require a thunk pointer in a non-executable data section.
    $pointerFound = $false
    foreach ($section in $pe.Sections) {
        if (($section.Flags -band 0x20000000) -ne 0) { continue }
        $data = $latin.GetString($Bytes,[int]$section.Raw,[int]$section.Size)
        foreach ($thunk in $thunks) {
            $needle = $latin.GetString([BitConverter]::GetBytes([uint32]$thunk))
            if ($data.IndexOf($needle,[StringComparison]::Ordinal) -ge 0) { $pointerFound = $true }
        }
    }
    if (-not $pointerFound) { throw 'Missing interface thunk pointer in data.' }
    return $candidate
}
