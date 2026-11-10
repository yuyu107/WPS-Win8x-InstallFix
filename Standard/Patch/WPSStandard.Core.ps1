# x64 KPacket predicate and NSIS block reader; Windows PowerShell 4.0.
$WPSStandardPattern = '40 53 48 83 EC 20 45 33 C0 48 8D 15 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 84 C0 74 68 33 C9 E8 ?? ?? ?? ?? 85 C0 75 50 45 33 C0 8D 48 0A 33 D2 E8 ?? ?? ?? ?? 84 C0 75 3F 48 89 7C 24 30 E8 ?? ?? ?? ?? 48 8B D8 E8 ?? ?? ?? ?? 48 8B F8 E8 ?? ?? ?? ?? 48 83 FB 06 75 0A 48 83 FF 01 76 04 B1 01 EB 02 32 C9 48 8B 7C 24 30 84 C0 74 38 84 C9 75 06 48 83 FB 0A 72 2E BB 01 00 00 00 8B C3 48 83 C4 20 5B C3 BB 01 00 00 00 8B CB E8 ?? ?? ?? ?? 85 C0 75 13 45 33 C0 8D 4B 09 33 D2 E8 ?? ?? ?? ?? 84 C0 75 02 33 DB 8B C3 48 83 C4 20 5B C3'
function Std-Range([byte[]]$b,[long]$o,[long]$n) {
    if ($o -lt 0 -or $n -lt 0 -or $o -gt $b.LongLength-$n) { throw 'Invalid or truncated PE range.' }
}
function Std-U16([byte[]]$b,[long]$o) { Std-Range $b $o 2; return [BitConverter]::ToUInt16($b,[int]$o) }
function Std-U32([byte[]]$b,[long]$o) { Std-Range $b $o 4; return [long][BitConverter]::ToUInt32($b,[int]$o) }
function Std-PE([byte[]]$b) {
    if ((Std-U16 $b 0) -ne 0x5A4D) { throw 'Missing MZ signature.' }
    $p=Std-U32 $b 60
    if ((Std-U32 $b $p) -ne 0x4550) { throw 'Missing PE signature.' }
    $opt=$p+24; $size=Std-U16 $b ($p+20); $n=Std-U16 $b ($p+6)
    Std-Range $b $opt $size
    $magic=Std-U16 $b $opt; $machine=Std-U16 $b ($p+4)
    if ($n -lt 1 -or $n -gt 96) { throw 'Invalid section count.' }
    if ($magic -eq 0x20B -and $machine -eq 0x8664 -and $size -ge 160) {
        $base=[BitConverter]::ToUInt64($b,[int]($opt+24)); $dir=$opt+112; $count=Std-U32 $b ($opt+108)
    } elseif ($magic -eq 0x10B -and $machine -eq 0x14C -and $size -ge 144) {
        $base=Std-U32 $b ($opt+28); $dir=$opt+96; $count=Std-U32 $b ($opt+92)
    } else { throw 'Unsupported PE architecture or optional header.' }
    if ($count -lt 6) { throw 'Missing PE data directories.' }
    $sections=@(); $end=0L
    for ($i=0;$i -lt $n;$i++) {
        $s=$opt+$size+40*$i; Std-Range $b $s 40
        $raw=Std-U32 $b ($s+20); $len=Std-U32 $b ($s+16)
        Std-Range $b $raw $len
        $sections += [pscustomobject]@{Raw=$raw; Size=$len; Rva=(Std-U32 $b ($s+12)); Flags=(Std-U32 $b ($s+36))}
        $end=[Math]::Max($end,$raw+$len)
    }
    return [pscustomobject]@{Machine=$machine; Base=$base; Sections=$sections; RawEnd=$end; ExceptionRva=(Std-U32 $b ($dir+24)); ExceptionSize=(Std-U32 $b ($dir+28)); RelocRva=(Std-U32 $b ($dir+40)); RelocSize=(Std-U32 $b ($dir+44))}
}
function Std-Raw($pe,[long]$rva,[long]$size=1) {
    $s=@($pe.Sections | Where-Object { $rva -ge $_.Rva -and $rva+$size -le $_.Rva+$_.Size })
    if ($size -lt 0 -or $s.Count -ne 1) { throw 'RVA does not map uniquely to bytes.' }
    return [long]($s[0].Raw+$rva-$s[0].Rva)
}
function Std-IsCode($pe,[long]$rva) {
    return @($pe.Sections | Where-Object { ($_.Flags -band 0x20000000) -ne 0 -and $rva -ge $_.Rva -and $rva -lt $_.Rva+$_.Size }).Count -eq 1
}
function Std-Ascii([byte[]]$b,$pe,[long]$rva,[int]$length) {
    $o=Std-Raw $pe $rva ($length+1)
    if ($b[$o+$length] -ne 0) { return '' }
    return [Text.Encoding]::ASCII.GetString($b,[int]$o,$length)
}
function Find-WPSStandardPatch([byte[]]$b) {
    $pe=Std-PE $b
    if ($pe.Machine -ne 0x8664) { throw 'This route requires a PE32+ AMD64 inner installer.' }
    $latin=[Text.Encoding]::GetEncoding(28591)
    $pieces=foreach ($t in ($WPSStandardPattern -split ' ')) { if ($t -eq '??') { '.' } else { '\x'+$t } }
    $rx=New-Object Text.RegularExpressions.Regex -ArgumentList ($pieces -join ''), ([Text.RegularExpressions.RegexOptions]::Singleline)
    $found=@()
    foreach ($section in $pe.Sections) {
        if (($section.Flags -band 0x20000000) -eq 0) { continue }
        $code=$latin.GetString($b,[int]$section.Raw,[int]$section.Size)
        foreach ($m in $rx.Matches($code)) {
            $o=$section.Raw+$m.Index; $rva=$section.Rva+$m.Index
            $support=$rva+16+[BitConverter]::ToInt32($b,[int]($o+12))
            $server=$rva+23+[BitConverter]::ToInt32($b,[int]($o+19))
            if ((Std-Ascii $b $pe $support 7) -ne 'support' -or (Std-Ascii $b $pe $server 19) -ne 'InstallOnServer2008') { continue }
            foreach ($at in @(23,34,51,65,73,81,143,160)) {
                $target=$rva+$at+5+[BitConverter]::ToInt32($b,[int]($o+$at+1))
                if (-not (Std-IsCode $pe $target)) { throw 'Predicate helper is outside executable code.' }
            }
            $found += [pscustomobject]@{Offset=$o; Rva=$rva; Profile='kpacket-amd64-osgate-v1'; Before='40534883EC20'; After='B801000000C3'}
        }
    }
    if ($found.Count -ne 1) { throw ('Expected one AMD64 OS predicate, found '+$found.Count+'. Unsupported, ambiguous or already patched.') }
    $plan=$found[0]
    # Runtime-function metadata confirms a real function entry (split functions allowed).
    if ($pe.ExceptionSize -eq 0 -or ($pe.ExceptionSize % 12) -ne 0) { throw 'Missing or malformed AMD64 exception directory.' }
    $p=Std-Raw $pe $pe.ExceptionRva $pe.ExceptionSize; $entries=0
    for ($q=$p;$q -lt $p+$pe.ExceptionSize;$q+=12) {
        if ((Std-U32 $b $q) -eq $plan.Rva) {
            $end=Std-U32 $b ($q+4)
            if ($end -lt $plan.Rva+6 -or -not (Std-IsCode $pe ($end-1))) { throw 'Invalid function metadata.' }
            $entries++
        }
    }
    if ($entries -ne 1) { throw 'Predicate entry is not unique in AMD64 function metadata.' }
    if ($pe.RelocSize -gt 0) {
        $q=Std-Raw $pe $pe.RelocRva $pe.RelocSize; $end=$q+$pe.RelocSize
        while ($q -lt $end) {
            if ($end-$q -lt 8) { throw 'Truncated relocation block.' }
            $page=Std-U32 $b $q; $size=Std-U32 $b ($q+4)
            if ($size -lt 8 -or ($size % 2) -ne 0 -or $q+$size -gt $end) { throw 'Invalid relocation block.' }
            for ($at=$q+8;$at -lt $q+$size;$at+=2) {
                $v=[BitConverter]::ToUInt16($b,[int]$at); $type=$v -shr 12
                if ($type -eq 0) { continue }
                $r=$page+($v -band 4095)
                if ($r -lt $plan.Rva+6 -and $r+8 -gt $plan.Rva) { throw 'Relocation overlaps patch bytes.' }
            }
            $q+=$size
        }
    }
    $calls=0; $thunks=@()
    foreach ($section in $pe.Sections) {
        if (($section.Flags -band 0x20000000) -eq 0) { continue }
        $code=$latin.GetString($b,[int]$section.Raw,[int]$section.Size)
        foreach ($m in [regex]::Matches($code,'[\xE8\xE9]....',[Text.RegularExpressions.RegexOptions]::Singleline)) {
            $o=$section.Raw+$m.Index
            if ($section.Rva+$m.Index+5+[BitConverter]::ToInt32($b,[int]($o+1)) -eq $plan.Rva) {
                if ($b[$o] -eq 0xE8) { $calls++ } else { $thunks+=($pe.Base+$section.Rva+$m.Index) }
            }
        }
    }
    if ($calls -lt 2 -or $thunks.Count -eq 0) { throw 'Shared backend calls or interface thunk missing.' }
    $pointer=$false
    foreach ($section in $pe.Sections) {
        if (($section.Flags -band 0x20000000) -ne 0) { continue }
        $data=$latin.GetString($b,[int]$section.Raw,[int]$section.Size)
        foreach ($thunk in $thunks) {
            if ($data.IndexOf($latin.GetString([BitConverter]::GetBytes([uint64]$thunk)),[StringComparison]::Ordinal) -ge 0) { $pointer=$true }
        }
    }
    if (-not $pointer) { throw 'Interface thunk pointer missing.' }
    return $plan
}

function Initialize-NSISReader {
    if ('WpsBoundedStream' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.IO;
public sealed class WpsBoundedStream : Stream {
    private Stream source; private long remaining;
    public WpsBoundedStream(Stream source, long length) { this.source=source; remaining=length; }
    public override bool CanRead { get { return true; } }
    public override bool CanSeek { get { return false; } }
    public override bool CanWrite { get { return false; } }
    public override long Length { get { throw new NotSupportedException(); } }
    public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
    public override int Read(byte[] b,int offset,int count) {
        int n=source.Read(b,offset,(int)Math.Min((long)count,remaining));
        if(n==0 && remaining>0) throw new EndOfStreamException();
        remaining-=n; return n;
    }
    public override void Flush() { }
    public override long Seek(long o,SeekOrigin s) { throw new NotSupportedException(); }
    public override void SetLength(long n) { throw new NotSupportedException(); }
    public override void Write(byte[] b,int o,int n) { throw new NotSupportedException(); }
}
'@
}
function Get-NSISBlocks([string]$Path) {
    $s=[IO.File]::OpenRead($Path)
    try {
        $limit=[int][Math]::Min($s.Length,16777216)
        [byte[]]$prefix=New-Object byte[] $limit
        $read=0
        while ($read -lt $limit) { $n=$s.Read($prefix,$read,$limit-$read); if ($n -eq 0) { throw 'Short NSIS read.' }; $read+=$n }
        $pe=Std-PE $prefix
        $latin=[Text.Encoding]::GetEncoding(28591)
        [byte[]]$magic=0xEF,0xBE,0xAD,0xDE,0x4E,0x75,0x6C,0x6C,0x73,0x6F,0x66,0x74,0x49,0x6E,0x73,0x74
        $text=$latin.GetString($prefix); $sig=$latin.GetString($magic)
        $headers=@(); $at=[int]$pe.RawEnd
        while ($at -lt $limit) {
            $hit=$text.IndexOf($sig,$at,[StringComparison]::Ordinal)
            if ($hit -lt 0) { break }
            $h=$hit-4; Std-Range $prefix $h 28
            $length=Std-U32 $prefix ($h+24); $headerLength=Std-U32 $prefix ($h+20)
            if ($h -ge $pe.RawEnd -and $length -ge 36 -and $h+$length -le $s.Length -and $headerLength -gt 0 -and $headerLength -le 16777216) { $headers+=$h }
            $at=$hit+16
        }
        if ($headers.Count -ne 1) { throw 'Expected one supported NSIS header in the first 16 MiB.' }
        $h=$headers[0]; $end=$h+(Std-U32 $prefix ($h+24))-4; $p=$h+28
        $blocks=@(); [byte[]]$word=New-Object byte[] 4
        while ($p -lt $end) {
            if ($end-$p -lt 4 -or $blocks.Count -ge 512) { throw 'Unsupported NSIS block table.' }
            $s.Position=$p
            if ($s.Read($word,0,4) -ne 4) { throw 'Truncated NSIS block.' }
            $v=[long][BitConverter]::ToUInt32($word,0); $size=$v -band 2147483647L
            if ($size -le 0 -or $p+4+$size -gt $end) { throw 'Invalid NSIS block boundary; solid/LZMA layouts are not supported.' }
            $blocks += [pscustomobject]@{Offset=($p+4); Size=$size; Compressed=(($v -band 2147483648L) -ne 0)}
            $p+=4+$size
        }
        return ,$blocks
    } finally { $s.Dispose() }
}
function Read-NSISBlock([string]$Path,$Block,[string]$Output,[switch]$Probe) {
    Initialize-NSISReader
    $s=[IO.File]::OpenRead($Path); $reader=$null; $bounded=$null; $target=$null
    try {
        $s.Position=$Block.Offset
        $bounded=New-Object WpsBoundedStream -ArgumentList $s,([long]$Block.Size)
        $reader=$bounded
        if ($Block.Compressed) { $reader=New-Object IO.Compression.DeflateStream -ArgumentList $bounded,([IO.Compression.CompressionMode]::Decompress),$true }
        if ($Probe) {
            [byte[]]$buf=New-Object byte[] 4096; $n=0
            while ($n -lt $buf.Length) { $r=$reader.Read($buf,$n,$buf.Length-$n); if ($r -eq 0) { break }; $n+=$r }
            if ($n -lt 64 -or $buf[0] -ne 0x4D -or $buf[1] -ne 0x5A) { return $false }
            $p=Std-U32 $buf 60
            return $p+6 -le $n -and (Std-U32 $buf $p) -eq 0x4550 -and (Std-U16 $buf ($p+4)) -eq 0x8664
        }
        $target=[IO.File]::Open($Output,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        [byte[]]$buf=New-Object byte[] 1048576; $total=0L
        while (($n=$reader.Read($buf,0,$buf.Length)) -gt 0) {
            $total+=$n
            if ($total -gt 1073741824) { throw 'Inner installer exceeds the 1 GiB extraction limit.' }
            $target.Write($buf,0,$n)
        }
    } finally {
        if ($target) { $target.Dispose() }
        if ($reader) { $reader.Dispose() }
        if ($bounded) { $bounded.Dispose() }
        $s.Dispose()
    }
}
