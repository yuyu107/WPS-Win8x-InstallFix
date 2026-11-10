using System;
using System.IO;
using System.Text;
using System.Collections.Generic;

// Compiled equivalent of the shared AMD64 predicate detector. No archive bytes,
// PowerShell pipelines, or per-byte PowerShell calls in the suspended-process path.
public sealed class WpsOnlinePredicate {
 public sealed class Plan {
  public long Offset, Rva;
  public string Profile="kpacket-amd64-osgate-v1";
 }
 sealed class Section { public long Raw,Size,Rva; public uint Flags; }
 readonly byte[] b;
 readonly List<Section> sections=new List<Section>();
 ulong imageBase; long exceptionRva,exceptionSize,relocRva,relocSize;
 WpsOnlinePredicate(byte[] bytes) { b=bytes; Parse(); }
 void Range(long o,long n) { if(o<0 || n<0 || o>b.LongLength-n) throw new InvalidDataException("Invalid PE byte range."); }
 ushort U16(long o) { Range(o,2); return BitConverter.ToUInt16(b,(int)o); }
 uint U32(long o) { Range(o,4); return BitConverter.ToUInt32(b,(int)o); }
 int I32(long o) { Range(o,4); return BitConverter.ToInt32(b,(int)o); }
 long Raw(long r,long n) {
  long result=-1; int count=0;
  foreach(Section s in sections) if(r>=s.Rva && n>=0 && r+n<=s.Rva+s.Size) {result=s.Raw+r-s.Rva;count++;}
  if(count!=1) throw new InvalidDataException("RVA does not map uniquely to bytes.");
  Range(result,n); return result;
 }
 bool Code(long r) {int count=0; foreach(Section s in sections) if((s.Flags&0x20000000)!=0 && r>=s.Rva && r<s.Rva+s.Size) count++; return count==1;}
 bool Ascii(long r,string text) {long o=Raw(r,text.Length+1); return b[o+text.Length]==0 && Encoding.ASCII.GetString(b,(int)o,text.Length)==text;}
 void Parse() {
  if(U16(0)!=0x5A4D) throw new InvalidDataException("Missing MZ signature.");
  long p=U32(60), opt=p+24;
  if(U32(p)!=0x4550 || U16(p+4)!=0x8664 || U16(opt)!=0x20B) throw new InvalidDataException("Requires PE32+ AMD64.");
  int count=U16(p+6), size=U16(p+20);
  if(count<1 || count>96 || size<160) throw new InvalidDataException("Invalid optional header or section count.");
  Range(opt,size); Range(opt+24,8); imageBase=BitConverter.ToUInt64(b,(int)(opt+24));
  if(U32(opt+108)<6) throw new InvalidDataException("Missing data directories.");
  exceptionRva=U32(opt+136); exceptionSize=U32(opt+140); relocRva=U32(opt+152); relocSize=U32(opt+156);
  for(int i=0;i<count;i++) {
   long o=opt+size+40L*i; Range(o,40);
   Section s=new Section();s.Raw=U32(o+20);s.Size=U32(o+16);s.Rva=U32(o+12);s.Flags=U32(o+36);
   Range(s.Raw,s.Size);sections.Add(s);
  }
 }
 Plan Find(string pattern) {
  string[] parts=pattern.Split(new char[]{' '},StringSplitOptions.RemoveEmptyEntries);
  if(parts.Length!=179) throw new InvalidDataException("Unexpected family template length.");
  int[] pat=new int[parts.Length];for(int i=0;i<pat.Length;i++) pat[i]=parts[i]=="??"?-1:Convert.ToInt32(parts[i],16);
  Plan found=null;int hits=0;
  foreach(Section s in sections) {
   if((s.Flags&0x20000000)==0) continue;
   for(long o=s.Raw;o<=s.Raw+s.Size-pat.Length;o++) {
    if(b[o]!=pat[0] || b[o+1]!=pat[1]) continue;
    bool match=true;for(int i=2;i<pat.Length;i++) if(pat[i]>=0 && b[o+i]!=pat[i]) {match=false;break;}
    if(!match) continue;
    long r=s.Rva+o-s.Raw;
    if(!Ascii(r+16+I32(o+12),"support") || !Ascii(r+23+I32(o+19),"InstallOnServer2008")) continue;
    foreach(int at in new int[]{23,34,51,65,73,81,143,160}) if(!Code(r+at+5+I32(o+at+1))) throw new InvalidDataException("Helper outside executable code.");
    found=new Plan();found.Offset=o;found.Rva=r;hits++;
   }
  }
  if(hits!=1) throw new InvalidDataException("Expected one AMD64 predicate; found "+hits+".");
  if(exceptionSize==0 || exceptionSize%12!=0) throw new InvalidDataException("Invalid runtime function directory.");
  long p=Raw(exceptionRva,exceptionSize);int entries=0;
  for(long q=p;q<p+exceptionSize;q+=12) if(U32(q)==found.Rva) {
   long end=U32(q+4);if(end<found.Rva+6 || !Code(end-1)) throw new InvalidDataException("Invalid function metadata.");entries++;
  }
  if(entries!=1) throw new InvalidDataException("Predicate runtime entry is not unique.");
  if(relocSize>0) {
   long q=Raw(relocRva,relocSize),end=q+relocSize;
   while(q<end) {
    if(end-q<8) throw new InvalidDataException("Truncated relocation block.");
    long page=U32(q),size=U32(q+4);
    if(size<8 || size%2!=0 || q+size>end) throw new InvalidDataException("Invalid relocation block.");
    for(long at=q+8;at<q+size;at+=2) {
     int v=U16(at);if((v>>12)==0) continue;
     long r=page+(v&4095);if(r<found.Rva+6 && r+8>found.Rva) throw new InvalidDataException("Relocation overlaps patch bytes.");
    } q+=size;
   }
  }
  int calls=0;List<ulong> thunks=new List<ulong>();
  foreach(Section s in sections) {
   if((s.Flags&0x20000000)==0) continue;
   for(long o=s.Raw;o+5<=s.Raw+s.Size;o++) {
    if(b[o]!=0xE8 && b[o]!=0xE9) continue;
    if(s.Rva+o-s.Raw+5+I32(o+1)==found.Rva) {
     if(b[o]==0xE8) calls++;else thunks.Add(checked(imageBase+(ulong)(s.Rva+o-s.Raw)));
    }
    o+=4; // Same non-overlapping E8/E9 matches as the shared regex detector.
   }
  }
  if(calls<2 || thunks.Count==0) throw new InvalidDataException("Shared calls or thunk missing.");
  bool pointer=false;
  foreach(Section s in sections) {
   if((s.Flags&0x20000000)!=0) continue;
   foreach(ulong thunk in thunks) {
    byte[] value=BitConverter.GetBytes(thunk);
    for(long o=s.Raw;o+8<=s.Raw+s.Size;o++) {
     if(b[o]!=value[0]) continue;
     bool equal=true;for(int i=1;i<8;i++) if(b[o+i]!=value[i]) {equal=false;break;}
     if(equal) {pointer=true;break;}
    }
   }
  }
  if(!pointer) throw new InvalidDataException("Thunk pointer missing.");
  return found;
 }
 public static Plan Analyze(byte[] bytes,string pattern) { return new WpsOnlinePredicate(bytes).Find(pattern); }
 public static Plan AnalyzeFile(string path,string pattern) { return Analyze(WpsOnlineNative.ReadImageSections(path),pattern); }
}
