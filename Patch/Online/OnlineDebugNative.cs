using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public static class WpsOnlineNative {
 [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
 public struct StartupInfo {
  public uint cb; public string reserved, desktop, title;
  public uint x,y,xSize,ySize,xChars,yChars,fill,flags;
  public ushort show,reservedSize; public IntPtr reservedPtr,input,output,error;
 }
 [StructLayout(LayoutKind.Sequential)]
 public struct ProcessInfo { public IntPtr process,thread; public uint pid,tid; }
 [StructLayout(LayoutKind.Explicit,Size=176)]
 public struct DebugEvent {
  [FieldOffset(0)] public uint code;
  [FieldOffset(4)] public uint pid;
  [FieldOffset(8)] public uint tid;
  [FieldOffset(16)] public IntPtr file;
  [FieldOffset(24)] public IntPtr process;
  [FieldOffset(32)] public IntPtr thread;
  [FieldOffset(40)] public IntPtr imageBase;
  [FieldOffset(16)] public uint exceptionCode;
  [FieldOffset(168)] public uint firstChance;
 }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
 static extern bool CreateProcessW(string app,StringBuilder command,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr env,string dir,ref StartupInfo si,out ProcessInfo pi);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool WaitForDebugEvent(out DebugEvent e,uint milliseconds);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool ContinueDebugEvent(uint pid,uint tid,uint status);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool DebugSetProcessKillOnExit(bool kill);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool DebugActiveProcessStop(uint pid);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageNameW(IntPtr process,uint flags,StringBuilder path,ref uint size);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool VirtualProtectEx(IntPtr process,IntPtr address,UIntPtr length,uint protection,out uint old);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool ReadProcessMemory(IntPtr process,IntPtr address,byte[] data,UIntPtr length,out UIntPtr read);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool WriteProcessMemory(IntPtr process,IntPtr address,byte[] data,UIntPtr length,out UIntPtr written);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool FlushInstructionCache(IntPtr process,IntPtr address,UIntPtr length);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool CloseHandle(IntPtr handle);

 public static ProcessInfo Start(string path) {
  if(IntPtr.Size!=8) throw new InvalidOperationException("Use 64-bit Windows PowerShell.");
  StartupInfo si=new StartupInfo(); si.cb=(uint)Marshal.SizeOf(typeof(StartupInfo));
  ProcessInfo pi;
  if(!CreateProcessW(path,new StringBuilder("\""+path+"\""),IntPtr.Zero,IntPtr.Zero,false,1,IntPtr.Zero,Path.GetDirectoryName(path),ref si,out pi)) throw new Win32Exception();
  // A closed launcher must not terminate installer processes.
  if(!DebugSetProcessKillOnExit(false)) { int error=Marshal.GetLastWin32Error(); DebugActiveProcessStop(pi.pid); CloseHandle(pi.thread); CloseHandle(pi.process); throw new Win32Exception(error); }
  return pi;
 }
 public static DebugEvent? Next(uint milliseconds) {
  DebugEvent e;
  if(WaitForDebugEvent(out e,milliseconds)) return e;
  int error=Marshal.GetLastWin32Error();
  if(error==121) return null;
  throw new Win32Exception(error);
 }
 public static void Continue(DebugEvent e,bool handled) {
  if(!ContinueDebugEvent(e.pid,e.tid,handled?0x00010002U:0x80010001U)) throw new Win32Exception();
 }
 public static void Detach(uint pid) { DebugActiveProcessStop(pid); }
 public static string ImagePath(IntPtr process) {
  StringBuilder path=new StringBuilder(32768); uint length=(uint)path.Capacity;
  if(!QueryFullProcessImageNameW(process,0,path,ref length)) throw new Win32Exception();
  return path.ToString();
 }
 public static void Patch(IntPtr process,IntPtr address,byte[] expected,byte[] replacement) {
  if(expected.Length!=replacement.Length || expected.Length==0) throw new ArgumentException("Patch size mismatch.");
  UIntPtr length=(UIntPtr)(uint)expected.Length, count; byte[] current=new byte[expected.Length];
  if(!ReadProcessMemory(process,address,current,length,out count) || count.ToUInt64()!=(ulong)expected.Length) throw new Win32Exception();
  for(int i=0;i<current.Length;i++) if(current[i]!=expected[i]) throw new InvalidOperationException("In-memory preimage mismatch.");
  uint old;
  if(!VirtualProtectEx(process,address,length,0x40,out old)) throw new Win32Exception();
  try {
   if(!WriteProcessMemory(process,address,replacement,length,out count) || count.ToUInt64()!=(ulong)replacement.Length) throw new Win32Exception();
   if(!FlushInstructionCache(process,address,length)) throw new Win32Exception();
  } finally { uint ignored; if(!VirtualProtectEx(process,address,length,old,out ignored)) throw new Win32Exception(); }
  if(!ReadProcessMemory(process,address,current,length,out count) || count.ToUInt64()!=(ulong)replacement.Length) throw new Win32Exception();
  for(int i=0;i<current.Length;i++) if(current[i]!=replacement[i]) throw new InvalidOperationException("Memory write verification failed.");
 }
}
