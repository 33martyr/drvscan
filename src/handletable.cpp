#include "handletable.h"
#include <windows.h>
#include <vector>
#include <string>
#include <unordered_map>

namespace drvscan {

HandleTableStats ScanGlobalHandleTable(const std::vector<std::string>& /*orphaned*/){
    HandleTableStats s;
    // S2 via existing handles.cpp EnumerateDeviceHandles but global scan: enumerate all handles
    // For v0.4 honest gap: global handle scan via SystemExtendedHandleInformation class 64 + type index match
    // is complex (requires resolving Driver type index per Windows version). Ship a stub that enumerates
    // handle count via NtQuerySystemInformation and reports object manager counts as corroboration.
    // Honest coverage: we already have per-process handles via --pid; global scan is pending full type-index wiring.
    HMODULE ntdllMod=GetModuleHandleW(L"ntdll.dll");
    if(!ntdllMod) ntdllMod=LoadLibraryW(L"ntdll.dll");
    if(!ntdllMod){ s.error="cannot load ntdll"; return s; }
    typedef LONG(WINAPI* PFN_QSI2)(ULONG,PVOID,ULONG,PULONG);
    auto pQSI=(PFN_QSI2)GetProcAddress(ntdllMod,"NtQuerySystemInformation");
    if(!pQSI){ s.error="NtQuerySystemInformation not found"; return s; }
    ULONG bufSize=1<<20; std::vector<uint8_t> buf(bufSize); ULONG retLen=0;
    LONG st=pQSI(64/*SystemExtendedHandleInformation*/, buf.data(), bufSize, &retLen);
    if(st!=0){ s.error="NtQuerySystemInformation(64) 0x"+std::to_string((uint32_t)st); return s; }
    struct HTE { PVOID Object; ULONG_PTR UniqueProcessId; ULONG_PTR HandleValue; ULONG GrantedAccess; USHORT CreatorBackTraceIndex; USHORT ObjectTypeIndex; ULONG HandleAttributes; ULONG Reserved; };
    struct HINFO { ULONG_PTR NumberOfHandles; ULONG_PTR Reserved; HTE Handles[1]; };
    auto* info=(HINFO*)buf.data();
    s.totalHandles=(int)info->NumberOfHandles;
    // Without type-index resolution, count handles would require opening each. For honest gap reporting,
    // leave driverHandles at 0 and document as pending in Section 3.
    s.driverHandles=0; s.orphanHandles=0;
    return s;
}

} // namespace drvscan
