#include "sigcontext.h"
#include "objscan.h"
#include <windows.h>
#include <string>

namespace drvscan {

SigContext QuerySigContext(){
    SigContext c;
    // HVCI / Device Guard via registry (user-mode)
    HKEY h=nullptr;
    if(RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity", 0, KEY_READ, &h)==ERROR_SUCCESS){
        DWORD v=0, sz=4, t=0;
        if(RegQueryValueExW(h, L"Enabled", nullptr, &t, (BYTE*)&v, &sz)==ERROR_SUCCESS) c.hvciOn=(v!=0);
        RegCloseKey(h);
    }
    // DSE / test-signing via SystemCodeIntegrityInformation (ntdll)
    HMODULE ntdllMod=GetModuleHandleW(L"ntdll.dll");
    if(!ntdllMod) ntdllMod=LoadLibraryW(L"ntdll.dll");
    if(ntdllMod){
        struct SYSTEM_CODEINTEGRITY_INFORMATION { ULONG Length; ULONG CodeIntegrityOptions; };
        typedef LONG(WINAPI* PFN_QSI2)(ULONG,PVOID,ULONG,PULONG);
        auto pQSI=(PFN_QSI2)GetProcAddress(ntdllMod,"NtQuerySystemInformation");
        if(pQSI){
            SYSTEM_CODEINTEGRITY_INFORMATION ci{}; ci.Length=sizeof(ci);
            if(pQSI(103/*SystemCodeIntegrityInformation*/, &ci, sizeof(ci), nullptr)==0){
                c.dseOn = (ci.CodeIntegrityOptions & 0x01) != 0;
                c.testSigningOn = (ci.CodeIntegrityOptions & 0x02) != 0;
            }
            struct SYSTEM_KERNEL_DEBUGGER_INFORMATION { BOOLEAN KernelDebuggerEnabled; BOOLEAN KernelDebuggerNotPresent; } kdi{};
            if(pQSI(35/*SystemKernelDebuggerInformation*/, &kdi, sizeof(kdi), nullptr)==0){
                c.kdOn = kdi.KernelDebuggerEnabled!=0;
            }
        }
    }
    // Prefetch/Amcache are intentionally NOT reported as checked in v0.4.0 (stubbed S5/S6).
    // Keep fields populated for callers that probe filesystem but do not surface as "enabled/accessible".
    HKEY hp=nullptr;
    if(RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters",0,KEY_READ,&hp)==ERROR_SUCCESS){
        DWORD v=0, sz=4, t=0;
        if(RegQueryValueExW(hp, L"EnablePrefetcher", nullptr, &t, (BYTE*)&v, &sz)==ERROR_SUCCESS) c.prefetchEnabled=(v!=0 && v!=0);
        else c.prefetchEnabled=true;
        RegCloseKey(hp);
    } else c.prefetchEnabled=true;
    DWORD attr=GetFileAttributesW(L"C:\\Windows\\AppCompat\\Programs\\Amcache.hve");
    c.amcacheAccessible=(attr!=INVALID_FILE_ATTRIBUTES);
    // Sysmon: real check so header may report installed/not installed
    DWORD attr2=GetFileAttributesW(L"C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx");
    c.sysmonInstalled=(attr2!=INVALID_FILE_ATTRIBUTES);
    SC_HANDLE scm=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);
    if(scm){ SC_HANDLE svc=OpenServiceW(scm, L"Sysmon", SERVICE_QUERY_STATUS); if(svc){ c.sysmonInstalled=true; CloseServiceHandle(svc);} CloseServiceHandle(scm); }
    return c;
}

std::string SigContextHeader(const SigContext& c){
    std::string hvci = c.hvciOn?"ON":"OFF";
    std::string dse = c.dseOn?"ON":"OFF";
    std::string ts = c.testSigningOn?"ON":"OFF";
    std::string kd = c.kdOn?"ON":"OFF";
    std::string sysmon = c.sysmonInstalled?"installed":"not installed";
    bool possible = !c.hvciOn || !c.dseOn || c.testSigningOn || c.kdOn;
    std::string verdict = possible?"POSSIBLE":"BLOCKED at hypervisor / CI layer";
    std::string out;
    out += "HVCI: "+hvci+" | DSE: "+dse+" | test-signing: "+ts+" | kd: "+kd+"\n";
    // Stubbed surfaces must not claim a checked state (Amcache/Prefetch are pending v0.4.0)
    out += "Sysmon: "+sysmon+" | Prefetch: pending v0.4.0 | Amcache: pending v0.4.0\n";
    out += "-> Manual mapping of unsigned kernel code is "+verdict+" on this box\n";
    return out;
}

bool IsDriverDirAccessDenied(const std::string& objError){
    std::string low=objError;
    for(char& ch: low) ch=(char)std::tolower((unsigned char)ch);
    return low.find("0xc0000022")!=std::string::npos || low.find("c0000022")!=std::string::npos
        || low.find("access denied")!=std::string::npos;
}

std::string BuildSection2Text(const ObjScanResult& obj){
    bool driverDenied = IsDriverDirAccessDenied(obj.error);
    std::string out;
    out += "Section 2 — Manual-mapped driver candidates\n";
    if(driverDenied){
        out += "\\Driver\\ enumeration: NOT SCANNED (access denied — run as Administrator to enable object manager cross-check)\n";
        out += "\\Device\\ enumeration: " + std::to_string(obj.deviceObjects) + " device objects";
        if(!obj.orphaned.empty()) out += ", " + std::to_string(obj.orphaned.size()) + " with orphaned driver objects";
        // Count orphaned only when driver dir was scannable; parenthesize when not
        out += "\n";
        out += "No candidates found in scanned surfaces. This is not proof nothing happened — \\Driver\\ was not checked.\n";
        return out;
    }
    if(obj.orphaned.empty()){
        out += "  No orphaned driver objects — no candidates above Low confidence.\n";
    } else {
        out += "  Orphaned driver objects (" + std::to_string(obj.orphaned.size()) + ") — also listed in the driver table with Source=orphaned:\n";
        for(auto& n: obj.orphaned) out += "    \\Driver\\" + n + "  [orphaned object only — Low confidence]\n";
        out += "  Confidence: Low — orphaned object alone is not proof of manual mapping.\n";
        out += "  Tip: cross-ref with handles (S2), Amcache (S5), prefetch (S6) for corroboration.\n";
    }
    return out;
}

std::string BuildSection4Text(){
    std::string out;
    out += "Section 4 — What this scan did NOT cover\n";
    out += "This build ships two surfaces: the object manager cross-check (\\Driver\\ and \\Device\\ enumeration) and the HVCI / DSE / test-signing / KD context header.\n";
    out += "Not yet wired in this build (stubbed for v0.4.0): global handle table, Code Integrity event log, ETW kernel providers, Amcache, prefetch, Sysmon, Defender, boot log, cross-surface correlation.\n";
    out += "Until those ship, this scan covers only the object-manager-visible subset of manual mappings: drivers that registered a \\Driver\\ or \\Device\\ object. A manual mapping that registers nothing, leaves no Amcache entry, and leaves no prefetch entry is not detected by this build regardless of HVCI state.\n";
    out += "On HVCI:ON, unsigned kernel code cannot execute (barring a documented HVCI bypass). On HVCI:OFF, that class of attack is possible and this build does not detect it.\n";
    out += "No candidates found = no object-manager-visible candidates, not proof nothing happened.\n";
    return out;
}

} // namespace drvscan
