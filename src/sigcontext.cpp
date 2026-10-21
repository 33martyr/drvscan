#include "sigcontext.h"
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
                // CODEINTEGRITY_OPTION_ENABLED etc.
                c.dseOn = (ci.CodeIntegrityOptions & 0x01) != 0;
                c.testSigningOn = (ci.CodeIntegrityOptions & 0x02) != 0;
            }
            struct SYSTEM_KERNEL_DEBUGGER_INFORMATION { BOOLEAN KernelDebuggerEnabled; BOOLEAN KernelDebuggerNotPresent; } kdi{};
            if(pQSI(35/*SystemKernelDebuggerInformation*/, &kdi, sizeof(kdi), nullptr)==0){
                c.kdOn = kdi.KernelDebuggerEnabled!=0;
            }
        }
    }
    // Prefetch enabled?
    HKEY hp=nullptr;
    if(RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters",0,KEY_READ,&hp)==ERROR_SUCCESS){
        DWORD v=0, sz=4, t=0;
        if(RegQueryValueExW(hp, L"EnablePrefetcher", nullptr, &t, (BYTE*)&v, &sz)==ERROR_SUCCESS) c.prefetchEnabled=(v!=0 && v!=0);
        else c.prefetchEnabled=true; // default on
        RegCloseKey(hp);
    } else c.prefetchEnabled=true;
    // Amcache accessible?
    DWORD attr=GetFileAttributesW(L"C:\\Windows\\AppCompat\\Programs\\Amcache.hve");
    c.amcacheAccessible=(attr!=INVALID_FILE_ATTRIBUTES);
    // Sysmon installed? Check evtx log existence
    DWORD attr2=GetFileAttributesW(L"C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx");
    c.sysmonInstalled=(attr2!=INVALID_FILE_ATTRIBUTES);
    // Also check service
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
    std::string prefetch = c.prefetchEnabled?"enabled":"disabled";
    std::string amcache = c.amcacheAccessible?"accessible":"not accessible";
    bool possible = !c.hvciOn || !c.dseOn || c.testSigningOn || c.kdOn;
    std::string verdict = possible?"POSSIBLE":"BLOCKED at hypervisor / CI layer";
    std::string out;
    out += "HVCI: "+hvci+" | DSE: "+dse+" | test-signing: "+ts+" | kd: "+kd+"\n";
    out += "Sysmon: "+sysmon+" | Prefetch: "+prefetch+" | Amcache: "+amcache+"\n";
    out += "-> Manual mapping of unsigned kernel code is "+verdict+" on this box\n";
    return out;
}

} // namespace drvscan
