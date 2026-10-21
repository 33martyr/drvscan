#include "handles.h"
#include <windows.h>
#include <tlhelp32.h>
#include <algorithm>
#include <cctype>
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace drvscan {

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

static std::string ToLowerStr(std::string s){ for(char& c:s) c=(char)std::tolower((unsigned char)c); return s; }

int LevenshteinDistance(const std::string& a, const std::string& b){
    size_t n=a.size(), m=b.size();
    std::vector<int> dp(m+1); for(size_t j=0;j<=m;++j) dp[j]=(int)j;
    for(size_t i=1;i<=n;++i){ int prev=dp[0]; dp[0]=(int)i;
        for(size_t j=1;j<=m;++j){ int cur=dp[j]; int cost=(ToLowerStr(std::string(1,a[i-1]))==ToLowerStr(std::string(1,b[j-1]))?0:1);
            dp[j]= std::min({dp[j]+1, dp[j-1]+1, prev+cost}); prev=cur; } }
    return dp[m];
}

std::string LevenshteinSuggestion(const std::string& needle, const std::vector<std::string>& cands){
    int best=999; std::string out;
    for(auto& c:cands){ int d=LevenshteinDistance(ToLowerStr(needle), ToLowerStr(c)); if(d<best){best=d; out=c;}}
    if(best<=2 && !out.empty()) return out;
    return {};
}

std::vector<DWORD> ResolveProcessArgument(const std::string& arg, std::string& outErr){
    outErr.clear();
    if(arg.empty()){ outErr="error: --pid requires a value"; return {}; }
    if(arg.find('\\')!=std::string::npos || arg.find('/')!=std::string::npos){
        outErr="error: full paths not supported for --pid; use the name shown in Task Manager, not the full path (e.g. --pid chrome.exe)";
        return {};
    }
    bool allDigits = !arg.empty() && std::all_of(arg.begin(), arg.end(), [](unsigned char c){ return std::isdigit(c); });
    if(allDigits){
        try{ DWORD pid=(DWORD)std::stoul(arg); if(pid>0) return {pid}; }catch(...){}
    }
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(snap==INVALID_HANDLE_VALUE){ outErr="error: cannot snapshot process list"; return {}; }
    std::string needle = ToLowerStr(arg);
    std::string needleNoExt = (needle.size()>=4 && needle.substr(needle.size()-4)==".exe") ? needle.substr(0, needle.size()-4) : needle;
    std::vector<DWORD> pids;
    std::vector<std::string> allNames;
    PROCESSENTRY32W pe{}; pe.dwSize=sizeof(pe);
    if(Process32FirstW(snap, &pe)){
        do{
            char exeName[MAX_PATH]{};
            int n=WideCharToMultiByte(CP_UTF8,0,pe.szExeFile,-1,exeName,sizeof(exeName),nullptr,nullptr);
            if(n<=0) continue;
            std::string name(exeName);
            std::string low=ToLowerStr(name);
            allNames.push_back(name);
            std::string lowNoExt = (low.size()>=4 && low.substr(low.size()-4)==".exe") ? low.substr(0,low.size()-4) : low;
            if(low==needle || lowNoExt==needleNoExt) pids.push_back(pe.th32ProcessID);
        }while(Process32NextW(snap,&pe));
    }
    CloseHandle(snap);
    if(!pids.empty()) return pids;
    std::string sug = LevenshteinSuggestion(arg, allNames);
    if(!sug.empty()) outErr = "error: no process named '" + arg + "' found (did you mean '" + sug + "'?)";
    else outErr = "error: no process named '" + arg + "' found";
    return {};
}

void TryEnableDebugPrivilege(){
    HANDLE tok=nullptr;
    if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &tok)) return;
    TOKEN_PRIVILEGES tp{}; LUID luid{};
    if(LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)){
        tp.PrivilegeCount=1; tp.Privileges[0].Luid=luid; tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        DWORD err=GetLastError();
        if(err!=ERROR_SUCCESS) fprintf(stderr,"note: SeDebugPrivilege not available (%lu) — some processes may require Administrator\n", (unsigned long)err);
    }
    CloseHandle(tok);
}

typedef NTSTATUS(WINAPI* PFN_NtQSI)(ULONG,PVOID,ULONG,PULONG);
typedef NTSTATUS(WINAPI* PFN_NtQO)(HANDLE,ULONG,PVOID,ULONG,PULONG);
#define SystemExtendedHandleInformation 64
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

struct UNICODE_STRING2 { USHORT Length; USHORT MaximumLength; PWSTR Buffer; };

static PFN_NtQSI pNtQSI=nullptr;
static PFN_NtQO pNtQO=nullptr;
static void EnsureNtdll(){
    if(pNtQSI) return;
    HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");
    if(!ntdll) ntdll=LoadLibraryW(L"ntdll.dll");
    if(ntdll){ pNtQSI=(PFN_NtQSI)GetProcAddress(ntdll,"NtQuerySystemInformation"); pNtQO=(PFN_NtQO)GetProcAddress(ntdll,"NtQueryObject"); }
}

struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX { PVOID Object; ULONG_PTR UniqueProcessId; ULONG_PTR HandleValue; ULONG GrantedAccess; USHORT CreatorBackTraceIndex; USHORT ObjectTypeIndex; ULONG HandleAttributes; ULONG Reserved; };
struct SYSTEM_HANDLE_INFORMATION_EX { ULONG_PTR NumberOfHandles; ULONG_PTR Reserved; SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1]; };

std::vector<DeviceHandle> FilterDeviceHandlesTest(const std::vector<DeviceHandle>& in){
    std::vector<DeviceHandle> tmp;
    tmp.reserve(in.size());
    for(auto& h: in){
        std::string low=ToLowerStr(h.device_path);
        if(low.rfind("\\device\\namedpipe\\",0)==0) continue;
        tmp.push_back(h);
    }
    std::vector<DeviceHandle> out;
    bool seenVol=false, seenShadow=false;
    std::unordered_set<std::string> seen;
    for(auto& h: tmp){
        std::string low=ToLowerStr(h.device_path);
        bool isShadow = (low.find("harddiskvolumeshadowcopy")!=std::string::npos);
        bool isVol = (!isShadow && low.rfind("\\device\\harddiskvolume",0)==0);
        if(isVol){ if(seenVol) continue; seenVol=true; DeviceHandle r=h; r.device_path="\\Device\\HarddiskVolume*"; out.push_back(r); continue; }
        if(isShadow){ if(seenShadow) continue; seenShadow=true; DeviceHandle r=h; r.device_path="\\Device\\HarddiskVolumeShadowCopy*"; out.push_back(r); continue; }
        if(seen.count(h.device_path)) continue;
        seen.insert(h.device_path);
        out.push_back(h);
    }
    return out;
}

std::variant<std::vector<DeviceHandle>, HandleError> EnumerateDeviceHandles(DWORD pid){
    EnsureNtdll();
    if(!pNtQSI || !pNtQO) return HandleError{"error: cannot load ntdll NtQuery* APIs",3};
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, FALSE, pid);
    if(!hProc){
        DWORD err=GetLastError();
        if(err==ERROR_ACCESS_DENIED) return HandleError{"error: found pid " + std::to_string(pid) + " but cannot open it (access denied). Run drvscan as Administrator for protected/system processes.",3};
        return HandleError{"error: cannot open pid " + std::to_string(pid) + " (" + std::to_string(err) + ")",3};
    }
    ULONG bufSize = 1<<20;
    std::vector<uint8_t> buf(bufSize);
    NTSTATUS st=0; ULONG retLen=0;
    for(int tries=0; tries<5; ++tries){
        st=pNtQSI(SystemExtendedHandleInformation, buf.data(), (ULONG)buf.size(), &retLen);
        if(st==0) break;
        if((uint32_t)st==0xC0000004u){ bufSize=retLen+8192; buf.resize(bufSize); continue; }
        break;
    }
    if(st!=0){ CloseHandle(hProc); return HandleError{"error: NtQuerySystemInformation failed",3}; }
    auto* info=(SYSTEM_HANDLE_INFORMATION_EX*)buf.data();
    std::vector<DeviceHandle> raw;
    for(ULONG_PTR i=0;i<info->NumberOfHandles;++i){
        auto& e=info->Handles[i];
        if((DWORD)(ULONG_PTR)e.UniqueProcessId != pid) continue;
        HANDLE dup=nullptr;
        if(!DuplicateHandle(hProc, (HANDLE)(ULONG_PTR)e.HandleValue, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS)){
            continue;
        }
        // 1) Avoid blocking on named pipes with no reader: GetFileType is a fast
        //    user-mode check that returns FILE_TYPE_PIPE without issuing an
        //    NtQueryObject(ObjectNameInformation) that would block in kernel.
        //    Chrome opens dozens of such pipes for IPC.
        DWORD ft = GetFileType(dup);
        if(ft == FILE_TYPE_PIPE){
            CloseHandle(dup);
            continue;
        }
        // 2) Query ObjectTypeInformation (safe, does not block on drivers).
        //    Only "File" objects can own \Device\ / \FileSystem\ names. Skip
        //    Events/Mutants/Semaphores/Keys/etc. without ever calling
        //    ObjectNameInformation on them — those were the hang source #2.
        bool isFileObject = false;
        {
            std::vector<uint8_t> tbuf(1024);
            ULONG tLen = 0;
            NTSTATUS tst = pNtQO(dup, ObjectTypeInformation, tbuf.data(), (ULONG)tbuf.size(), &tLen);
            if((uint32_t)tst == 0xC0000023u || (uint32_t)tst == 0x80000005u){
                // STATUS_BUFFER_OVERFLOW / STATUS_BUFFER_TOO_SMALL — retry with required size
                tbuf.resize(tLen + 64);
                tst = pNtQO(dup, ObjectTypeInformation, tbuf.data(), (ULONG)tbuf.size(), &tLen);
            }
            if(tst == 0){
                auto* typeStr = reinterpret_cast<UNICODE_STRING2*>(tbuf.data());
                if(typeStr->Length > 0 && typeStr->Buffer){
                    std::wstring w(typeStr->Buffer, typeStr->Length / 2);
                    if(_wcsicmp(w.c_str(), L"File") == 0) isFileObject = true;
                }
            } else {
                // Can't determine type — skip rather than risk hanging Name query (covers #3).
                CloseHandle(dup);
                continue;
            }
        }
        if(!isFileObject){
            CloseHandle(dup);
            continue;
        }
        // 3) Synchronous, bounded ObjectNameInformation query — no thread/timeout/
        //    TerminateThread. The two filters above have removed the 3 hang
        //    classes, so this call is now safe to issue directly.
        std::string devPath;
        {
            ULONG qSize = 2048;
            for(int attempt = 0; attempt < 3; ++attempt){
                std::vector<uint8_t> qbuf(qSize);
                ULONG qLen = 0;
                NTSTATUS qst = pNtQO(dup, ObjectNameInformation, qbuf.data(), qSize, &qLen);
                if(qst == 0){
                    auto* uni = reinterpret_cast<UNICODE_STRING2*>(qbuf.data());
                    if(uni->Length > 0 && uni->Buffer){
                        int n = WideCharToMultiByte(CP_UTF8, 0, uni->Buffer, uni->Length / 2, nullptr, 0, nullptr, nullptr);
                        std::string s(n, 0);
                        WideCharToMultiByte(CP_UTF8, 0, uni->Buffer, uni->Length / 2, s.data(), n, nullptr, nullptr);
                        devPath = std::move(s);
                    }
                    break;
                }
                if((uint32_t)qst == 0xC0000023u || (uint32_t)qst == 0x80000005u){
                    qSize = qLen + 512;
                    if(qSize > 8192) qSize = 8192;
                    continue;
                }
                break;
            }
        }
        CloseHandle(dup);
        if(devPath.empty()) continue;
        std::string low = ToLowerStr(devPath);
        bool isDevice = (low.rfind("\\device\\", 0) == 0);
        bool isFs = (low.rfind("\\filesystem\\", 0) == 0);
        if(!isDevice && !isFs) continue;
        DeviceHandle dh;
        dh.handle_value = (uint32_t)(ULONG_PTR)e.HandleValue;
        dh.access_mask = e.GrantedAccess;
        dh.device_path = devPath;
        raw.push_back(std::move(dh));
    }
    CloseHandle(hProc);
    auto filtered = FilterDeviceHandlesTest(raw);
    if(filtered.empty()){
        HANDLE chk=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if(!chk) return HandleError{"error: process " + std::to_string(pid) + " terminated during scan",3};
        CloseHandle(chk);
        return HandleError{"no device handles found for pid " + std::to_string(pid),4};
    }
    return filtered;
}

} // namespace drvscan
