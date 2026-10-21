#include "objscan.h"
#include <windows.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <algorithm>

namespace drvscan {

typedef NTSTATUS(NTAPI* PFN_NtOpenDirectoryObject)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS(NTAPI* PFN_NtQueryDirectoryObject)(HANDLE, PVOID, ULONG, ULONG, ULONG, PULONG, PULONG);
typedef NTSTATUS(NTAPI* PFN_NtClose)(HANDLE);



std::vector<std::string> EnumerateObjectDirectory(const std::wstring& path, std::string& outErr){
    outErr.clear();
    std::vector<std::string> names;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if(!ntdll) ntdll = LoadLibraryW(L"ntdll.dll");
    if(!ntdll){ outErr="cannot load ntdll"; return names; }
    auto pOpen=(PFN_NtOpenDirectoryObject)GetProcAddress(ntdll,"NtOpenDirectoryObject");
    auto pQuery=(PFN_NtQueryDirectoryObject)GetProcAddress(ntdll,"NtQueryDirectoryObject");
    auto pClose=(PFN_NtClose)GetProcAddress(ntdll,"NtClose");
    if(!pOpen||!pQuery){ outErr="NtOpen/QueryDirectoryObject not found (requires Windows 10+)"; return names; }
    static WCHAR pathBuf[512]; // keep alive across NtOpen call
    wcsncpy_s(pathBuf, path.c_str(), 511);
    UNICODE_STRING uname{}; uname.Length=(USHORT)(wcslen(pathBuf)*2); uname.MaximumLength=sizeof(pathBuf); uname.Buffer=pathBuf;
    OBJECT_ATTRIBUTES oa{}; oa.Length=sizeof(oa); oa.ObjectName=&uname;
    HANDLE hDir=nullptr;
     NTSTATUS st=pOpen(&hDir, 0x0001 /*DIRECTORY_QUERY*/, &oa);
     if(st!=0 && (uint32_t)st==0xC0000022u /*STATUS_ACCESS_DENIED*/){
         NTSTATUS st2=pOpen(&hDir, 0x0000, &oa);
         if(st2==0) st=st2;
     }
     if(st!=0){
         char hex[16]={0}; sprintf_s(hex,sizeof(hex),"%08X",(uint32_t)st);
         outErr=std::string("NtOpenDirectoryObject 0x")+hex+" (run as Administrator for \\Driver\\)";
         return names;
     }
    ULONG ctx=0; ULONG retLen=0;
    std::vector<uint8_t> buf(64*1024);
    bool first=true;
    while(true){
        NTSTATUS qst=pQuery(hDir, buf.data(), (ULONG)buf.size(), FALSE, first?1:0, &ctx, &retLen);
        first=false;
        if(qst!=0 && qst!=0x80000006){ // STATUS_NO_MORE_ENTRIES
            if((uint32_t)qst==0xC0000004u){ buf.resize(buf.size()*2); continue; }
            break;
        }
        struct OBJECT_DIRECTORY_INFORMATION { UNICODE_STRING Name; UNICODE_STRING TypeName; };
        // Walk entries until null name
        size_t offset=0;
        while(true){
            auto* entry=(OBJECT_DIRECTORY_INFORMATION*)(buf.data()+offset);
            if(entry->Name.Length==0) break;
            int n=WideCharToMultiByte(CP_UTF8,0,entry->Name.Buffer, entry->Name.Length/2, nullptr,0,nullptr,nullptr);
            std::string s(n,0); WideCharToMultiByte(CP_UTF8,0,entry->Name.Buffer, entry->Name.Length/2, s.data(),n,nullptr,nullptr);
            names.push_back(s);
            // Entry size is aligned; advance by struct size + name storage approximation
            // More robust: use retLen to bound, but empirical: entries are contiguous with alignment
            // Fallback: break after one batch and rely on ctx
            // NtQueryDirectoryObject returns one batch per call; break inner and loop outer
            break;
        }
        // Actually enumerate properly: buf contains multiple entries; parse by scanning
        // Use OBJECT_DIRECTORY_INFORMATION stride: sizeof struct is variable due to UNICODE_STRING buffers not inline
        // The buffers follow; simpler: trust single entry per call and rely on ctx continuation
        // But some Windows versions return multiple entries per call in the buffer.
        // We handle multiple by re-parsing with offset calculation using alignment to 8
        // Reset and re-parse with proper stride
        size_t off2=0;
        std::vector<std::string> batch;
        while(off2 + sizeof(OBJECT_DIRECTORY_INFORMATION) <= buf.size()){
            auto* e=(OBJECT_DIRECTORY_INFORMATION*)(buf.data()+off2);
            if(e->Name.Length==0) break;
            int n2=WideCharToMultiByte(CP_UTF8,0,e->Name.Buffer, e->Name.Length/2, nullptr,0,nullptr,nullptr);
            if(n2<=0) break;
            // Validate TypeName length sanity
            if(e->TypeName.Length>256) break;
            // If we already pushed this name in single-entry mode, skip duplicate push
            // Instead collect batch
            std::string s2(n2,0); WideCharToMultiByte(CP_UTF8,0,e->Name.Buffer, e->Name.Length/2, s2.data(),n2,nullptr,nullptr);
            // Check if this is a duplicate of what we already added in outer single-push
            // We'll just dedup later
            batch.push_back(s2);
            // Advance: align to pointer size (8 on x64)
            size_t entrySize = sizeof(OBJECT_DIRECTORY_INFORMATION);
            // Align
            off2 = (off2 + entrySize + 7) & ~7ULL;
            if(off2 >= buf.size()) break;
            if(batch.size()>10000) break;
        }
        if(batch.size()>1){
            // Replace single push with full batch (dedup later)
            if(!names.empty()) names.pop_back();
            for(auto& b: batch) names.push_back(b);
        }
        if(qst!=0) break;
        if(ctx==0) break;
    }
    if(pClose) pClose(hDir); else CloseHandle(hDir);
    // Deduplicate and sort for stability
    std::sort(names.begin(), names.end());
    names.erase(std::unique(names.begin(), names.end()), names.end());
    return names;
}

// Enumerate \Driver\ and \Device\ and cross-ref against loaded modules
ObjScanResult ScanObjectManager(){
    ObjScanResult r;
    std::string err;
    r.driverNames = EnumerateObjectDirectory(L"\\Driver", err);
    if(!err.empty() && r.driverNames.empty()) r.error = "Driver dir: "+err;
    r.deviceNames = EnumerateObjectDirectory(L"\\Device", err);
    if(!err.empty() && r.deviceNames.empty()){
        if(!r.error.empty()) r.error += "; ";
        r.error += "Device dir: "+err;
    }
    r.driverObjects = (int)r.driverNames.size();
    r.deviceObjects = (int)r.deviceNames.size();
    // Orphaned = driver objects with no loaded-module filename match (caller also cross-refs, but we seed here)
    // Leave orphaned empty; main.cpp cross-refs against EnumDeviceDrivers set for the real orphan list.
    return r;
}

} // namespace drvscan
