#include "devmap.h"
#include <windows.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <fstream>
#include <nlohmann/json.hpp>

namespace drvscan {

static std::string ToLowerStr2(std::string s){ for(char& c:s) c=(char)std::tolower((unsigned char)c); return s; }

struct MapCache {
    std::unordered_map<std::string,std::string> exact; // lower -> driver
    std::vector<std::pair<std::string,std::string>> wildcards; // lower pattern without *, driver
    bool loaded=false;
};

static MapCache g_cache;
static std::mutex g_mu;

static std::string StripPrefix(const std::string& p){
    std::string low=ToLowerStr2(p);
    std::string stripped=p;
    if(low.rfind("\\device\\",0)==0) stripped=p.substr(8);
    else if(low.rfind("\\filesystem\\",0)==0) stripped=p.substr(12);
    else stripped=p;
    // Also trim leading slash
    while(!stripped.empty() && (stripped[0]=='\\' || stripped[0]=='/')) stripped=stripped.substr(1);
    return stripped;
}

static std::wstring GetExeDir2(){
    wchar_t buf[MAX_PATH]{}; DWORD n=GetModuleFileNameW(nullptr,buf,MAX_PATH);
    if(n==0||n>=MAX_PATH) return L".";
    std::wstring s(buf,n); size_t pos=s.find_last_of(L"\\/"); if(pos!=std::wstring::npos) s=s.substr(0,pos+1); else s=L".\\";
    return s;
}

static std::string LoadFile(const std::wstring& wpath){
    HANDLE h=CreateFileW(wpath.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN,nullptr);
    if(h==INVALID_HANDLE_VALUE) return {};
    DWORD sz=GetFileSize(h,nullptr); if(sz==INVALID_FILE_SIZE||sz>1<<20){CloseHandle(h); return {};}
    std::string s(sz,0); DWORD rd=0; ReadFile(h,s.data(),sz,&rd,nullptr); CloseHandle(h); s.resize(rd); return s;
}

static void EnsureLoaded(){
    std::lock_guard<std::mutex> lk(g_mu);
    if(g_cache.loaded) return;
    g_cache.loaded=true;
    std::vector<std::wstring> cands;
    std::wstring exeDir=GetExeDir2();
    cands.push_back(exeDir + L"data\\device_map.json");
    cands.push_back(exeDir + L"device_map.json");
    cands.push_back(L"data\\device_map.json");
    cands.push_back(L".\\data\\device_map.json");
    std::string body;
    for(auto& p: cands){ body=LoadFile(p); if(!body.empty()) break; }
    if(body.empty()) return;
    try{
        auto j=nlohmann::json::parse(body);
        if(j.contains("devices") && j["devices"].is_object()){
            for(auto& [k,v]: j["devices"].items()){
                std::string drv; if(v.contains("driver") && v["driver"].is_string()) drv=v["driver"].get<std::string>();
                if(!drv.empty()) g_cache.exact[ToLowerStr2(k)]=ToLowerStr2(drv);
            }
        }
        if(j.contains("wildcards") && j["wildcards"].is_array()){
            // Insert longer patterns first so HarddiskVolumeShadowCopy* matches before HarddiskVolume*
            std::vector<std::pair<std::string,std::string>> wcs;
            for(auto& w: j["wildcards"]){
                std::string pat,drv;
                if(w.contains("pattern") && w["pattern"].is_string()) pat=w["pattern"].get<std::string>();
                if(w.contains("driver") && w["driver"].is_string()) drv=w["driver"].get<std::string>();
                if(pat.empty()||drv.empty()) continue;
                std::string low=ToLowerStr2(pat);
                if(!low.empty() && low.back()=='*') low.pop_back();
                wcs.push_back({low, ToLowerStr2(drv)});
            }
            std::sort(wcs.begin(), wcs.end(), [](auto& a, auto& b){ return a.first.size() > b.first.size(); });
            for(auto& p: wcs) g_cache.wildcards.push_back(p);
        }
    }catch(...){}
}

std::string ResolveDeviceToDriver(const std::string& device_path){
    if(device_path.empty()) return {};
    EnsureLoaded();
    std::string name = StripPrefix(device_path);
    std::string low = ToLowerStr2(name);
    // Exact match
    auto it=g_cache.exact.find(low);
    if(it!=g_cache.exact.end()) return it->second;
    // Base name before \ if any
    auto slash=low.find_first_of("\\/");
    std::string base = (slash==std::string::npos)? low : low.substr(0,slash);
    it=g_cache.exact.find(base);
    if(it!=g_cache.exact.end()) return it->second;
    // Wildcard match in order
    for(auto& w: g_cache.wildcards){
        if(low.rfind(w.first,0)==0) return w.second;
        if(base.rfind(w.first,0)==0) return w.second;
    }
    return {};
}

void ClearDeviceMapCacheForTest(){
    std::lock_guard<std::mutex> lk(g_mu);
    g_cache.exact.clear(); g_cache.wildcards.clear(); g_cache.loaded=false;
}

} // namespace drvscan
