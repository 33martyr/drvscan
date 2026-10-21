#include "prefetch.h"
#include <windows.h>
#include <string>
#include <vector>
namespace drvscan {
PrefetchStats ScanPrefetch(const std::vector<std::string>&){
    PrefetchStats s;
    WIN32_FIND_DATAW fd{};
    HANDLE h=FindFirstFileW(L"C:\\Windows\\Prefetch\\*.pf", &fd);
    if(h==INVALID_HANDLE_VALUE){ s.error="prefetch not accessible or disabled"; return s; }
    do{ s.files++; }while(FindNextFileW(h,&fd));
    FindClose(h);
    s.error="prefetch header parse pending";
    return s;
}
}
