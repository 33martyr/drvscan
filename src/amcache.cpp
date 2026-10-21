#include "amcache.h"
#include <windows.h>
namespace drvscan {
AmcacheStats ScanAmcache(){
    AmcacheStats s;
    DWORD attr=GetFileAttributesW(L"C:\\Windows\\AppCompat\\Programs\\Amcache.hve");
    if(attr==INVALID_FILE_ATTRIBUTES){ s.error="Amcache.hve not accessible (service lock or not present)"; return s; }
    s.error="hive parsing pending (shadow copy / offline hive)";
    s.driverEntries=0;
    return s;
}
}
