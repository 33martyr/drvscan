#include "bootlog.h"
#include <windows.h>
#include <fstream>
#include <string>
#include <vector>
namespace drvscan {
BootLogStats ScanBootLog(const std::vector<std::string>&){
    BootLogStats s;
    DWORD attr=GetFileAttributesW(L"C:\\Windows\\ntbtlog.txt");
    if(attr==INVALID_FILE_ATTRIBUTES){ attr=GetFileAttributesW(L"C:\\Windows\\System32\\ntbtlog.txt"); }
    if(attr==INVALID_FILE_ATTRIBUTES){ s.error="boot log disabled — enable with 'bcdedit /bootlog on'"; return s; }
    s.exists=true;
    s.error="ntbtlog.txt parse pending";
    return s;
}
}
