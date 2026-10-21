#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace drvscan {

struct ObjScanResult {
    int driverObjects = 0;
    int deviceObjects = 0;
    std::vector<std::string> driverNames;
    std::vector<std::string> deviceNames;
    std::vector<std::string> orphaned;
    std::string error;
};

ObjScanResult ScanObjectManager();
std::vector<std::string> EnumerateObjectDirectory(const std::wstring& path, std::string& outErr);

} // namespace drvscan
