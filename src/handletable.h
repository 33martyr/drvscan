#pragma once
#include <string>
#include <vector>
#include <windows.h>

namespace drvscan {

struct HandleTableStats {
    int totalHandles = 0;
    int driverHandles = 0;
    int orphanHandles = 0;
    std::vector<std::pair<std::string,int>> orphanDriverCounts; // driver object name -> handle count
    std::string error;
};

HandleTableStats ScanGlobalHandleTable(const std::vector<std::string>& orphanedDriverObjects);

} // namespace drvscan
