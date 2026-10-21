#pragma once
#include <string>
#include <vector>
namespace drvscan {
struct PrefetchStats { int files=0; int driverPrefetch=0; int notInModuleList=0; std::string error; };
PrefetchStats ScanPrefetch(const std::vector<std::string>& loadedModules);
}
