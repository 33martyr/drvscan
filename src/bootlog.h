#pragma once
#include <string>
#include <vector>
namespace drvscan {
struct BootLogStats { int drivers=0; int notInModuleList=0; std::string error; bool exists=false; };
BootLogStats ScanBootLog(const std::vector<std::string>& loadedModules);
}
