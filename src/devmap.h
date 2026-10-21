#pragma once
#include <string>

namespace drvscan {
std::string ResolveDeviceToDriver(const std::string& device_path);
void ClearDeviceMapCacheForTest();
} // namespace drvscan
