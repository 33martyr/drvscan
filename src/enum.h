#pragma once
#include "types.h"
#include <string>
#include <vector>

namespace drvscan {

// Normalize NT paths: \SystemRoot\ -> C:\Windows, \??\ -> strip, \\?\ -> strip
std::string NormalizeNtPath(const std::string& ntPath);

// Hybrid enumeration: documented EnumDeviceDrivers (primary) + NtQuerySystemInformation supplement for ImageSize/path.
std::vector<DriverInfo> EnumerateDrivers(std::string& err);

// Helpers exposed for testing
std::string ExtractFileName(const std::string& path);
std::string BaseAddressToHex(void* base);

} // namespace drvscan
