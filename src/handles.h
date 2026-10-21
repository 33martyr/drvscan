#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <variant>

namespace drvscan {

struct DeviceHandle {
    uint32_t handle_value = 0;
    uint32_t access_mask = 0;
    std::string device_path; // \Device\... or \FileSystem\...
};

struct HandleError {
    std::string message;
    int exit_code = 3;
};

// Resolve --pid argument to PIDs. Handles numeric PIDs and case-insensitive name match
// (with or without .exe). Returns empty if no match; caller prints suggestion + exit 3.
// Full paths (contain \ or /) are rejected by ResolveProcessArgument with exit 3 message.
std::vector<DWORD> ResolveProcessArgument(const std::string& arg, std::string& outErr);
int LevenshteinDistance(const std::string& a, const std::string& b);
std::string LevenshteinSuggestion(const std::string& needle, const std::vector<std::string>& candidates);

// Enable SeDebugPrivilege (best-effort); logs to stderr if unavailable.
void TryEnableDebugPrivilege();

// NtQuerySystemInformation(64) filtered to pid's \Device\ / \FileSystem\ handles.
// Dedupe by device_path (keep first access_mask), collapse HarddiskVolume*,
// skip \Device\NamedPipe\*.
// Handles ERROR_MORE_DATA by retrying larger buffer. Avoids NtQueryObject hangs
// by pre-filtering handles: GetFileType==PIPE is skipped before any NtQueryObject,
// and ObjectTypeInformation is queried to allow only "File" objects — other types
// (Event/Mutant/etc.) are skipped without ever calling ObjectNameInformation.
std::variant<std::vector<DeviceHandle>, HandleError> EnumerateDeviceHandles(DWORD pid);

// For tests: inject handle array and run the filter/dedup/collapse logic directly
std::vector<DeviceHandle> FilterDeviceHandlesTest(const std::vector<DeviceHandle>& in);

} // namespace drvscan
