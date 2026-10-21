#pragma once
#include <string>

namespace drvscan {
int RunUpdateBlocklist(const std::wstring& destPath);
// Exposed for tests: verifies body against pinned hash in data/blocklist.sha256
bool VerifyBlocklistPin(const std::string& body, const std::wstring& blocklistPath, std::string& outErr);
} // namespace drvscan
