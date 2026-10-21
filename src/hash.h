#pragma once
#include <string>
#include <cstdint>

namespace drvscan {
std::string Sha256Bytes(const uint8_t* data, size_t len);
std::string Sha256File(const std::wstring& path, std::string& err);
std::string ToLowerHex(const std::string& s);
} // namespace drvscan
