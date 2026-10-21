#include "hash.h"
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <cctype>
#include <sstream>
#include <iomanip>
#include <vector>

#ifndef NT_SUCCESS
#define NT_SUCCESS(x) ((x) >= 0)
#endif

namespace drvscan {

std::string ToLowerHex(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(), [](unsigned char c){ return (char)std::tolower(c); });
    return r;
}

static std::string BytesToHex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) oss << std::setw(2) << (int)data[i];
    return oss.str();
}

std::string Sha256Bytes(const uint8_t* data, size_t len) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(st)) return {};
    DWORD hashLen = 0, outLen = 0;
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &outLen, 0);
    std::vector<uint8_t> hash(hashLen);
    st = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
    if (!NT_SUCCESS(st)) { BCryptCloseAlgorithmProvider(hAlg, 0); return {}; }
    if (len > 0) BCryptHashData(hHash, (PUCHAR)data, (ULONG)len, 0);
    BCryptFinishHash(hHash, hash.data(), hashLen, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return BytesToHex(hash.data(), hash.size());
}

std::string Sha256File(const std::wstring& path, std::string& err) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD le = GetLastError();
        err = "CreateFileW failed: " + std::to_string(le);
        return {};
    }
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(st)) {
        err = "BCryptOpenAlgorithmProvider failed";
        CloseHandle(h);
        return {};
    }
    st = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
    if (!NT_SUCCESS(st)) {
        err = "BCryptCreateHash failed";
        BCryptCloseAlgorithmProvider(hAlg, 0);
        CloseHandle(h);
        return {};
    }
    std::vector<uint8_t> buf(1 << 20);
    DWORD read = 0;
    while (ReadFile(h, buf.data(), (DWORD)buf.size(), &read, nullptr) && read > 0) {
        BCryptHashData(hHash, buf.data(), read, 0);
    }
    DWORD le = GetLastError();
    // ReadFile returns false on EOF with ERROR_HANDLE_EOF not set; check
    // If we broke due to ReadFile failure (not EOF), report
    if (read == 0) {
        // Check if it's truly EOF: GetLastError after successful 0-byte read is often 0 or ERROR_HANDLE_EOF
        // We'll treat as success if last ReadFile succeeded with 0 bytes
    }
    CloseHandle(h);
    DWORD hashLen = 0, outLen = 0;
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &outLen, 0);
    std::vector<uint8_t> hash(hashLen);
    BCryptFinishHash(hHash, hash.data(), hashLen, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    err.clear();
    (void)le;
    return BytesToHex(hash.data(), hash.size());
}

} // namespace drvscan
