#include "update.h"
#include "hash.h"
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <cstdio>
#include <fstream>
#include <algorithm>

namespace drvscan {

static bool HttpGet(const std::wstring& host, const std::wstring& path, std::string& out, std::string& err) {
    HINTERNET hSession = WinHttpOpen(L"drvscan/0.2", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { err = "WinHttpOpen failed"; return false; }
    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { err = "WinHttpConnect failed"; WinHttpCloseHandle(hSession); return false; }
    HINTERNET hReq = WinHttpOpenRequest(hConnect, L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hReq) { err = "WinHttpOpenRequest failed"; WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }
    WinHttpSetTimeouts(hReq, 5000, 5000, 15000, 15000);
    BOOL ok = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!ok) { err = "WinHttpSendRequest failed: " + std::to_string(GetLastError()); WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }
    ok = WinHttpReceiveResponse(hReq, nullptr);
    if (!ok) { err = "WinHttpReceiveResponse failed: " + std::to_string(GetLastError()); WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }
    DWORD status = 0; DWORD slen = sizeof(status);
    WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &slen, WINHTTP_NO_HEADER_INDEX);
    if (status != 200) { err = "HTTP status " + std::to_string(status); WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }
    std::string body;
    DWORD avail = 0, read = 0;
    std::vector<char> buf(8192);
    while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
        if (avail > buf.size()) buf.resize(avail);
        if (!WinHttpReadData(hReq, buf.data(), avail, &read)) break;
        body.append(buf.data(), read);
    }
    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    out = std::move(body);
    return true;
}

// Release-coupled hash pin: compare SHA-256(body) against data/blocklist.sha256 committed alongside each release.
// If the pin file is missing or contains placeholder, warn and proceed without verification (sample mode).
// If pin present and mismatch => refuse to install. To rotate: update data/blocklist.json and recompute
// its SHA-256 (Sha256Bytes) and write to data/blocklist.sha256 in the same commit; CI's test_update verifies
// pin matches file. This resolves the chicken-and-egg: the download is verified against the pin that shipped
// WITH THIS BINARY, not against the download itself.
static std::string LoadPinnedHash(const std::wstring& blocklistPath) {
    // Derive pin path: same dir as blocklist, file "blocklist.sha256"
    size_t slash = blocklistPath.find_last_of(L"\\/");
    std::wstring pinPath = (slash == std::wstring::npos) ? L"data\\blocklist.sha256" : blocklistPath.substr(0, slash + 1) + L"blocklist.sha256";
    HANDLE h = CreateFileW(pinPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        // Try exe-relative fallback
        wchar_t exeBuf[MAX_PATH]{};
        GetModuleFileNameW(nullptr, exeBuf, MAX_PATH);
        std::wstring exeDir(exeBuf);
        size_t pos = exeDir.find_last_of(L"\\/");
        if (pos != std::wstring::npos) {
            std::wstring alt = exeDir.substr(0, pos + 1) + L"data\\blocklist.sha256";
            h = CreateFileW(alt.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
            if (h == INVALID_HANDLE_VALUE) {
                h = CreateFileW(L"data\\blocklist.sha256", GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
            }
        }
    }
    if (h == INVALID_HANDLE_VALUE) return {};
    DWORD sz = GetFileSize(h, nullptr);
    if (sz == INVALID_FILE_SIZE || sz > 256) { CloseHandle(h); return {}; }
    std::string s(sz, '\0');
    DWORD rd = 0;
    ReadFile(h, s.data(), sz, &rd, nullptr);
    CloseHandle(h);
    s.resize(rd);
    // Trim whitespace and newlines
    while (!s.empty() && (s.back()=='\n' || s.back()=='\r' || s.back()==' ' || s.back()=='\t')) s.pop_back();
    while (!s.empty() && (s.front()==' ' || s.front()=='\t')) s.erase(s.begin());
    // Only take first hex token (allow "abc...  blocklist.json" style)
    auto sp = s.find_first_of(" \t");
    if (sp != std::string::npos) s = s.substr(0, sp);
    // Validate hex, normalize
    std::string low = ToLowerHex(s);
    if (low.size() != 64) return {}; // not a real pin yet (placeholder)
    bool placeholder = (low.find("override") != std::string::npos);
    if (placeholder) return {};
    // Reject placeholder-like all-same or obvious dummy
    if (low == std::string(64,'0') || low == std::string(64,'f')) return {};
    return low;
}

// Exposed for test_update: verifies body against pin. Returns true if pin absent (unpinned sample mode) or matches.
bool VerifyBlocklistPin(const std::string& body, const std::wstring& blocklistPath, std::string& outErr);
bool VerifyBlocklistPin(const std::string& body, const std::wstring& blocklistPath, std::string& outErr) {
    std::string pin = LoadPinnedHash(blocklistPath);
    if (pin.empty()) {
        // Sample or dev mode: no verification, warn caller
        return true;
    }
    std::string got = Sha256Bytes(reinterpret_cast<const uint8_t*>(body.data()), body.size());
    if (ToLowerHex(got) != pin) {
        outErr = "Downloaded blocklist SHA-256 " + got.substr(0,16) + "... does not match pinned hash " + pin.substr(0,16) + "... in data/blocklist.sha256 — refusing to install (possible MITM or stale pin; see docs/UPDATE.md for rotation)";
        return false;
    }
    return true;
}

int RunUpdateBlocklist(const std::wstring& destPath) {
    std::string body, err;
    bool got = HttpGet(L"www.loldrivers.io", L"/api/drivers.json", body, err);
    if (!got) {
        std::string err2;
        if (!HttpGet(L"raw.githubusercontent.com", L"/lorenzo-bonfiglioli/loldrivers/main/drivers.json", body, err2)) {
            fprintf(stderr, "update failed: %s; fallback also failed: %s\n", err.c_str(), err2.c_str());
            fprintf(stderr, "No network or endpoint unavailable — existing blocklist not modified. Exit 1.\n");
            return 1;
        }
    }
    if (body.size() < 10 || body.find("sha256") == std::string::npos) {
        fprintf(stderr, "update failed: response did not look like a driver blocklist (no sha256 field) — existing blocklist not modified. Exit 1.\n");
        return 1;
    }
    // Pin verification (release-coupled)
    {
        std::string pinErr;
        if (!VerifyBlocklistPin(body, destPath, pinErr)) {
            fprintf(stderr, "update rejected: %s\n", pinErr.c_str());
            fprintf(stderr, "Existing blocklist not modified. To accept this update, refresh the pin: compute SHA-256 of the downloaded body and commit it to data/blocklist.sha256 alongside the new blocklist. See docs/UPDATE.md.\n");
            return 1;
        }
        std::string pin = LoadPinnedHash(destPath);
        if (pin.empty()) {
            fprintf(stderr, "warning: no pinned hash found at data/blocklist.sha256 — update proceeding without pin verification (sample/dev mode). TLS still validates the source.\n");
            fprintf(stderr, "To enable pin verification, add a 64-hex SHA-256 to data/blocklist.sha256 and commit it with the next blocklist update. See docs/UPDATE.md.\n");
        } else {
            fprintf(stderr, "pin verified: downloaded body matches data/blocklist.sha256\n");
        }
    }
    std::wstring tmp = destPath + L".tmp";
    HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Cannot write temp file: %lu — existing blocklist not modified. Exit 1.\n", GetLastError());
        return 1;
    }
    DWORD written = 0;
    WriteFile(h, body.data(), (DWORD)body.size(), &written, nullptr);
    CloseHandle(h);
    if (!MoveFileExW(tmp.c_str(), destPath.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        fprintf(stderr, "MoveFileEx failed: %lu — existing blocklist not modified.\n", GetLastError());
        DeleteFileW(tmp.c_str());
        return 1;
    }
    fprintf(stdout, "Blocklist updated: %zu bytes written to %ls\n", body.size(), destPath.c_str());
    fprintf(stdout, "Note: blocklist is a versioned snapshot. Run --verify-blocklist to check pin and schema.\n");
    return 0;
}

} // namespace drvscan
