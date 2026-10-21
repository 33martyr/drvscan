#include "enum.h"
#include <windows.h>
#include <psapi.h>
#include <algorithm>
#include <cctype>
#include <sstream>
#include <iomanip>

namespace drvscan {

std::string ExtractFileName(const std::string& path) {
    size_t pos = path.find_last_of("\\/");
    if (pos == std::string::npos) return path;
    return path.substr(pos + 1);
}

std::string BaseAddressToHex(void* base) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setw(sizeof(void*) * 2) << std::setfill('0')
        << reinterpret_cast<uintptr_t>(base);
    return oss.str();
}

static std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return (char)std::tolower(c); });
    return s;
}

std::string NormalizeNtPath(const std::string& ntPath) {
    if (ntPath.empty()) return ntPath;
    std::string s = ntPath;

    // Strip NT prefixes
    const char* prefixes[] = { "\\??\\", "\\\\?\\", "\\SystemRoot\\", "\\SYSTEMROOT\\" };
    // \??\ and \\?\ are device prefixes
    if (s.rfind("\\??\\", 0) == 0) s = s.substr(4);
    else if (s.rfind("\\\\?\\", 0) == 0) s = s.substr(4);

    // Re-check after stripping prefix: \SystemRoot\ may now be at start
    // Do case-insensitive check
    std::string lower = ToLower(s);
    const std::string sr = "\\systemroot\\";
    if (lower.rfind(sr, 0) == 0) {
        char winDir[MAX_PATH];
        UINT len = GetWindowsDirectoryA(winDir, MAX_PATH);
        std::string wd = (len > 0) ? std::string(winDir) : std::string("C:\\Windows");
        s = wd + "\\" + s.substr(sr.size());
    } else if (lower.rfind("\\windows\\", 0) == 0) {
        // Already windows-relative but with leading backslash — prepend drive
        char winDir[MAX_PATH];
        UINT len = GetWindowsDirectoryA(winDir, MAX_PATH);
        if (len >= 2) {
            std::string drive = std::string(winDir).substr(0, 2); // "C:"
            s = drive + s;
        }
    }

    // Normalize slashes: keep as-is but ensure drive letter is uppercase
    if (s.size() >= 2 && s[1] == ':') s[0] = (char)std::toupper((unsigned char)s[0]);
    return s;
}

// Minimal RTL structs for NtQuerySystemInformation
struct RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
};
struct RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
};

std::vector<DriverInfo> EnumerateDrivers(std::string& err) {
    std::vector<DriverInfo> out;

    // Step 1: documented EnumDeviceDrivers for bases
    LPVOID addrs[1024];
    DWORD needed = 0;
    std::vector<std::pair<void*, std::string>> psapiEntries; // base -> fileName path
    if (EnumDeviceDrivers(addrs, sizeof(addrs), &needed) && needed > 0) {
        size_t count = needed / sizeof(LPVOID);
        if (count > 1024) count = 1024;
        for (size_t i = 0; i < count; ++i) {
            char fname[MAX_PATH] = {};
            std::string p;
            if (GetDeviceDriverFileNameA(addrs[i], fname, MAX_PATH) && fname[0] != '\0') {
                p = fname;
            }
            psapiEntries.push_back({addrs[i], p});
        }
    } else {
        // psapi failed; we'll rely solely on NtQuery. Not fatal.
        DWORD le = GetLastError();
        if (le != 0) {
            // keep err for later; don't fail yet
            err = "EnumDeviceDrivers failed: " + std::to_string(le);
        }
    }

    // Step 2: NtQuerySystemInformation for ImageSize + full NT path enrichment
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    using NtQSI = LONG(WINAPI*)(ULONG, PVOID, ULONG, PULONG);
    NtQSI pNtQSI = nullptr;
    if (ntdll) pNtQSI = (NtQSI)GetProcAddress(ntdll, "NtQuerySystemInformation");

    // Map base -> {ImageSize, FullPathName}
    struct Extra { ULONG size; std::string full; };
    std::vector<std::pair<void*, Extra>> extras;

    if (pNtQSI) {
        constexpr ULONG SystemModuleInformation = 11;
        ULONG bufSize = 1 << 20; // 1 MB initial
        std::vector<uint8_t> buf(bufSize);
        LONG status = 0;
        ULONG retLen = 0;
        // Grow if needed
        for (int tries = 0; tries < 4; ++tries) {
            status = pNtQSI(SystemModuleInformation, buf.data(), (ULONG)buf.size(), &retLen);
            if (status == 0) break; // STATUS_SUCCESS
            // STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
            if ((ULONG)status == 0xC0000004u) {
                bufSize = retLen + 4096;
                buf.resize(bufSize);
                continue;
            }
            break;
        }
        if (status == 0) {
            auto* mods = reinterpret_cast<RTL_PROCESS_MODULES*>(buf.data());
            for (ULONG i = 0; i < mods->NumberOfModules; ++i) {
                auto& m = mods->Modules[i];
                std::string full(reinterpret_cast<char*>(m.FullPathName));
                extras.push_back({m.ImageBase, Extra{m.ImageSize, full}});
            }
        }
    }

    // Build result: prefer psapi bases (documented), enrich with extras; if psapi empty, use extras directly
    if (!psapiEntries.empty()) {
        for (auto& [base, psPath] : psapiEntries) {
            DriverInfo di;
            di.baseAddress = base;
            di.baseHex = BaseAddressToHex(base);
            // Find matching extra by base
            std::string ntFull;
            uint32_t kSize = 0;
            for (auto& [ebase, ex] : extras) {
                if (ebase == base) { kSize = ex.size; ntFull = ex.full; break; }
            }
            di.kernelImageSize = kSize;
            // Prefer Nt full path (has image size companion), fallback to psapi
            std::string raw = !ntFull.empty() ? ntFull : psPath;
            di.kernelPath = raw;
            di.normalizedPath = NormalizeNtPath(raw);
            di.fileName = ExtractFileName(di.normalizedPath.empty() ? raw : di.normalizedPath);
            out.push_back(std::move(di));
        }
    } else if (!extras.empty()) {
        for (auto& [base, ex] : extras) {
            DriverInfo di;
            di.baseAddress = base;
            di.baseHex = BaseAddressToHex(base);
            di.kernelImageSize = ex.size;
            di.kernelPath = ex.full;
            di.normalizedPath = NormalizeNtPath(ex.full);
            di.fileName = ExtractFileName(di.normalizedPath);
            out.push_back(std::move(di));
        }
    }

    if (out.empty() && err.empty()) {
        err = "No drivers enumerated (both EnumDeviceDrivers and NtQuerySystemInformation returned no data). Try running elevated.";
    } else if (!out.empty()) {
        err.clear(); // success overrides earlier psapi warning
    }
    return out;
}

} // namespace drvscan
