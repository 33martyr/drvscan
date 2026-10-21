#include "pathcheck.h"
#include <algorithm>
#include <cctype>
#include <windows.h>

namespace drvscan {

static std::string ToLowerStr(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return (char)std::tolower(c); });
    return s;
}

PathResult CheckDriverPath(const std::string& normalizedPath) {
    PathResult r;
    if (normalizedPath.empty()) {
        r.verdict = PathVerdict::Suspicious;
        r.reason = "Empty path — cannot verify driver location (contextual risk, not proof of malware)";
        r.recommendation = "Investigate how driver was loaded; check event logs";
        return r;
    }
    std::string lower = ToLowerStr(normalizedPath);

    // Suspicious indicators — contextual risk, not proof of malware
    auto contains = [&](const std::string& needle){ return lower.find(needle) != std::string::npos; };

    // UNC / network
    if (lower.rfind("\\\\", 0) == 0 || lower.rfind("//", 0) == 0) {
        r.verdict = PathVerdict::Suspicious;
        r.reason = "Driver loaded from UNC/network path — contextual risk indicator, not proof of malware";
        r.recommendation = "Verify network source; check if expected";
        return r;
    }
    if (contains("\\device\\") || contains("\\Device\\")) {
        r.verdict = PathVerdict::Suspicious;
        r.reason = "Driver path contains NT device namespace — contextual risk indicator";
        r.recommendation = "Resolve to Win32 path and verify origin";
        return r;
    }
    if (contains("\\appdata\\") || contains("\\temp\\") || contains("\\tmp\\") ) {
        r.verdict = PathVerdict::Suspicious;
        r.reason = "Driver loaded from user temp/AppData — contextual risk indicator, not proof of malware (legit installers rarely place drivers here)";
        r.recommendation = "Check which process dropped the driver; inspect creation time";
        return r;
    }
    if (contains("\\downloads\\")) {
        r.verdict = PathVerdict::Suspicious;
        r.reason = "Driver loaded from Downloads — contextual risk indicator";
        r.recommendation = "Verify download source and driver signature";
        return r;
    }

    // Non-system drive without vendor prefix is suspicious
    // Get system drive
    char winDir[MAX_PATH] = {};
    GetWindowsDirectoryA(winDir, MAX_PATH);
    std::string sysDrive = "c:";
    if (winDir[0] && winDir[1] == ':') { sysDrive[0] = (char)std::tolower(winDir[0]); sysDrive[1] = ':'; }
    if (lower.size() >= 2 && lower[1] == ':' && lower.substr(0,2) != sysDrive) {
        // Allow Program Files on other drives? Still warn
        if (!contains("\\program files")) {
            r.verdict = PathVerdict::Suspicious;
            r.reason = "Driver on non-system drive outside Program Files — contextual risk indicator";
            r.recommendation = "Verify driver install location is expected";
            return r;
        }
    }

    // Regular locations
    if (contains("\\windows\\system32\\drivers\\") || contains("\\windows\\system32\\driverstore\\")) {
        r.verdict = PathVerdict::Regular;
        r.reason = "Standard driver location";
        return r;
    }
    if (contains("\\windows\\system32\\")) {
        r.verdict = PathVerdict::Regular;
        r.reason = "System32 — standard location";
        return r;
    }

    // Warn: Program Files vendor path — legit but non-canonical for kernel drivers
    if (contains("\\program files")) {
        r.verdict = PathVerdict::Warn;
        r.reason = "Driver in Program Files — legitimate vendor path but non-canonical for kernel drivers; verify signature";
        r.recommendation = "Verify Authenticode signature and vendor is expected";
        return r;
    }
    return r;
}

PathResult CheckDriverPathWithSig(const std::string& normalizedPath, bool isSignedValid) {
    if (isSignedValid) {
        std::string lower = ToLowerStr(normalizedPath);
        auto contains = [&](const std::string& needle){ return lower.find(needle) != std::string::npos; };
        // Signed driver in Program Files is expected (AMD RyzenMaster, NVIDIA, etc.) — not a warn.
        if (contains("\\program files")) {
            PathResult r;
            r.verdict = PathVerdict::Regular;
            r.reason = "Program Files — signed driver, expected vendor location";
            r.recommendation = "No action";
            return r;
        }
    }
    return CheckDriverPath(normalizedPath);
}

} // namespace drvscan
