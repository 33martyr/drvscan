#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace drvscan {

enum class Verdict { Clean = 0, Warn = 1, Suspicious = 2 };
enum class Confidence { High = 0, Medium = 1, Low = 2 };
enum class SigStatus { Valid, Unsigned, Modified, Revoked, Expired, UntrustedRoot, Unverifiable };
enum class PathVerdict { Regular, Warn, Suspicious };

inline const char* ToString(Verdict v) {
    switch (v) {
        case Verdict::Clean: return "clean";
        case Verdict::Warn: return "warn";
        case Verdict::Suspicious: return "suspicious";
    }
    return "unknown";
}
inline const char* ToString(Confidence c) {
    switch (c) {
        case Confidence::High: return "high";
        case Confidence::Medium: return "medium";
        case Confidence::Low: return "low";
    }
    return "unknown";
}
inline const char* ToString(SigStatus s) {
    switch (s) {
        case SigStatus::Valid: return "valid";
        case SigStatus::Unsigned: return "unsigned";
        case SigStatus::Modified: return "modified";
        case SigStatus::Revoked: return "revoked";
        case SigStatus::Expired: return "expired";
        case SigStatus::UntrustedRoot: return "untrusted_root";
        case SigStatus::Unverifiable: return "unverifiable";
    }
    return "unknown";
}
inline Verdict MaxVerdict(Verdict a, Verdict b) {
    return (static_cast<int>(a) > static_cast<int>(b)) ? a : b;
}

struct DriverInfo {
    void* baseAddress = nullptr;
    uint32_t kernelImageSize = 0;
    std::string kernelPath;      // raw NT path from enumeration
    std::string normalizedPath;  // Win32 normalized path (C:\...)
    std::string fileName;        // basename
    std::string baseHex;         // hex string of baseAddress for display
};

// Evidence produced by a single collector; provenance + recommendation included.
struct Evidence {
    std::string check;          // e.g. "authenticode", "hash_blocklist", "cert_blocklist", "path", "image_size"
    Verdict verdict = Verdict::Clean;
    Confidence confidence = Confidence::High;
    std::string detail;         // human-readable detail
    std::string provenance;     // source attribution, e.g. "loldrivers.io v2024.10.20"
    std::string recommendation; // next investigation step
    // Structured fields for machine consumers; stable alongside free-text detail.
    // e.g. {"observed":"0x...","expected":"0x...","kernel_value":"...","on_disk_value":"..."}
    std::vector<std::pair<std::string,std::string>> fields;
};

struct DriverReport {
    DriverInfo driver;
    std::vector<Evidence> evidence;
    Verdict overall = Verdict::Clean;
    Confidence overallConfidence = Confidence::High;
    std::string summary;
    std::string nextStep;
};

} // namespace drvscan
