#pragma once
#include <string>
#include <windows.h>

namespace drvscan {

struct SigContext {
    bool hvciOn = false;
    bool dseOn = true;
    bool testSigningOn = false;
    bool kdOn = false;
    bool sysmonInstalled = false;
    // Retained for backward compat but not reported as checked in v0.4.0;
    // v0.4.0 surfaces for Amcache/Prefetch are stubbed — header reports "pending v0.4.0"
    bool prefetchEnabled = false;
    bool amcacheAccessible = false;
    std::string error;
};

SigContext QuerySigContext();
std::string SigContextHeader(const SigContext& c);

// Honesty helpers (testable): Section 1/2/4 formatters and driver-dir denial check
bool IsDriverDirAccessDenied(const std::string& objError);
std::string BuildSection2Text(const struct ObjScanResult& obj);
std::string BuildSection4Text();

} // namespace drvscan
