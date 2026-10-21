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
    bool prefetchEnabled = false;
    bool amcacheAccessible = false;
    std::string error;
};

SigContext QuerySigContext();
std::string SigContextHeader(const SigContext& c);

} // namespace drvscan
