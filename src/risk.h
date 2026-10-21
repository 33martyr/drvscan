#pragma once
#include "types.h"
#include <vector>

namespace drvscan {
namespace risk {

struct RiskDecision {
    Verdict verdict = Verdict::Clean;
    Confidence confidence = Confidence::High;
    std::string summary;
    std::string nextStep;
};

// Versioned rules: Evidence[] -> overall verdict with confidence and guidance.
// Pure function, no I/O — testable with synthetic evidence.
RiskDecision Assess(const std::vector<Evidence>& ev);

// Helper to aggregate evidence into a DriverReport
DriverReport MakeReport(const DriverInfo& driver, std::vector<Evidence> ev);

} // namespace risk
} // namespace drvscan
