#pragma once
#include "types.h"
#include <string>

namespace drvscan {
struct PathResult {
    PathVerdict verdict = PathVerdict::Regular;
    std::string reason;
    std::string recommendation;
};
// Pure string check (no sig). Kept for tests.
PathResult CheckDriverPath(const std::string& normalizedPath);

// Signature-aware wrapper: Program Files + Valid signature => Regular, else Warn.
PathResult CheckDriverPathWithSig(const std::string& normalizedPath, bool isSignedValid);
} // namespace drvscan
