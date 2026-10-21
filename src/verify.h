#pragma once
#include "types.h"
#include <string>
#include <vector>
#include <windows.h>

namespace drvscan {

struct VerifyResult {
    SigStatus status = SigStatus::Unverifiable;
    std::string message;
    std::vector<std::string> certThumbprints; // lowercase hex SHA-1 (leaf..root)
    std::string signerSubject;
    HRESULT hresult = 0;
};

VerifyResult VerifyEmbeddedSignature(const std::wstring& filePath);

// Checks whether any cert in the chain matches the pinned Microsoft root/intermediate list
// (data/microsoft_roots.json). Uses thumbprint comparison, not subject substring.
// Returns true only if chain is Valid and a thumbprint matches the pinned set.
bool IsMicrosoftSigned(const VerifyResult& vr);

// For testing: allow injecting a custom roots set.
bool IsMicrosoftSignedWithRoots(const VerifyResult& vr, const std::vector<std::string>& pinnedThumbprintsLowerHex);

// Pure HR -> SigStatus for table-driven testing.
SigStatus MapVerifyHr(HRESULT hr);

} // namespace drvscan
