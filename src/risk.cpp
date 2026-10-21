#include "risk.h"

namespace drvscan {
namespace risk {

// Rules (v1):
// - Any Suspicious evidence -> overall Suspicious. Hash blocklist hit overrides valid signature.
// - Valid signature never downgrades a hash/cert hit.
// - Cert-only hit -> Medium confidence (signal, not proof of compromise).
// - Path Suspicious alone (contextual) without corroboration -> downgrade confidence to Low unless paired.
// - Any Warn with no Suspicious -> Warn.
// - Else Clean.

RiskDecision Assess(const std::vector<Evidence>& ev) {
    // Unmapped evidence is handled by callers: callers set DriverReport::overall = Unmapped
    // directly and do not route those reports through Assess. If Unmapped does reach
    // Assess (e.g. synthetic tests), treat it as "cannot audit" -> return Unmapped.
    for (auto& e : ev) if (e.verdict == Verdict::Unmapped) {
        RiskDecision dd; dd.verdict = Verdict::Unmapped; dd.confidence = Confidence::Low;
        dd.summary = e.detail; dd.nextStep = e.recommendation; return dd;
    }
    RiskDecision d;
    if (ev.empty()) {
        d.verdict = Verdict::Clean;
        d.confidence = Confidence::High;
        d.summary = "No findings";
        d.nextStep = "No action required";
        return d;
    }

    bool hasSusp = false, hasWarn = false, hasHashSusp = false, hasCertOnly = false, hasPathSusp = false, hasSigSusp = false;
    for (auto& e : ev) {
        if (e.verdict == Verdict::Suspicious) {
            hasSusp = true;
            if (e.check == "hash_blocklist") hasHashSusp = true;
            if (e.check == "cert_blocklist") hasCertOnly = true; // will refine below
            if (e.check == "path") hasPathSusp = true;
            if (e.check == "authenticode") hasSigSusp = true;
        }
        if (e.verdict == Verdict::Warn) hasWarn = true;
    }
    // Cert-only: if Suspicious evidence is exclusively cert_blocklist, it's signal not proof
    bool onlyCertSusp = hasSusp;
    for (auto& e : ev) if (e.verdict == Verdict::Suspicious && e.check != "cert_blocklist") onlyCertSusp = false;

    if (hasSusp) {
        d.verdict = Verdict::Suspicious;
        if (hasHashSusp) {
            d.confidence = Confidence::High;
            d.summary = "Driver matches known-vulnerable/malicious blocklist — valid signature does not imply safe (BYOVD)";
            d.nextStep = "Remove or update the driver; check vendor advisory; block hash via WDAC/AV";
        } else if (hasSigSusp) {
            d.confidence = Confidence::High;
            d.summary = "Signature invalid or untrusted — file may be tampered or unsigned";
            d.nextStep = "Verify file origin; reinstall from vendor; check for tampering";
        } else if (onlyCertSusp) {
            d.confidence = Confidence::Medium;
            d.summary = "Signing certificate associated with past abuse — signal, not proof of compromise";
            d.nextStep = "Corroborate with hash/path; check cert revocation status; verify vendor";
        } else if (hasPathSusp && !hasHashSusp && !hasSigSusp && !onlyCertSusp) {
            // Path-only suspicious without corroboration -> lower confidence
            // But if there's also size mismatch corroboration, keep Medium
            bool hasSizeSusp = false;
            for (auto& e : ev) if (e.verdict == Verdict::Suspicious && e.check == "image_size") hasSizeSusp = true;
            if (hasSizeSusp) {
                d.confidence = Confidence::Medium;
                d.summary = "Suspicious path combined with image size divergence — requires investigation";
                d.nextStep = "Check driver creation time, dropping process, and on-disk vs loaded image";
            } else {
                d.confidence = Confidence::Low;
                d.summary = "Suspicious path alone — contextual risk indicator, not proof of malware";
                d.nextStep = "Verify install location is expected; corroborate with signature and hash checks";
            }
        } else {
            d.confidence = Confidence::Medium;
            d.summary = "One or more checks flagged suspicious — requires investigation";
            d.nextStep = "Review failed checks, verify driver source and necessity";
        }
        return d;
    }
    if (hasWarn) {
        d.verdict = Verdict::Warn;
        d.confidence = Confidence::Medium;
        d.summary = "Non-critical finding — review recommended";
        d.nextStep = "Verify driver is expected and signed by intended vendor";
        return d;
    }
    d.verdict = Verdict::Clean;
    d.confidence = Confidence::High;
    d.summary = "No suspicious indicators";
    d.nextStep = "No action required";
    return d;
}

DriverReport MakeReport(const DriverInfo& driver, std::vector<Evidence> ev) {
    DriverReport r;
    r.driver = driver;
    r.evidence = std::move(ev);
    auto dec = Assess(r.evidence);
    r.overall = dec.verdict;
    r.overallConfidence = dec.confidence;
    r.summary = dec.summary;
    r.nextStep = dec.nextStep;
    return r;
}

} // namespace risk
} // namespace drvscan
