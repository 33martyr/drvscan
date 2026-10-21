#include <doctest/doctest.h>
#include "risk.h"

using namespace drvscan;
using namespace drvscan::risk;

static Evidence MakeEv(const std::string& check, Verdict v, Confidence c = Confidence::High) {
    Evidence e;
    e.check = check;
    e.verdict = v;
    e.confidence = c;
    e.detail = check + " detail";
    return e;
}

TEST_CASE("Risk: valid sig + vulnerable hash => suspicious high") {
    // This is the BYOVD crux: valid sig must not override hash hit
    std::vector<Evidence> ev = {
        MakeEv("authenticode", Verdict::Clean),
        MakeEv("hash_blocklist", Verdict::Suspicious, Confidence::High),
        MakeEv("cert_blocklist", Verdict::Clean),
        MakeEv("path", Verdict::Clean),
        MakeEv("image_size", Verdict::Clean),
    };
    auto d = Assess(ev);
    CHECK(d.verdict == Verdict::Suspicious);
    CHECK(d.confidence == Confidence::High);
}

TEST_CASE("Risk: cert-only hit => medium signal not proof") {
    std::vector<Evidence> ev = {
        MakeEv("authenticode", Verdict::Clean),
        MakeEv("hash_blocklist", Verdict::Clean),
        MakeEv("cert_blocklist", Verdict::Suspicious, Confidence::Medium),
        MakeEv("path", Verdict::Clean),
    };
    auto d = Assess(ev);
    CHECK(d.verdict == Verdict::Suspicious);
    CHECK(d.confidence == Confidence::Medium);
}

TEST_CASE("Risk: path-only suspicious => low contextual") {
    std::vector<Evidence> ev = {
        MakeEv("authenticode", Verdict::Clean),
        MakeEv("hash_blocklist", Verdict::Clean),
        MakeEv("path", Verdict::Suspicious, Confidence::Low),
        MakeEv("image_size", Verdict::Clean),
    };
    auto d = Assess(ev);
    CHECK(d.verdict == Verdict::Suspicious);
    CHECK(d.confidence == Confidence::Low);
}

TEST_CASE("Risk: warn only => warn") {
    std::vector<Evidence> ev = { MakeEv("path", Verdict::Warn) };
    auto d = Assess(ev);
    CHECK(d.verdict == Verdict::Warn);
}

TEST_CASE("Risk: all clean => clean") {
    std::vector<Evidence> ev = { MakeEv("authenticode", Verdict::Clean), MakeEv("path", Verdict::Clean) };
    auto d = Assess(ev);
    CHECK(d.verdict == Verdict::Clean);
    CHECK(d.confidence == Confidence::High);
}

TEST_CASE("Risk: revoked sig => suspicious high") {
    std::vector<Evidence> ev = { MakeEv("authenticode", Verdict::Suspicious, Confidence::High) };
    auto d = Assess(ev);
    CHECK(d.verdict == Verdict::Suspicious);
    CHECK(d.confidence == Confidence::High);
}
