#include <doctest/doctest.h>
#include "blocklist.h"
#include <nlohmann/json.hpp>

using namespace drvscan;

TEST_CASE("Blocklist load versioned") {
    auto j = nlohmann::json::parse(R"({
        "version":"2024.10.20",
        "snapshot_date":"2024-10-20",
        "sources":["loldrivers.io","microsoft:DriverSiPolicy"],
        "drivers":[{"sha256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","filename":"capcom.sys","category":"vulnerable","source":"loldrivers.io"}],
        "certs":[{"thumbprint":"0123456789abcdef0123456789abcdef01234567","owner":"CrossCert A","source":"microsoft:CertificateThumbprint"}]
    })");
    std::string err;
    Blocklist bl = Blocklist::LoadFromJson(j, err);
    CHECK(err.empty());
    CHECK(bl.version() == "2024.10.20");
    CHECK(bl.snapshotDate() == "2024-10-20");
    CHECK(bl.sources().size() == 2);
    CHECK(bl.hashCount() == 1);
    CHECK(bl.certCount() == 1);
    CHECK(bl.IsHashBlocked("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    CHECK(bl.IsHashBlocked("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")); // case-insensitive
    CHECK_FALSE(bl.IsHashBlocked("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
    CHECK(bl.IsCertBlocked("0123456789abcdef0123456789abcdef01234567"));
    auto* e = bl.FindHash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    REQUIRE(e != nullptr);
    CHECK(e->fileName == "capcom.sys");
    CHECK(e->source == "loldrivers.io");
}

TEST_CASE("Blocklist file load") {
    std::string err;
    std::wstring path = L"C:\\Users\\007\\drvscan\\data\\blocklist.json";
    Blocklist bl = Blocklist::Load(path, err);
    CHECK(err.empty());
    CHECK(bl.version() == "2026.10.20");
    CHECK(bl.schemaVersion() == "0.2.0");
    CHECK(bl.isSample() == true);
    CHECK(bl.hashCount() > 0);
}
