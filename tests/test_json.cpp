#include <windows.h>
#include <doctest/doctest.h>
#include "types.h"
#include "blocklist.h"
#include "output.h"
#include "risk.h"
#include <nlohmann/json.hpp>
#include <cstdio>

using namespace drvscan;

TEST_CASE("JSON report round-trip") {
    Blocklist bl;
    std::string err;
    nlohmann::json j = nlohmann::json::parse(R"({"version":"1.0","snapshot_date":"2024-01-01","sources":["test"],"drivers":[],"certs":[]})");
    bl = Blocklist::LoadFromJson(j, err);
    REQUIRE(err.empty());

    DriverInfo di;
    di.baseAddress = (void*)0x1000;
    di.baseHex = "0x0000000000001000";
    di.kernelImageSize = 4096;
    di.kernelPath = "\\SystemRoot\\System32\\drivers\\test.sys";
    di.normalizedPath = "C:\\Windows\\System32\\drivers\\test.sys";
    di.fileName = "test.sys";

    Evidence e;
    e.check = "hash_blocklist";
    e.verdict = Verdict::Clean;
    e.confidence = Confidence::High;
    e.detail = "not in blocklist";
    e.provenance = "test v1.0";
    e.recommendation = "No action";

    auto report = risk::MakeReport(di, {e});
    std::vector<DriverReport> reports = {report};

    const char* tmp = "C:\\Users\\007\\drvscan\\build\\test_json_tmp.json";
    FILE* f = fopen(tmp, "wb");
    REQUIRE(f != nullptr);
    PrintJson(reports, &bl, f);
    fclose(f);

    // Re-parse and validate
    FILE* rf = fopen(tmp, "rb");
    REQUIRE(rf != nullptr);
    fseek(rf, 0, SEEK_END);
    long sz = ftell(rf);
    fseek(rf, 0, SEEK_SET);
    std::string content(sz, 0);
    fread(content.data(), 1, sz, rf);
    fclose(rf);
    DeleteFileA(tmp);

    auto parsed = nlohmann::json::parse(content);
    CHECK(parsed["driver_count"] == 1);
    CHECK(parsed["blocklist_version"] == "1.0");
    CHECK(parsed["drivers"][0]["fileName"] == "test.sys");
    CHECK(parsed["drivers"][0]["verdict"] == "clean");
    CHECK(parsed["drivers"][0]["checks"].size() == 1);
    CHECK(parsed["disclaimer"].get<std::string>().find("suspicious is not malicious") != std::string::npos);
}

TEST_CASE("Table output does not crash") {
    DriverInfo di;
    di.baseHex = "0x0000000000001000";
    di.fileName = "a.sys";
    di.kernelImageSize = 0;
    auto r = risk::MakeReport(di, {});
    std::vector<DriverReport> v = {r};
    // Should not crash; write to temp file
    const char* tmp = "C:\\Users\\007\\drvscan\\build\\test_table_tmp.txt";
    FILE* f = fopen(tmp, "wb");
    REQUIRE(f != nullptr);
    PrintTable(v, f);
    fclose(f);
    DeleteFileA(tmp);
}
