#include <doctest/doctest.h>
#include "pathcheck.h"

using namespace drvscan;

TEST_CASE("Path regular locations") {
    CHECK(CheckDriverPath("C:\\Windows\\System32\\drivers\\ntoskrnl.exe").verdict == PathVerdict::Regular);
    CHECK(CheckDriverPath("C:\\Windows\\System32\\DriverStore\\FileRepository\\foo\\bar.sys").verdict == PathVerdict::Regular);
    CHECK(CheckDriverPath("C:\\Windows\\System32\\ntoskrnl.exe").verdict == PathVerdict::Regular);
}

TEST_CASE("Path warn Program Files") {
    auto r = CheckDriverPath("C:\\Program Files\\Vendor\\driver.sys");
    CHECK(r.verdict == PathVerdict::Warn);
    CHECK(r.reason.find("Program Files") != std::string::npos);
}

TEST_CASE("Path suspicious contextual") {
    CHECK(CheckDriverPath("C:\\Users\\alice\\AppData\\Local\\Temp\\evil.sys").verdict == PathVerdict::Suspicious);
    CHECK(CheckDriverPath("C:\\Windows\\Temp\\drv.sys").verdict == PathVerdict::Suspicious);
    CHECK(CheckDriverPath("C:\\Users\\bob\\Downloads\\capcom.sys").verdict == PathVerdict::Suspicious);
    CHECK(CheckDriverPath("\\\\server\\share\\drv.sys").verdict == PathVerdict::Suspicious);
    CHECK(CheckDriverPath("\\Device\\HarddiskVolume1\\drv.sys").verdict == PathVerdict::Suspicious);
}

TEST_CASE("Path suspicious message is contextual") {
    auto r = CheckDriverPath("C:\\Users\\x\\AppData\\Local\\Temp\\a.sys");
    CHECK(r.reason.find("contextual") != std::string::npos);
    CHECK(r.reason.find("not proof") != std::string::npos);
}

TEST_CASE("Empty path suspicious") {
    CHECK(CheckDriverPath("").verdict == PathVerdict::Suspicious);
}
