#include <doctest/doctest.h>
#include "handles.h"
#include "sigcontext.h"
#include "objscan.h"
using namespace drvscan;
TEST_CASE("ResolveProcessArgument numeric"){
    std::string err; auto pids=ResolveProcessArgument(std::to_string(GetCurrentProcessId()), err);
    CHECK(!pids.empty());
}
TEST_CASE("ResolveProcessArgument name case-insensitive"){
    // current exe name
    char buf[MAX_PATH]{}; GetModuleFileNameA(nullptr, buf, MAX_PATH);
    std::string base=std::string(buf); size_t pos=base.find_last_of("\\/"); if(pos!=std::string::npos) base=base.substr(pos+1);
    std::string err; auto pids=ResolveProcessArgument(base, err);
    CHECK(!pids.empty());
    // without .exe
    std::string noExt=base; if(noExt.size()>4 && noExt.substr(noExt.size()-4)==".exe") noExt=noExt.substr(0,noExt.size()-4);
    err.clear(); auto pids2=ResolveProcessArgument(noExt, err);
    CHECK(!pids2.empty());
    // lower case
    std::string low=base; for(char& c: low) c=(char)std::tolower((unsigned char)c);
    err.clear(); auto pids3=ResolveProcessArgument(low, err);
    CHECK(!pids3.empty());
}
TEST_CASE("ResolveProcessArgument typo suggestion"){
    std::string err; auto pids=ResolveProcessArgument("chrom.exe", err);
    // Empty result + error contains suggestion if close, but at least error non-empty
    CHECK(pids.empty());
    CHECK(!err.empty());
}
TEST_CASE("ResolveProcessArgument nonexistent"){
    std::string err; auto pids=ResolveProcessArgument("nonexistent_xyz_999.exe", err);
    CHECK(pids.empty());
    CHECK(!err.empty());
}
TEST_CASE("ResolveProcessArgument full path rejected"){
    std::string err; auto pids=ResolveProcessArgument("C:\\Windows\\System32\\notepad.exe", err);
    CHECK(pids.empty());
    CHECK(err.find("full paths not supported")!=std::string::npos);
}
TEST_CASE("Levenshtein distance"){
    CHECK(LevenshteinDistance("chrom.exe","chrome.exe")==1);
    CHECK(LevenshteinDistance("chrome.exe","chrome.exe")==0);
}

TEST_CASE("SigContext header is pending for stubbed surfaces"){
    SigContext c; c.hvciOn=false; c.dseOn=true;
    std::string h = SigContextHeader(c);
    CHECK(h.find("pending v0.4.0")!=std::string::npos);
    // Must not claim checked states for stubbed surfaces
    CHECK(h.find("Amcache: pending v0.4.0")!=std::string::npos);
    CHECK(h.find("Prefetch: pending v0.4.0")!=std::string::npos);
    // Must NOT contain per-surface checked wording
    if(h.find("Amcache: accessible")!=std::string::npos) FAIL("Amcache must not claim accessible when stubbed");
    if(h.find("Amcache: not accessible")!=std::string::npos) FAIL("Amcache must not claim not accessible when stubbed");
    if(h.find("Prefetch: enabled")!=std::string::npos) FAIL("Prefetch must not claim enabled when stubbed");
    if(h.find("Prefetch: disabled")!=std::string::npos) FAIL("Prefetch must not claim disabled when stubbed");
}

TEST_CASE("Section2 honest when Driver dir access denied"){
    ObjScanResult obj;
    obj.error = "Driver dir: NtOpenDirectoryObject 0xC0000022 (run as Administrator for \\Driver\\)";
    obj.deviceObjects = 294;
    obj.driverObjects = 0;
    std::string s2 = BuildSection2Text(obj);
    CHECK(s2.find("NOT SCANNED")!=std::string::npos);
    CHECK(s2.find("access denied")!=std::string::npos);
    CHECK(s2.find("\\Device\\ enumeration:")!=std::string::npos);
    CHECK(s2.find("This is not proof nothing happened")!=std::string::npos);
    CHECK(s2.find("No orphaned driver objects")==std::string::npos);
}

TEST_CASE("Section2 normal when Driver dir accessible"){
    ObjScanResult obj;
    obj.error.clear();
    obj.deviceObjects = 10;
    std::string s2 = BuildSection2Text(obj);
    CHECK(s2.find("NOT SCANNED")==std::string::npos);
    CHECK(s2.find("No orphaned driver objects")!=std::string::npos);
}

TEST_CASE("Section4 honest stubbed-surface text"){
    std::string s4 = BuildSection4Text();
    // Must name what this build actually ships and what is stubbed
    CHECK(s4.find("object manager cross-check")!=std::string::npos);
    CHECK(s4.find("Not yet wired")!=std::string::npos);
    CHECK(s4.find("global handle table")!=std::string::npos);
    CHECK(s4.find("Code Integrity")!=std::string::npos);
    CHECK(s4.find("Amcache")!=std::string::npos);
    CHECK(s4.find("prefetch")!=std::string::npos);
    CHECK(s4.find("Sysmon")!=std::string::npos);
    CHECK(s4.find("Defender")!=std::string::npos);
    // Final honesty line
    CHECK(s4.find("object-manager-visible candidates")!=std::string::npos);
}

TEST_CASE("IsDriverDirAccessDenied detection"){
    CHECK(IsDriverDirAccessDenied("NtOpenDirectoryObject 0xC0000022") == true);
    CHECK(IsDriverDirAccessDenied("0xc0000022 access denied") == true);
    CHECK(IsDriverDirAccessDenied("") == false);
    CHECK(IsDriverDirAccessDenied("some other error") == false);
}
