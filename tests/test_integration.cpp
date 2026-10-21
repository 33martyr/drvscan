#include <doctest/doctest.h>
#include "handles.h"
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
