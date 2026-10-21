#include <doctest/doctest.h>
#include "handles.h"
using namespace drvscan;
TEST_CASE("empty handle array -> empty"){
    std::vector<DeviceHandle> in;
    CHECK(FilterDeviceHandlesTest(in).empty());
}
TEST_CASE("one handle to Ntfs"){
    DeviceHandle h{}; h.device_path="\\Device\\Ntfs"; h.access_mask=0x100000;
    auto out=FilterDeviceHandlesTest({h});
    REQUIRE(out.size()==1); CHECK(out[0].device_path=="\\Device\\Ntfs");
}
TEST_CASE("FileSystem Npfs kept"){
    DeviceHandle h{}; h.device_path="\\FileSystem\\Npfs";
    auto out=FilterDeviceHandlesTest({h});
    REQUIRE(out.size()==1);
}
TEST_CASE("NamedPipe filtered"){
    DeviceHandle h{}; h.device_path="\\Device\\NamedPipe\\foo";
    CHECK(FilterDeviceHandlesTest({h}).empty());
}
TEST_CASE("HarddiskVolume collapse single"){
    DeviceHandle h{}; h.device_path="\\Device\\HarddiskVolume3";
    auto out=FilterDeviceHandlesTest({h});
    REQUIRE(out.size()==1); CHECK(out[0].device_path=="\\Device\\HarddiskVolume*");
}
TEST_CASE("HarddiskVolume five -> one"){
    std::vector<DeviceHandle> in;
    for(auto s: {"\\Device\\HarddiskVolume3","\\Device\\HarddiskVolume4","\\Device\\HarddiskVolume5","\\Device\\HarddiskVolume6","\\Device\\HarddiskVolume7"}){ DeviceHandle h{}; h.device_path=s; in.push_back(h); }
    auto out=FilterDeviceHandlesTest(in);
    CHECK(out.size()==1);
}
TEST_CASE("ShadowCopy collapse"){
    std::vector<DeviceHandle> in;
    for(auto s: {"\\Device\\HarddiskVolumeShadowCopy4","\\Device\\HarddiskVolumeShadowCopy5"}){ DeviceHandle h{}; h.device_path=s; in.push_back(h); }
    auto out=FilterDeviceHandlesTest(in);
    CHECK(out.size()==1);
    CHECK(out[0].device_path=="\\Device\\HarddiskVolumeShadowCopy*");
}
TEST_CASE("dedupe by path"){
    DeviceHandle a{}; a.device_path="\\Device\\Tcp"; a.access_mask=1;
    DeviceHandle b{}; b.device_path="\\Device\\Tcp"; b.access_mask=2;
    auto out=FilterDeviceHandlesTest({a,b});
    REQUIRE(out.size()==1); CHECK(out[0].access_mask==1);
}
