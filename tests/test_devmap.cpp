#include <doctest/doctest.h>
#include "devmap.h"
using namespace drvscan;
TEST_CASE("devmap exact Ntfs"){
    CHECK(ResolveDeviceToDriver("\\Device\\Ntfs")=="ntfs.sys");
}
TEST_CASE("devmap Nsi"){
    CHECK(ResolveDeviceToDriver("\\Device\\Nsi")=="nsiproxy.sys");
}
TEST_CASE("devmap wildcard HarddiskVolume3"){
    CHECK(ResolveDeviceToDriver("\\Device\\HarddiskVolume3")=="disk.sys");
}
TEST_CASE("devmap wildcard ShadowCopy4"){
    CHECK(ResolveDeviceToDriver("\\Device\\HarddiskVolumeShadowCopy4")=="volsnap.sys");
}
TEST_CASE("devmap unmapped Foo"){
    CHECK(ResolveDeviceToDriver("\\Device\\Foo")=="");
}
TEST_CASE("devmap empty"){
    CHECK(ResolveDeviceToDriver("")=="");
}
TEST_CASE("devmap FileSystem prefix"){
    CHECK(ResolveDeviceToDriver("\\FileSystem\\Npfs")=="npfs.sys");
}
