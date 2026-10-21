#include <windows.h>
#include <doctest/doctest.h>
#include "hash.h"
#include <string>

using namespace drvscan;

TEST_CASE("Sha256Bytes known vectors") {
    // Empty
    CHECK(Sha256Bytes(nullptr, 0) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    // "abc"
    const uint8_t abc[] = {'a','b','c'};
    CHECK(Sha256Bytes(abc, 3) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    // "hello"
    const uint8_t hello[] = {'h','e','l','l','o'};
    CHECK(Sha256Bytes(hello, 5) == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
}

TEST_CASE("Sha256File round-trip via bytes") {
    // Create temp file and hash
    const char* tmp = "C:\\Users\\007\\drvscan\\build\\test_hash_tmp.bin";
    const uint8_t data[] = {'d','r','v','s','c','a','n'};
    {
        FILE* f = fopen(tmp, "wb");
        REQUIRE(f != nullptr);
        fwrite(data, 1, sizeof(data), f);
        fclose(f);
    }
    std::string err;
    std::wstring wtmp;
    {
        int n = MultiByteToWideChar(CP_UTF8, 0, tmp, -1, nullptr, 0);
        wtmp.assign(n-1, 0);
        MultiByteToWideChar(CP_UTF8, 0, tmp, -1, wtmp.data(), n);
    }
    std::string hex = Sha256File(wtmp, err);
    CHECK(err.empty());
    CHECK(hex == Sha256Bytes(data, sizeof(data)));
    DeleteFileA(tmp);
}

TEST_CASE("ToLowerHex") {
    CHECK(ToLowerHex("ABCDEF0123") == "abcdef0123");
    CHECK(ToLowerHex("aBcDeF") == "abcdef");
}
