#include <doctest/doctest.h>
#include "pe.h"
#include <windows.h>
#include <vector>

using namespace drvscan;

static std::vector<uint8_t> MakeMinimalPe(bool is64, uint32_t sizeOfImage) {
    // Build minimal DOS + NT headers sufficient for TryGetPeSizeOfImageFromBytes
    std::vector<uint8_t> buf(4096, 0);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x80;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(buf.data() + dos->e_lfanew);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = is64 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386;
    nt->FileHeader.NumberOfSections = 1;
    if (is64) {
        auto* opt = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(&nt->OptionalHeader);
        opt->Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        opt->SizeOfImage = sizeOfImage;
        opt->SizeOfHeaders = 0x400;
    } else {
        auto* opt = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(&nt->OptionalHeader);
        opt->Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
        opt->SizeOfImage = sizeOfImage;
        opt->SizeOfHeaders = 0x400;
    }
    return buf;
}

TEST_CASE("PE SizeOfImage x64") {
    auto buf = MakeMinimalPe(true, 0x12345);
    PeInfo pi{};
    std::string err;
    CHECK(TryGetPeSizeOfImageFromBytes(buf.data(), buf.size(), pi, err));
    CHECK(pi.sizeOfImage == 0x12345);
    CHECK(pi.is64 == true);
}

TEST_CASE("PE SizeOfImage x86") {
    auto buf = MakeMinimalPe(false, 0xABCD);
    PeInfo pi{};
    std::string err;
    CHECK(TryGetPeSizeOfImageFromBytes(buf.data(), buf.size(), pi, err));
    CHECK(pi.sizeOfImage == 0xABCD);
    CHECK(pi.is64 == false);
}

TEST_CASE("PE bad magic") {
    auto buf = MakeMinimalPe(true, 0x1000);
    buf[0] = 'X';
    PeInfo pi{};
    std::string err;
    CHECK_FALSE(TryGetPeSizeOfImageFromBytes(buf.data(), buf.size(), pi, err));
}

TEST_CASE("PE file round-trip") {
    auto buf = MakeMinimalPe(true, 0x7777);
    const char* path = "C:\\Users\\007\\drvscan\\build\\test_pe_tmp.sys";
    {
        FILE* f = fopen(path, "wb");
        REQUIRE(f != nullptr);
        fwrite(buf.data(), 1, buf.size(), f);
        fclose(f);
    }
    std::wstring wpath;
    {
        int n = MultiByteToWideChar(CP_UTF8, 0, path, -1, nullptr, 0);
        wpath.assign(n-1, 0);
        MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath.data(), n);
    }
    PeInfo pi{};
    std::string err;
    CHECK(TryGetPeSizeOfImage(wpath, pi, err));
    CHECK(pi.sizeOfImage == 0x7777);
    DeleteFileA(path);
}
