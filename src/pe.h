#pragma once
#include <string>
#include <cstdint>
#include <vector>

namespace drvscan {

struct PeInfo {
    uint32_t sizeOfImage = 0;
    bool is64 = false;
};
bool TryGetPeSizeOfImage(const std::wstring& path, PeInfo& out, std::string& err);
bool TryGetPeSizeOfImageFromBytes(const uint8_t* data, size_t len, PeInfo& out, std::string& err);

// v1.1 — PE structural analysis (on-disk file only, no kernel access)
enum class PeValidity {
    Valid,
    MalformedHeader,    // couldn't parse DOS/NT headers
    MalformedSections,  // section table inconsistent with header
    NotAPe,             // no MZ/PE signature
};

struct PeSectionInfo {
    std::string name;
    uint32_t    virtual_address = 0;
    uint32_t    virtual_size = 0;
    uint32_t    raw_offset = 0;
    uint32_t    raw_size = 0;
    uint32_t    characteristics = 0;
};

struct PeStructure {
    PeValidity              validity = PeValidity::MalformedHeader;
    uint32_t                size_of_image = 0;
    uint32_t                size_of_headers = 0;
    uint32_t                section_alignment = 0;
    uint32_t                file_alignment = 0;
    uint32_t                address_of_entry_point = 0;
    uint32_t                header_checksum = 0;
    uint32_t                computed_checksum = 0;
    uint32_t                timestamp = 0;
    uint16_t                coff_characteristics = 0; // IMAGE_FILE_HEADER.Characteristics — for FIX 4 DLL check
    std::vector<PeSectionInfo> sections;
    bool                    is64 = false;
    bool                    has_imports = false;
    bool                    has_exports = false;
    bool                    has_driver_entry = false; // heuristic: "DriverEntry" in import names or raw scan
};

PeStructure ParsePeStructure(const std::vector<uint8_t>& bytes);

// Utility for main.cpp: read entire file into buffer (single I/O for hash+checksum+PE)
bool ReadFileToBuffer(const std::wstring& path, std::vector<uint8_t>& out, std::string& err);

// C1–C7 — each returns 0..N Evidence-worthy findings; callers build Evidence from them.
// We expose pure check functions so tests can call them directly on PeStructure.

struct PeFinding {
    std::string check;  // C1..C7 name
    std::string detail;
};

// C1: section overlap (virtual + raw)
std::vector<PeFinding> CheckSectionOverlap(const PeStructure& pe);
// C2: section escapes SizeOfImage
std::vector<PeFinding> CheckSectionEscapesImage(const PeStructure& pe);
// C3: entry point sanity (needs has_driver_entry; caller may override with SigStatus)
std::vector<PeFinding> CheckEntryPoint(const PeStructure& pe);
// C4: alignment consistency
std::vector<PeFinding> CheckAlignment(const PeStructure& pe);
// C5: checksum field vs computed (computed must be filled by ParsePeStructure)
std::vector<PeFinding> CheckChecksum(const PeStructure& pe);
// C6: timestamp sanity
std::vector<PeFinding> CheckTimestamp(const PeStructure& pe);
// C7: section name sanity
std::vector<PeFinding> CheckSectionNames(const PeStructure& pe);

} // namespace drvscan
