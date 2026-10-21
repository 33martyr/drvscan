#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <nlohmann/json.hpp>

namespace drvscan {

struct BlockEntry {
    std::string sha256;   // lowercase hex
    std::string fileName;
    std::string category; // vulnerable / malicious
    std::string source;   // provenance
};
struct CertEntry {
    std::string thumbprint; // lowercase hex SHA-1
    std::string owner;
    std::string source;
};

class Blocklist {
public:
    static Blocklist Load(const std::wstring& jsonPath, std::string& err);
    static Blocklist LoadFromJson(const nlohmann::json& j, std::string& err);

    bool IsHashBlocked(const std::string& sha256Lower) const;
    bool IsCertBlocked(const std::string& thumbLower) const;
    const BlockEntry* FindHash(const std::string& sha256Lower) const;
    const CertEntry*  FindCert(const std::string& thumbLower) const;

    const std::vector<BlockEntry>& hashes() const { return hashes_; }
    const std::vector<CertEntry>& certs() const { return certs_; }
    size_t hashCount() const { return hashes_.size(); }
    size_t certCount() const { return certs_.size(); }
    const std::string& version() const { return version_; }
    const std::string& snapshotDate() const { return snapshotDate_; }
    const std::string& schemaVersion() const { return schemaVersion_; }
    bool isSample() const { return isSample_; }
    const std::vector<std::string>& sources() const { return sources_; }
    bool empty() const { return hashes_.empty() && certs_.empty(); }

private:
    std::string version_;          // snapshot version e.g. 2026.10.20
    std::string snapshotDate_;     // alias for snapshot_date
    std::string schemaVersion_;    // blocklist schema version e.g. 0.2.0
    bool isSample_ = false;        // true => bundled sample, not full coverage
    std::vector<std::string> sources_;
    std::vector<BlockEntry> hashes_;
    std::vector<CertEntry> certs_;
    std::unordered_map<std::string, size_t> hashIndex_;
    std::unordered_map<std::string, size_t> certIndex_;
};

} // namespace drvscan
