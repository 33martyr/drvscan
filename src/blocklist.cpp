#include "blocklist.h"
#include "hash.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <windows.h>

namespace drvscan {

Blocklist Blocklist::Load(const std::wstring& jsonPath, std::string& err) {
    std::ifstream f(jsonPath);
    if (!f) {
        // Try wide path via _wfopen fallback
        FILE* wf = _wfopen(jsonPath.c_str(), L"rb");
        if (!wf) { err = "Cannot open blocklist file"; return Blocklist{}; }
        std::string content;
        char buf[4096];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), wf)) > 0) content.append(buf, n);
        fclose(wf);
        try {
            auto j = nlohmann::json::parse(content);
            return LoadFromJson(j, err);
        } catch (const std::exception& e) {
            err = std::string("JSON parse error: ") + e.what();
            return Blocklist{};
        }
    }
    try {
        nlohmann::json j;
        f >> j;
        return LoadFromJson(j, err);
    } catch (const std::exception& e) {
        err = std::string("JSON parse error: ") + e.what();
        return Blocklist{};
    }
}

Blocklist Blocklist::LoadFromJson(const nlohmann::json& j, std::string& err) {
    Blocklist bl;
    try {
        if (j.contains("version") && j["version"].is_string()) bl.version_ = j["version"].get<std::string>();
        if (j.contains("snapshot_date") && j["snapshot_date"].is_string()) bl.snapshotDate_ = j["snapshot_date"].get<std::string>();
        if (j.contains("schema_version") && j["schema_version"].is_string()) bl.schemaVersion_ = j["schema_version"].get<std::string>();
        else bl.schemaVersion_ = "0.2.0";
        if (j.contains("is_sample") && j["is_sample"].is_boolean()) bl.isSample_ = j["is_sample"].get<bool>();
        if (j.contains("sources") && j["sources"].is_array()) {
            for (auto& s : j["sources"]) if (s.is_string()) bl.sources_.push_back(s.get<std::string>());
        }
        if (j.contains("drivers") && j["drivers"].is_array()) {
            for (auto& e : j["drivers"]) {
                BlockEntry be;
                if (e.contains("sha256") && e["sha256"].is_string()) be.sha256 = ToLowerHex(e["sha256"].get<std::string>());
                if (e.contains("filename") && e["filename"].is_string()) be.fileName = e["filename"].get<std::string>();
                if (e.contains("category") && e["category"].is_string()) be.category = e["category"].get<std::string>();
                if (e.contains("source") && e["source"].is_string()) be.source = e["source"].get<std::string>();
                if (be.sha256.empty()) continue;
                bl.hashIndex_[be.sha256] = bl.hashes_.size();
                bl.hashes_.push_back(std::move(be));
            }
        }
        if (j.contains("certs") && j["certs"].is_array()) {
            for (auto& e : j["certs"]) {
                CertEntry ce;
                if (e.contains("thumbprint") && e["thumbprint"].is_string()) ce.thumbprint = ToLowerHex(e["thumbprint"].get<std::string>());
                if (e.contains("owner") && e["owner"].is_string()) ce.owner = e["owner"].get<std::string>();
                if (e.contains("source") && e["source"].is_string()) ce.source = e["source"].get<std::string>();
                if (ce.thumbprint.empty()) continue;
                bl.certIndex_[ce.thumbprint] = bl.certs_.size();
                bl.certs_.push_back(std::move(ce));
            }
        }
        err.clear();
    } catch (const std::exception& e) {
        err = std::string("blocklist load error: ") + e.what();
    }
    return bl;
}

bool Blocklist::IsHashBlocked(const std::string& s) const { return hashIndex_.find(ToLowerHex(s)) != hashIndex_.end(); }
bool Blocklist::IsCertBlocked(const std::string& s) const { return certIndex_.find(ToLowerHex(s)) != certIndex_.end(); }
const BlockEntry* Blocklist::FindHash(const std::string& s) const {
    auto it = hashIndex_.find(ToLowerHex(s));
    if (it == hashIndex_.end()) return nullptr;
    return &hashes_[it->second];
}
const CertEntry* Blocklist::FindCert(const std::string& s) const {
    auto it = certIndex_.find(ToLowerHex(s));
    if (it == certIndex_.end()) return nullptr;
    return &certs_[it->second];
}

} // namespace drvscan
