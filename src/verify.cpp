#include "verify.h"
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <mscat.h>
#include <sstream>
#include <iomanip>
#include <vector>

namespace drvscan {

SigStatus MapVerifyHr(HRESULT hr) {
    switch ((uint32_t)hr) {
        case 0: return SigStatus::Valid;
        case TRUST_E_NOSIGNATURE: return SigStatus::Unsigned;
        case TRUST_E_BAD_DIGEST: // 0x80096010 — same value as TRUST_E_SUBJECT_FORM_UNKNOWN but spec says Modified
            return SigStatus::Modified;
        case TRUST_E_COUNTER_SIGNER: return SigStatus::Modified;
        case CERT_E_REVOKED: return SigStatus::Revoked;
        case CERT_E_EXPIRED: return SigStatus::Expired;
        case TRUST_E_EXPLICIT_DISTRUST:
        case CERT_E_UNTRUSTEDROOT: return SigStatus::UntrustedRoot;
        case CRYPT_E_FILE_ERROR: return SigStatus::Unverifiable;
        default: break;
    }
    if (hr == CERT_E_CHAINING || hr == CERT_E_WRONG_USAGE) return SigStatus::UntrustedRoot;
    if (hr == 0x80096010) return SigStatus::Unsigned; // TRUST_E_SUBJECT_FORM_UNKNOWN
    return SigStatus::Unverifiable;
}

static std::string HrToHex(HRESULT hr) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setw(8) << std::setfill('0') << (uint32_t)hr;
    return oss.str();
}

// Microsoft roots pin set — loaded from data/microsoft_roots.json next to exe, with fallback to built-ins.
static std::vector<std::string> LoadMicrosoftRoots() {
    // Try exe-relative then CWD
    std::vector<std::wstring> candidates;
    {
        wchar_t exeBuf[MAX_PATH]{};
        GetModuleFileNameW(nullptr, exeBuf, MAX_PATH);
        std::wstring exeDir(exeBuf);
        size_t pos = exeDir.find_last_of(L"\\/");
        if (pos != std::wstring::npos) {
            candidates.push_back(exeDir.substr(0, pos + 1) + L"data\\microsoft_roots.json");
            candidates.push_back(exeDir.substr(0, pos + 1) + L"microsoft_roots.json");
        }
    }
    candidates.push_back(L"data\\microsoft_roots.json");
    candidates.push_back(L".\\data\\microsoft_roots.json");
    for (auto& p : candidates) {
        HANDLE h = CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (h == INVALID_HANDLE_VALUE) continue;
        DWORD sz = GetFileSize(h, nullptr);
        if (sz == INVALID_FILE_SIZE || sz > 65536) { CloseHandle(h); continue; }
        std::string body(sz, '\0');
        DWORD rd=0; ReadFile(h, body.data(), sz, &rd, nullptr); CloseHandle(h);
        body.resize(rd);
        try {
            // Minimal parse: look for "thumbprint":"<64hex>" without pulling nlohmann here
            std::vector<std::string> out;
            size_t pos2=0;
            while (true) {
                auto k = body.find("\"thumbprint\"", pos2);
                if (k==std::string::npos) break;
                auto colon = body.find(':', k);
                if (colon==std::string::npos) break;
                auto q1 = body.find('"', colon);
                if (q1==std::string::npos) break;
                auto q2 = body.find('"', q1+1);
                if (q2==std::string::npos) break;
                std::string tp = body.substr(q1+1, q2-q1-1);
                // normalize
                for(char& c: tp) c = (char)std::tolower((unsigned char)c);
                // accept 40 hex (SHA1) or 64 hex (SHA256) — we store SHA1 40
                if ((tp.size()==40 || tp.size()==64) && tp.find_first_not_of("0123456789abcdef") == std::string::npos) out.push_back(tp);
                pos2 = q2+1;
            }
            if (!out.empty()) return out;
        } catch(...) {}
    }
    return {};
}

static const std::vector<std::string>& MicrosoftRootsPinned() {
    static std::vector<std::string> roots = LoadMicrosoftRoots();
    if (roots.empty()) {
        // Built-in fallback (must match data/microsoft_roots.json). Update both together.
        roots = {
            "580a6f4cc4e4b669b9ebdc1b2b3e087b80d0678d",
            "a43489159a520f0d93d032ccaf37e7fe20a8b419",
            "566a209664f2b1b1e3f3211b47528767a7c9e435",
        };
    }
    return roots;
}

bool IsMicrosoftSignedWithRoots(const VerifyResult& vr, const std::vector<std::string>& pinned) {
    if (vr.certThumbprints.empty()) return false;
    for (auto& tp : vr.certThumbprints) {
        std::string low = tp;
        for(char& c: low) c=(char)std::tolower((unsigned char)c);
        for (auto& pin : pinned) {
            std::string pl = pin;
            for(char& c: pl) c=(char)std::tolower((unsigned char)c);
            if (low == pl) return true;
        }
    }
    return false;
}

bool IsMicrosoftSigned(const VerifyResult& vr) {
    return IsMicrosoftSignedWithRoots(vr, MicrosoftRootsPinned());
}

static HRESULT VerifyWithState(const std::wstring& filePath, DWORD stateAction, HRESULT* outHr) {
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = filePath.c_str();
    WINTRUST_DATA wd{};
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE; // offline/no network; avoid false unverifiable on air-gapped
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fileInfo;
    wd.dwStateAction = stateAction;
    wd.dwProvFlags = 0;
    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    HRESULT hr = WinVerifyTrust(nullptr, &policy, &wd);
    if (outHr) *outHr = hr;
    if (stateAction == WTD_STATEACTION_VERIFY) {
        wd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &policy, &wd);
    }
    return hr;
}

static bool IsCatalogSigned(const std::wstring& filePath) {
    // Dynamically load CryptCAT* to avoid mscat.lib link requirement (not in this SDK)
    HMODULE hWintrust = GetModuleHandleW(L"wintrust.dll");
    if (!hWintrust) hWintrust = LoadLibraryW(L"wintrust.dll");
    if (!hWintrust) return false;
    using PFN_Acquire = BOOL(WINAPI*)(HANDLE*, const GUID*, const WCHAR*, void*, DWORD);
    using PFN_Hash = BOOL(WINAPI*)(HANDLE, HANDLE, DWORD*, BYTE*, DWORD);
    using PFN_Enum = HANDLE(WINAPI*)(HANDLE, BYTE*, DWORD, DWORD, HANDLE*);
    using PFN_ReleaseCat = BOOL(WINAPI*)(HANDLE, HANDLE, DWORD);
    using PFN_ReleaseCtx = BOOL(WINAPI*)(HANDLE, DWORD);
    auto pAcquire = (PFN_Acquire)GetProcAddress(hWintrust, "CryptCATAdminAcquireContext2");
    auto pHash = (PFN_Hash)GetProcAddress(hWintrust, "CryptCATAdminCalcHashFromFileHandle2");
    auto pEnum = (PFN_Enum)GetProcAddress(hWintrust, "CryptCATAdminEnumCatalogFromHash");
    auto pRelCat = (PFN_ReleaseCat)GetProcAddress(hWintrust, "CryptCATAdminReleaseCatalogContext");
    auto pRelCtx = (PFN_ReleaseCtx)GetProcAddress(hWintrust, "CryptCATAdminReleaseContext");
    if (!pAcquire || !pHash || !pEnum || !pRelCat || !pRelCtx) return false;
    HANDLE hCatAdmin = nullptr;
    if (!pAcquire(&hCatAdmin, nullptr, nullptr, nullptr, 0)) return false;
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) { pRelCtx(hCatAdmin, 0); return false; }
    DWORD hashLen = 0;
    pHash(hCatAdmin, hFile, &hashLen, nullptr, 0);
    std::vector<BYTE> hash(hashLen);
    bool hasHash = pHash(hCatAdmin, hFile, &hashLen, hash.data(), 0);
    CloseHandle(hFile);
    if (!hasHash) { pRelCtx(hCatAdmin, 0); return false; }
    HANDLE hCatInfo = pEnum(hCatAdmin, hash.data(), hashLen, 0, nullptr);
    bool found = (hCatInfo != nullptr);
    if (hCatInfo) pRelCat(hCatAdmin, hCatInfo, 0);
    pRelCtx(hCatAdmin, 0);
    return found;
}

VerifyResult VerifyEmbeddedSignature(const std::wstring& filePath) {
    VerifyResult res;

    DWORD attr = GetFileAttributesW(filePath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) {
        DWORD le = GetLastError();
        res.status = SigStatus::Unverifiable;
        res.message = "File not found or inaccessible (GetLastError=" + std::to_string(le) + ")";
        res.hresult = HRESULT_FROM_WIN32(le);
        return res;
    }

    HRESULT hr = 0;
    VerifyWithState(filePath, WTD_STATEACTION_VERIFY, &hr);
    res.hresult = hr;

    // If TRUST_E_NOSIGNATURE, check catalog signing — many inbox drivers are catalog-signed, not embedded
    bool catalogSigned = false;
    if ((uint32_t)hr == TRUST_E_NOSIGNATURE) {
        catalogSigned = IsCatalogSigned(filePath);
        if (catalogSigned) {
            res.status = SigStatus::Valid;
            res.message = "Signature valid via catalog (catalog-signed; no embedded signature)";
            res.hresult = 0;
            hr = 0;
        }
    }

    if ((uint32_t)hr != TRUST_E_NOSIGNATURE || catalogSigned) {
        // hr already handled for catalog case
    }
    if (res.status != SigStatus::Valid || hr != 0) {
        res.status = MapVerifyHr(hr);
        switch (res.status) {
            case SigStatus::Valid: res.message = "Signature valid (WinVerifyTrust succeeded)"; break;
            case SigStatus::Unsigned: res.message = "No embedded or catalog signature (TRUST_E_NOSIGNATURE " + HrToHex(hr) + ")"; break;
            case SigStatus::Modified: res.message = "File modified after signing / bad digest (hr=" + HrToHex(hr) + ")"; break;
            case SigStatus::Revoked: res.message = "Certificate revoked (CERT_E_REVOKED " + HrToHex(hr) + ")"; break;
            case SigStatus::Expired: res.message = "Certificate expired (CERT_E_EXPIRED " + HrToHex(hr) + ")"; break;
            case SigStatus::UntrustedRoot: res.message = "Untrusted root / explicit distrust / chaining error (hr=" + HrToHex(hr) + ")"; break;
            case SigStatus::Unverifiable: default: res.message = "Verification failed (hr=" + HrToHex(hr) + ")"; break;
        }
        // Refine Unverifiable vs chaining already handled by MapVerifyHr; keep specific messages for common cases
        if (hr == TRUST_E_EXPLICIT_DISTRUST || hr == CERT_E_UNTRUSTEDROOT) res.message = "Untrusted root / explicit distrust (hr=" + HrToHex(hr) + ")";
        else if (hr == CRYPT_E_FILE_ERROR) res.message = "File error during verification (CRYPT_E_FILE_ERROR " + HrToHex(hr) + ")";
        else if (hr == CERT_E_CHAINING || hr == CERT_E_WRONG_USAGE) res.message = "Certificate chaining/usage error (hr=" + HrToHex(hr) + ")";
        else if (hr == 0x80096010) res.message = "Subject form unknown — likely unsigned (hr=" + HrToHex(hr) + ")";
    }

    // Collect cert thumbprints for blocklist correlation (even on failure, if a cert chain exists)
    // Use CryptQueryObject to extract cert chain from the file
    HCERTSTORE hStore = nullptr;
    HCRYPTMSG hMsg = nullptr;
    DWORD enc = 0, contentType = 0, formatType = 0;
    if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, filePath.c_str(),
                         CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                         CERT_QUERY_FORMAT_FLAG_BINARY, 0,
                         &enc, &contentType, &formatType, &hStore, &hMsg, nullptr)) {
        // Enumerate certs in store and collect SHA-1 thumbprints
        PCCERT_CONTEXT ctx = nullptr;
        while ((ctx = CertEnumCertificatesInStore(hStore, ctx)) != nullptr) {
            DWORD hashLen = 20;
            BYTE hash[20];
            if (CertGetCertificateContextProperty(ctx, CERT_HASH_PROP_ID, hash, &hashLen) && hashLen == 20) {
                std::ostringstream oss;
                oss << std::hex << std::setfill('0');
                for (DWORD i = 0; i < hashLen; ++i) oss << std::setw(2) << (int)hash[i];
                res.certThumbprints.push_back(oss.str());
            }
            // Capture leaf subject for display (first cert)
            if (res.signerSubject.empty()) {
                char subj[512] = {};
                if (CertGetNameStringA(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, subj, sizeof(subj)) > 1) {
                    res.signerSubject = subj;
                }
            }
        }
        if (hStore) CertCloseStore(hStore, 0);
        if (hMsg) CryptMsgClose(hMsg);
    }

    return res;
}

} // namespace drvscan
