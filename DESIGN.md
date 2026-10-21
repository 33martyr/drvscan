# drvscan — Design Doc (rev 2 — evidence-backed)

## 0. Thesis

A valid signature does **not** mean safe. A legitimately signed driver can be vulnerable or abused (BYOVD). `drvscan` becomes useful only when it correlates multiple *independent* signals and for every flag explains: what fired, why it matters, how confident we are, and what to do next — with provenance.

A driver with a valid Authenticode chain but a SHA-256 that matches the lolDrivers vulnerable set is **suspicious, not clean**. A driver in `Temp` is **contextual risk, not automatic malware**. The risk engine must encode that judgment.

## 1. Scope push-back

### Five checks in 4 weeks of evenings?

All five are user-mode and <200 LOC each if scoped tightly. If forced to three for an MVP that still catches BYOVD, ship:

1. **Authenticode (WinVerifyTrust)** — invalid / unsigned / unverifiable taxonomy.
2. **SHA-256 vs bundled lolDrivers snapshot** (versioned, attributed).
3. **Path regularity** as contextual indicator.

Defer in order: (4) cert-thumbprint reputation, (5) ImageSize comparison. Both are valuable but are refinements; the first three already make the tool hireable.

**Decision: build all five.** They share the same I/O (read the on-disk file once) and ship incrementally so you can stop after (c).

### What is (and isn't) implementable from user-mode

| Check | User-mode? | How |
|---|---|---|
| Loaded drivers | Yes | Primary: documented `EnumDeviceDrivers` + `GetDeviceDriverBaseNameW`/`GetDeviceDriverFileNameW` (`psapi`). Supplement: `NtQuerySystemInformation(SystemModuleInformation)` for `ImageSize` + full NT path + base. Hybrid gives documented API compliance plus the size/path data `psapi` alone doesn't provide. |
| Authenticode | Yes | `wintrust!WinVerifyTrust` over the on-disk file. Distinguish `Unsigned` / `Modified` / `Revoked` / `Expired` / `UntrustedRoot` / `Unverifiable` (file missing, access denied). Valid ≠ safe — recorded as one signal only. |
| Hash blocklist | Yes | `bcrypt!BCrypt*` SHA-256 over the on-disk file vs bundled JSON (SHA-256 + source). No kernel read. |
| Cert reputation | Yes | `CryptQueryObject` + `CertGetCertificateChain` + `CERT_HASH_PROP_ID` SHA-1 thumbprints vs bundled list. Thumbprint hit is a *signal, not proof of compromise* — an explicit confidence downgrade. |
| Path regularity | Yes | Pure string policy on the normalized path. Flag is contextual risk, not malware verdict. |
| Image size mismatch | Yes, with caveat | Compare trustworthy on-disk `OptionalHeader.SizeOfImage` vs kernel-reported `ImageSize` from `SYSTEM_MODULE_INFORMATION`. A mismatch is *unexplained divergence*, not proof of manual mapping or file replacement — both have alternative explanations (updates, patched file). No live kernel memory read (would require a driver — out of scope as a separate advanced feature). |

No live kernel memory reading is attempted. Signature verification does **not** establish that the on-disk file is identical to the in-memory image — that would be a separate `in-memory tampering` feature.

### lolDrivers / blocklist — legal + attributable

Ship only SHA-256 strings + driver names already published as hashes; do not redistribute `DriverSiPolicy.p7b`. Every entry carries `source` (e.g. `loldrivers.io`, `microsoft:DriverSiPolicy`) and `version` / `snapshot_date` at the file header for attribution. Empty blocklist is valid — scanner warns `blocklist empty — run --update-blocklist`. Also document the Windows nuance: enumeration returns image base + size, but the returned path, the on-disk file, and the in-memory image are **not interchangeable sources of truth**.

## 2. Architecture

```
Driver Enumerator (psapi + ntdll)
        |
        v
Evidence Collectors (pure functions, no verdict)
  File metadata · SHA-256 · Authenticode · Cert chain · Path · PE Size
        |
        v
Risk Assessment Engine (versioned rules, provenance, confidence)
        |
        +---> CLI table (human) 
        +---> JSON report (machine)
```

Collectors return `Evidence` structs with provenance; the engine maps `Evidence[] -> Verdict` with confidence and alternative explanations. This separation lets tests exercise detection logic against synthetic evidence without loading drivers.

Stack: **C++20**, MSVC, CMake, Windows SDK (`ntdll`, `bcrypt`, `wintrust`, `crypt32`, `shlwapi`, `psapi`, `winhttp`), `nlohmann/json` (header-only, vendored), `doctest` (header-only, vendored). Binary self-contained. Targets Windows 10 19045 and 11.

## 3. File tree — one paragraph + public interface per file

```
drvscan/
  CMakeLists.txt              C++20, MSVC, SDK libs, ctest
  README.md                   usage, exit codes, demo, loud disclaimer
  LIMITATIONS.md              explicit non-claims
  DESIGN.md                   this file
  data/blocklist.json         versioned snapshot {version,snapshot_date,sources,drivers,certs}
  vendor/nlohmann/json.hpp
  vendor/doctest/doctest.h
  src/
    types.h                   Verdict, Confidence, Evidence, DriverInfo, DriverReport + helpers
    enum.h/.cpp               Hybrid enumeration (EnumDeviceDrivers primary + NtQuery supplement)
    hash.h/.cpp               BCrypt SHA-256 (file + bytes)
    blocklist.h/.cpp          versioned, attributable blocklist loader + O(1) lookup
    verify.h/.cpp             WinVerifyTrust taxonomy + cert chain thumbprints
    pathcheck.h/.cpp          contextual path policy (Regular/Warn/Suspicious + reason)
    pe.h/.cpp                 on-disk PE SizeOfImage parser
    risk.h/.cpp               Risk Assessment Engine (Evidence[] -> Verdict + confidence + next step)
    output.h/.cpp             table + JSON emitters (evidence-backed, provenance included)
    update.h/.cpp             --update-blocklist fetcher (WinHTTP, atomic write)
    main.cpp                  CLI, orchestration, exit codes 0/1/2
  tests/
    test_hash.cpp             known-vector SHA-256
    test_pe.cpp               synthetic PE SizeOfImage (x86 + x64)
    test_path.cpp             path matrix (regular / warn / suspicious)
    test_json.cpp             report JSON round-trip + snapshot schema
    test_blocklist.cpp        blocklist load + lookup
    test_risk.cpp             risk engine: valid-sig + vulnerable hash => suspicious, etc.
    fixtures/                 tiny synthetic PEs generated by tests
```

### `src/types.h`
Vocabulary. `enum class Verdict {Clean,Warn,Suspicious}`, `enum class SigStatus {Valid,Unsigned,Modified,Revoked,Expired,UntrustedRoot,Unverifiable}`, `enum class Confidence {High,Medium,Low}`, `struct DriverInfo {void* base; uint32_t kernelImageSize; std::string kernelPath; std::string normalizedPath; std::string fileName;}`, `struct Evidence {std::string check; Verdict verdict; Confidence confidence; std::string detail; std::string provenance; std::string recommendation;}`, `struct DriverReport {DriverInfo driver; std::vector<Evidence> evidence; Verdict overall; Confidence overallConfidence; std::string summary;}`, helpers `ToString(Verdict)`, `ToString(Confidence)`, `Max(Verdict,Verdict)`. No logic.

### `src/enum.h` / `enum.cpp`
Public: `std::vector<DriverInfo> EnumerateDrivers(std::string& err);` `std::string NormalizeNtPath(const std::string& ntPath);` Strategy: call `EnumDeviceDrivers` for base addresses; for each base call `GetDeviceDriverFileNameW` for a path; then call `NtQuerySystemInformation(SystemModuleInformation)` to enrich with `ImageSize` and canonical `FullPathName` by matching `ImageBase` (O(n*m) with tiny n). Falls back to `psapi`-only if `ntdll` query fails. Loads `NtQuerySystemInformation` dynamically. `NormalizeNtPath` expands `\SystemRoot\` → `%SystemRoot%`, handles `\??\`, `\\?\`, lowercases drive.

### `src/hash.h` / `hash.cpp`
Public: `std::string Sha256File(const std::wstring& path, std::string& err);` `std::string Sha256Bytes(const uint8_t* data, size_t len);` CNG `BCrypt*` SHA-256, 1 MiB chunked reads. Lowercase hex.

### `src/blocklist.h` / `blocklist.cpp`
Versioned + attributable. File schema: `{ "version":"2024.10.20", "snapshot_date":"2024-10-20", "sources":["loldrivers.io","microsoft:DriverSiPolicy"], "drivers":[{"sha256":"…","filename":"capcom.sys","category":"vulnerable","source":"loldrivers.io"}], "certs":[{"thumbprint":"…","owner":"CrossCert 2021","source":"microsoft:CertificateThumbprint"}] }`. Public: `struct BlockEntry {string sha256; string fileName; string category; string source;}; struct CertEntry {string thumbprint; string owner; string source;}; class Blocklist { static Blocklist Load(const std::wstring& p, string& e); static Blocklist LoadFromJson(const nlohmann::json& j, string& e); bool IsHashBlocked(string) const; bool IsCertBlocked(string) const; const BlockEntry* FindHash(string) const; const CertEntry* FindCert(string) const; string version() const; string snapshotDate() const; }`

### `src/verify.h` / `verify.cpp`
Public: `struct VerifyResult {SigStatus status; std::string message; std::vector<std::string> certThumbprints; std::string signerSubject; HRESULT hresult;}; VerifyResult VerifyEmbeddedSignature(const std::wstring& filePath);` `WinVerifyTrust(WTD_CHOICE_FILE)` → map `HRESULT` to `SigStatus` taxonomy (explicit `Unverifiable` for `CRYPT_E_FILE_ERROR` / missing file). On non-Unsigned files, `CryptQueryObject` + `CertGetCertificateChain` to collect leaf-to-root SHA-1 thumbprints.

### `src/pathcheck.h` / `pathcheck.cpp`
Contextual risk. Public: `struct PathResult {PathVerdict verdict; std::string reason; std::string recommendation;}; PathResult CheckDriverPath(const std::string& normalizedPath);` Regular: `System32\drivers\`, `System32\DriverStore\`, `System32\` (allow-list). Warn: `Program Files*` vendor path (legit but non-canonical). Suspicious (contextual): `\AppData\`, `\Temp\`, `\TMP\`, `\Downloads\`, `\\`, UNC, `\Device\`, non-system drive with no vendor prefix. Message explicitly says "contextual risk indicator, not proof of malware".

### `src/pe.h` / `pe.cpp`
Public: `struct PeInfo {uint32_t sizeOfImage; bool is64;}; bool TryGetPeSizeOfImage(const std::wstring& path, PeInfo& out, std::string& err);` Parses DOS+NT headers, returns `SizeOfImage`. Mismatch evidence will say "on-disk SizeOfImage vs kernel ImageSize diverge — alternative explanations: file updated after load; manual-map with doctored header would also present this way — not proof of manual mapping."

### `src/risk.h` / `risk.cpp`
Risk Assessment Engine — separate from collectors. Public: `struct RiskDecision {Verdict verdict; Confidence confidence; std::string summary; std::string nextStep;}; RiskDecision Assess(const std::vector<Evidence>& ev);` Rules (versioned, testable without drivers): any `Suspicious` evidence → overall `Suspicious` (hash hit overrides valid sig; valid sig alone never downgrades a hash hit); any `Warn` with no `Suspicious` → `Warn`; else `Clean`. Downgrades cert-only hits to `Medium` confidence (signal, not proof). Warn-level path alone → `Low` confidence suspicious only if corroborated. Produces `summary` and `nextStep` strings included in both table and JSON.

### `src/output.h` / `output.cpp`
Evidence-backed emitters. Public: `void PrintTable(const std::vector<DriverReport>&, FILE* out);` `void PrintJson(const std::vector<DriverReport>&, const Blocklist* bl, FILE* out);` Table columns: `Base | Size | Verdict | Confidence | File | Evidence (check:detail [provenance])`. JSON includes per-driver `checks[]` with `check`, `verdict`, `confidence`, `detail`, `provenance`, `recommendation`, plus top-level `blocklist_version` / `snapshot_date` / `sources`.

### `src/update.h` / `update.cpp`
Public: `int RunUpdateBlocklist(const std::wstring& destPath);` WinHTTP GET from `loldrivers.io` / GitHub raw, 15 s timeout, validates schema + lowercases hashes, atomic `.tmp` + `MoveFileExW`. Offline/non-200 → non-zero without clobbering.

### `src/main.cpp`
CLI: `--json`, `--blocklist <path>`, `--update-blocklist`, `--help`, `--version`. Scan: `EnumerateDrivers` → resolve on-disk path → collectors (hash→blocklist, verify, cert→blocklist, path, pe size) → `Evidence[]` → `risk::Assess` → `DriverReport` → `PrintTable`/`PrintJson` → exit `0` Clean / `1` Warn / `2` Suspicious (enumeration failure also `2`).

## 4. Build order — each stage ships complete files, not stubs

(a) Enumeration + text output — `types.h`, `enum.h/.cpp`, `risk.h/.cpp` (minimal), `output.h/.cpp` (table), `main.cpp` (table), `CMakeLists.txt`. Must list 180+ drivers.
(b) JSON + exit codes — `PrintJson`, `--json`, `OverallVerdict` via `risk::Assess`, `0/1/2`.
(c) Hash blocklist + `--update-blocklist` — `hash.h/.cpp`, `blocklist.h/.cpp`, `update.h/.cpp`, `data/blocklist.json` (versioned), wire hash check.
(d) Signature verification — `verify.h/.cpp`, taxonomy, wire.
(e) Cert reputation — extend blocklist certs, wire thumbprint vs blocklist (confidence Medium, "signal not proof").
(f) Path + size mismatch — `pathcheck.h/.cpp`, `pe.h/.cpp`, wire with careful wording (contextual / not proof).
(g) Tests + fixtures + docs — `tests/test_*.cpp` (doctest), synthetic PEs, `README.md`, `LIMITATIONS.md`, `ctest`.

## 5. LIMITATIONS.md (outline)

* User-mode only; kernel tampering (DKOM, `NtQuerySystemInformation` hooks) can hide/falsify results.
* Blocklist is a versioned snapshot, not live — stale immediately; `--update-blocklist`.
* "Suspicious" ≠ "malicious" — confidence + alternative explanations in every finding; valid signature does not imply safe.
* Path flag is contextual risk only; vendor drivers outside `System32` are rare but real.
* ImageSize mismatch is divergence, not proof of manual mapping.
* Signature verification is over the on-disk file, not the in-memory image; in-memory tampering is a separate advanced feature.
* Returned image path / on-disk file / loaded memory image are not interchangeable sources of truth.
* No cleaning, no real-time monitoring — triage only.

## 6. Demo scenarios

* **Clean box:** stock Windows 10/11 → `drvscan` table, 180+ rows, all `clean`, exit `0`; `drvscan --json` reports `blocklist_version` + all `clean`.
* **Capcom.sys (BYOVD):** source `Capcom.sys` from `loldrivers.io` (README documents it). Load via OSR Loader / `sc create` / `--fixture` synthetic injection for CI. Rescan row shows `suspicious` with correlated evidence: `hash:blocklisted (capcom.sys, loldrivers.io) [blocklist v…]`, `sig:revoked|untrusted [WinVerifyTrust hr=…]`, `cert:blocklisted (CrossCert 2021) [thumbprint …] — signal, not proof`, `path:contextual risk (Temp)`, each with confidence + recommendation, exit `2`.
