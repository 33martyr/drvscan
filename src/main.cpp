#include "types.h"
#include "enum.h"
#include "hash.h"
#include "blocklist.h"
#include "verify.h"
#include "pathcheck.h"
#include "pe.h"
#include "risk.h"
#include "output.h"
#include "update.h"
#include "handles.h"
#include "devmap.h"
#include "objscan.h"
#include "sigcontext.h"
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <sstream>
#include <variant>
#include <unordered_map>

using namespace drvscan;

static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), n);
    return w;
}
static std::wstring AnsiToWide(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_ACP, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), (int)s.size(), w.data(), n);
    return w;
}
static std::wstring ToWidePath(const std::string& s) {
    std::wstring w = Utf8ToWide(s);
    if (!w.empty()) return w;
    return AnsiToWide(s);
}

static std::wstring GetExeDir() {
    wchar_t buf[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return L".";
    std::wstring s(buf, n);
    size_t pos = s.find_last_of(L"\\/");
    if (pos != std::wstring::npos) return s.substr(0, pos);
    return L".";
}

static std::wstring ResolveBlocklistPath(const std::wstring& overridePath) {
    if (!overridePath.empty()) return overridePath;
    std::wstring exeDir = GetExeDir();
    std::wstring cands[] = {
        exeDir + L"\\data\\blocklist.json",
        exeDir + L"\\blocklist.json",
        L"data\\blocklist.json",
        L".\\data\\blocklist.json",
    };
    for (auto& p : cands) {
        DWORD attr = GetFileAttributesW(p.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES) return p;
    }
    return exeDir + L"\\data\\blocklist.json";
}

static void PrintHelp() {
    printf("drvscan 0.4.0 — enumerate loaded kernel drivers and flag suspicious ones\n");
    printf("\nUsage: drvscan [options]\n");
    printf("  --json                    Emit JSON report to stdout\n");
    printf("  --verbose                 Show all evidence in table (default hides Clean)\n");
    printf("  --redact-paths            Redact C:\\Users\\<name>\\ to C:\\Users\\<user>\\ in output\n");
    printf("  --pid <name|pid>            Per-process mode: audit drivers for handles held by PID or name.exe\n");
    printf("  --pid-exact               With --pid name.exe: error if multiple matches (for scripts)\n");
    printf("  --blocklist <path>        Use blocklist JSON at <path>\n");
    printf("  --update-blocklist        Refresh bundled blocklist from network and exit\n");
    printf("  --strict                  Promote Warn to exit 2 (for CI strict mode)\n");
    printf("  --legacy-exit-codes       Warn->1, Suspicious->2 (compat for v1.1.1 CI)\n");
    printf("  --help                    Show this help\n");
    printf("  --version                 Show version (tool 0.4.0, schema 0.2.0, snapshot 2026.10.20)\n");
    printf("\nExit codes (default): 0 clean, 1 warn, 2 suspicious, 3 scan failed\n");
    printf("  --strict: 0 clean, 2 warn|suspect, 3 failed\n");
    printf("  --legacy-exit-codes: 0 clean, 1 warn, 2 suspicious, 3 failed (v1.1.1 compat)\n");
    printf("\nBlocklist update failure modes:\n");
    printf("  exit 0 updated, exit 1 network/shape failure (old kept, no clobber),\n");
    printf("  exit 1 pin mismatch (old kept), see data/blocklist.sha256 and docs/UPDATE.md\n");
    printf("\nNotes:\n");
    printf("  - User-mode only; kernel tampering can hide drivers.\n");
    printf("  - Bundled blocklist is a SAMPLE — run --update-blocklist before relying on detection.\n");
    printf("  - 'suspicious' is not 'malicious' — check confidence and provenance.\n");
    printf("  - Valid signature does not imply safe (BYOVD).\n");
    printf("  - PE checks are on-disk only; 'consistent with' != 'is' manual-mapped.\n");
    printf("  - Until HMAC pin verification is configured, --update-blocklist trusts source over TLS.\n");
    printf("    Do not run --update-blocklist on a network you do not trust.\n");
}

static std::string ToLowerStrMain(std::string s){ for(char& c:s) c=(char)std::tolower((unsigned char)c); return s; }
static std::string JoinFindings(const std::vector<PeFinding>& v, const std::string& sep = " | ") {
    std::string s;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) s += sep;
        s += v[i].detail;
    }
    return s;
}

int main(int argc, char* argv[]) {
    bool jsonOut = false;
    bool verbose = false;
    bool redactPaths = false;
    bool strictMode = false;
    bool legacyExitCodes = false;
    std::wstring blocklistOverride;
    bool doUpdate = false;

    // First pass: scan for --pid value position to skip its argument in validation
    int pidValueIdx = -1;
    for(int i=1;i<argc;++i){ std::string a=argv[i]; if(a=="--pid" && i+1<argc){ pidValueIdx=i+1; break; } }
    for (int i = 1; i < argc; ++i) {
        if(i==pidValueIdx) continue;
        std::string a = argv[i];
        if (a == "--json") jsonOut = true;
        else if (a == "--verbose") verbose = true;
        else if (a == "--redact-paths") redactPaths = true;
        else if (a == "--strict") strictMode = true;
        else if (a == "--legacy-exit-codes") legacyExitCodes = true;
        else if (a == "--help" || a == "-h") { PrintHelp(); return 0; }
        else if (a == "--version") {
            printf("drvscan 0.4.0 (blocklist schema 0.2.0, blocklist snapshot 2026.10.20)\n");
            return 0;
        }
        else if (a == "--pid" || a == "--pid-exact") { }
        else if (a.rfind("--pid=",0)==0) { }
        else if (a == "--update-blocklist") doUpdate = true;
        else if (a == "--blocklist" && i + 1 < argc) {
            blocklistOverride = AnsiToWide(argv[++i]);
        } else if (a == "--blocklist") {
            fprintf(stderr, "error: --blocklist requires a value\n"); PrintHelp(); return 3;
        } else {
            fprintf(stderr, "Unknown option: %s\n", a.c_str());
            PrintHelp();
            return 3;
        }
    }
    if (strictMode && legacyExitCodes) {
        fprintf(stderr, "--strict and --legacy-exit-codes are mutually exclusive\n");
        return 3;
    }
    // --pid mode detection (second pass for value-bearing args)
    std::string pidArg; bool pidExact=false; bool pidMode=false;
    for(int i=1;i<argc;++i){
        std::string a=argv[i];
        if(a=="--pid-exact"){ pidExact=true; pidMode=true; }
        else if(a=="--pid" && i+1<argc){ pidArg=argv[++i]; pidMode=true; }
        else if(a.rfind("--pid=",0)==0){ pidArg=a.substr(6); pidMode=true; }
    }
    if(pidMode && pidArg.empty()){ fprintf(stderr,"error: --pid requires a value (PID or name.exe)\n"); PrintHelp(); return 3; }
    if(pidMode && doUpdate){ fprintf(stderr,"error: --pid and --update-blocklist are mutually exclusive\n"); return 3; }

    if (doUpdate) {
        std::wstring dest = ResolveBlocklistPath(blocklistOverride);
        size_t pos = dest.find_last_of(L"\\/");
        if (pos != std::wstring::npos) {
            std::wstring dir = dest.substr(0, pos);
            CreateDirectoryW(dir.c_str(), nullptr);
        }
        return RunUpdateBlocklist(dest);
    }
    if (pidMode) {
        // Resolve PID(s)
        std::string pidErr;
        auto pids = ResolveProcessArgument(pidArg, pidErr);
        if(pids.empty()){
            fprintf(stderr,"%s\n", pidErr.c_str());
            return 3;
        }
        if(pidExact && pids.size()>1){
            fprintf(stderr,"error: %zu matches for '%s'; pass --pid <numeric> to disambiguate\n", pids.size(), pidArg.c_str());
            return 3;
        }
        std::wstring blPath2 = ResolveBlocklistPath(blocklistOverride);
        std::string blErr2; Blocklist bl2 = Blocklist::Load(blPath2, blErr2);
        bool blOk = blErr2.empty();
        if(!blOk) bl2 = Blocklist();
        TryEnableDebugPrivilege();
        // Per-PID scan: enumerate handles, map to driver files, run engine
        std::vector<std::tuple<std::string,DWORD,std::vector<DeviceHandle>,std::vector<DriverReport>>> perPid;
        int maxExit=0;
        // Need all drivers index for lookup by file name
        std::string enumErr2; auto allDrivers = EnumerateDrivers(enumErr2);
        std::unordered_map<std::string, DriverInfo> driverByFile;
        for(auto& d: allDrivers){ driverByFile[ToLowerStrMain(d.fileName)] = d; }
        auto toLower2 = [](std::string s){ for(char& c:s) c=(char)std::tolower((unsigned char)c); return s; };
        for(DWORD pid: pids){
            auto handlesOrErr = EnumerateDeviceHandles(pid);
            if(std::holds_alternative<HandleError>(handlesOrErr)){
                auto& he = std::get<HandleError>(handlesOrErr);
                fprintf(stderr,"%s\n", he.message.c_str());
                maxExit = std::max(maxExit, he.exit_code);
                continue;
            }
            auto handles = std::get<std::vector<DeviceHandle>>(handlesOrErr);
            // Map each device to driver file, then to DriverInfo if possible; fallback DriverInfo for unknown
            std::vector<std::pair<DeviceHandle, DriverInfo>> mapped;
            std::vector<DeviceHandle> orderedHandles;
            std::vector<DriverReport> pidReports;
            for(auto& h: handles){
                std::string drvFile = ResolveDeviceToDriver(h.device_path);
                if(drvFile.empty()){
                    DriverInfo di; di.fileName="<unknown>"; di.normalizedPath=""; di.kernelPath=h.device_path;
                    di.baseAddress=nullptr; di.baseHex="-"; di.kernelImageSize=0;
                    Evidence ne; ne.check="device_map"; ne.verdict=Verdict::Warn; ne.confidence=Confidence::Low;
                    ne.provenance="data/device_map.json (60% coverage on stock Windows)";
                    ne.detail="Device " + h.device_path + " has no mapped driver in device_map.json — cannot audit without file path (skipped)";
                    ne.recommendation="Unmapped devices report as <unknown> and are not silently dropped — see LIMITATIONS.md";
                    std::vector<Evidence> nev{ne};
                    DriverReport nr = risk::MakeReport(di, std::move(nev));
                    nr.driver.fileName = "<unknown>";
                    pidReports.push_back(std::move(nr));
                    orderedHandles.push_back(h);
                    continue;
                }
                auto it = driverByFile.find(toLower2(drvFile));
                if(it!=driverByFile.end()) mapped.push_back({h, it->second});
                else {
                    DriverInfo di; di.fileName=drvFile; di.kernelPath=h.device_path;
                    di.normalizedPath = "C:\\Windows\\System32\\drivers\\" + drvFile;
                    mapped.push_back({h, di});
                }
            }
            // pidReports/orderedHandles already seeded for unmapped; mapped reports follow
            for(auto& pr2: mapped){
                DeviceHandle dh2 = pr2.first;
                DriverInfo d = pr2.second;
                orderedHandles.push_back(dh2);
                // Reuse engine: run checks on d (same as default mode per-driver loop)
                std::vector<Evidence> ev;
                std::wstring wpath = ToWidePath(d.normalizedPath.empty()? d.kernelPath : d.normalizedPath);
                std::vector<uint8_t> fileBytes; std::string readErr;
                bool haveBytes = false;
                if(!wpath.empty() && wpath.size()>4) haveBytes = ReadFileToBuffer(wpath, fileBytes, readErr);
                PeStructure pe{}; bool haveValidPe=false;
                if(haveBytes){ pe=ParsePeStructure(fileBytes); haveValidPe=(pe.validity==PeValidity::Valid); }
                VerifyResult vr{};
                // Hash
                { Evidence e; e.check="hash_blocklist"; e.provenance=blOk?(bl2.version()+" "+bl2.snapshotDate()):"no blocklist";
                  if(!blOk||bl2.empty()){e.verdict=Verdict::Clean; e.detail="Blocklist unavailable — hash check skipped";}
                  else if(!haveBytes){e.verdict=Verdict::Warn; e.detail="Cannot hash file: "+readErr;}
                  else{ std::string hex=Sha256Bytes(fileBytes.data(),fileBytes.size()); auto* hit=bl2.FindHash(hex);
                    if(hit){e.verdict=Verdict::Suspicious; e.detail="SHA-256 matches blocklist for "+hit->fileName+" ("+hit->category+", source="+hit->source+")"; e.provenance=hit->source+" "+bl2.version();}
                    else e.detail="SHA-256 not in blocklist ("+hex.substr(0,16)+"…)"; } ev.push_back(std::move(e)); }
                // Sig + cert
                { Evidence e; e.check="authenticode"; e.provenance="WinVerifyTrust (on-disk file; does not prove in-memory image is identical)";
                  vr=VerifyEmbeddedSignature(wpath); e.detail=vr.message; if(!vr.signerSubject.empty()) e.detail+=" signer="+vr.signerSubject;
                  switch(vr.status){case SigStatus::Valid:e.verdict=Verdict::Clean;break;case SigStatus::Unsigned:e.verdict=Verdict::Suspicious;break;case SigStatus::Modified:e.verdict=Verdict::Suspicious;break;case SigStatus::Revoked:e.verdict=Verdict::Suspicious;break;case SigStatus::Expired:e.verdict=Verdict::Warn;break;case SigStatus::UntrustedRoot:e.verdict=Verdict::Suspicious;break;default:e.verdict=Verdict::Warn;break;} ev.push_back(std::move(e));
                  Evidence ce; ce.check="cert_blocklist"; ce.provenance=blOk?(bl2.version()+" cert list"):"no blocklist";
                  if(!blOk||bl2.empty()||vr.certThumbprints.empty()) ce.detail="No cert chain available for thumbprint check";
                  else { bool hit=false; for(auto& th: vr.certThumbprints) if(bl2.IsCertBlocked(th)){hit=true; break;} if(hit){ce.verdict=Verdict::Suspicious; ce.detail="Signing cert thumbprint matches blocklist — signal, not proof of compromise";} else ce.detail="No cert thumbprint in blocklist ("+std::to_string(vr.certThumbprints.size())+" certs checked)"; } ev.push_back(std::move(ce)); }
                // Path
                { Evidence e; e.check="path"; e.provenance="Path policy (contextual risk indicator, not proof of malware)";
                  PathResult pr = CheckDriverPathWithSig(d.normalizedPath.empty()?d.kernelPath:d.normalizedPath, vr.status==SigStatus::Valid);
                  e.detail=pr.reason; e.recommendation=pr.recommendation;
                  if(pr.verdict==PathVerdict::Regular) e.verdict=Verdict::Clean; else if(pr.verdict==PathVerdict::Warn) e.verdict=Verdict::Warn; else e.verdict=Verdict::Suspicious; ev.push_back(std::move(e)); }
                // Image size
                { Evidence e; e.check="image_size"; e.provenance="On-disk PE SizeOfImage vs kernel-reported ImageSize (not live memory)";
                  if(d.kernelImageSize==0) e.detail="Kernel ImageSize unavailable";
                  else if(!haveValidPe) e.detail="Cannot read on-disk PE SizeOfImage: "+readErr;
                  else if(pe.size_of_image!=d.kernelImageSize) e.detail="Mismatch: kernel ImageSize="+std::to_string(d.kernelImageSize)+" vs SizeOfImage="+std::to_string(pe.size_of_image);
                  else e.detail="SizeOfImage matches kernel ImageSize ("+std::to_string(pe.size_of_image)+")";
                  if(d.kernelImageSize!=0 && haveValidPe && pe.size_of_image!=d.kernelImageSize) e.verdict=Verdict::Suspicious; else if(!haveValidPe) e.verdict=Verdict::Warn; 
                  ev.push_back(std::move(e)); }
                // PE C1-C7 (abbreviated: reuse same FIX-correct functions)
                if(!haveBytes){ /* skip */ } else if(!haveValidPe){ Evidence e; e.check="pe_parse"; e.verdict=Verdict::Suspicious; e.detail="Malformed PE"; ev.push_back(std::move(e)); }
                else {
                    (void)0;
                    // Real dispatch per check for correct fields
                    { auto f=CheckSectionOverlap(pe); Evidence e; e.check="pe_section_overlap"; e.provenance="On-disk PE sections (no kernel memory)"; if(f.empty()){e.detail="No section overlaps";} else {e.verdict=Verdict::Suspicious; e.detail=JoinFindings(f);} ev.push_back(std::move(e)); }
                    { auto f=CheckSectionEscapesImage(pe); Evidence e; e.check="pe_section_escape"; if(f.empty()) e.detail="All sections within SizeOfImage"; else {e.verdict=Verdict::Suspicious; e.detail=JoinFindings(f);} ev.push_back(std::move(e)); }
                    { auto f=CheckEntryPoint(pe); Evidence e; e.check="pe_entry_point"; if(f.empty()) e.detail="AddressOfEntryPoint "+std::to_string(pe.address_of_entry_point)+" falls inside a section and within image"; else { bool isZ=(pe.address_of_entry_point==0); if(isZ && pe.has_driver_entry){e.verdict=Verdict::Suspicious; e.detail=f[0].detail;} else if(isZ){e.verdict=Verdict::Warn; e.detail=f[0].detail;} else {e.verdict=Verdict::Suspicious; e.detail=JoinFindings(f);} } ev.push_back(std::move(e)); }
                    { auto f=CheckAlignment(pe); Evidence e; e.check="pe_alignment"; if(f.empty()) e.detail="SectionAlignment/FileAlignment and SizeOfImage alignment valid"; else if(f.size()>=2){e.verdict=Verdict::Suspicious; e.detail=JoinFindings(f);} else {e.verdict=Verdict::Warn; e.detail=JoinFindings(f);} ev.push_back(std::move(e)); }
                    { auto f=CheckChecksum(pe); Evidence e; e.check="pe_checksum"; if(f.empty()) e.detail=(pe.header_checksum==0?"Header CheckSum is 0 — not computed":"Header CheckSum matches computed checksum"); else { if(pe.header_checksum==0) e.verdict=Verdict::Warn; else if(vr.status==SigStatus::Valid||IsMicrosoftSigned(vr)) e.verdict=Verdict::Suspicious; else e.verdict=Verdict::Warn; e.detail=f[0].detail;} ev.push_back(std::move(e)); }
                    { auto f=CheckTimestamp(pe); Evidence e; e.check="pe_timestamp"; if(f.empty()) e.detail="TimeDateStamp plausible (within 2000-01-01 to now+30d)"; else { bool isZ=(f.size()==1&&f[0].detail.find("is 0")!=std::string::npos); bool isHash=(f[0].detail.find("plausible reproducible-build hash")!=std::string::npos); if(isZ){e.verdict=Verdict::Warn; e.detail=f[0].detail;} else if(isHash){e.verdict=Verdict::Clean; e.detail=f[0].detail;} else {e.verdict=Verdict::Warn; e.detail=JoinFindings(f);} } ev.push_back(std::move(e)); }
                    { auto f=CheckSectionNames(pe); Evidence e; e.check="pe_section_name"; if(f.empty()) e.detail="All section names match known-good patterns"; else {e.verdict=Verdict::Warn; e.detail=JoinFindings(f);} ev.push_back(std::move(e)); }
                }
                // Risk assess
                auto report = risk::MakeReport(d, std::move(ev));
                pidReports.push_back(std::move(report));
            }
            maxExit = std::max(maxExit, (int)OverallVerdict(pidReports));
            std::string label = pidArg;
            perPid.emplace_back(label, pid, orderedHandles, pidReports);
        }
        // Output
        if(jsonOut){
            WritePidJson(stdout, &bl2, redactPaths, "0.4.0", "0.2.0", perPid, pidArg);
        } else {
            for(auto& t: perPid){
                auto& label=std::get<0>(t); auto pid=std::get<1>(t); auto& handles=std::get<2>(t); auto& reports=std::get<3>(t);
                PrintPidTable(stdout, label, pid, handles, reports, verbose);
            }
            // Aggregate summary
            int totalDevices=0, unique=0, clean=0,warn=0,susp=0, unmapped2=0;
            std::unordered_map<std::string,int> uniq2;
            for(auto& t2: perPid){ auto& hh2=std::get<2>(t2); auto& rr2=std::get<3>(t2); totalDevices+=(int)hh2.size();
                for(auto& rr: rr2){ uniq2[rr.driver.fileName]++; if(rr.overall==Verdict::Clean) clean++; else if(rr.overall==Verdict::Warn) warn++; else susp++; }
                if((int)hh2.size() > (int)rr2.size()) unmapped2 += (int)hh2.size() - (int)rr2.size(); }
            unique=(int)uniq2.size();
            if(perPid.size()==1){
                fprintf(stdout, "%d devices -> %d unique drivers -> %d clean · %d warn · %d suspicious\n", totalDevices, unique, clean,warn,susp);
                if(unmapped2) fprintf(stdout, "%d devices unmapped (see LIMITATIONS.md for coverage)\n", unmapped2);
            } else {
                fprintf(stdout, "%s x %zu processes\n", pidArg.c_str(), perPid.size());
                fprintf(stdout, "%zu processes -> %d devices -> %d unique drivers -> %d clean · %d warn · %d suspicious\n", perPid.size(), totalDevices, unique, clean,warn,susp);
                if(unmapped2) fprintf(stdout, "%d devices unmapped (see LIMITATIONS.md for coverage)\n", unmapped2);
            }
            fprintf(stdout, "Note: handles do not prove intent — a process opening \\Device\\Capcom proves handle, not malice.\n");
        }
        if(legacyExitCodes){
            if(maxExit==2) return 2;
            if(maxExit==1) return 1;
            return 0;
        }
        if(strictMode){ if(maxExit==1||maxExit==2) return 2; return 0; }
        return maxExit;
    }

    std::wstring blPath = ResolveBlocklistPath(blocklistOverride);
    std::string blErr;
    Blocklist bl = Blocklist::Load(blPath, blErr);
    bool blLoaded = blErr.empty();
    if (!blLoaded) {
        fprintf(stderr, "Warning: blocklist not loaded (%s) — hash/cert checks will be skipped. Run --update-blocklist or check --blocklist path.\n", blErr.c_str());
        bl = Blocklist();
    } else {
        if (bl.isSample()) {
            fprintf(stderr, "Note: bundled blocklist is a SAMPLE (version %s, snapshot %s) — run drvscan --update-blocklist before relying on detection. Without it, 'clean' may be a false negative.\n", bl.version().c_str(), bl.snapshotDate().c_str());
        }
        if (bl.empty()) {
            fprintf(stderr, "Warning: blocklist empty (version=%s) — run --update-blocklist to populate.\n", bl.version().c_str());
        }
    }

    std::string enumErr;
    auto drivers = EnumerateDrivers(enumErr);
    if (drivers.empty()) {
        fprintf(stderr, "Failed to enumerate drivers: %s\n", enumErr.c_str());
        return 3;
    }

    std::vector<DriverReport> reports;
    reports.reserve(drivers.size());

    for (auto& d : drivers) {
        std::vector<Evidence> ev;
        std::wstring wpath = ToWidePath(d.normalizedPath);

        // Single buffer read for hash + PE checks
        std::vector<uint8_t> fileBytes;
        std::string readErr;
        bool haveBytes = ReadFileToBuffer(wpath, fileBytes, readErr);
        PeStructure pe{};
        bool haveValidPe = false;
        if (haveBytes) {
            pe = ParsePeStructure(fileBytes);
            haveValidPe = (pe.validity == PeValidity::Valid);
        }

        // 1) SHA-256 hash vs blocklist (uses buffer if available)
        {
            Evidence e;
            e.check = "hash_blocklist";
            e.provenance = blLoaded ? (bl.version() + " " + bl.snapshotDate()) : "no blocklist";
            if (!blLoaded || bl.empty()) {
                e.verdict = Verdict::Clean;
                e.confidence = Confidence::High;
                e.detail = "Blocklist unavailable — hash check skipped";
                e.recommendation = "Run --update-blocklist to enable hash blocking";
            } else if (!haveBytes) {
                e.verdict = Verdict::Warn;
                e.confidence = Confidence::Low;
                e.detail = "Cannot hash file: " + readErr + " — file may be missing or inaccessible (on-disk file and loaded image are not interchangeable)";
                e.recommendation = "Verify file exists at reported path; check access permissions";
            } else {
                std::string hex = Sha256Bytes(fileBytes.data(), fileBytes.size());
                if (hex.empty()) {
                    e.verdict = Verdict::Warn;
                    e.confidence = Confidence::Low;
                    e.detail = "Cannot hash file — empty buffer";
                    e.recommendation = "Verify file exists";
                } else {
                    auto* hit = bl.FindHash(hex);
                    if (hit) {
                        e.verdict = Verdict::Suspicious;
                        e.confidence = Confidence::High;
                        e.detail = "SHA-256 matches blocklist entry for " + hit->fileName + " (" + hit->category + ", source=" + hit->source + ", hash=" + hex.substr(0,16) + "…)";
                        e.provenance = hit->source + " " + bl.version();
                        e.recommendation = "Known-vulnerable driver — valid signature does not imply safe (BYOVD); remove or update per vendor advisory";
                    } else {
                        e.verdict = Verdict::Clean;
                        e.confidence = Confidence::High;
                        e.detail = "SHA-256 not in blocklist (" + hex.substr(0,16) + "…)";
                        e.recommendation = "No action";
                    }
                }
            }
            ev.push_back(std::move(e));
        }

        // Keep VerifyResult for cert check later
        VerifyResult vr{};

        // 2) Authenticode
        {
            Evidence e;
            e.check = "authenticode";
            e.provenance = "WinVerifyTrust (on-disk file; does not prove in-memory image is identical)";
            vr = VerifyEmbeddedSignature(wpath);
            e.detail = vr.message;
            if (!vr.signerSubject.empty()) e.detail += " signer=" + vr.signerSubject;
            switch (vr.status) {
                case SigStatus::Valid:
                    e.verdict = Verdict::Clean;
                    e.confidence = Confidence::High;
                    e.recommendation = "Signature valid — but valid does not imply safe; correlate with hash blocklist";
                    break;
                case SigStatus::Unsigned:
                    e.verdict = Verdict::Suspicious;
                    e.confidence = Confidence::High;
                    e.detail += " — unsigned kernel driver is high risk";
                    e.recommendation = "Verify driver source; unsigned drivers should not be loaded on production systems";
                    break;
                case SigStatus::Modified:
                    e.verdict = Verdict::Suspicious;
                    e.confidence = Confidence::High;
                    e.detail += " — file modified after signing";
                    e.recommendation = "Reinstall from vendor; check for tampering";
                    break;
                case SigStatus::Revoked:
                    e.verdict = Verdict::Suspicious;
                    e.confidence = Confidence::High;
                    e.detail += " — signing cert revoked";
                    e.recommendation = "Remove driver; check revocation reason and vendor advisory";
                    break;
                case SigStatus::Expired:
                    e.verdict = Verdict::Warn;
                    e.confidence = Confidence::Medium;
                    e.detail += " — cert expired (may still be valid if timestamped, but warrants review)";
                    e.recommendation = "Check timestamp and vendor support status";
                    break;
                case SigStatus::UntrustedRoot:
                    e.verdict = Verdict::Suspicious;
                    e.confidence = Confidence::High;
                    e.recommendation = "Untrusted root — verify CA and driver source";
                    break;
                case SigStatus::Unverifiable:
                default:
                    e.verdict = Verdict::Warn;
                    e.confidence = Confidence::Low;
                    e.detail += " — verification inconclusive (file may be missing; on-disk vs loaded image differ)";
                    e.recommendation = "Verify file accessibility; check alternative explanations";
                    break;
            }
            ev.push_back(std::move(e));

            // 3) Cert thumbprint blocklist
            {
                Evidence ce;
                ce.check = "cert_blocklist";
                ce.provenance = blLoaded ? (bl.version() + " cert list") : "no blocklist";
                if (!blLoaded || bl.empty() || vr.certThumbprints.empty()) {
                    ce.verdict = Verdict::Clean;
                    ce.confidence = Confidence::High;
                    if (vr.certThumbprints.empty()) ce.detail = "No cert chain available for thumbprint check";
                    else ce.detail = "Blocklist unavailable — cert check skipped";
                    ce.recommendation = "No action";
                } else {
                    bool hitFound = false;
                    const CertEntry* hitEntry = nullptr;
                    std::string hitThumb;
                    for (auto& th : vr.certThumbprints) {
                        auto* h = bl.FindCert(th);
                        if (h) { hitFound = true; hitEntry = h; hitThumb = th; break; }
                    }
                    if (hitFound) {
                        ce.verdict = Verdict::Suspicious;
                        ce.confidence = Confidence::Medium;
                        ce.detail = "Signing cert thumbprint " + hitThumb.substr(0,16) + "… matches blocklist (" + hitEntry->owner + ", source=" + hitEntry->source + ") — signal, not proof of compromise";
                        ce.provenance = hitEntry->source + " " + bl.version();
                        ce.recommendation = "Corroborate with hash/path; check revocation; verify vendor — cert match alone does not prove compromise";
                    } else {
                        ce.verdict = Verdict::Clean;
                        ce.confidence = Confidence::High;
                        ce.detail = "No cert thumbprint in blocklist (" + std::to_string(vr.certThumbprints.size()) + " certs checked)";
                        ce.recommendation = "No action";
                    }
                }
                ev.push_back(std::move(ce));
            }
        }

        // 4) Path regularity (contextual) — signed Program Files drivers are Clean, not Warn
        {
            Evidence e;
            e.check = "path";
            e.provenance = "Path policy (contextual risk indicator, not proof of malware)";
            bool isSigned = (vr.status == SigStatus::Valid);
            PathResult pr = CheckDriverPathWithSig(d.normalizedPath, isSigned);
            e.detail = pr.reason;
            e.recommendation = pr.recommendation.empty() ? "No action" : pr.recommendation;
            if (pr.verdict == PathVerdict::Regular) { e.verdict = Verdict::Clean; e.confidence = Confidence::High; }
            else if (pr.verdict == PathVerdict::Warn) { e.verdict = Verdict::Warn; e.confidence = Confidence::Medium; }
            else { e.verdict = Verdict::Suspicious; e.confidence = Confidence::Low; }
            ev.push_back(std::move(e));
        }

        // 5) Image size mismatch (on-disk vs kernel metadata)
        {
            Evidence e;
            e.check = "image_size";
            e.provenance = "On-disk PE SizeOfImage vs kernel-reported ImageSize (not live memory)";
            if (d.kernelImageSize == 0) {
                e.verdict = Verdict::Warn;
                e.confidence = Confidence::Low;
                e.detail = "Kernel ImageSize unavailable (enumeration did not provide size)";
                e.recommendation = "Cannot compare — check enumeration method";
            } else if (!haveValidPe) {
                e.verdict = Verdict::Warn;
                e.confidence = Confidence::Low;
                std::string why = !haveBytes ? readErr : "PE parse failed";
                if (haveBytes && pe.validity != PeValidity::Valid) {
                    why = (pe.validity == PeValidity::NotAPe ? "Not a valid PE" :
                           pe.validity == PeValidity::MalformedHeader ? "Malformed PE header" : "Malformed section table");
                }
                e.detail = "Cannot read on-disk PE SizeOfImage: " + why + " — file may be missing; not proof of tampering";
                e.recommendation = "Verify file exists and is a valid PE";
            } else {
                // Tolerance: EnumDeviceDrivers/NtQuery ImageSize is page-aligned; legitimate rounding is up to one page (0x1000).
                // Truncation (kernel < on-disk) is more suspicious than rounding up.
                int64_t delta = (int64_t)d.kernelImageSize - (int64_t)pe.size_of_image;
                int64_t absDelta = delta >= 0 ? delta : -delta;
                if (absDelta == 0) {
                    e.verdict = Verdict::Clean;
                    e.confidence = Confidence::High;
                    e.detail = "SizeOfImage matches kernel ImageSize (" + std::to_string(pe.size_of_image) + ")";
                    e.recommendation = "No action";
                } else if (delta > 0 && absDelta <= 0x1000) {
                    e.verdict = Verdict::Warn;
                    e.confidence = Confidence::Low;
                    e.detail = "Small mismatch: kernel ImageSize=" + std::to_string(d.kernelImageSize) + " vs on-disk SizeOfImage=" + std::to_string(pe.size_of_image) + " (delta +" + std::to_string(absDelta) + ", within one page) — likely page-alignment rounding, not suspicious";
                    e.recommendation = "No action — within expected kernel rounding tolerance (0x1000)";
                } else if (delta < 0) {
                    e.verdict = Verdict::Suspicious;
                    e.confidence = Confidence::High;
                    e.detail = "Truncation: kernel ImageSize=" + std::to_string(d.kernelImageSize) + " < on-disk SizeOfImage=" + std::to_string(pe.size_of_image) + " (delta " + std::to_string(delta) + ") — more suspicious than rounding up; may indicate tampering or replacement";
                    e.recommendation = "Check file modification time vs boot time; verify on-disk file matches loaded driver";
                } else {
                    e.verdict = Verdict::Suspicious;
                    e.confidence = Confidence::Medium;
                    e.detail = "Mismatch: kernel ImageSize=" + std::to_string(d.kernelImageSize) + " vs on-disk SizeOfImage=" + std::to_string(pe.size_of_image) + " (delta +" + std::to_string(absDelta) + " > 0x1000) — divergence beyond rounding tolerance; not proof of manual mapping";
                    e.recommendation = "Check file modification time vs boot time; corroborate with other signals";
                }
            }
            ev.push_back(std::move(e));
        }

        // 6) PE structural checks C1–C7 (on-disk only, consistent with / indicator of, never "is")
        if (!haveBytes) {
            Evidence e;
            e.check = "pe_structure";
            e.verdict = Verdict::Warn;
            e.confidence = Confidence::Low;
            e.provenance = "On-disk PE structural analysis (no kernel memory)";
            e.detail = "Cannot perform PE structural checks — file not readable: " + readErr;
            e.recommendation = "Verify file exists and is accessible";
            ev.push_back(std::move(e));
        } else if (pe.validity != PeValidity::Valid) {
            Evidence e;
            e.check = "pe_parse";
            e.verdict = Verdict::Suspicious;
            e.confidence = Confidence::Medium;
            e.provenance = "On-disk PE parse (no kernel memory)";
            std::string reason = (pe.validity == PeValidity::NotAPe ? "Not a valid PE (missing MZ/PE signature)" :
                                  pe.validity == PeValidity::MalformedHeader ? "Malformed DOS/NT headers — file may be truncated or synthetic" :
                                  "Malformed section table — section headers inconsistent with header");
            e.detail = reason + " — indicator of synthetic or corrupted file, not proof of manual mapping";
            e.recommendation = "Inspect file with PE tool; verify it is a legitimate driver binary";
            ev.push_back(std::move(e));
        } else {
            // C1 — Section overlap
            {
                auto findings = CheckSectionOverlap(pe);
                Evidence e;
                e.check = "pe_section_overlap";
                e.provenance = "On-disk PE sections (no kernel memory)";
                if (findings.empty()) {
                    e.verdict = Verdict::Clean;
                    e.confidence = Confidence::High;
                    e.detail = "No section overlaps in virtual or raw space";
                    e.recommendation = "No action";
                } else {
                    bool hasRaw = false;
                    for (auto& f : findings) if (f.check == "section_overlap_raw") hasRaw = true;
                    e.verdict = Verdict::Suspicious;
                    e.confidence = hasRaw ? Confidence::High : Confidence::Medium;
                    e.detail = "Overlapping sections detected — consistent with hand-rolled manual mapper, not real linker output: " + JoinFindings(findings);
                    e.recommendation = "Compare section layout to vendor toolchain output; overlapping virtual sections are a strong synthetic indicator";
                }
                if (e.verdict != Verdict::Clean || findings.size()==0) ev.push_back(std::move(e));
                else ev.push_back(std::move(e));
            }
            // C2 — Section escapes image bounds
            {
                auto findings = CheckSectionEscapesImage(pe);
                Evidence e;
                e.check = "pe_section_escape";
                e.provenance = "On-disk PE SizeOfImage vs section VAs (no kernel memory)";
                if (findings.empty()) {
                    e.verdict = Verdict::Clean;
                    e.confidence = Confidence::High;
                    e.detail = "All sections within SizeOfImage";
                    e.recommendation = "No action";
                } else {
                    e.verdict = Verdict::Suspicious;
                    e.confidence = Confidence::High;
                    e.detail = "Section(s) escape SizeOfImage — consistent with manual-mapping artifact (image would be larger than declared): " + JoinFindings(findings);
                    e.recommendation = "Verify SizeOfImage and section VAs with PE tool; check for doctored header";
                }
                ev.push_back(std::move(e));
            }
            // C3 — Entry point sanity (FIX 4: DLLs skipped inside CheckEntryPoint)
            {
                // FIX 4: isDll check is inside CheckEntryPoint; if EP==0 on DLL, findings is empty → Clean.
                auto findings = CheckEntryPoint(pe);
                Evidence e;
                e.check = "pe_entry_point";
                e.provenance = "On-disk PE AddressOfEntryPoint vs sections (no kernel memory)";
                if (findings.empty()) {
                    e.verdict = Verdict::Clean;
                    e.confidence = Confidence::High;
                    e.detail = "AddressOfEntryPoint " + std::to_string(pe.address_of_entry_point) + " falls inside a section and within image";
                    e.recommendation = "No action";
                } else {
                    // Distinguish EP==0 Warn vs Suspicious
                    bool isZeroCase = (pe.address_of_entry_point == 0);
                    if (isZeroCase) {
                        // If has_driver_entry / imports/exports, zero is more suspicious
                        if (pe.has_driver_entry) {
                            e.verdict = Verdict::Suspicious;
                            e.confidence = Confidence::Medium;
                            e.detail = findings[0].detail + " — consistent with synthetic PE, indicator of tampering, not proof";
                            e.recommendation = "Check for DriverEntry in imports/exports; zero EP with executable content is unusual";
                        } else {
                            e.verdict = Verdict::Warn;
                            e.confidence = Confidence::Low;
                            e.detail = findings[0].detail + " — informational; may be legitimate for resource-only driver";
                            e.recommendation = "Verify driver type; if it should have DriverEntry, this is unusual";
                        }
                    } else {
                        e.verdict = Verdict::Suspicious;
                        e.confidence = Confidence::Medium;
                        e.detail = JoinFindings(findings) + " — consistent with tampered or synthetic PE";
                        e.recommendation = "Verify entry point with PE tool; check section layout";
                    }
                }
                ev.push_back(std::move(e));
            }
            // C4 — Section alignment
            {
                auto findings = CheckAlignment(pe);
                Evidence e;
                e.check = "pe_alignment";
                e.provenance = "On-disk PE SectionAlignment/FileAlignment (no kernel memory)";
                if (findings.empty()) {
                    e.verdict = Verdict::Clean;
                    e.confidence = Confidence::High;
                    e.detail = "SectionAlignment/FileAlignment and SizeOfImage alignment valid";
                    e.recommendation = "No action";
                } else if (findings.size() >= 2) {
                    e.verdict = Verdict::Suspicious;
                    e.confidence = Confidence::High;
                    e.detail = "Multiple alignment violations — consistent with hand-rolled PE, not legitimate toolchain: " + JoinFindings(findings);
                    e.recommendation = "Compare alignment fields to legitimate driver PE; hand-rolled PEs get this wrong";
                } else {
                    e.verdict = Verdict::Warn;
                    e.confidence = Confidence::Low;
                    e.detail = "Single alignment issue — possible minor toolchain quirk, but worth review: " + JoinFindings(findings);
                    e.recommendation = "Verify with PE tool; single minor violation may be benign";
                }
                ev.push_back(std::move(e));
            }
            // C5 — Checksum: restore severity. Non-zero mismatch IS a tamper indicator.
            // Tiered display (not downgrade) handles the flood; classification must reflect risk.
            {
                auto findings = CheckChecksum(pe);
                Evidence e;
                e.check = "pe_checksum";
                e.provenance = "On-disk PE CheckSum vs computed via imagehlp (no kernel memory)";
                if (findings.empty()) {
                    e.verdict = Verdict::Clean;
                    e.confidence = Confidence::High;
                    if (pe.header_checksum == 0) {
                        e.detail = "Header CheckSum is 0 — not computed (common, not flagged)";
                    } else {
                        e.detail = "Header CheckSum matches computed checksum";
                    }
                    e.recommendation = "No action";
                } else {
                    if (pe.header_checksum == 0) {
                        e.verdict = Verdict::Warn;
                        e.confidence = Confidence::Low;
                        e.detail = findings[0].detail + " — zero checksum on signed driver is unusual but not conclusive";
                        e.recommendation = "If driver claims to be signed, zero checksum is unusual; otherwise informational";
                    } else if (vr.status == SigStatus::Valid || IsMicrosoftSigned(vr)) {
                        e.verdict = Verdict::Suspicious;
                        e.confidence = Confidence::Medium;
                        e.detail = findings[0].detail + " — file modified after signing: checksum mismatch on a validated signature is a tamper indicator";
                        e.recommendation = "Do not run — remove or reinstall from vendor; file appears modified after signing";
                    } else {
                        e.verdict = Verdict::Warn;
                        e.confidence = Confidence::Medium;
                        e.detail = findings[0].detail + " — checksum mismatch on unsigned/unverified file; less conclusive without signature";
                        e.recommendation = "Verify file integrity; checksum mismatch without signature is less conclusive";
                    }
                }
                ev.push_back(std::move(e));
            }
            // C6 — FIX 1 plausible window: ts ==0 → Warn, ts outside [2000-01-01, now+30d] → Info, inside → Clean.
            // No high-bit heuristic, no signed-context branch.
            {
                auto findings = CheckTimestamp(pe);
                Evidence e;
                e.check = "pe_timestamp";
                e.provenance = "On-disk PE TimeDateStamp (no kernel memory)";
                if (findings.empty()) {
                    e.verdict = Verdict::Clean;
                    e.confidence = Confidence::High;
                    e.detail = "TimeDateStamp plausible (within 2000-01-01 to now+30d)";
                    e.recommendation = "No action";
                } else {
                    bool isZero = (findings.size()==1 && findings[0].detail.find("is 0") != std::string::npos);
                    bool isHash = (findings[0].detail.find("plausible reproducible-build hash") != std::string::npos);
                    if (isZero) {
                        e.verdict = Verdict::Warn;
                        e.confidence = Confidence::Low;
                        e.detail = findings[0].detail + (vr.status == SigStatus::Valid ? " — unusual for a signed driver" : "") + " — stripped timestamp, not proof of tampering";
                        e.recommendation = "Check if timestamp stripping is expected for this toolchain";
                    } else if (isHash) {
                        // FIX 1 Info tier: hash timestamp — not suspicious, not warn; Clean with provenance
                        e.verdict = Verdict::Clean;
                        e.confidence = Confidence::High;
                        e.detail = findings[0].detail;
                        e.recommendation = "Reproducible-build hash — expected for /Brepro builds; no action";
                    } else {
                        e.verdict = Verdict::Warn;
                        e.confidence = Confidence::Low;
                        e.detail = JoinFindings(findings);
                        e.recommendation = "Verify timestamp with PE tool";
                    }
                }
                ev.push_back(std::move(e));
            }
            // C7 — Section name sanity (informative, always Warn if any)
            {
                auto findings = CheckSectionNames(pe);
                Evidence e;
                e.check = "pe_section_name";
                e.provenance = "On-disk PE section names (no kernel memory)";
                if (findings.empty()) {
                    e.verdict = Verdict::Clean;
                    e.confidence = Confidence::High;
                    e.detail = "All section names match known-good patterns";
                    e.recommendation = "No action";
                } else {
                    e.verdict = Verdict::Warn;
                    e.confidence = Confidence::Low;
                    e.detail = "Unusual section name(s) — informational indicator, not proof of manual mapping: " + JoinFindings(findings);
                    e.recommendation = "Compare section names to legitimate compiler output; garbage names may indicate packing or synthetic PE";
                }
                ev.push_back(std::move(e));
            }
        }

        auto report = risk::MakeReport(d, std::move(ev));
        reports.push_back(std::move(report));
    }

    // v0.4 Sections 1-4: context (S10), candidates (S1 orphaned), surface coverage, not-covered.
    // In default mode sections print to stdout before the driver table; in --json they go into JSON.
    // Keep existing driver reports for the table/JSON below; sections are additive.
    ObjScanResult obj{}; SigContext sig{};
    {
        obj = ScanObjectManager();
        sig = QuerySigContext();
        // Cross-ref orphaned: driver objects with no loaded-module filename match
        // ScanObjectManager leaves orphaned empty; compute here against drivers.
        std::vector<std::string> loadedLower;
        for(auto& d: drivers) loadedLower.push_back(ToLowerStrMain(d.fileName));
        std::vector<std::string> orphaned;
        for(auto& dn: obj.driverNames){
            std::string dl = ToLowerStrMain(dn);
            // Match: driver object name often equals service name, which is filename minus .sys
            bool found=false;
            for(auto& ll: loadedLower){
                std::string base = ll; size_t dot=base.rfind('.'); if(dot!=std::string::npos) base=base.substr(0,dot);
                if(ll==dl || base==dl || ll.find(dl)!=std::string::npos) found=true;
            }
            if(!found) orphaned.push_back(dn);
        }
        obj.orphaned = orphaned;
        // Promote orphaned objects into the main driver table as Source=orphaned rows
        // so the table itself distinguishes in-memory (PsLoadedModuleList) vs
        // manual-map candidates (\Driver\ without a loaded module).
        for(auto& n : orphaned){
            DriverInfo di;
            di.fileName = n;
            di.kernelPath = "\\Driver\\" + n;
            di.normalizedPath = "";
            di.baseHex = "-";
            di.baseAddress = nullptr;
            di.kernelImageSize = 0;
            di.source = DriverSource::Orphaned;
            Evidence ev;
            ev.check = "driver_object";
            ev.verdict = Verdict::Warn;
            ev.confidence = Confidence::Low;
            ev.detail = "Orphaned \\Driver\\" + n + " with no PsLoadedModuleList entry — possible manual-mapped driver or stale object (Low confidence; not proof of manual mapping)";
            ev.provenance = "Object Manager (NtOpenDirectoryObject \\Driver\\) vs PsLoadedModuleList (EnumDeviceDrivers/NtQuerySystemInformation)";
            ev.recommendation = "Cross-ref with handles (--pid), Amcache, prefetch; if no other surface corroborates, likely stale/legacy object";
            std::vector<Evidence> evs{ev};
            auto rep = risk::MakeReport(di, std::move(evs));
            rep.overallConfidence = Confidence::Low; // keep Low for orphaned-only signal
            reports.push_back(std::move(rep));
        }
        if(!jsonOut){
            fprintf(stdout, "Section 1 — Context\n");
            std::string hdr = SigContextHeader(sig);
            fprintf(stdout, "%s", hdr.c_str());
            fprintf(stdout, "\nSection 2 — Manual-mapped driver candidates\n");
            if(orphaned.empty()){
                fprintf(stdout, "  No orphaned driver objects — no candidates above Low confidence.\n");
            } else {
                fprintf(stdout, "  Orphaned driver objects (%zu) — also listed in the driver table with Source=orphaned:\n", orphaned.size());
                for(auto& n: orphaned) fprintf(stdout, "    \\Driver\\%s  [orphaned object only — Low confidence]\n", n.c_str());
                fprintf(stdout, "  Confidence: Low — orphaned object alone is not proof of manual mapping.\n");
                fprintf(stdout, "  Tip: cross-ref with handles (S2), Amcache (S5), prefetch (S6) for corroboration.\n");
            }
            fprintf(stdout, "\nSection 3 — Surface coverage\n");
            fprintf(stdout, "  Object manager:  %d driver objects, %d device objects%s\n", obj.driverObjects, obj.deviceObjects, obj.error.empty()?"":(" ("+obj.error+")").c_str());
            if(!orphaned.empty()) fprintf(stdout, "    orphaned: %zu\n", orphaned.size());
            fprintf(stdout, "  Global handles:  (S2 handletable — pending)\n");
            fprintf(stdout, "  Code Integrity:  (S3 wevtapi — pending)\n");
            fprintf(stdout, "  Amcache:         (S5 — pending)\n");
            fprintf(stdout, "  Prefetch:        (S6 — pending)\n");
            fprintf(stdout, "  Sysmon:          %s\n", sig.sysmonInstalled?"installed — pending":"not installed");
            fprintf(stdout, "  Boot log:        (S9 — pending)\n");
            fprintf(stdout, "  Defender:        (S8 — pending)\n");
        }
    }

    std::stable_sort(reports.begin(), reports.end(), [](const DriverReport& a, const DriverReport& b){
        // Keep orphaned rows grouped after in-memory ones when verdict equal — then by name
        if (a.overall != b.overall) return (int)a.overall > (int)b.overall;
        if (a.driver.source != b.driver.source) return (int)a.driver.source < (int)b.driver.source;
        return a.driver.fileName < b.driver.fileName;
    });

    if(!jsonOut) fprintf(stdout, "\n=== Driver audit (driver table — Source=memory is PsLoadedModuleList, Source=orphaned is \\Driver\\ without a loaded module) ===\n");
    if (jsonOut) {
        PrintJson(reports, &bl, stdout, redactPaths, "0.4.0", "0.2.0");
    } else {
        PrintTable(reports, stdout, verbose);
    }

    if(!jsonOut){
        fprintf(stdout, "\nSection 4 — What this scan did NOT cover\n");
        fprintf(stdout, "  Manual-mapped drivers that registered no objects, left no Amcache/prefetch entry,\n");
        fprintf(stdout, "  and were loaded after the last code-integrity event are pure-payload kernel patches.\n");
        fprintf(stdout, "  Detecting them requires kernel memory reads, which user mode cannot do.\n");
        fprintf(stdout, "  On HVCI:ON this class is blocked for unsigned code (barring HVCI bypass).\n");
        fprintf(stdout, "  On HVCI:OFF this class is possible and this tool will not detect it.\n");
        fprintf(stdout, "  No candidates found = no visible candidates, not proof nothing happened.\n");
    }

    Verdict ov = OverallVerdict(reports);
    if (legacyExitCodes) {
        if (ov == Verdict::Suspicious) return 2;
        if (ov == Verdict::Warn) return 1;
        return 0;
    }
    if (strictMode) {
        if (ov == Verdict::Suspicious || ov == Verdict::Warn) return 2;
        return 0;
    }
    if (ov == Verdict::Suspicious) return 2;
    if (ov == Verdict::Warn) return 1;
    return 0;
}
