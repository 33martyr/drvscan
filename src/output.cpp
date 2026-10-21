#include "output.h"
#include "handles.h"
#include "devmap.h"
#include "blocklist.h"
#include <nlohmann/json.hpp>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <tuple>
#include <unordered_map>

namespace drvscan {

Verdict OverallVerdict(const std::vector<DriverReport>& reports) {
    Verdict v = Verdict::Clean;
    for (auto& r : reports) v = MaxVerdict(v, r.overall);
    return v;
}

static std::string RedactUsername(const std::string& path, bool doRedact) {
    if (!doRedact || path.empty()) return path;
    std::string low = path;
    for (char& ch : low) ch = (char)std::tolower((unsigned char)ch);
    const std::string needle = "\\users\\";
    size_t pos = low.find(needle);
    if (pos == std::string::npos) return path;
    size_t start = pos + needle.size();
    size_t end = path.find('\\', start);
    if (end == std::string::npos) end = path.find('/', start);
    if (end == std::string::npos) return path;
    return path.substr(0, start) + "<user>" + path.substr(end);
}

static const char* SourceLabel(DriverSource s) {
    return s == DriverSource::Orphaned ? "orphaned" : "memory";
}

void PrintTable(const std::vector<DriverReport>& reports, FILE* out, bool verbose) {
    fprintf(out, "%-18s %-8s %-11s %-8s %-9s %-30s %s\n", "Base", "Size", "Verdict", "Conf", "Source", "File", "Evidence");
    fprintf(out, "%-18s %-8s %-11s %-8s %-9s %-30s %s\n", "------------------", "--------", "-----------", "--------", "---------", "------------------------------", "--------");
    for (auto& r : reports) {
        std::string evStr;
        if (r.evidence.empty()) {
            evStr = "-";
        } else {
            bool first = true;
            for (auto& e : r.evidence) {
                if (!verbose && e.verdict == Verdict::Clean) continue;
                if (!first) evStr += " | ";
                first = false;
                evStr += e.check + ":" + ToString(e.verdict) + "(" + e.detail;
                if (!e.provenance.empty()) evStr += " [" + e.provenance + "]";
                evStr += ")";
            }
            if (evStr.empty()) evStr = "(all checks clean; --verbose to show)";
        }
        std::string fn = r.driver.fileName;
        if (fn.size() > 30) fn = fn.substr(0, 27) + "...";
        fprintf(out, "%-18s %-8u %-11s %-8s %-9s %-30s %s\n",
                r.driver.baseHex.c_str(),
                r.driver.kernelImageSize,
                ToString(r.overall),
                ToString(r.overallConfidence),
                SourceLabel(r.driver.source),
                fn.c_str(),
                evStr.c_str());
        if (!r.summary.empty() && r.overall != Verdict::Clean) {
            fprintf(out, "  -> %s\n", r.summary.c_str());
            if (!r.nextStep.empty()) fprintf(out, "     next: %s\n", r.nextStep.c_str());
        }
    }
    int clean = 0, warn = 0, susp = 0, cntOrphaned = 0, cntMemory = 0;
    for (auto& r : reports) {
        if (r.overall == Verdict::Clean) ++clean;
        else if (r.overall == Verdict::Warn) ++warn;
        else ++susp;
        if (r.driver.source == DriverSource::Orphaned) ++cntOrphaned;
        else ++cntMemory;
    }
    fprintf(out, "\n%d drivers (%d memory, %d orphaned): %d clean, %d warn, %d suspicious\n",
            (int)reports.size(), cntMemory, cntOrphaned, clean, warn, susp);
    if (susp > 0) fprintf(out, "Note: 'suspicious' is not 'malicious' — see LIMITATIONS.md and per-finding confidence.\n");
    if (cntOrphaned > 0) fprintf(out, "Note: Source=orphaned means a \\Driver\\ object with no PsLoadedModuleList entry (possible manual map / legacy object).\n");
}

void PrintTable(const std::vector<DriverReport>& reports, FILE* out) {
    PrintTable(reports, out, false);
}

static std::string IsoNow() {
    time_t t = time(nullptr);
    struct tm tmv{};
    gmtime_s(&tmv, &t);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tmv);
    return buf;
}

void PrintJson(const std::vector<DriverReport>& reports, const Blocklist* blocklist, FILE* out, bool redactPaths, const std::string& toolVersion, const std::string& blocklistSchemaVersion) {
    nlohmann::json j;
    j["generated_at"] = IsoNow();
    j["tool_version"] = toolVersion;
    j["blocklist_schema_version"] = blocklistSchemaVersion;
    j["driver_count"] = reports.size();
    if (blocklist) {
        j["blocklist_version"] = blocklist->version();
        j["blocklist_snapshot_date"] = blocklist->snapshotDate();
        j["blocklist_is_sample"] = blocklist->isSample();
        j["blocklist_schema_version"] = blocklist->schemaVersion().empty() ? blocklistSchemaVersion : blocklist->schemaVersion();
        j["blocklist_sources"] = blocklist->sources();
    }
    int clean = 0, warn = 0, susp = 0;
    for (auto& r : reports) {
        if (r.overall == Verdict::Clean) ++clean;
        else if (r.overall == Verdict::Warn) ++warn;
        else ++susp;
    }
    {
        nlohmann::json summ;
        summ["clean"] = clean;
        summ["warn"] = warn;
        summ["suspicious"] = susp;
        j["summary"] = summ;
    }
    j["disclaimer"] = std::string("suspicious is not malicious; see LIMITATIONS.md; valid signature does not imply safe; cert hits are signals not proof of compromise");
    nlohmann::json arr = nlohmann::json::array();
    for (auto& r : reports) {
        nlohmann::json o;
        o["base"] = r.driver.baseHex;
        o["imageSize"] = r.driver.kernelImageSize;
        o["kernelPath"] = redactPaths ? RedactUsername(r.driver.kernelPath, true) : r.driver.kernelPath;
        o["normalizedPath"] = redactPaths ? RedactUsername(r.driver.normalizedPath, true) : r.driver.normalizedPath;
        o["fileName"] = r.driver.fileName;
        o["source"] = SourceLabel(r.driver.source);
        o["verdict"] = ToString(r.overall);
        o["confidence"] = ToString(r.overallConfidence);
        o["summary"] = r.summary;
        o["next_step"] = r.nextStep;
        nlohmann::json checks = nlohmann::json::array();
        for (auto& e : r.evidence) {
            nlohmann::json c;
            c["check"] = e.check;
            c["verdict"] = ToString(e.verdict);
            c["confidence"] = ToString(e.confidence);
            c["detail"] = redactPaths ? RedactUsername(e.detail, true) : e.detail;
            c["provenance"] = redactPaths ? RedactUsername(e.provenance, true) : e.provenance;
            c["recommendation"] = e.recommendation;
            if (!e.fields.empty()) {
                nlohmann::json fields = nlohmann::json::object();
                for (auto& kv : e.fields) fields[kv.first] = redactPaths ? RedactUsername(kv.second, true) : kv.second;
                c["fields"] = fields;
            }
            checks.push_back(c);
        }
        o["checks"] = checks;
        arr.push_back(o);
    }
    j["drivers"] = arr;
    std::string s = j.dump(2);
    fwrite(s.c_str(), 1, s.size(), out);
    fputc('\n', out);
}

void PrintJson(const std::vector<DriverReport>& reports, const Blocklist* blocklist, FILE* out) {
    PrintJson(reports, blocklist, out, false, "0.2.0", "0.2.0");
}

void PrintPidTable(FILE* out, const std::string& procLabel, DWORD pid, const std::vector<DeviceHandle>& handles, const std::vector<DriverReport>& reports, bool verbose) {
    fprintf(out, "=== %s (pid %u) ===\n", procLabel.c_str(), (unsigned)pid);
    if (handles.empty()) { fprintf(out, "(no device handles)\n\n"); return; }
    fprintf(out, "%-27s %-18s %-8s %-11s %-8s %-9s %s\n", "Device", "Base", "Size", "Verdict", "Conf", "Source", "File");
    fprintf(out, "%-27s %-18s %-8s %-11s %-8s %-9s %s\n", "---------------------------", "------------------", "--------", "-----------", "--------", "---------", "----------------");
    for (size_t i=0;i<reports.size();++i){
        const auto& r = reports[i];
        std::string dev = (i<handles.size()) ? handles[i].device_path : "";
        if(dev.size()>27) dev=dev.substr(0,24)+"...";
        std::string fn=r.driver.fileName; if(fn.size()>22) fn=fn.substr(0,19)+"...";
        std::string ev;
        if(r.evidence.empty()) ev="-";
        else { bool first=true; for(auto& e:r.evidence){ if(!verbose && e.verdict==Verdict::Clean) continue; if(!first) ev+=" | "; first=false; ev+=e.check+":"+ToString(e.verdict)+"("+e.detail+")"; } if(ev.empty()) ev="(clean)"; }
        fprintf(out, "%-27s %-18s %-8u %-11s %-8s %-9s %s\n", dev.c_str(), r.driver.baseHex.c_str(), r.driver.kernelImageSize, ToString(r.overall), ToString(r.overallConfidence), SourceLabel(r.driver.source), fn.c_str());
        if(!ev.empty() && ev!="(clean)") fprintf(out, "  %s\n", ev.c_str());
        if(!r.nextStep.empty() && r.overall!=Verdict::Clean) fprintf(out, "  next: %s\n", r.nextStep.c_str());
    }
    if(reports.size() < handles.size()){
        for(size_t i=reports.size(); i<handles.size(); ++i){
            fprintf(out, "%-27s %-18s %-8s %-11s %-8s %-9s %s\n", handles[i].device_path.c_str(), "-", "-", "unknown", "-", "-", "<unmapped>");
        }
    }
    fprintf(out, "\n");
}

int WritePidJson(FILE* out, const Blocklist* blocklist, bool redactPaths, const std::string& toolVersion, const std::string& blocklistSchema,
                 const std::vector<std::tuple<std::string,DWORD,std::vector<DeviceHandle>,std::vector<DriverReport>>>& perPid, const std::string& queryName) {
    nlohmann::json root; root["generated_at"]=IsoNow(); root["tool_version"]=toolVersion; root["blocklist_schema_version"]=blocklistSchema;
    if(blocklist){ root["blocklist_version"]=blocklist->version(); root["blocklist_is_sample"]=blocklist->isSample(); root["blocklist_sources"]=blocklist->sources(); }
    root["query"]=queryName; root["disclaimer"]=std::string("suspicious is not malicious; handles do not prove intent — handles prove open device, not malice; see LIMITATIONS.md");
    nlohmann::json arr=nlohmann::json::array();
    int totalDevices=0; std::unordered_map<std::string,int> uniqDrivers; int clean=0,warn=0,susp=0; int unmapped=0;
    for(const auto& t: perPid){
        const std::string& label=std::get<0>(t);
        DWORD pid=std::get<1>(t);
        const std::vector<DeviceHandle>& handles=std::get<2>(t);
        const std::vector<DriverReport>& reports=std::get<3>(t);
        nlohmann::json entry; entry["process"]=label; entry["pid"]=pid;
        nlohmann::json devs=nlohmann::json::array();
        for(const auto& h: handles){ nlohmann::json d; d["device"]=redactPaths?RedactUsername(h.device_path,true):h.device_path; d["access_mask"]=h.access_mask; devs.push_back(d); }
        entry["devices"]=devs;
        nlohmann::json reps=nlohmann::json::array();
        for(const auto& r: reports){
            nlohmann::json o; o["base"]=r.driver.baseHex; o["imageSize"]=r.driver.kernelImageSize;
            o["kernelPath"]=redactPaths?RedactUsername(r.driver.kernelPath,true):r.driver.kernelPath;
            o["fileName"]=r.driver.fileName; o["source"]=SourceLabel(r.driver.source); o["verdict"]=ToString(r.overall); o["confidence"]=ToString(r.overallConfidence);
            o["summary"]=r.summary; o["next_step"]=r.nextStep;
            nlohmann::json chs=nlohmann::json::array();
            for(const auto& e:r.evidence){ nlohmann::json c; c["check"]=e.check; c["verdict"]=ToString(e.verdict); c["confidence"]=ToString(e.confidence);
                c["detail"]=redactPaths?RedactUsername(e.detail,true):e.detail; c["provenance"]=e.provenance; c["recommendation"]=e.recommendation; if(!e.fields.empty()){ nlohmann::json f=nlohmann::json::object(); for(auto& kv:e.fields) f[kv.first]=kv.second; c["fields"]=f; } chs.push_back(c); }
            o["checks"]=chs;
            nlohmann::json darr=nlohmann::json::array();
            for(const auto& h: handles){
                std::string mapped2 = ResolveDeviceToDriver(h.device_path);
                std::string lowMapped=mapped2, lowFile=r.driver.fileName;
                for(char& c: lowMapped) c=(char)std::tolower((unsigned char)c);
                for(char& c: lowFile) c=(char)std::tolower((unsigned char)c);
                if(!lowMapped.empty() && lowMapped==lowFile) darr.push_back(redactPaths?RedactUsername(h.device_path,true):h.device_path);
            }
            o["devices"]=darr;
            reps.push_back(o);
            uniqDrivers[r.driver.fileName]++;
            if(r.overall==Verdict::Clean) clean++; else if(r.overall==Verdict::Warn) warn++; else susp++;
        }
        entry["drivers"]=reps;
        arr.push_back(entry);
        totalDevices+=(int)handles.size();
        if((int)handles.size() > (int)reports.size()) unmapped += (int)handles.size() - (int)reports.size();
    }
    root["processes"]=arr;
    root["aggregate"]=nlohmann::json{{"total_devices",totalDevices},{"unique_drivers",(int)uniqDrivers.size()},{"clean",clean},{"warn",warn},{"suspicious",susp},{"unmapped_devices",unmapped}};
    std::string s=root.dump(2); fwrite(s.c_str(),1,s.size(),out); fputc('\n',out);
    return susp?2:(warn?1:0);
}

} // namespace drvscan
