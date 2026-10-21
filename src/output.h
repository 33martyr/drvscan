#pragma once
#include "types.h"
#include <windows.h>
#include <cstdio>
#include <vector>
#include <string>
#include <tuple>

namespace drvscan {
class Blocklist;
struct DeviceHandle;
struct DriverReport;
void PrintTable(const std::vector<DriverReport>& reports, FILE* out);
void PrintTable(const std::vector<DriverReport>& reports, FILE* out, bool verbose);
void PrintJson(const std::vector<DriverReport>& reports, const Blocklist* blocklist, FILE* out);
void PrintJson(const std::vector<DriverReport>& reports, const Blocklist* blocklist, FILE* out, bool redactPaths, const std::string& toolVersion, const std::string& blocklistSchemaVersion);
Verdict OverallVerdict(const std::vector<DriverReport>& reports);
// --pid helpers
void PrintPidTable(FILE* out, const std::string& procLabel, DWORD pid,
                   const std::vector<DeviceHandle>& handles,
                   const std::vector<DriverReport>& reports, bool verbose);
int WritePidJson(FILE* out, const Blocklist* blocklist, bool redactPaths,
                 const std::string& toolVersion, const std::string& blocklistSchema,
                 const std::vector<std::tuple<std::string,DWORD,std::vector<DeviceHandle>,std::vector<DriverReport>>>& perPid,
                 const std::string& queryName);
} // namespace drvscan
