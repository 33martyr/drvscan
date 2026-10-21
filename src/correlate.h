#pragma once
#include <string>
#include <vector>
#include "objscan.h"
#include "handletable.h"
#include "eventlog.h"
#include "amcache.h"
#include "prefetch.h"
#include "bootlog.h"
#include "defender.h"
#include "etw.h"
#include "sigcontext.h"

namespace drvscan {

struct Candidate {
    std::string driverObject; // \Driver\Name
    std::string confidence; // Low/Medium/High/Very High
    std::vector<std::string> surfaces; // which S corroborated
    std::string blocklistMatch; // loldrivers entry if any
    std::string recommendation;
};

struct CorrelatedResult {
    std::vector<Candidate> candidates;
    struct Coverage
    { int driverObjects=0; int deviceObjects=0; int orphaned=0;
      int handles=0; int codeIntegrity=0; int amcache=0; int prefetch=0;
      bool sysmon=false; bool defender=false; bool bootlog=false; bool etw=false;
      std::string notes;
    } coverage;
};

CorrelatedResult CorrelateAll(
    const ObjScanResult& obj,
    const HandleTableStats& ht,
    const EventLogStats& ci,
    const EventLogStats& sysmon,
    const AmcacheStats& amcache,
    const PrefetchStats& prefetch,
    const BootLogStats& boot,
    const DefenderStats& defender,
    const EtwStats& etw,
    const SigContext& sig);

} // namespace drvscan
