#include "correlate.h"
namespace drvscan {
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
    const SigContext& /*sig*/){
    CorrelatedResult r;
    r.coverage.driverObjects=obj.driverObjects;
    r.coverage.deviceObjects=obj.deviceObjects;
    r.coverage.orphaned=(int)obj.orphaned.size();
    r.coverage.handles=ht.totalHandles;
    r.coverage.codeIntegrity=ci.integrityBlocks;
    r.coverage.amcache=amcache.driverEntries;
    r.coverage.prefetch=prefetch.files;
    r.coverage.bootlog=boot.exists;
    // Build candidates from orphaned driver objects
    for(auto& name: obj.orphaned){
        Candidate c; c.driverObject="\\Driver\\"+name; c.confidence="Low";
        c.surfaces.push_back("S1 orphaned object");
        // Cross-ref against Amcache etc. would bump confidence here
        c.recommendation="hash the on-disk file, remove if not needed; check with --pid for handle corroboration";
        r.candidates.push_back(std::move(c));
    }
    (void)sysmon; (void)defender; (void)etw;
    return r;
}
}
