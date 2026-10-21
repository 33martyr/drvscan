#pragma once
#include <string>
namespace drvscan {
struct EventLogStats { int integrityBlocks=0; int sysmonLoads=0; std::string error; int scanned=0; };
EventLogStats ScanCodeIntegrityLog(int lookbackHours=24);
EventLogStats ScanSysmonLog(int lookbackHours=24);
}
