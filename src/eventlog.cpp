#include "eventlog.h"
#include <windows.h>
#include <winevt.h>
namespace drvscan {
EventLogStats ScanCodeIntegrityLog(int lookbackHours){
    (void)lookbackHours;
    EventLogStats s;
    EVT_HANDLE h=EvtQuery(nullptr, L"Microsoft-Windows-CodeIntegrity/Operational", nullptr, EvtQueryChannelPath);
    if(h){ s.error="wevtapi query pending wiring"; EvtClose(h); } else s.error="CodeIntegrity log not accessible";
    return s;
}
EventLogStats ScanSysmonLog(int){
    EventLogStats s;
    EVT_HANDLE h=EvtQuery(nullptr, L"Microsoft-Windows-Sysmon/Operational", nullptr, EvtQueryChannelPath);
    if(h){ s.error="wevtapi pending"; EvtClose(h);} else s.error="Sysmon not installed or wevtapi pending";
    return s;
}
}
