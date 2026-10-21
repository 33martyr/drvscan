#include "defender.h"
#include <windows.h>
namespace drvscan {
DefenderStats QueryDefender(){
    DefenderStats s;
    s.error="WMI MSFT_MpThreatDetection query pending";
    return s;
}
}
