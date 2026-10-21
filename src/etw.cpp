#include "etw.h"
namespace drvscan {
EtwStats ScanKernelEtw(int){ EtwStats s; s.error="ETW kernel providers pending (EtwEventRegister/ProcessTrace)"; return s; }
}
