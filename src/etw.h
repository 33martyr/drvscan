#pragma once
#include <string>
namespace drvscan {
struct EtwStats { int driverLoadEvents=0; std::string error; };
EtwStats ScanKernelEtw(int lookbackMinutes=5);
}
