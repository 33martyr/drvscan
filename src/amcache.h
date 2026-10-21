#pragma once
#include <string>
namespace drvscan {
struct AmcacheStats { int driverEntries=0; int loldriversMatches=0; std::string error; };
AmcacheStats ScanAmcache();
}
