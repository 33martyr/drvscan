#pragma once
#include <string>
namespace drvscan {
struct DefenderStats { int threats=0; bool tamperProtection=false; std::string error; };
DefenderStats QueryDefender();
}
