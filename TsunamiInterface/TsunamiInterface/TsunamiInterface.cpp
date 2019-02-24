#include "KeInterface.h"
#include "Tools.h"

int main() {
	KeInterface Driver("\\\\.\\tsunami", Tools::GetProcessID("notepad.exe"));

	ULONG64 moduleBase;
	if (Driver.GetModuleBase(L"kernel32.dll", &moduleBase)) {
		std::cout << "0x" << std::hex << moduleBase << "\n";
	}
	else {
		std::cout << "GetModuleBase failed.\n";
	}
	
	std::cout << Driver.Read<int>(0x9BA06FFA08) << "\n";
	std::cout << Driver.Read<float>(0x9BA06FFA0C) << "\n";
	Driver.Write<int>(0x9BA06FFA08, 234234231);

	Driver.UnloadDriver();
	getchar();
	return 0;
}