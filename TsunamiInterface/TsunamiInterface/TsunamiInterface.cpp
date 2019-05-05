#include "KeInterface.h"
#include "Tools.h"

int main() {
	KeInterface Driver("\\\\.\\tsunami", Tools::GetProcessID("Dummy.exe"));
	ULONG64 moduleBase;
	if (Driver.GetModuleBase(L"Dummy.exe", &moduleBase)) {
		std::cout << "0x" << std::hex << moduleBase << "\n";
	}
	else {
		std::cout << "GetModuleBase failed.\n";
	}
	
	std::cout << std::dec << Driver.Read<int>(0xc6774ffd08) << "\n";
	std::cout << Driver.Read<float>(0xc6774ffd0c) << "\n";
	Driver.Write<int>(0xc6774ffd08, 234234231);

	Driver.Unload();
	getchar();
	return 0;
}