#include "KeInterface.h"
#include "Tools.h"

int main() {
	KeInterface Driver("\\\\.\\tsunami", Tools::GetProcessID("Dummy.exe"));
	Driver.Unload();
	getchar();
	ULONG64 moduleBase;
	if (Driver.GetModuleBase(L"Dummy.exe", &moduleBase)) {
		std::cout << "0x" << std::hex << moduleBase << "\n";
	}
	else {
		std::cout << "GetModuleBase failed.\n";
	}
	
	/*std::cout << std::dec << Driver.Read<int>(0xfc776ff828) << "\n";
	std::cout << Driver.Read<float>(0xfc776ff82c) << "\n";
	Driver.Write<int>(0xfc776ff828, 234234231);*/

	Driver.Unload();
	getchar();
	return 0;
}