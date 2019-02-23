#include "KeInterface.h"
#include "Tools.h"

int main() {
	KeInterface Driver("\\\\.\\tsunami", Tools::GetProcessID("Dummy.exe"));

	std::cout << Driver.Read<int>(0x9BA06FFA08) << "\n";
	std::cout << Driver.Read<float>(0x9BA06FFA0C) << "\n";
	Driver.Write<int>(0x9BA06FFA08, 234234231);
	getchar();
	return 0;
}