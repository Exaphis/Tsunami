#include "KeInterface.h"
#include "Tools.h"

#include <chrono>

class Timer
{
public:
	Timer() : beg_(clock_::now()) {}
	void reset() { beg_ = clock_::now(); }
	double elapsed() const {
		return std::chrono::duration_cast<second_>
			(clock_::now() - beg_).count();
	}

private:
	typedef std::chrono::high_resolution_clock clock_;
	typedef std::chrono::duration<double, std::ratio<1> > second_;
	std::chrono::time_point<clock_> beg_;
};

int main() {
	KeInterface Driver("\\\\.\\tsunami", Tools::GetProcessID("Dummy.exe"));
	/*ULONG64 moduleBase;
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
	*/
	
	Timer timer;
	int loops = 5000000;

	UCHAR buffer[4096];

	// Test read speed
	timer.reset();
	for (int i = 0; i < loops; i++) {
		Driver.ReadVirtualMemory(0xB7001DF678, buffer, 4);
	}
	std::cout << "Driver read took " << timer.elapsed() << "s.\n";

	timer.reset();
	for (int i = 0; i < loops; i++) {
		if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)&loops, (LPVOID)buffer, 4, NULL)) {
			std::cout << GetLastError() << "\n";
			break;
		}
	}
	std::cout << "RPM took " << timer.elapsed() << "s.\n";
	std::cout << *(int*)buffer << "\n";
	getchar();

	getchar();

	return 0;
}