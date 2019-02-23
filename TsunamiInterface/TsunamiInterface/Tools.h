#pragma once
#include <Windows.h>
#include <TlHelp32.h>

namespace Tools {
	DWORD GetProcessID(const char* processName);
	MODULEENTRY32 GetModule(const char* moduleName, uintptr_t processID);
	bool gluInvertMatrix(const float m[16], float invOut[16]);
}