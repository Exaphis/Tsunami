#pragma once

#include <Windows.h>
#include <iostream>

#define SHARED_MEMORY_NUM_BYTES 4 * 1024 * 1024

enum Operation {
	Read,
	Write,
	GetModule,
	Unload
};

struct _KERNEL_OPERATION_REQUEST
{
	Operation operationType;
	BOOLEAN success;
	ULONG64 processID;
	ULONG64 address;
	SIZE_T size;
	UCHAR data[SHARED_MEMORY_NUM_BYTES];
};

typedef _KERNEL_OPERATION_REQUEST* PKERNEL_OPERATION_REQUEST;

class KeInterface
{
public:
	HANDLE hRequestEvent;
	HANDLE hCompletionEvent;
	HANDLE hFileMapping;

	LPVOID sharedMemoryBuffer;
	PKERNEL_OPERATION_REQUEST request;

	ULONG64 pid;

	KeInterface(LPCSTR RegistryPath, ULONG64 inPid)
	{
		pid = inPid;

		// Initialize event handles
		hRequestEvent = OpenEvent(EVENT_ALL_ACCESS, FALSE, "Global\\TsunamiSharedRequestEvent");
		if (hRequestEvent == INVALID_HANDLE_VALUE) {
			std::cout << "[-] OpenEvent (TsunamiSharedRequestEvent) failed, Error: " << std::dec << GetLastError() << "\n";
			throw std::runtime_error("Failed to load driver interface.");
		}

		hCompletionEvent = OpenEvent(EVENT_ALL_ACCESS, FALSE, "Global\\TsunamiSharedCompletionEvent");
		if (hCompletionEvent == INVALID_HANDLE_VALUE) {
			std::cout << "[-] OpenEvent (TsunamiSharedCompletionEvent) failed, Error: " << std::dec << GetLastError() << "\n";
			throw std::runtime_error("Failed to load driver interface.");
		}

		// Map shared memory
		hFileMapping = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, "Global\\TsunamiSharedMemory");
		if (hFileMapping == INVALID_HANDLE_VALUE) {
			std::cout << "[-] OpenFileMappingA failed, Error: " << std::dec << GetLastError() << "\n";
			throw std::runtime_error("Failed to load driver interface.");
		}

		sharedMemoryBuffer = MapViewOfFile(hFileMapping, FILE_MAP_WRITE, 0, 0, sizeof(_KERNEL_OPERATION_REQUEST));
		if (!sharedMemoryBuffer) {
			std::cout << "[-] MapViewOfFile failed, Error: " << std::dec << GetLastError() << "\n";
			throw std::runtime_error("Failed to load driver interface.");
		}

		CloseHandle(hFileMapping);

		request = (PKERNEL_OPERATION_REQUEST)sharedMemoryBuffer;
	}

	~KeInterface() {
		UnmapViewOfFile(sharedMemoryBuffer);
	}

	bool ReadVirtualMemory(ULONG64 readAddress, UCHAR* buffer, SIZE_T size)
	{
		if (size > sizeof(request->data))
			return false;

		request->operationType = Operation::Read;
		request->processID = pid;
		request->address = readAddress;
		request->size = size;

		SetEvent(hRequestEvent);
		WaitForSingleObject(hCompletionEvent, INFINITE);
		ResetEvent(hCompletionEvent);

		if (request->success) {
			memcpy(buffer, request->data, size);
			return true;
		}
		return false;
	}

	bool WriteVirtualMemory(ULONG64 writeAddress, UCHAR* buffer, SIZE_T size)
	{
		if (size > sizeof(request->data))
			return false;

		request->operationType = Operation::Write;
		request->processID = pid;
		request->address = writeAddress;
		request->size = size;
		memcpy(request->data, buffer, size);

		SetEvent(hRequestEvent);
		WaitForSingleObject(hCompletionEvent, INFINITE);
		ResetEvent(hCompletionEvent);

		return request->success;
	}

	bool GetModuleBase(LPCWSTR moduleName, ULONG64* base) {
		request->operationType = Operation::GetModule;
		request->processID = pid;
		wcscpy_s((wchar_t*)request->data, sizeof(request->data), moduleName);

		SetEvent(hRequestEvent);
		WaitForSingleObject(hCompletionEvent, INFINITE);
		ResetEvent(hCompletionEvent);

		*base = *(ULONG64*)request->data;

		return request->success;
	}

	void UnloadDriver() {
		request->operationType = Operation::Unload;
		SetEvent(hRequestEvent);
	}

	template <typename type>
	type Read(ULONG64 readAddress)
	{
		UCHAR buffer[sizeof(type)];
		if (ReadVirtualMemory(readAddress, buffer, sizeof(type)))
			return *(type*)buffer;
		throw std::runtime_error("Read failed.");
		return *(type*)buffer;
	}

	template <typename type>
	type Read(ULONG64 readAddress, bool* success)
	{
		UCHAR buffer[sizeof(type)];
		*success = ReadVirtualMemory(readAddress, buffer, sizeof(type));
		return *(type*)buffer;
	}


	template <typename type>
	bool Write(ULONG64 address, type buffer)
	{
		return WriteVirtualMemory(address, (UCHAR*)&buffer, sizeof(type));
	}
};