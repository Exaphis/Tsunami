#include <ntifs.h>
#include <windef.h>

#ifdef DEBUG
#define DPRINT(...) DbgPrintEx(0, 0, __VA_ARGS__)
#else
#define DPRINT(...)
#endif
#define SHARED_MEMORY_NUM_BYTES 4 * 1024 * 1024

NTKERNELAPI NTSTATUS MmCopyVirtualMemory(
	IN PEPROCESS		SourceProcess,
	IN PVOID			SourceAddress,
	IN PEPROCESS		TargetProcess,
	IN PVOID			TargetAddress,
	IN SIZE_T			BufferSize,
	IN KPROCESSOR_MODE  PreviousMode,
	OUT PSIZE_T			ReturnSize
);

NTKERNELAPI PPEB NTAPI PsGetProcessPeb(
	__in PEPROCESS Process
);

typedef struct _PEB_LDR_DATA {
	ULONG      Length;
	BOOLEAN    Initialized;
	PVOID      SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY     InLoadOrderLinks;
	LIST_ENTRY     InMemoryOrderLinks;
	LIST_ENTRY     InInitializationOrderLinks;
	PVOID          DllBase;
	PVOID          Entrypoint;
	ULONG          SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
	BYTE          Reserved1[2];
	BYTE          BeingDebugged;
	BYTE          Reserved2[21];
	PPEB_LDR_DATA LoaderData;
	PVOID         ProcessParameters;
	BYTE          Reserved3[520];
	PVOID         PostProcessInitRoutine;
	BYTE          Reserved4[136];
	ULONG         SessionId;
} PEB, *ppeb;

PVOID pSharedSection;
HANDLE hSection;

PKEVENT pSharedRequestEvent;
HANDLE hRequestEvent;
PKEVENT pSharedCompletionEvent;
HANDLE hCompletionEvent;

typedef enum Operation {
	Read,
	Write,
	GetModule,
	Unload
} Operation;

typedef struct _KERNEL_OPERATION_REQUEST
{
	Operation operationType;
	BOOLEAN success;
	ULONG64 processID;
	ULONG64 address;
	SIZE_T size;
	UCHAR data[SHARED_MEMORY_NUM_BYTES];
} _KERNEL_OPERATION_REQUEST, *PKERNEL_OPERATION_REQUEST;

NTSTATUS CopyVirtualMemory(PEPROCESS process, PVOID sourceAddress, PVOID targetAddress, SIZE_T size, BOOLEAN write)
{
	SIZE_T bytes;
	return MmCopyVirtualMemory(write ? PsGetCurrentProcess() : process, sourceAddress, write ? process : PsGetCurrentProcess(), targetAddress, size, KernelMode, &bytes);
}

NTSTATUS GetModuleBase(PEPROCESS process, LPCWSTR moduleName, ULONG64* baseAddress) {
	UNICODE_STRING uModuleName = { 0 };
	RtlInitUnicodeString(&uModuleName, moduleName);

	KAPC_STATE apcState;
	KeStackAttachProcess(process, &apcState);

	PPEB peb = PsGetProcessPeb(process);
	if (!peb) {
		KeUnstackDetachProcess(&apcState);
		DPRINT("[-] PsGetProcessPeb failed.");
		return STATUS_UNSUCCESSFUL;
	}

	PPEB_LDR_DATA ldr = peb->LoaderData;
	if (!ldr) {
		KeUnstackDetachProcess(&apcState);
		DPRINT("[-] peb->LoaderData is invalid.");
		return STATUS_UNSUCCESSFUL;
	}

	int waitCount = 0;
	LARGE_INTEGER waitTime;
	waitTime.QuadPart = -2500000;
	if (!ldr->Initialized) {
		while (!ldr->Initialized && waitCount++ < 4) {
			KeDelayExecutionThread(KernelMode, TRUE, &waitTime);
		}

		if (!ldr->Initialized) {
			KeUnstackDetachProcess(&apcState);
			DPRINT("[-] LoaderData not initialized.");
			return STATUS_UNSUCCESSFUL;
		}
	}

	for (PLIST_ENTRY listEntry = (PLIST_ENTRY)ldr->InLoadOrderModuleList.Flink; listEntry != &ldr->InLoadOrderModuleList; listEntry = (PLIST_ENTRY)listEntry->Flink) {
		PLDR_DATA_TABLE_ENTRY ldrEntry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		DPRINT("Module name: %ls, base: %p", ldrEntry->BaseDllName.Buffer, ldrEntry->DllBase);
		if (RtlEqualUnicodeString(&ldrEntry->BaseDllName, &uModuleName, TRUE)) {
			*baseAddress = (ULONG64)ldrEntry->DllBase;
			KeUnstackDetachProcess(&apcState);
			return STATUS_SUCCESS;
		}
	}

	KeUnstackDetachProcess(&apcState);
	DPRINT("Module not found.");
	return STATUS_NOT_FOUND;
}

VOID UnloadDriver() {
	// Unmap view of section in kernel address space
	if (pSharedSection) {
		if (!NT_SUCCESS(MmUnmapViewInSystemSpace(pSharedSection))) {
			DPRINT("[-] MmUnmapViewInSystemSpace failed.");
		}
		DPRINT("Shared section unmapped.");
	}

	// Close handle to section
	if (hSection) {
		ZwClose(hSection);
		DPRINT("Handle to section closed.");
	}

	// Close handles to events
	if (hRequestEvent) {
		ZwClose(hRequestEvent);
		DPRINT("Handle to request event closed.");
	}
	if (hCompletionEvent) {
		ZwClose(hCompletionEvent);
		DPRINT("Handle to completion event closed.");
	}
}

VOID RequestHandler(PVOID parameter)
{
	// Free work item pool
	ExFreePoolWithTag(parameter, 'looP');

	NTSTATUS status;
	PEPROCESS process;
	PKERNEL_OPERATION_REQUEST request = (PKERNEL_OPERATION_REQUEST)pSharedSection;

	DPRINT("[+] Tsunami loaded.");

	while (1) {
		// Wait for user-mode process to request a read/write/kill
		DPRINT("\n[+] Waiting for request event...");
		KeWaitForSingleObject(pSharedRequestEvent, Executive, KernelMode, FALSE, NULL);
		
		// Clear event once received
		KeClearEvent(pSharedRequestEvent);
		DPRINT("[+] Event received and cleared.");
		DPRINT("Request type: %d", request->operationType);

		switch (request->operationType) {

		// Read request
		case Read:
			DPRINT("Read request received.");
			DPRINT("PID: %lu, address: 0x%I64X, size: %lu ", request->processID, request->address, request->size);

			status = PsLookupProcessByProcessId((HANDLE)request->processID, &process);

			if (NT_SUCCESS(status)) {
				status = CopyVirtualMemory(process, (PVOID)request->address, (PVOID)&request->data, request->size, FALSE);
				ObDereferenceObject(process);

				if (!NT_SUCCESS(status)) {
					DPRINT("[-] CopyVirtualMemory failed. Status: %p", status);
				}
			}
			else {
				DPRINT("[-] PsLookupProcessByProcessId failed. Status: %p", status);
			}

			request->success = NT_SUCCESS(status);
			break;

		// Write request
		case Write:
			DPRINT("Write request received.");
			DPRINT("PID: %lu, address: 0x%I64X, size: %lu ", request->processID, request->address, request->size);

			status = PsLookupProcessByProcessId((HANDLE)request->processID, &process);

			if (NT_SUCCESS(status)) {
				status = CopyVirtualMemory(process, (PVOID)&request->data, (PVOID)request->address, request->size, TRUE);
				ObDereferenceObject(process);

				if (!NT_SUCCESS(status)) {
					DPRINT("[-] CopyVirtualMemory failed. Status: %p", status);
				}
			}
			else {
				DPRINT("[-] PsLookupProcessByProcessId failed. Status: %p", status);
			}

			request->success = NT_SUCCESS(status);
			break;
		
		// Module base request
		case GetModule:
			DPRINT("GetModuleBase request received.");

			LPCWSTR moduleName = (LPCWSTR)request->data;
			DPRINT("PID: %lu, module name: %ls", request->processID, moduleName);

			status = PsLookupProcessByProcessId((HANDLE)request->processID, &process);
			if (NT_SUCCESS(status)) {
				status = GetModuleBase(process, moduleName, (ULONG64*)request->data);
				ObDereferenceObject(process);

				if (NT_SUCCESS(status)) {
					DPRINT("GetModuleBase succeeded, module base: 0x%I64X", *(ULONG64*)request->data);
				}
				else {
					DPRINT("GetModuleBase failed. Status: %p", status);
				}
			}
			else {
				DPRINT("[-] PsLookupProcessByProcessId failed. Status: %p", status);
			}

			request->success = NT_SUCCESS(status);
			break;

		// Unload request
		case Unload:
			DPRINT("Unload request received.");
			UnloadDriver();
			DPRINT("[+] Tsunami unloaded.");

			return;
		}

		// Notify user-mode process that processing has completed
		KeSetEvent(pSharedCompletionEvent, IO_NO_INCREMENT, FALSE);
	}
	return;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {
	UNREFERENCED_PARAMETER(pDriverObject);
	UNREFERENCED_PARAMETER(pRegistryPath);

	NTSTATUS status;

	// Create shared memory
	DPRINT("[+] Creating shared memory...");

	UNICODE_STRING sectionName = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\TsunamiSharedMemory");

	OBJECT_ATTRIBUTES objAttributes = { 0 };
	InitializeObjectAttributes(&objAttributes, &sectionName, OBJ_KERNEL_HANDLE, NULL, NULL);

	LARGE_INTEGER lMaxSize = { 0 };
	lMaxSize.QuadPart = sizeof(_KERNEL_OPERATION_REQUEST);
	status = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, &objAttributes, &lMaxSize, PAGE_READWRITE, SEC_COMMIT, NULL);
	if (!NT_SUCCESS(status))
	{
		DPRINT("[-] ZwCreateSection fail! Status: %p", status);
		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}
	DPRINT("[+] Shared memory created.");

	// Get pointer to shared section in context
	PVOID pContextSharedSection;
	ObReferenceObjectByHandle(hSection, SECTION_ALL_ACCESS, NULL, KernelMode, &pContextSharedSection, NULL);

	// Map shared section in context to system's address space so it can be accessed anywhere
	SIZE_T ulViewSize = 0;
	status = MmMapViewInSystemSpace(pContextSharedSection, &pSharedSection, &ulViewSize);
	if (!NT_SUCCESS(status))
	{
		DPRINT("[-] MmMapViewInSystemSpace fail! Status: %p", status);
		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}
	DPRINT("[+] MmMapViewInSystemSpace completed!");
	DPRINT("pSharedSection = 0x%p", pSharedSection);

	// Dereference shared section object
	ObDereferenceObject(pContextSharedSection);

	// Create named events
	UNICODE_STRING uRequestEventName = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\TsunamiSharedRequestEvent");
	UNICODE_STRING uCompletionEventName = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\TsunamiSharedCompletionEvent");

	pSharedRequestEvent = IoCreateNotificationEvent(&uRequestEventName, &hRequestEvent);
	pSharedCompletionEvent = IoCreateNotificationEvent(&uCompletionEventName, &hCompletionEvent);

	if (!pSharedRequestEvent || !pSharedCompletionEvent) {
		DPRINT("[-] IoCreateNotificationEvent failed!");
		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}
	DPRINT("[+] IoCreateNotificationEvent completed!");

	// Clear events since they start in the signaled state
	KeClearEvent(pSharedRequestEvent);
	KeClearEvent(pSharedCompletionEvent);

	// Start request handler in system worker thread
	PWORK_QUEUE_ITEM workItem;
	workItem = ExAllocatePoolWithTag(NonPagedPool, sizeof(WORK_QUEUE_ITEM), 'looP');
	ExInitializeWorkItem(workItem, (PWORKER_THREAD_ROUTINE)RequestHandler, workItem);
	ExQueueWorkItem(workItem, DelayedWorkQueue);

	return STATUS_SUCCESS;
}
