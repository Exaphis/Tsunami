#include <ntifs.h>
#include <windef.h>
#include <ntstrsafe.h>
#include <initguid.h>

#ifdef DEBUG
#define DPRINT(...) DbgPrintEx(0, 0, __VA_ARGS__)
#else
#define DPRINT(...)
#endif
#define SHARED_MEMORY_NUM_BYTES 4 * 1024 * 1024

#define GUID_SECTION "{90CF650F-8C64-4799-AD29-D96BC77BFE32}"
#define GUID_REQUEST_EVENT "{EFAA3FD1-2242-4F91-8915-F06D0A56B297}"
#define GUID_COMPLETION_EVENT "{A45188BE-8DA7-4A22-9479-8E71155C0EC7}"

NTKERNELAPI NTSTATUS MmCopyVirtualMemory(
	IN PEPROCESS       SourceProcess,
	IN PVOID           SourceAddress,
	IN PEPROCESS       TargetProcess,
	IN PVOID           TargetAddress,
	IN SIZE_T          BufferSize,
	IN KPROCESSOR_MODE PreviousMode,
	OUT PSIZE_T        ReturnSize
);

NTKERNELAPI PPEB NTAPI PsGetProcessPeb(
	IN PEPROCESS Process
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
} PEB, *PPEB;

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

PVOID pSharedSection;
HANDLE hSection;

PKEVENT pSharedRequestEvent;
HANDLE hRequestEvent;
PKEVENT pSharedCompletionEvent;
HANDLE hCompletionEvent;

NTSTATUS GetModuleBase(PEPROCESS process, LPCWSTR moduleName, ULONG64* baseAddress) {
	// Source: https://www.unknowncheats.me/forum/c-and-c-/190555-kernel-module-base-adress.html

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
			KeDelayExecutionThread(KernelMode, FALSE, &waitTime);
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
	KIRQL oldIrql;
	KeRaiseIrql(APC_LEVEL, &oldIrql);

	// Free work item pool
	ExFreePoolWithTag(parameter, 'looP');

	NTSTATUS status;
	SIZE_T bytes;
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
				status = MmCopyVirtualMemory(process, (PVOID)request->address, PsGetCurrentProcess(), (PVOID)&request->data, request->size, KernelMode, &bytes);
				ObDereferenceObject(process);

				if (!NT_SUCCESS(status)) {
					DPRINT("[-] MmCopyVirtualMemory failed. Status: %p", status);
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
				status = MmCopyVirtualMemory(PsGetCurrentProcess(), (PVOID)&request->data, process, (PVOID)request->address, request->size, KernelMode, &bytes);
				ObDereferenceObject(process);

				if (!NT_SUCCESS(status)) {
					DPRINT("[-] MmCopyVirtualMemory failed. Status: %p", status);
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
			goto cleanup;
		}

		// Notify user-mode process that processing has completed
		KeSetEvent(pSharedCompletionEvent, IO_NO_INCREMENT, FALSE);
	}

cleanup:
	DPRINT("Tsunami request handler terminated.");
	KeLowerIrql(oldIrql);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {
	UNREFERENCED_PARAMETER(pDriverObject);
	UNREFERENCED_PARAMETER(pRegistryPath);

	NTSTATUS status;

	// Create names from GUID
	UNICODE_STRING sectionName = RTL_CONSTANT_STRING("\\BaseNamedObjects\\" GUID_SECTION);
	UNICODE_STRING requestEventName = RTL_CONSTANT_STRING("\\BaseNamedObjects\\" GUID_REQUEST_EVENT);
	UNICODE_STRING completionEventName = RTL_CONSTANT_STRING("\\BaseNamedObjects\\" GUID_COMPLETION_EVENT);

	DPRINT("[>] Section name: %wZ", &sectionName);
	DPRINT("[>] Request event name: %wZ", &requestEventName);
	DPRINT("[>] Completion event name: %wZ", &completionEventName);

	// Create shared memory
	DPRINT("[+] Creating shared memory...");

	OBJECT_ATTRIBUTES objAttributes = { 0 };
	InitializeObjectAttributes(&objAttributes, &sectionName, OBJ_KERNEL_HANDLE, NULL, NULL);

	LARGE_INTEGER lMaxSize = { 0 };
	lMaxSize.QuadPart = sizeof(_KERNEL_OPERATION_REQUEST);
	status = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, &objAttributes, &lMaxSize, PAGE_READWRITE, SEC_COMMIT, NULL);
	if (!NT_SUCCESS(status))
	{
		DPRINT("[-] ZwCreateSection failed. Status: %p", status);
		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}
	DPRINT("[+] Shared memory created.");

	// Get pointer to shared section in context
	PVOID pContextSharedSection;
	status = ObReferenceObjectByHandle(hSection, SECTION_ALL_ACCESS, NULL, KernelMode, &pContextSharedSection, NULL);
	if (!NT_SUCCESS(status))
	{
		DPRINT("[-] ObReferenceObjectByHandle failed. Status: %p", status);
		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}

	// Map shared section in context to system's address space so it can be accessed anywhere
	SIZE_T ulViewSize = 0;
	status = MmMapViewInSystemSpace(pContextSharedSection, &pSharedSection, &ulViewSize);
	if (!NT_SUCCESS(status))
	{
		DPRINT("[-] MmMapViewInSystemSpace failed. Status: %p", status);
		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}
	DPRINT("[+] MmMapViewInSystemSpace completed.");
	DPRINT("pSharedSection = 0x%p", pSharedSection);

	// Dereference shared section object
	ObDereferenceObject(pContextSharedSection);

	// Create named events
	pSharedRequestEvent = IoCreateNotificationEvent(&requestEventName, &hRequestEvent);
	pSharedCompletionEvent = IoCreateNotificationEvent(&completionEventName, &hCompletionEvent);

	if (!pSharedRequestEvent || !pSharedCompletionEvent) {
		DPRINT("[-] IoCreateNotificationEvent failed.");
		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}
	DPRINT("[+] IoCreateNotificationEvent completed.");

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
