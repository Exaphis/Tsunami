#include <ntifs.h>

#define DEBUG
#ifdef DEBUG
#define DPRINT(...) DbgPrintEx(0, 0, __VA_ARGS__)
#else
#define DPRINT(...)
#endif
#define SHARED_MEMORY_NUM_BYTES 4 * 1024 * 1024

PVOID pSharedSection;
HANDLE hSection;

PKEVENT pSharedRequestEvent;
HANDLE hRequestEvent;
PKEVENT pSharedCompletionEvent;
HANDLE hCompletionEvent;

typedef enum Operation_t {
	Read,
	Write,
	Kill
} Operation_t;

typedef struct _KERNEL_OPERATION_REQUEST
{
	Operation_t operationType;
	BOOLEAN success;
	ULONG64 processID;
	ULONG64 address;
	SIZE_T size;
	UCHAR data[SHARED_MEMORY_NUM_BYTES];
} _KERNEL_OPERATION_REQUEST, *PKERNEL_OPERATION_REQUEST;

NTSTATUS CopyVirtualMemory(PEPROCESS process, PVOID sourceAddress, PVOID targetAddress, SIZE_T size, BOOLEAN write)
{
	KAPC_STATE apcState;
	KeStackAttachProcess(process, &apcState);

	// Secure user virtual address range
	HANDLE hMemory = MmSecureVirtualMemory(write ? targetAddress : sourceAddress, size, write ? PAGE_READWRITE : PAGE_READONLY);
	if (!hMemory) {
		KeUnstackDetachProcess(&apcState);
		return STATUS_INVALID_ADDRESS;
	}

	RtlCopyMemory(targetAddress, sourceAddress, size);
	MmUnsecureVirtualMemory(hMemory);

	KeUnstackDetachProcess(&apcState);

	return STATUS_SUCCESS;
}

NTSTATUS RequestHandler()
{
	NTSTATUS status;
	PKERNEL_OPERATION_REQUEST request = (PKERNEL_OPERATION_REQUEST)pSharedSection;

	DPRINT("[+] Tsunami loaded.\n");

	while (1) {
		// Wait for user-mode process to request a read/write/kill
		DPRINT("[+] Waiting for request event...\n");
		KeWaitForSingleObject(pSharedRequestEvent, Executive, KernelMode, FALSE, NULL);
		
		// Clear event once received
		KeClearEvent(pSharedRequestEvent);
		DPRINT("\n[+] Event received and cleared.\n");
		DPRINT("Request type: %d\n", request->operationType);

		// Read request
		if (request->operationType == Read) {
			DPRINT("[+] Read request received.\n");
			DPRINT("PID: %lu, address: 0x%I64X, size: %lu \n", request->processID, request->address, request->size);

			PEPROCESS process;
			status = PsLookupProcessByProcessId((HANDLE)request->processID, &process);

			if (NT_SUCCESS(status)) {
				status = CopyVirtualMemory(process, (PVOID)request->address, (PVOID)&request->data, request->size, FALSE);
				ObDereferenceObject(process);

				if (!NT_SUCCESS(status)) {
					DPRINT("[-] CopyVirtualMemory failed. Status: %p\n", status);
				}
			}
			else {
				DPRINT("[-] PsLookupProcessByProcessId failed. Status: %p\n", status);
			}

			request->success = NT_SUCCESS(status);
		}

		// Write request
		else if (request->operationType == Write) {
			DPRINT("[+] Write request received.\n");
			DPRINT("PID: %lu, address: 0x%I64X, size: %lu \n", request->processID, request->address, request->size);

			PEPROCESS process;
			status = PsLookupProcessByProcessId((HANDLE)request->processID, &process);

			if (NT_SUCCESS(status)) {
				status = CopyVirtualMemory(process, (PVOID)&request->data, (PVOID)request->address, request->size, TRUE);
				ObDereferenceObject(process);

				if (!NT_SUCCESS(status)) {
					DPRINT("[-] CopyVirtualMemory failed. Status: %p\n", status);
				}
			}
			else {
				DPRINT("[-] PsLookupProcessByProcessId failed. Status: %p\n", status);
			}

			request->success = NT_SUCCESS(status);
		}

		// Kill request
		else if (request->operationType == Kill) {
			DPRINT("[+] Tsunami unload routine called.\n");

			// Unmap view of section in kernel address space
			if (pSharedSection) {
				if (!NT_SUCCESS(MmUnmapViewInSystemSpace(pSharedSection))) {
					DPRINT("[-] MmUnmapViewInSystemSpace failed.\n");
				}
				DPRINT("Shared section unmapped.\n");
			}

			// Close handle to section
			if (hSection) {
				ZwClose(hSection);
				DPRINT("Handle to section closed.\n");
			}

			// Close handles to events
			if (hRequestEvent) {
				ZwClose(hRequestEvent);
				DPRINT("Handle to request event closed.\n");
			}
			if (hCompletionEvent) {
				ZwClose(hCompletionEvent);
				DPRINT("Handle to completion event closed.\n");
			}

			DPRINT("[+] Tsunami unloaded.\n");
			return STATUS_SUCCESS;
		}

		// Notify user-mode process that processing has completed
		KeSetEvent(pSharedCompletionEvent, IO_NO_INCREMENT, FALSE);
	}
	return STATUS_SUCCESS;
}

NTSTATUS CreateSharedMemory()
{
	// Source: https://raw.githubusercontent.com/mq1n/EasyRing0/master/Tutorial_6_ShareMem_Communication_SYS/main.c
	DPRINT("[+] Creating shared memory...\n");
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	UNICODE_STRING uSectionName = { 0 };
	RtlInitUnicodeString(&uSectionName, L"\\BaseNamedObjects\\TsunamiSharedMemory");

	OBJECT_ATTRIBUTES objAttributes = { 0 };
	InitializeObjectAttributes(&objAttributes, &uSectionName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	LARGE_INTEGER lMaxSize = { 0 };
	lMaxSize.HighPart = 0;
	lMaxSize.LowPart = sizeof(_KERNEL_OPERATION_REQUEST);
	status = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, &objAttributes, &lMaxSize, PAGE_READWRITE, SEC_COMMIT, NULL);
	if (status != STATUS_SUCCESS)
	{
		DPRINT("[-] ZwCreateSection fail! Status: %p\n", status);
		return status;
	}
	DPRINT("[+] ZwCreateSection completed!\n");

	return status;
}

// Fake Driver entrypoint
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {
	UNREFERENCED_PARAMETER(pDriverObject);
	UNREFERENCED_PARAMETER(pRegistryPath);

	NTSTATUS status;

	// Create shared section
	status = CreateSharedMemory();

	if (!NT_SUCCESS(status)) {
		DPRINT("[-] CreateSharedMemory fail!\n");
		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}

	DPRINT("[+] Shared memory created.\n");

	// Try to open section
	UNICODE_STRING uSectionName = { 0 };
	RtlInitUnicodeString(&uSectionName, L"\\BaseNamedObjects\\TsunamiSharedMemory");

	OBJECT_ATTRIBUTES objAttributes = { 0 };
	InitializeObjectAttributes(&objAttributes, &uSectionName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	HANDLE tempSectionHandle;
	status = ZwOpenSection(&tempSectionHandle, SECTION_ALL_ACCESS, &objAttributes);
	if (!NT_SUCCESS(status)) {
		DPRINT("[-] ZwOpenSection fail! Status: %p\n", status);

		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}
	else {
		DPRINT("[+] ZwOpenSection succeeded. Handle: %p\n", tempSectionHandle);
		ZwClose(tempSectionHandle);
	}

	// Get pointer to shared section in context
	PVOID pContextSharedSection;
	ObReferenceObjectByHandle(hSection, SECTION_ALL_ACCESS, NULL, KernelMode, &pContextSharedSection, NULL);

	// Map shared section in context to system's address space so it can be accessed anywhere
	SIZE_T ulViewSize = 0;
	status = MmMapViewInSystemSpace(pContextSharedSection, &pSharedSection, &ulViewSize);
	if (!NT_SUCCESS(status))
	{
		DPRINT("MmMapViewInSystemSpace fail! Status: %p\n", status);

		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}
	DPRINT("[+] MmMapViewInSystemSpace completed!\n");
	DPRINT("pSharedSection = 0x%p\n", pSharedSection);

	// Dereference shared section object
	ObDereferenceObject(pContextSharedSection);

	// Create named events
	UNICODE_STRING uRequestEventName = { 0 };
	UNICODE_STRING uCompletionEventName = { 0 };
	RtlInitUnicodeString(&uRequestEventName, L"\\BaseNamedObjects\\TsunamiSharedRequestEvent");
	RtlInitUnicodeString(&uCompletionEventName, L"\\BaseNamedObjects\\TsunamiSharedCompletionEvent");

	pSharedRequestEvent = IoCreateNotificationEvent(&uRequestEventName, &hRequestEvent);
	pSharedCompletionEvent = IoCreateNotificationEvent(&uCompletionEventName, &hCompletionEvent);

	if (!pSharedRequestEvent || !pSharedCompletionEvent) {
		DPRINT("[-] IoCreateNotificationEvent failed!\n");
		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}

	KeClearEvent(pSharedRequestEvent);
	KeClearEvent(pSharedCompletionEvent);
	DPRINT("[+] IoCreateNotificationEvent completed!\n");

	// Create thread for request handler
	HANDLE hThread;
	OBJECT_ATTRIBUTES threadAttributes = { 0 };
	InitializeObjectAttributes(&threadAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, &threadAttributes, NULL, NULL, (PKSTART_ROUTINE)RequestHandler, NULL);
	if (!NT_SUCCESS(status))
	{
		DPRINT("PsCreateSystemThread fail! Status: %p\n", status);

		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}
	DPRINT("[+] PsCreateSystemThread completed!\n");

	return STATUS_SUCCESS;
}
