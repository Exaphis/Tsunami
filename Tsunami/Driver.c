#include <ntifs.h>

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
	UCHAR data[4 * 1024 * 1024];
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

#ifdef DEBUG
	DbgPrintEx(0, 0, "[+] Tsunami loaded.\n");
#endif

	while (1) {
		// Wait for user-mode process to request a read/write/kill
#ifdef DEBUG
		DbgPrintEx(0, 0, "[+] Waiting for request event...\n");
#endif
		KeWaitForSingleObject(pSharedRequestEvent, Executive, KernelMode, FALSE, NULL);
		
		// Clear event once received
		KeClearEvent(pSharedRequestEvent);
#ifdef DEBUG
		DbgPrintEx(0, 0, "\n[+] Event received and cleared.\n");
		DbgPrintEx(0, 0, "Request type: %d\n", request->operationType);
#endif

		// Read request
		if (request->operationType == Read) {
#ifdef DEBUG
			DbgPrintEx(0, 0, "[+] Read request received.\n");
			DbgPrintEx(0, 0, "PID: %lu, address: 0x%I64X, size: %lu \n", request->processID, request->address, request->size);
#endif

			PEPROCESS process;
			status = PsLookupProcessByProcessId((HANDLE)request->processID, &process);

			if (NT_SUCCESS(status)) {
				status = CopyVirtualMemory(process, (PVOID)request->address, (PVOID)&request->data, request->size, FALSE);
				ObDereferenceObject(process);

#ifdef DEBUG
				if (!NT_SUCCESS(status)) {
					DbgPrintEx(0, 0, "[-] CopyVirtualMemory failed. Status: %p\n", status);
				}
#endif
			}
#ifdef DEBUG
			else {
				DbgPrintEx(0, 0, "[-] PsLookupProcessByProcessId failed. Status: %p\n", status);
			}
#endif

			request->success = NT_SUCCESS(status);
		}

		// Write request
		else if (request->operationType == Write) {
#ifdef DEBUG
			DbgPrintEx(0, 0, "[+] Write request received.\n");
			DbgPrintEx(0, 0, "PID: %lu, address: 0x%I64X, size: %lu \n", request->processID, request->address, request->size);
#endif

			PEPROCESS process;
			status = PsLookupProcessByProcessId((HANDLE)request->processID, &process);

			if (NT_SUCCESS(status)) {
				status = CopyVirtualMemory(process, (PVOID)&request->data, (PVOID)request->address, request->size, TRUE);
				ObDereferenceObject(process);

#ifdef DEBUG
				if (!NT_SUCCESS(status)) {
					DbgPrintEx(0, 0, "[-] CopyVirtualMemory failed. Status: %p\n", status);
				}
#endif
			}
#ifdef DEBUG
			else {
				DbgPrintEx(0, 0, "[-] PsLookupProcessByProcessId failed. Status: %p\n", status);
			}
#endif

			request->success = NT_SUCCESS(status);
		}

		// Kill request
		else if (request->operationType == Kill) {
#ifdef DEBUG
			DbgPrintEx(0, 0, "[+] Tsunami unload routine called.\n");
#endif

			// Unmap view of section in kernel address space
			if (pSharedSection) {
				if (!NT_SUCCESS(MmUnmapViewInSystemSpace(pSharedSection))) {
#ifdef DEBUG
					DbgPrintEx(0, 0, "[-] MmUnmapViewInSystemSpace failed.\n");
#endif
				}
#ifdef DEBUG
				DbgPrintEx(0, 0, "Shared section unmapped.\n");
#endif
			}

			// Close handle to section
			if (hSection) {
				ZwClose(hSection);
#ifdef DEBUG
				DbgPrintEx(0, 0, "Handle to section closed.\n");
#endif
			}

			// Close handles to events
			if (hRequestEvent) {
				ZwClose(hRequestEvent);
#ifdef DEBUG
				DbgPrintEx(0, 0, "Handle to request event closed.\n");
#endif
			}
			if (hCompletionEvent) {
				ZwClose(hCompletionEvent);
#ifdef DEBUG
				DbgPrintEx(0, 0, "Handle to completion event closed.\n");
#endif
			}

#ifdef DEBUG
			DbgPrintEx(0, 0, "[+] Tsunami unloaded.\n");
#endif
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
#ifdef DEBUG
	DbgPrintEx(0, 0, "[+] Creating shared memory...\n");
#endif
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
#ifdef DEBUG
		DbgPrintEx(0, 0, "[-] ZwCreateSection fail! Status: %p\n", status);
#endif
		return status;
	}
#ifdef DEBUG
	DbgPrintEx(0, 0, "[+] ZwCreateSection completed!\n");
#endif

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
#ifdef DEBUG
		DbgPrintEx(0, 0, "[-] CreateSharedMemory fail!\n");
#endif
		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}

#ifdef DEBUG
	DbgPrintEx(0, 0, "[+] Shared memory created.\n");
#endif

	// Try to open section
	UNICODE_STRING uSectionName = { 0 };
	RtlInitUnicodeString(&uSectionName, L"\\BaseNamedObjects\\TsunamiSharedMemory");

	OBJECT_ATTRIBUTES objAttributes = { 0 };
	InitializeObjectAttributes(&objAttributes, &uSectionName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	HANDLE tempSectionHandle;
	status = ZwOpenSection(&tempSectionHandle, SECTION_ALL_ACCESS, &objAttributes);
	if (!NT_SUCCESS(status)) {
#ifdef DEBUG
		DbgPrintEx(0, 0, "[-] ZwOpenSection fail! Status: %p\n", status);
#endif

		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}
	else {
#ifdef DEBUG
		DbgPrintEx(0, 0, "[+] ZwOpenSection succeeded. Handle: %p\n", tempSectionHandle);
#endif
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
#ifdef DEBUG
		DbgPrintEx(0, 0, "MmMapViewInSystemSpace fail! Status: %p\n", status);
#endif

		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}
#ifdef DEBUG
	DbgPrintEx(0, 0, "[+] MmMapViewInSystemSpace completed!\n");
	DbgPrintEx(0, 0, "pSharedSection = 0x%p\n", pSharedSection);
#endif

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
#ifdef DEBUG
		DbgPrintEx(0, 0, "[-] IoCreateNotificationEvent failed!\n");
#endif
		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}

	KeClearEvent(pSharedRequestEvent);
	KeClearEvent(pSharedCompletionEvent);
#ifdef DEBUG
	DbgPrintEx(0, 0, "[+] IoCreateNotificationEvent completed!\n");
#endif

	// Create thread for request handler
	HANDLE hThread;
	OBJECT_ATTRIBUTES threadAttributes = { 0 };
	InitializeObjectAttributes(&threadAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, &threadAttributes, NULL, NULL, (PKSTART_ROUTINE)RequestHandler, NULL);
	if (!NT_SUCCESS(status))
	{
#ifdef DEBUG
		DbgPrintEx(0, 0, "PsCreateSystemThread fail! Status: %p\n", status);
#endif

		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}
#ifdef DEBUG
	DbgPrintEx(0, 0, "[+] PsCreateSystemThread completed!\n");
#endif

	return STATUS_SUCCESS;
}
