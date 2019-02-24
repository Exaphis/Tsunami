#include <ntifs.h>

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

PVOID pSharedSection;
HANDLE hSection;

PKEVENT pSharedRequestEvent;
HANDLE hRequestEvent;
PKEVENT pSharedCompletionEvent;
HANDLE hCompletionEvent;

typedef enum Operation {
	Read,
	Write,
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

VOID RequestHandler(PVOID parameter)
{
	// Free work item pool
	ExFreePoolWithTag(parameter, 'looP');

	NTSTATUS status;
	PEPROCESS process;
	PKERNEL_OPERATION_REQUEST request = (PKERNEL_OPERATION_REQUEST)pSharedSection;

	DPRINT("[+] Tsunami loaded.\n");

	while (1) {
		// Wait for user-mode process to request a read/write/kill
		DPRINT("\n[+] Waiting for request event...\n");
		KeWaitForSingleObject(pSharedRequestEvent, Executive, KernelMode, FALSE, NULL);
		
		// Clear event once received
		KeClearEvent(pSharedRequestEvent);
		DPRINT("[+] Event received and cleared.\n");
		DPRINT("Request type: %d\n", request->operationType);

		switch (request->operationType) {

		// Read request
		case Read:
			DPRINT("Read request received.\n");
			DPRINT("PID: %lu, address: 0x%I64X, size: %lu \n", request->processID, request->address, request->size);

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
			break;

		// Write request
		case Write:
			DPRINT("Write request received.\n");
			DPRINT("PID: %lu, address: 0x%I64X, size: %lu \n", request->processID, request->address, request->size);

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
			break;

		// Unload request
		case Unload:
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
	DPRINT("[+] Creating shared memory...\n");

	UNICODE_STRING uSectionName = { 0 };
	RtlInitUnicodeString(&uSectionName, L"\\BaseNamedObjects\\TsunamiSharedMemory");

	OBJECT_ATTRIBUTES objAttributes = { 0 };
	InitializeObjectAttributes(&objAttributes, &uSectionName, OBJ_KERNEL_HANDLE, NULL, NULL);

	LARGE_INTEGER lMaxSize = { 0 };
	lMaxSize.QuadPart = sizeof(_KERNEL_OPERATION_REQUEST);
	status = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, &objAttributes, &lMaxSize, PAGE_READWRITE, SEC_COMMIT, NULL);
	if (!NT_SUCCESS(status))
	{
		DPRINT("[-] ZwCreateSection fail! Status: %p\n", status);
		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}
	DPRINT("[+] Shared memory created.\n");

	// Get pointer to shared section in context
	PVOID pContextSharedSection;
	ObReferenceObjectByHandle(hSection, SECTION_ALL_ACCESS, NULL, KernelMode, &pContextSharedSection, NULL);

	// Map shared section in context to system's address space so it can be accessed anywhere
	SIZE_T ulViewSize = 0;
	status = MmMapViewInSystemSpace(pContextSharedSection, &pSharedSection, &ulViewSize);
	if (!NT_SUCCESS(status))
	{
		DPRINT("[-] MmMapViewInSystemSpace fail! Status: %p\n", status);
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
	DPRINT("[+] IoCreateNotificationEvent completed!\n");

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
