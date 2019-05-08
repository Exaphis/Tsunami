#include "nt.h"

#ifdef DEBUG
#define DPRINT(...) DbgPrintEx(0, 0, __VA_ARGS__)
#else
#define DPRINT(...)
#endif
#define SHARED_MEMORY_NUM_BYTES 4 * 1024 * 1024

#define GUID_SECTION L"{3FE2EC3F-7CAF-43AF-878F-85612D10AB6B}"
#define GUID_REQUEST_EVENT L"{9399F41C-E15B-4A95-8B1C-7A9EF219F61E}"
#define GUID_COMPLETION_EVENT L"{E60F327F-4C6F-4790-9E31-83862DF81EC2}"

typedef enum Operation {
	Read,
	Write,
	GetModule,
	Unload
} Operation;

typedef struct _REQUEST_HANDLER_PARAMS {
	PVOID pSharedSection;
	HANDLE hSection;
	PKEVENT pSharedRequestEvent;
	HANDLE hRequestEvent;
	PKEVENT pSharedCompletionEvent;
	HANDLE hCompletionEvent;
} REQUEST_HANDLER_PARAMS, *PREQUEST_HANDLER_PARAMS;

typedef struct _KERNEL_OPERATION_REQUEST
{
	Operation operationType;
	BOOLEAN success;
	ULONG64 processID;
	ULONG_PTR address;
	SIZE_T size;
	UCHAR data[SHARED_MEMORY_NUM_BYTES];
} KERNEL_OPERATION_REQUEST, *PKERNEL_OPERATION_REQUEST;

NTSTATUS GetModuleBase(PEPROCESS process, LPCWSTR moduleName, ULONG_PTR* baseAddress) {
	// Source: https://www.unknowncheats.me/forum/c-and-c-/190555-kernel-module-base-adress.html

	UNICODE_STRING uModuleName = { 0 };
	RtlInitUnicodeString(&uModuleName, moduleName);

	KAPC_STATE apcState;
	KeStackAttachProcess(process, &apcState);

	PPEB peb = PsGetProcessPeb(process);
	if (!peb) {
		KeUnstackDetachProcess(&apcState);
		DPRINT("[-] PsGetProcessPeb failed.\n");
		return STATUS_UNSUCCESSFUL;
	}

	PPEB_LDR_DATA ldr = peb->LoaderData;
	if (!ldr) {
		KeUnstackDetachProcess(&apcState);
		DPRINT("[-] peb->LoaderData is invalid.\n");
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
			DPRINT("[-] LoaderData not initialized.\n");
			return STATUS_UNSUCCESSFUL;
		}
	}

	for (PLIST_ENTRY listEntry = (PLIST_ENTRY)ldr->InLoadOrderModuleList.Flink; listEntry != &ldr->InLoadOrderModuleList; listEntry = (PLIST_ENTRY)listEntry->Flink) {
		PLDR_DATA_TABLE_ENTRY ldrEntry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		DPRINT("Module name: %ls, base: %p\n", ldrEntry->BaseDllName.Buffer, ldrEntry->DllBase);
		if (RtlEqualUnicodeString(&ldrEntry->BaseDllName, &uModuleName, TRUE)) {
			*baseAddress = (ULONG_PTR)ldrEntry->DllBase;
			KeUnstackDetachProcess(&apcState);
			return STATUS_SUCCESS;
		}
	}

	KeUnstackDetachProcess(&apcState);
	DPRINT("Module not found.\n");
	return STATUS_NOT_FOUND;
}

VOID UnloadDriver(PREQUEST_HANDLER_PARAMS context) {
	// Unmap view of section in kernel address space
	if (context->pSharedSection) {
		if (!NT_SUCCESS(MmUnmapViewInSystemSpace(context->pSharedSection))) {
			DPRINT("[-] MmUnmapViewInSystemSpace failed.\n");
		}
		DPRINT("Shared section unmapped.\n");
	}

	// Close handle to section
	if (context->hSection) {
		ZwClose(context->hSection);
		DPRINT("Handle to section closed.\n");
	}

	// Close handles to events
	if (context->hRequestEvent) {
		ZwClose(context->hRequestEvent);
		DPRINT("Handle to request event closed.\n");
	}
	if (context->hCompletionEvent) {
		ZwClose(context->hCompletionEvent);
		DPRINT("Handle to completion event closed.\n");
	}

	ExFreePool(context);
}

VOID RequestHandler(PVOID parameter)
{
	PREQUEST_HANDLER_PARAMS params = (PREQUEST_HANDLER_PARAMS)parameter;

	NTSTATUS status;
	SIZE_T bytes;
	PEPROCESS process;
	PKERNEL_OPERATION_REQUEST request = (PKERNEL_OPERATION_REQUEST)params->pSharedSection;

	DPRINT("[+] Tsunami loaded.\n");
	DPRINT("current irql: %d\n", KeGetCurrentIrql());
	DPRINT("pSharedSection = 0x%p\n", params->pSharedSection);

	while (1) {
		// Wait for user-mode process to request a read/write/kill
		DPRINT("\n[+] Waiting for request event...\n");
		status = KeWaitForSingleObject(params->pSharedRequestEvent, Executive, KernelMode, FALSE, NULL);

		// Clear event once received
		KeClearEvent(params->pSharedRequestEvent);
		DPRINT("[+] Event received and cleared.\n");
		DPRINT("Request type: %d\n", request->operationType);

		switch (request->operationType) {

		// Read request
		case Read:
			DPRINT("Read request received.\n");
			DPRINT("PID: %lu, address: 0x%I64X, size: %lu\n", request->processID, request->address, request->size);

			status = PsLookupProcessByProcessId((HANDLE)request->processID, &process);

			if (NT_SUCCESS(status)) {
				status = MmCopyVirtualMemory(process, (PVOID)request->address, PsGetCurrentProcess(), (PVOID)&request->data, request->size, KernelMode, &bytes);
				ObDereferenceObject(process);

				if (!NT_SUCCESS(status)) {
					DPRINT("[-] MmCopyVirtualMemory failed. Status: %p\n", status);
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
			DPRINT("PID: %lu, address: 0x%I64X, size: %lu\n", request->processID, request->address, request->size);

			status = PsLookupProcessByProcessId((HANDLE)request->processID, &process);

			if (NT_SUCCESS(status)) {
				status = MmCopyVirtualMemory(PsGetCurrentProcess(), (PVOID)&request->data, process, (PVOID)request->address, request->size, KernelMode, &bytes);
				ObDereferenceObject(process);

				if (!NT_SUCCESS(status)) {
					DPRINT("[-] MmCopyVirtualMemory failed. Status: %p\n", status);
				}
			}
			else {
				DPRINT("[-] PsLookupProcessByProcessId failed. Status: %p\n", status);
			}

			request->success = NT_SUCCESS(status);
			break;
		
		// Module base request
		case GetModule:
			DPRINT("GetModuleBase request received.\n");

			LPCWSTR moduleName = (LPCWSTR)request->data;
			DPRINT("PID: %lu, module name: %ls\n", request->processID, moduleName);

			status = PsLookupProcessByProcessId((HANDLE)request->processID, &process);
			if (NT_SUCCESS(status)) {
				status = GetModuleBase(process, moduleName, (ULONG_PTR*)request->data);
				ObDereferenceObject(process);

				if (NT_SUCCESS(status)) {
					DPRINT("GetModuleBase succeeded, module base: 0x%I64X\n", *(ULONG_PTR*)request->data);
				}
				else {
					DPRINT("GetModuleBase failed. Status: %p\n", status);
				}
			}
			else {
				DPRINT("[-] PsLookupProcessByProcessId failed. Status: %p\n", status);
			}

			request->success = NT_SUCCESS(status);
			break;

		// Unload request
		case Unload:
			DPRINT("Unload request received.\n");
			UnloadDriver(params);
			goto cleanup;
		}

		// Notify user-mode process that processing has completed
		KeSetEvent(params->pSharedCompletionEvent, IO_NO_INCREMENT, FALSE);
	}

cleanup:
	DPRINT("Tsunami request handler terminated.\n");
	PsTerminateSystemThread(STATUS_SUCCESS);
}

PVOID FindPattern(PVOID start, SIZE_T length, LPCSTR pattern, LPCSTR mask) {
	PCHAR data = (PCHAR)start;
	SIZE_T patternLength = strlen(mask);

	for (SIZE_T i = 0; i <= length - patternLength; i++) {
		BOOLEAN found = TRUE;

		for (SIZE_T j = 0; j < patternLength; j++) {
			if (!MmIsAddressValid((PVOID)((ULONG_PTR)data + i + j))) {
				found = FALSE;
				break;
			}

			if (mask[j] != '?' && data[i + j] != pattern[j]) {
				found = FALSE;
				break;
			}
		}

		if (found) {
			return (PVOID)((ULONG_PTR)data + i);
		}
	}

	return NULL;
}

PVOID FindDiscardableSection(SIZE_T minSize) {
	NTSTATUS status;

	// Find discardable section to hijack (Source: https://www.unknowncheats.me/forum/anti-cheat-bypass/327295-driver-discardable-section-device-dispatch-hijacking-bypass.html)
	// First, iterate all driver objects (Source: https://www.unknowncheats.me/forum/c-and-c-/274073-iterating-driver_objects.html)
	HANDLE directoryHandle;
	UNICODE_STRING dirName = RTL_CONSTANT_STRING(L"\\Driver");
	OBJECT_ATTRIBUTES dirAttributes = { 0 };
	InitializeObjectAttributes(&dirAttributes, &dirName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwOpenDirectoryObject(&directoryHandle, DIRECTORY_ALL_ACCESS, &dirAttributes);
	if (!NT_SUCCESS(status)) {
		DPRINT("ZwOpenDirectoryObject failed.\n");
		return NULL;
	}

	POBJECT_DIRECTORY directoryObject;
	status = ObReferenceObjectByHandle(directoryHandle, DIRECTORY_ALL_ACCESS, NULL, KernelMode, &directoryObject, NULL);
	if (!NT_SUCCESS(status)) {
		ZwClose(directoryHandle);
		DPRINT("ObReferenceObjectByHandle failed.\n");
		return NULL;
	}

	PIMAGE_SECTION_HEADER discardableSectionHeader = NULL;
	PDRIVER_OBJECT targetDriverObject = NULL;

	ExAcquirePushLockExclusiveEx(&directoryObject->Lock, 0);
	for (SIZE_T i = 0; i < OBJECT_HASH_TABLE_SIZE; i++) {
		for (POBJECT_DIRECTORY_ENTRY entry = directoryObject->HashBuckets[i]; entry != NULL && entry->Object != NULL; entry = entry->ChainLink) {
			PDRIVER_OBJECT driver = (PDRIVER_OBJECT)entry->Object;

			DPRINT("DriverName: %wZ\n", &driver->DriverName);

			PIMAGE_NT_HEADERS driverNtHeader = RtlImageNtHeader(driver->DriverStart);
			PIMAGE_SECTION_HEADER firstSection = IMAGE_FIRST_SECTION(driverNtHeader);

			for (PIMAGE_SECTION_HEADER section = firstSection; section < firstSection + driverNtHeader->FileHeader.NumberOfSections; section++)
			{
				// assume INIT section is RWX - implement assert
				if (section->Characteristics & 0x02000000 && section->Misc.VirtualSize >= minSize) // IMAGE_SCN_MEM_DISCARDABLE
				{
					DPRINT("    Section @ %p\n    Size: 0x%lx\n", section, section->Misc.VirtualSize);

					discardableSectionHeader = section;
					targetDriverObject = driver;
					goto sectionFound;
				}
			}
		}
	}

sectionFound:
	ExReleasePushLockExclusiveEx(&directoryObject->Lock, 0);
	ObDereferenceObject(directoryObject);
	ZwClose(directoryHandle);

	if (discardableSectionHeader) {
		DPRINT("usable discardable section found @ 0x%p\n", discardableSectionHeader);
		return (PVOID)((ULONG_PTR)targetDriverObject->DriverStart + discardableSectionHeader->VirtualAddress);
	}
	DPRINT("usable discardable section not found.", discardableSectionHeader);
	return NULL;
}

BOOLEAN LocatePiDDB(PERESOURCE* lock, PRTL_AVL_TABLE* table) {
	PVOID pLock = NULL, pTable = NULL;

	pLock = FindPattern(kernelBaseAddress, kernelBaseSize, "\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x8C", "xxx????x????xxx");
	if (!pLock) {
		DPRINT("Unable to find pointer to PiDDBLock.\n");
		return FALSE;
	}

	pTable = FindPattern(kernelBaseAddress, kernelBaseSize, "\x66\x03\xD2\x48\x8D\x0D", "xxxxxx");
	if (!pTable) {
		DPRINT("Unable to find pointer to PiDDBCacheTable.\n");
		return FALSE;
	}

	pTable = (PVOID)((ULONG_PTR)pTable + 3);

	*lock = (PERESOURCE)ResolveRelativeAddress(pLock, 3, 7);
	*table = (PRTL_AVL_TABLE)ResolveRelativeAddress(pTable, 3, 7);

	return TRUE;
}

BOOLEAN ClearPiDDBCacheTable() {
	// Source: https://www.unknowncheats.me/forum/anti-cheat-bypass/324665-clearing-piddbcachetable.html
	PERESOURCE piDDBLock;
	PRTL_AVL_TABLE piDDBCacheTable;
	
	if (!LocatePiDDB(&piDDBLock, &piDDBCacheTable)) {
		DPRINT("LocatePiDDB failed.\n");
		return FALSE;
	}

	UNICODE_STRING kdmapperName = RTL_CONSTANT_STRING(L"iqvw64e.sys");
	PiDDBCacheEntry kdmapperEntry = { 0 };
	kdmapperEntry.DriverName = kdmapperName;
	kdmapperEntry.TimeDateStamp = 0x5284EAC3;

	UNICODE_STRING capcomName = RTL_CONSTANT_STRING(L"capcom.sys");
	PiDDBCacheEntry capcomEntry = { 0 };
	capcomEntry.DriverName = capcomName;
	capcomEntry.TimeDateStamp = 0x57CD1415;

	ExAcquireResourceExclusiveLite(piDDBLock, TRUE);

	// Iterate table elements (https://github.com/ApexLegendsUC/anti-cheat-emulator/blob/master/Source.cpp#L618)
	//for (PiDDBCacheEntry* p = RtlEnumerateGenericTableAvl(piDDBCacheTable, TRUE); p != NULL; p = RtlEnumerateGenericTableAvl(piDDBCacheTable, FALSE)) {
	//	if (p->TimeDateStamp == 0x5284eac3) {
	//		DPRINT("kdmapper detected, driver: %wZ\n", p->DriverName);
	//	}
	//	else if (p->TimeDateStamp == 0x57CD1415) {
	//		DPRINT("drvmap detected, driver: %wZ\n", p->DriverName);
	//	}
	//}

	PiDDBCacheEntry* pFoundEntry = RtlLookupElementGenericTableAvl(piDDBCacheTable, &kdmapperEntry);
	if (pFoundEntry) {
		RemoveEntryList(&pFoundEntry->List);
		if (RtlDeleteElementGenericTableAvl(piDDBCacheTable, pFoundEntry)) {
			DPRINT("kdmapper detected and cleared.\n");
		}
		else {
			DPRINT("failed to delete element from table.");
		}
	}

	pFoundEntry = RtlLookupElementGenericTableAvl(piDDBCacheTable, &capcomEntry);
	if (pFoundEntry) {
		RemoveEntryList(&pFoundEntry->List);
		if (RtlDeleteElementGenericTableAvl(piDDBCacheTable, pFoundEntry)) {
			DPRINT("drvmap detected and cleared.\n");
		}
		else {
			DPRINT("failed to delete element from table.");
		}
	}

	ExReleaseResourceLite(piDDBLock);
	return TRUE;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {
	UNREFERENCED_PARAMETER(pDriverObject);
	UNREFERENCED_PARAMETER(pRegistryPath);

	kernelBaseAddress = *(VOID**)((ULONG_PTR)PsLoadedModuleList + 0x30);
	kernelBaseSize = *(SIZE_T*)((ULONG_PTR)PsLoadedModuleList + 0x40);

	NTSTATUS status;

	PVOID pSharedSection;
	HANDLE hSection;

	PKEVENT pSharedRequestEvent, pSharedCompletionEvent;
	HANDLE hRequestEvent, hCompletionEvent;

	DPRINT("[>] UnloadDriver: %p\n", UnloadDriver);
	DPRINT("[>] RequestHandler: %p\n", RequestHandler);
	DPRINT("[>] DriverEntry: %p\n", DriverEntry);

	DPRINT("Clearing PiDDBCacheTable...\n");
	if (ClearPiDDBCacheTable()) {
		DPRINT("Clear successful.\n");
	}
	else {
		DPRINT("Clear unsuccessful.\n");
	}

	// Locate MiGetPteAddress
	MiGetPteAddress = (PMMPTE(*)(PVOID))FindPattern(kernelBaseAddress, kernelBaseSize, "\x48\xC1\xE9\x09\x48\xB8\xF8\xFF\xFF\xFF\x7F\x00\x00\x00\x48\x23\xC8\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x48\x03\xC1\xC3", "xxxxxxxxxxxxxxxxxxx????????xxxx");
	if (!MiGetPteAddress) {
		DPRINT("MiGetPteAddress is null\n");
		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}

	// Locate the DOS and NT headers of our driver image to find its size, iterating by PAGE_SIZE
	// Find DOS header
	ULONG_PTR driverEntryAligned = (ULONG_PTR)DriverEntry;
	driverEntryAligned -= driverEntryAligned % PAGE_SIZE;

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)((ULONG_PTR)driverEntryAligned - PAGE_SIZE);
	while (dosHeader->e_magic != 'ZM') {
		dosHeader = (PIMAGE_DOS_HEADER)((ULONG_PTR)dosHeader - PAGE_SIZE);
	}
	
	DPRINT("\ndos header address: %p\n", dosHeader);
	DPRINT("dos header magic: %.*s\n", 2, &dosHeader->e_magic);
	
	// Find NT header
	PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)((ULONG_PTR)dosHeader + dosHeader->e_lfanew);
	if (ntHeader->Signature != 'EP') {
		DPRINT("nt header magic incorrect.\n");
	}
	else if (ntHeader->OptionalHeader.Magic != 0x20B) {
		DPRINT("image not 64 bit.\n");
	}
	
	DPRINT("\nnt header address: %p\n", ntHeader);
	DPRINT("nt header magic: %.*s\n", 4, &ntHeader->Signature);
	DPRINT("optional header magic: 0x%hx\n", ntHeader->OptionalHeader.Magic);
	DPRINT("image size: 0x%lx\n", ntHeader->OptionalHeader.SizeOfImage);
	DPRINT("entry point offset: 0x%lx\n", ntHeader->OptionalHeader.AddressOfEntryPoint);
	DPRINT("size of headers: 0x%lx\n", ntHeader->OptionalHeader.SizeOfHeaders);
	
	// Find discardable section to be hijacked
	PVOID discardableSection = FindDiscardableSection(ntHeader->OptionalHeader.SizeOfImage);
	if (!discardableSection) {
		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}

	// Allocate buffer for new discardable section
	PVOID discardableAllocatedBuffer = ExAllocatePool(NonPagedPoolExecute, ROUND_TO_PAGES(ntHeader->OptionalHeader.SizeOfImage - ntHeader->OptionalHeader.SizeOfHeaders));
	if (!discardableAllocatedBuffer) {
		DPRINT("ExAllocatePool for discardableAllocatedBuffer failed.\n");
		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}

	// Replace discardable section PTEs
	for (SIZE_T i = 0; i < ROUND_TO_PAGES(ntHeader->OptionalHeader.SizeOfImage); i += PAGE_SIZE) {
		PMMPTE discardableSectionPte = MiGetPteAddress((PVOID)((ULONG_PTR)discardableSection + i));
		PMMPTE discardableAllocatedBufferPte = MiGetPteAddress((PVOID)((ULONG_PTR)discardableAllocatedBuffer + i));

		DPRINT("offset 0x%llx\n", i);
		DPRINT("    discardable section pte @ 0x%p\n", discardableSectionPte);
		DPRINT("    allocated pte @ 0x%p\n", discardableAllocatedBufferPte);

		*discardableSectionPte = *discardableAllocatedBufferPte;
	}

	memcpy(discardableSection, (PVOID)((ULONG_PTR)dosHeader + ntHeader->OptionalHeader.SizeOfHeaders), ntHeader->OptionalHeader.SizeOfImage - ntHeader->OptionalHeader.SizeOfHeaders);
	DPRINT("sections copied without headers.\n");

	// Create names from GUID
	UNICODE_STRING sectionName = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\" GUID_SECTION);
	UNICODE_STRING requestEventName = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\" GUID_REQUEST_EVENT);
	UNICODE_STRING completionEventName = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\" GUID_COMPLETION_EVENT);

	DPRINT("[>] Section name: %wZ\n", &sectionName);
	DPRINT("[>] Request event name: %wZ\n", &requestEventName);
	DPRINT("[>] Completion event name: %wZ\n", &completionEventName);

	// Create shared memory
	DPRINT("[+] Creating shared memory...\n");

	OBJECT_ATTRIBUTES objAttributes = { 0 };
	InitializeObjectAttributes(&objAttributes, &sectionName, OBJ_KERNEL_HANDLE, NULL, NULL);

	LARGE_INTEGER lMaxSize = { 0 };
	lMaxSize.QuadPart = sizeof(KERNEL_OPERATION_REQUEST);
	status = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, &objAttributes, &lMaxSize, PAGE_READWRITE, SEC_COMMIT, NULL);
	if (!NT_SUCCESS(status))
	{
		DPRINT("[-] ZwCreateSection failed. Status: %p\n", status);
		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}
	DPRINT("[+] Shared memory created.\n");

	// Get pointer to shared section in context
	PVOID pContextSharedSection;
	status = ObReferenceObjectByHandle(hSection, SECTION_ALL_ACCESS, NULL, KernelMode, &pContextSharedSection, NULL);
	if (!NT_SUCCESS(status))
	{
		DPRINT("[-] ObReferenceObjectByHandle failed. Status: %p\n", status);
		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}

	// Map shared section in context to system's address space so it can be accessed anywhere
	SIZE_T ulViewSize = 0;
	status = MmMapViewInSystemSpace(pContextSharedSection, &pSharedSection, &ulViewSize);
	if (!NT_SUCCESS(status))
	{
		DPRINT("[-] MmMapViewInSystemSpace failed. Status: %p\n", status);
		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}
	DPRINT("[+] MmMapViewInSystemSpace completed.\n");
	DPRINT("pSharedSection = 0x%p\n", pSharedSection);

	// Dereference shared section object
	ObDereferenceObject(pContextSharedSection);

	// Create named events
	pSharedRequestEvent = IoCreateNotificationEvent(&requestEventName, &hRequestEvent);
	pSharedCompletionEvent = IoCreateNotificationEvent(&completionEventName, &hCompletionEvent);

	if (!pSharedRequestEvent || !pSharedCompletionEvent) {
		DPRINT("[-] IoCreateNotificationEvent failed.\n");
		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}
	DPRINT("[+] IoCreateNotificationEvent completed.\n");

	// Clear events since they start in the signaled state
	KeClearEvent(pSharedRequestEvent);
	KeClearEvent(pSharedCompletionEvent);

	// Initialize params structure so new thread can access events and shared section
	PREQUEST_HANDLER_PARAMS params = ExAllocatePool(NonPagedPoolNx, sizeof(REQUEST_HANDLER_PARAMS));
	if (!params) {
		DPRINT("ExAllocatePool for PREQUEST_HANDLER_PARAMS failed.\n");
		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}
	params->hCompletionEvent = hCompletionEvent;
	params->hRequestEvent = hRequestEvent;
	params->hSection = hSection;
	params->pSharedCompletionEvent = pSharedCompletionEvent;
	params->pSharedRequestEvent = pSharedRequestEvent;
	params->pSharedSection = pSharedSection;

	DPRINT("context @ 0x%p\n", params);

	// Create new system thread, pass in our initialized params
	HANDLE hThread;
	OBJECT_ATTRIBUTES threadAttributes = { 0 };
	InitializeObjectAttributes(&threadAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, &threadAttributes, NULL, NULL, (PKSTART_ROUTINE)((ULONG_PTR)RequestHandler - ((ULONG_PTR)dosHeader + ntHeader->OptionalHeader.SizeOfHeaders) + (ULONG_PTR)discardableSection), params);
	if (!NT_SUCCESS(status))
	{
		DPRINT("[-] PsCreateSystemThread fail! Status: %p\n", status);
		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}

	return STATUS_SUCCESS;
}
