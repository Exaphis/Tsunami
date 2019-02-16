#include <ntifs.h>
#include "SharedMemoryTools.h"

typedef NTSTATUS (*PDRIVER_INITIALIZE) (IN struct _DRIVER_OBJECT *DriverObject, IN PUNICODE_STRING RegistryPath);

NTKERNELAPI NTSTATUS IoCreateDriver(
	IN PUNICODE_STRING DriverName, 
	IN PDRIVER_INITIALIZE InitializationFunction
);

// Request to read virtual user memory (memory of a program) from kernel space
#define IO_READ_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x203, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Request to write virtual user memory (memory of a program) from kernel space
#define IO_WRITE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x204, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Number of bytes in the shared memory (Max: 4294967295)
#define SHARED_MEMORY_NUM_BYTES 4 * 1024 * 1024

PDEVICE_OBJECT pDeviceObject; // Our driver object
UNICODE_STRING dev, dos; // Driver registry paths

PVOID pSharedSection;
HANDLE hSection;

typedef struct _KERNEL_READ_REQUEST
{
	ULONG64 processID;
	ULONG64 address;
	SIZE_T size;
} KERNEL_READ_REQUEST, *PKERNEL_READ_REQUEST;

typedef struct _KERNEL_WRITE_REQUEST
{
	ULONG64 processID;
	ULONG64 address;
	SIZE_T size;
} KERNEL_WRITE_REQUEST, *PKERNEL_WRITE_REQUEST;

NTSTATUS KeCopyMemory(PEPROCESS process, PVOID sourceAddress, PVOID targetAddress, SIZE_T size)
{
	KAPC_STATE apcState;
	KeStackAttachProcess(process, &apcState);
	RtlCopyMemory(targetAddress, sourceAddress, size);
	KeUnstackDetachProcess(&apcState);

	return STATUS_SUCCESS;
}

BOOLEAN IsAddressAccessible(PEPROCESS process, ULONG64 targetAddress, SIZE_T size, BOOLEAN writable) {
	NTSTATUS status;

	HANDLE hProcess;
	status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, NULL, 0, 0, KernelMode, &hProcess);
	if (!NT_SUCCESS(status)) {
		return FALSE;
	}

	MEMORY_BASIC_INFORMATION mbi;
	status = ZwQueryVirtualMemory(hProcess, (PVOID)targetAddress, MemoryBasicInformation, &mbi, sizeof(mbi), NULL);
	ZwClose(hProcess);
	if (!NT_SUCCESS(status)) {
		return FALSE;
	}

	if (mbi.State != MEM_COMMIT)
		return FALSE;

	if (mbi.Protect == PAGE_NOACCESS || mbi.Protect == PAGE_EXECUTE)
		return FALSE;

	if (writable && (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_READONLY))
		return FALSE;

	if (targetAddress + size > (ULONG64)mbi.BaseAddress + mbi.RegionSize)
		return FALSE;

	return TRUE;
}

void UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
#ifdef DEBUG
	DbgPrintEx(0, 0, "[+] Tsunami unload routine called.\n");
#endif

	// Unmap view of section in kernel address space
	if (pSharedSection) {
		if (!NT_SUCCESS(MmUnmapViewInSystemSpace(pSharedSection))) {
			DbgPrintEx(0, 0, "[-] MmUnmapViewInSystemSpace failed.\n");
		}
#ifdef DEBUG
		DbgPrintEx(0, 0, "[+] Shared section unmapped.\n");
#endif
	}

	// Close handle to section
	if (hSection) {
		ZwClose(hSection);
#ifdef DEBUG
		DbgPrintEx(0, 0, "[+] Handle to section closed.\n");
#endif
	}

	IoDeleteSymbolicLink(&dos);
	IoDeleteDevice(pDriverObject->DeviceObject);
}

NTSTATUS TsunamiDispatchDefault(PDEVICE_OBJECT deviceObject, PIRP irp)
{
	UNREFERENCED_PARAMETER(deviceObject);

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

// IOCTL Call Handler function
NTSTATUS TsunamiDispatchDeviceControl(PDEVICE_OBJECT deviceObject, PIRP irp)
{
	UNREFERENCED_PARAMETER(deviceObject);

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG bytes = 0;
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);

	// Code received from user space
	ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;

	if (controlCode == IO_READ_REQUEST)
	{
		// Get the input buffer & format it to our struct
		PKERNEL_READ_REQUEST readRequest = (PKERNEL_READ_REQUEST)irp->AssociatedIrp.SystemBuffer;
		bytes = sizeof(KERNEL_READ_REQUEST);

		// Raise IRQL to APC_LEVEL so address validity does not change between checking and accessing
		KIRQL originalIRQL;
		KeRaiseIrql(APC_LEVEL, &originalIRQL);

#ifdef DEBUG
		DbgPrintEx(0, 0, "[+] Read: %lu, 0x%I64X, %lu \n", readRequest->processID, readRequest->address, readRequest->size);
#endif

		// Get our process
		PEPROCESS process;
		status = PsLookupProcessByProcessId((HANDLE)readRequest->processID, &process);

		if (NT_SUCCESS(status))
		{
			if (IsAddressAccessible(process, readRequest->address, readRequest->size, FALSE)) {
				status = KeCopyMemory(process, (PVOID)readRequest->address, pSharedSection, readRequest->size);
				ObDereferenceObject(process);
			}
#ifdef DEBUG
			else {
				DbgPrintEx(0, 0, "[-] Address inaccessible.");
				status = STATUS_INVALID_ADDRESS;
			}
#endif
		}
#ifdef DEBUG
		else {
			DbgPrintEx(0, 0, "[-] PsLookupProcessByProcessId failed. Status: %p\n", status);
		}
#endif

		// Lower IRQL to original
		KeLowerIrql(originalIRQL);
	}
	else if (controlCode == IO_WRITE_REQUEST)
	{
		// Get the input buffer & format it to our struct
		PKERNEL_WRITE_REQUEST writeRequest = (PKERNEL_WRITE_REQUEST)irp->AssociatedIrp.SystemBuffer;
		bytes = sizeof(KERNEL_WRITE_REQUEST);

		// Raise IRQL to APC_LEVEL so address validity does not change between checking and accessing
		KIRQL originalIRQL;
		KeRaiseIrql(APC_LEVEL, &originalIRQL);

#ifdef DEBUG
		DbgPrintEx(0, 0, "[+] Write: %lu, 0x%I64X, %lu \n", writeRequest->processID, writeRequest->address, writeRequest->size);
#endif

		// Get our process
		PEPROCESS process;
		status = PsLookupProcessByProcessId((HANDLE)writeRequest->processID, &process);

		if (NT_SUCCESS(status))
		{
			if (IsAddressAccessible(process, writeRequest->address, writeRequest->size, TRUE)) {
				status = KeCopyMemory(process, pSharedSection, (PVOID)writeRequest->address, writeRequest->size);
				ObDereferenceObject(process);
			}
#ifdef DEBUG
			else {
				DbgPrintEx(0, 0, "[-] Address inaccessible.");
				status = STATUS_INVALID_ADDRESS;
			}
#endif
		}
#ifdef DEBUG
		else {
			DbgPrintEx(0, 0, "[-] PsLookupProcessByProcessId failed. Status: %p\n", status);
		}
#endif

		// Lower IRQL to original
		KeLowerIrql(originalIRQL);
	}
	else
	{
		// if the code is unknown
		status = STATUS_INVALID_PARAMETER;
		bytes = 0;
	}

	// Complete the request
	irp->IoStatus.Status = status;
	irp->IoStatus.Information = bytes;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return status;
}

NTSTATUS CreateSharedMemory()
{
	// Source: https://raw.githubusercontent.com/mq1n/EasyRing0/master/Tutorial_6_ShareMem_Communication_SYS/main.c
#ifdef DEBUG
	DbgPrintEx(0, 0, "[+] Creating shared memory...\n");
#endif
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

	UNICODE_STRING uSectionName = { 0 };
	RtlInitUnicodeString(&uSectionName, L"\\BaseNamedObjects\\TsunamiSharedMemory");

	OBJECT_ATTRIBUTES objAttributes = { 0 };
	InitializeObjectAttributes(&objAttributes, &uSectionName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	LARGE_INTEGER lMaxSize = { 0 };
	lMaxSize.HighPart = 0;
	lMaxSize.LowPart = SHARED_MEMORY_NUM_BYTES;
	ntStatus = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, &objAttributes, &lMaxSize, PAGE_READWRITE, SEC_COMMIT, NULL);
	if (ntStatus != STATUS_SUCCESS)
	{
#ifdef DEBUG
		DbgPrintEx(0, 0, "[-] ZwCreateSection fail! Status: %p\n", ntStatus);
#endif
		return ntStatus;
	}
#ifdef DEBUG
	DbgPrintEx(0, 0, "[+] ZwCreateSection completed!\n");
#endif

	PACL pACL = NULL;
	PSECURITY_DESCRIPTOR pSecurityDescriptor = { 0 };
	ntStatus = CreateStandardSCAndACL(&pSecurityDescriptor, &pACL);
	if (ntStatus != STATUS_SUCCESS)
	{
#ifdef DEBUG
		DbgPrintEx(0, 0, "[-] CreateStandardSCAndACL fail! Status: %p\n", ntStatus);
#endif
		ZwClose(hSection);
		return ntStatus;
	}

	ntStatus = GrantAccess(hSection, pACL);
	if (ntStatus != STATUS_SUCCESS)
	{
#ifdef DEBUG
		DbgPrintEx(0, 0, "[-] GrantAccess fail! Status: %p\n", ntStatus);
#endif
		ExFreePool(pACL);
		ExFreePool(pSecurityDescriptor);
		ZwClose(hSection);
		return ntStatus;
	}

	ExFreePool(pACL);
	ExFreePool(pSecurityDescriptor);

	return ntStatus;
}

// Real Driver entrypoint
NTSTATUS DriverInitialize(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pRegistryPath);

#ifdef DEBUG
	DbgPrintEx(0, 0, "[+] Tsunami load routine called...\n");
	DbgPrintEx(0, 0, "Running in process %lu (%p)\n", PsGetCurrentProcessId(), PsGetCurrentProcess());
#endif

	RtlInitUnicodeString(&dev, L"\\Device\\tsunami");
	RtlInitUnicodeString(&dos, L"\\DosDevices\\tsunami");

	IoCreateDevice(pDriverObject, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
	IoCreateSymbolicLink(&dos, &dev);

	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		pDriverObject->MajorFunction[i] = TsunamiDispatchDefault;
	}
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = TsunamiDispatchDeviceControl;
	pDriverObject->DriverUnload = NULL; // No driver unload, using drvmap!

	pDeviceObject->Flags |= DO_BUFFERED_IO;
	pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	NTSTATUS status;

	// Create shared section
	status = CreateSharedMemory();

	if (!NT_SUCCESS(status)) {
		DbgPrintEx(0, 0, "[-] CreateSharedMemory fail!\n");
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
		DbgPrintEx(0, 0, "[-] ZwOpenSection fail! Status: %p\n", status);

		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}
	else {
		DbgPrintEx(0, 0, "[+] ZwOpenSection succeeded. Handle: %p\n", tempSectionHandle);
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
		DbgPrintEx(0, 0, "MmMapViewInSystemSpace fail! Status: %p\n", status);

		return STATUS_DRIVER_UNABLE_TO_LOAD;
	}
#ifdef DEBUG
	DbgPrintEx(0, 0, "[+] MmMapViewInSystemSpace completed!\n");
	DbgPrintEx(0, 0, "pSharedSection = 0x%p\n", pSharedSection);
#endif

	// Dereference shared section object
	ObDereferenceObject(pContextSharedSection);

#ifdef DEBUG
	DbgPrintEx(0, 0, "[+] Tsunami loaded.\n");
#endif

	return STATUS_SUCCESS;
}

// Fake Driver entrypoint
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {
	UNREFERENCED_PARAMETER(pDriverObject);
	UNREFERENCED_PARAMETER(pRegistryPath);

	UNICODE_STRING drvName;
	RtlInitUnicodeString(&drvName, L"\\Driver\\tsunami");
	return IoCreateDriver(&drvName, &DriverInitialize);
}
