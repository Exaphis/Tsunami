#include <ntifs.h>
#include "SharedMemoryTools.h"

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

PVOID poolAddress;

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

	__try
	{
		RtlCopyMemory(targetAddress, sourceAddress, size);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KeUnstackDetachProcess(&apcState);
		return STATUS_INTERNAL_ERROR;
	}

	KeUnstackDetachProcess(&apcState);

	return STATUS_SUCCESS;
}

void UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
#ifdef DEBUG
	DbgPrintEx(0, 0, "Tsunami unload routine called.\n");
#endif

	ExFreePoolWithTag(poolAddress, 'looP');

	if (pSharedSection) {
		ZwUnmapViewOfSection(NtCurrentProcess(), pSharedSection);
	}
	if (hSection) {
		ZwClose(hSection);
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

	// Unmap shared section if already mapped
	if (pSharedSection) {
		ZwUnmapViewOfSection(ZwCurrentProcess(), pSharedSection);
	}

	// Map shared section
	SIZE_T ulViewSize = 0;
	status = ZwMapViewOfSection(hSection, ZwCurrentProcess(), &pSharedSection, 0, SHARED_MEMORY_NUM_BYTES, NULL, &ulViewSize, ViewShare, 0, PAGE_READWRITE | PAGE_NOCACHE);
	if (status != STATUS_SUCCESS)
	{
#ifdef DEBUG
		DbgPrintEx(0, 0, "ZwMapViewOfSection fail! Status: %p\n", status);
#endif
		ZwClose(hSection);

		irp->IoStatus.Status = status;
		irp->IoStatus.Information = bytes;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
	}
#ifdef DEBUG
	DbgPrintEx(0, 0, "ZwMapViewOfSection completed!\n");
#endif
	// Code received from user space
	ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;

	if (controlCode == IO_READ_REQUEST)
	{
		// Get the input buffer & format it to our struct
		PKERNEL_READ_REQUEST readRequest = (PKERNEL_READ_REQUEST)irp->AssociatedIrp.SystemBuffer;

		// Get our process
		PEPROCESS process;
		status = PsLookupProcessByProcessId((HANDLE)readRequest->processID, &process);

		if (NT_SUCCESS(status))
		{
			status = KeCopyMemory(process, (PVOID)readRequest->address, poolAddress, readRequest->size);
			if (NT_SUCCESS(status))
			{
				RtlCopyMemory(pSharedSection, poolAddress, readRequest->size);
			}
		}
		else
		{
			status = STATUS_UNSUCCESSFUL;
		}

#ifdef DEBUG
		DbgPrintEx(0, 0, "Read:  %lu, 0x%I64X, %lu \n", readRequest->processID, readRequest->address, readRequest->size);
#endif

		ObDereferenceObject(process);
		bytes = sizeof(KERNEL_READ_REQUEST);
	}
	else if (controlCode == IO_WRITE_REQUEST)
	{
		// Get the input buffer & format it to our struct
		PKERNEL_WRITE_REQUEST writeRequest = (PKERNEL_WRITE_REQUEST)irp->AssociatedIrp.SystemBuffer;

		// Get our process
		PEPROCESS process;
		status = PsLookupProcessByProcessId((HANDLE)writeRequest->processID, &process);

		RtlCopyMemory(poolAddress, pSharedSection, writeRequest->size);

		if (NT_SUCCESS(status))
		{
			status = KeCopyMemory(process, poolAddress, (PVOID)writeRequest->address, writeRequest->size);
		}
		else
		{
			status = STATUS_UNSUCCESSFUL;
		}

#ifdef DEBUG
		DbgPrintEx(0, 0, "Write:  %lu, 0x%I64X, %lu \n", writeRequest->processID, writeRequest->address, writeRequest->size);
#endif

		ObDereferenceObject(process);
		bytes = sizeof(KERNEL_WRITE_REQUEST);
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
#ifdef DEBUG
	DbgPrintEx(0, 0, "Creating shared memory...\n");
#endif
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

	UNICODE_STRING uSectionName = { 0 };
	RtlInitUnicodeString(&uSectionName, L"\\BaseNamedObjects\\TsunamiSharedMemory");

	OBJECT_ATTRIBUTES objAttributes = { 0 };
	InitializeObjectAttributes(&objAttributes, &uSectionName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	LARGE_INTEGER lMaxSize = { 0 };
	lMaxSize.HighPart = 0;
	lMaxSize.LowPart = SHARED_MEMORY_NUM_BYTES;
	ntStatus = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, &objAttributes, &lMaxSize, PAGE_READWRITE, SEC_COMMIT, NULL);
	if (ntStatus != STATUS_SUCCESS)
	{
#ifdef DEBUG
		DbgPrintEx(0, 0, "ZwCreateSection fail! Status: %p\n", ntStatus);
#endif
		return ntStatus;
	}
#ifdef DEBUG
	DbgPrintEx(0, 0, "ZwCreateSection completed!\n");
#endif

	PACL pACL = NULL;
	PSECURITY_DESCRIPTOR pSecurityDescriptor = { 0 };
	ntStatus = CreateStandardSCAndACL(&pSecurityDescriptor, &pACL);
	if (ntStatus != STATUS_SUCCESS)
	{
#ifdef DEBUG
		DbgPrintEx(0, 0, "CreateStandardSCAndACL fail! Status: %p\n", ntStatus);
#endif
		ZwClose(hSection);
		return ntStatus;
	}

	ntStatus = GrantAccess(hSection, pACL);
	if (ntStatus != STATUS_SUCCESS)
	{
#ifdef DEBUG
		DbgPrintEx(0, 0, "GrantAccess fail! Status: %p\n", ntStatus);
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

// Driver Entrypoint
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pRegistryPath);

#ifdef DEBUG
	DbgPrintEx(0, 0, "Tsunami load routine called...\n");
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
	pDriverObject->DriverUnload = UnloadDriver;

#ifdef DEBUG
	DbgPrintEx(0, 0, "Calling CreateSharedMemory...\n");
#endif
	CreateSharedMemory();
#ifdef DEBUG
	DbgPrintEx(0, 0, "Shared memory created, address: %p\n", pSharedSection);
#endif

	poolAddress = ExAllocatePoolWithTag(NonPagedPool, SHARED_MEMORY_NUM_BYTES, 'looP');
#ifdef DEBUG
	DbgPrintEx(0, 0, "Pool buffer created, address: %p\n", poolAddress);
#endif

	pDeviceObject->Flags |= DO_BUFFERED_IO;

#ifdef DEBUG
	DbgPrintEx(0, 0, "Tsunami loaded.\n");
#endif

	return STATUS_SUCCESS;
}
