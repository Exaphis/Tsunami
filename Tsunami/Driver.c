#include "ntos.h"

// #define DEBUG 1

// Request to read virtual user memory (memory of a program) from kernel space
#define IO_READ_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0701, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Request to write virtual user memory (memory of a program) from kernel space
#define IO_WRITE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0702, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

PDEVICE_OBJECT pDeviceObject; // Our driver object
UNICODE_STRING dev, dos; // Driver registry paths

typedef struct _KERNEL_READ_REQUEST
{
	ULONG ProcessId;

	ULONGLONG Address;
	UCHAR Response[8192];
	ULONG Size;

} KERNEL_READ_REQUEST, *PKERNEL_READ_REQUEST;

typedef struct _KERNEL_WRITE_REQUEST
{
	ULONG ProcessId;

	ULONGLONG Address;
	UCHAR Value[8192];
	ULONG Size;

} KERNEL_WRITE_REQUEST, *PKERNEL_WRITE_REQUEST;

NTSTATUS KeOperateProcessMemory(PEPROCESS process, PVOID sourceAddress, PVOID targetAddress, SIZE_T size)
{
	KAPC_STATE apcState;
	KeStackAttachProcess(process, &apcState);
	__try {
		RtlCopyMemory(targetAddress, sourceAddress, size);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		KeUnstackDetachProcess(&apcState);
		return STATUS_ACCESS_DENIED;
	}
	KeUnstackDetachProcess(&apcState);
}

void UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
#ifdef DEBUG
	DbgPrintEx(0, 0, "Tsunami unload routine called.\n");
#endif

	IoDeleteSymbolicLink(&dos);
	IoDeleteDevice(pDriverObject->DeviceObject);
}

NTSTATUS TsunamiDispatchCreate(PDEVICE_OBJECT deviceObject, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS TsunamiDispatchClose(PDEVICE_OBJECT deviceObject, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

// IOCTL Call Handler function
NTSTATUS TsunamiDispatchDeviceControl(PDEVICE_OBJECT deviceObject, PIRP irp)
{
	NTSTATUS status;
	ULONG bytes = 0;

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);

	// Code received from user space
	ULONG ControlCode = stack->Parameters.DeviceIoControl.IoControlCode;

	if (ControlCode == IO_READ_REQUEST)
	{
		// Get the input buffer & format it to our struct
		PKERNEL_READ_REQUEST readRequest = (PKERNEL_READ_REQUEST)irp->AssociatedIrp.SystemBuffer;

		// Get our process
		PEPROCESS process;
		status = PsLookupProcessByProcessId(readRequest->ProcessId, &process);

		if (NT_SUCCESS(status))
		{
			status = KeOperateProcessMemory(process, readRequest->Address, &readRequest->Response, readRequest->Size);
		}
			
#ifdef DEBUG
		DbgPrintEx(0, 0, "Read:  %lu, 0x%I64X, %lu \n", ReadInput->ProcessId, ReadInput->Address, ReadInput->Size);
#endif

		ObDereferenceObject(process);
		bytes = sizeof(KERNEL_READ_REQUEST);
	}
	else if (ControlCode == IO_WRITE_REQUEST)
	{
		// Get the input buffer & format it to our struct
		PKERNEL_WRITE_REQUEST writeRequest = (PKERNEL_WRITE_REQUEST)irp->AssociatedIrp.SystemBuffer;

		// Get our process
		PEPROCESS process;
		status = PsLookupProcessByProcessId(writeRequest->ProcessId, &process);

		if (NT_SUCCESS(status))
		{
			KeOperateProcessMemory(process, &writeRequest->Value, writeRequest->Address, writeRequest->Size);
		}
			
#ifdef DEBUG
		DbgPrintEx(0, 0, "Write:  %lu, 0x%I64X \n", WriteInput->ProcessId, WriteInput->Address);
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

// Driver Entrypoint
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
#ifdef DEBUG
	DbgPrintEx(0, 0, "Tsunami load routine called...\n");
#endif

	RtlInitUnicodeString(&dev, L"\\Device\\tsunami");
	RtlInitUnicodeString(&dos, L"\\DosDevices\\tsunami");

	IoCreateDevice(pDriverObject, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
	IoCreateSymbolicLink(&dos, &dev);

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = TsunamiDispatchCreate;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = TsunamiDispatchClose;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = TsunamiDispatchDeviceControl;
	pDriverObject->DriverUnload = UnloadDriver;

#ifdef DEBUG
	DbgPrintEx(0, 0, "Tsunami loaded.\n");
#endif

	return STATUS_SUCCESS;
}
