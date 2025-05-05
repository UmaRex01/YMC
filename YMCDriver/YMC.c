#include "YMC.h"
#include "Public.h"

UNICODE_STRING g_deviceName = RTL_CONSTANT_STRING(L"\\Device\\YMC");
UNICODE_STRING g_symLink = RTL_CONSTANT_STRING(L"\\??\\YMC");

NTSTATUS CreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS Create(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	KdPrint(("YMC!Create\n"));
	return CreateClose(DeviceObject, Irp);
}

NTSTATUS Close(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	KdPrint(("YMC!Close\n"));
	return CreateClose(DeviceObject, Irp);
}

NTSTATUS Control(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	KdPrint(("YMC!Control\n"));
	UNREFERENCED_PARAMETER(DeviceObject);

	ULONG_PTR length = 0;
	NTSTATUS status = STATUS_SUCCESS;

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	void* pReq;

	switch (stack->Parameters.DeviceIoControl.IoControlCode)
	{

	case YMC_IOCTL_PROTECT_PROCESS:
	case YMC_IOCTL_UNPROTECT_PROCESS:
		if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(YMCREQ_PROTECT_PROCESS)) {
			KdPrint(("YMC!Control # Input buffer too small for YMCREQ_PROTECT_PROCESS\n"));
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		if (stack->Parameters.DeviceIoControl.Type3InputBuffer == NULL) {
			KdPrint(("YMC!Control # Input buffer is null\n"));
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		pReq = stack->Parameters.DeviceIoControl.Type3InputBuffer;
		if (stack->Parameters.DeviceIoControl.IoControlCode == YMC_IOCTL_PROTECT_PROCESS)
			status = PP_ProtectProcess((PYMCREQ_PROTECT_PROCESS)pReq);
		else
			status = PP_UnprotectProcess((PYMCREQ_PROTECT_PROCESS)pReq);
		break;

	case YMC_IOCTL_SET_PROCESS_PRIVS:
		if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(YMCREQ_PROCESS_PRIVS)) {
			KdPrint(("YMC!Control # Input buffer too small for YMCREQ_PROCESS_PRIVS\n"));
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		if (stack->Parameters.DeviceIoControl.Type3InputBuffer == NULL) {
			KdPrint(("YMC!Control # Input buffer is null\n"));
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		pReq = stack->Parameters.DeviceIoControl.Type3InputBuffer;
		status = PV_SetPrivileges((PYMCREQ_PROCESS_PRIVS)pReq);
		break;

	case YMC_IOCTL_GET_PROCESS_CALLBACKS:
	case YMC_IOCTL_GET_THREAD_CALLBACKS:
	case YMC_IOCTL_GET_IMAGE_CALLBACKS:
		if (stack->Parameters.DeviceIoControl.OutputBufferLength < (sizeof(YMCRES_CALLBACKS) * MAX_CALLBACKS)) {
			KdPrint(("YMC!Control # Output buffer too small for YMCRES_CALLBACKS\n"));
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		if (Irp->UserBuffer == NULL) {
			KdPrint(("YMC!Control # Output buffer is null\n"));
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		pReq = Irp->UserBuffer;
		if (stack->Parameters.DeviceIoControl.IoControlCode == YMC_IOCTL_GET_PROCESS_CALLBACKS)
			status = CB_GetProcessNotificationCallbacks((PYMCRES_CALLBACKS)pReq, &length);
		else if (stack->Parameters.DeviceIoControl.IoControlCode == YMC_IOCTL_GET_THREAD_CALLBACKS)
			status = CB_GetThreadNotificationCallbacks((PYMCRES_CALLBACKS)pReq, &length);
		else if (stack->Parameters.DeviceIoControl.IoControlCode == YMC_IOCTL_GET_IMAGE_CALLBACKS)
			status = CB_GetImageNotificationCallbacks((PYMCRES_CALLBACKS)pReq, &length);
		break;

	case YMC_IOCTL_DEL_PROCESS_CALLBACKS:
	case YMC_IOCTL_DEL_THREAD_CALLBACKS:
	case YMC_IOCTL_DEL_IMAGE_CALLBACKS:
		if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(YMCREQ_CALLBACKS)) {
			KdPrint(("YMC!Control # Input buffer too small for YMCREQ_CALLBACKS\n"));
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		if (stack->Parameters.DeviceIoControl.Type3InputBuffer == NULL) {
			KdPrint(("YMC!Control # Input buffer is null\n"));
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		pReq = stack->Parameters.DeviceIoControl.Type3InputBuffer;
		if (stack->Parameters.DeviceIoControl.IoControlCode == YMC_IOCTL_DEL_PROCESS_CALLBACKS)
			status = CB_DelProcessNotificationCallbacks((PYMCREQ_CALLBACKS)pReq);
		else if (stack->Parameters.DeviceIoControl.IoControlCode == YMC_IOCTL_DEL_THREAD_CALLBACKS)
			status = CB_DelThreadNotificationCallbacks((PYMCREQ_CALLBACKS)pReq);
		else if (stack->Parameters.DeviceIoControl.IoControlCode == YMC_IOCTL_DEL_IMAGE_CALLBACKS)
			status = CB_DelImageNotificationCallbacks((PYMCREQ_CALLBACKS)pReq);
		break;

	default:
		status = STATUS_INVALID_DEVICE_REQUEST;;
		KdPrint(("[!] YMC!Control # Unknown IOCTL code!\n"));
		break;

	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = length;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}

void Cleanup(PDRIVER_OBJECT DriverObject)
{
	KdPrint(("YMC!Cleanup\n"));
	IoDeleteSymbolicLink(&g_symLink);
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT pDeviceObject;

	UNREFERENCED_PARAMETER(RegistryPath);
	KdPrint(("YMC!DriverEntry\n"));

	status = IoCreateDevice(DriverObject, 0, &g_deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDeviceObject);
	if (!NT_SUCCESS(status)) {
		KdPrint(("YMC!DriverEntry # IoCreateDevice failed: 0x%08X\n", status));
		return status;
	}
	status = IoCreateSymbolicLink(&g_symLink, &g_deviceName);
	if (!NT_SUCCESS(status)) {
		KdPrint(("YMC!DriverEntry # IoCreateSymbolicLink failed: 0x%08X\n", status));
		IoDeleteDevice(pDeviceObject);
		return status;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE] = Create;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = Close;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Control;
	DriverObject->DriverUnload = Cleanup;

	return status;
}