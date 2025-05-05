#include <ntifs.h>
#include <aux_klib.h>
#include "YMC.h"
#include "Nt.h"

static const VERSION_SUPPORT supportedVersions[] = {
	{10, 0, 19045, 0x552030, 0x5523C0, 0x5525A0}
};
static int CB_STATUS = 0;
static ULONG64 CB_P_PROCSNOTIFY_ARRAY = 0;
static ULONG64 CB_P_THREDNOTIFY_ARRAY = 0;
static ULONG64 CB_P_IMAGENOTIFY_ARRAY = 0;

static NTSTATUS CB_Check()
{
	if (CB_STATUS > 0)
		return STATUS_SUCCESS;
	if (CB_STATUS < 0)
		return STATUS_NOT_SUPPORTED;

	RTL_OSVERSIONINFOW osInfo;
	NTSTATUS status = GetWindowsVersion(&osInfo);
	if (!NT_SUCCESS(status)) {
		KdPrint(("YMC!CB_Check # RtlGetVersion faield: 0x%08X\n", status));
		return status;
	}

	for (int i = 0; i < (sizeof(supportedVersions) / sizeof(supportedVersions[0])); i++) {
		if (
			supportedVersions[i].MajorVersion == osInfo.dwMajorVersion &&
			supportedVersions[i].MinorVersion == osInfo.dwMinorVersion &&
			supportedVersions[i].BuildNumber == osInfo.dwBuildNumber
			) {
			UNICODE_STRING functionName;

			RtlInitUnicodeString(&functionName, L"PsSetCreateProcessNotifyRoutine");
			CB_P_PROCSNOTIFY_ARRAY = (ULONG64)MmGetSystemRoutineAddress(&functionName) + supportedVersions[i].Offset1;

			RtlInitUnicodeString(&functionName, L"PsSetCreateThreadNotifyRoutine");
			CB_P_THREDNOTIFY_ARRAY = (ULONG64)MmGetSystemRoutineAddress(&functionName) + supportedVersions[i].Offset2;

			RtlInitUnicodeString(&functionName, L"PsSetLoadImageNotifyRoutine");
			CB_P_IMAGENOTIFY_ARRAY = (ULONG64)MmGetSystemRoutineAddress(&functionName) + supportedVersions[i].Offset3;
		}
	}

	if (CB_P_PROCSNOTIFY_ARRAY == 0 || CB_P_THREDNOTIFY_ARRAY == 0 || CB_P_IMAGENOTIFY_ARRAY == 0) {
		status = STATUS_NOT_SUPPORTED;
		CB_STATUS = -1;
	}
	KdPrint(("YMC!CB_Check # Calculated CB_P_PROCSNOTIFY_ARRAY: 0x%llX\n", CB_P_PROCSNOTIFY_ARRAY));
	KdPrint(("YMC!CB_Check # Calculated CB_P_THREDNOTIFY_ARRAY: 0x%llX\n", CB_P_THREDNOTIFY_ARRAY));
	KdPrint(("YMC!CB_Check # Calculated CB_P_IMAGENOTIFY_ARRAY: 0x%llX\n", CB_P_IMAGENOTIFY_ARRAY));

	status = AuxKlibInitialize();
	if (!NT_SUCCESS(status)) {
		KdPrint(("YMC!CB_Check # AuxKlibInitialize faield: 0x%08X\n", status));
		return status;
	}

	CB_STATUS = 1;
	return status;
}

static NTSTATUS CB_GetCallbacks(ULONG64 callbacksArray, PYMCRES_CALLBACKS pReq, PULONG_PTR respLength)
{
	ULONG modulesSize = 0;
	*respLength = 0;

	NTSTATUS status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
	if (!NT_SUCCESS(status)) {
		KdPrint(("YMC!CB_GetCallbacks 1 # AuxKlibQueryModuleInformation faield: 0x%08X\n", status));
		return status;
	}
	ULONG64 numberOfModules = modulesSize / sizeof(AUX_MODULE_EXTENDED_INFO);

	PAUX_MODULE_EXTENDED_INFO modules = (PAUX_MODULE_EXTENDED_INFO)ExAllocatePool2(
		POOL_FLAG_PAGED, modulesSize, YMC_TAG
	);
	if (modules == 0) {
		KdPrint(("YMC!CB_GetCallbacks # ExAllocatePool2 faield\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory(modules, modulesSize);

	status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), modules);
	if (!NT_SUCCESS(status)) {
		KdPrint(("YMC!CB_GetCallbacks 2 # AuxKlibQueryModuleInformation faield: 0x%08X\n", status));
		ExFreePoolWithTag(modules, YMC_TAG);
		return status;
	}

	ULONG64 arrayPointer = callbacksArray;
	for (int i = 0; i < MAX_CALLBACKS; i++)
	{
		ULONG64 callbackAddress = *(PULONG64)(arrayPointer);
		if (callbackAddress > 0) {
			//https://codemachine.com/articles/kmdf_handles_and_pointers.html
			ULONG64 rawPointer = *(PULONG64)(callbackAddress & 0xfffffffffffffff8);

			KdPrint(("YMC!CB_GetCallbacks # #%d pCallbacksArray[0x%llx] 0x%llx ==> 0x%llx", i, arrayPointer, callbackAddress, rawPointer));
			pReq[i].Address = rawPointer;

			for (int k = 0; k < numberOfModules; k++) {
				ULONG64 startAddress = (ULONG64)(modules[k].BasicInfo.ImageBase);
				ULONG64 endAddress = (ULONG64)(startAddress + modules[k].ImageSize);
				if (rawPointer > startAddress && rawPointer < endAddress) {
					KdPrint((" (%s)", modules[k].FullPathName));
					strcpy(pReq[i].Module, (char*)(modules[k].FullPathName + modules[k].FileNameOffset));
					break;
				}
			}
			KdPrint(("\n"));
			*respLength += sizeof(YMCRES_CALLBACKS);
		}
		arrayPointer += 8;
	}

	ExFreePoolWithTag(modules, YMC_TAG);
	return status;
}

static NTSTATUS CB_DelCallback(ULONG64 callbacksArray, PYMCREQ_CALLBACKS pReq)
{
	if (pReq->TargetCallbackId < 0 || pReq->TargetCallbackId > MAX_CALLBACKS) {
		KdPrint(("YMC!CB_DelCallback # invalid target id\n"));
		return STATUS_INVALID_PARAMETER;
	}

	ULONG64 arrayPointer = callbacksArray;
	arrayPointer += 8 * pReq->TargetCallbackId;

	KdPrint(("YMC!CB_DelCallback # zeroing value at address 0x%llx\n", arrayPointer));
	*(PULONG64)arrayPointer = 0x0;

	return STATUS_SUCCESS;
}

NTSTATUS CB_GetProcessNotificationCallbacks(_In_ PYMCRES_CALLBACKS pReq, _Out_ PULONG_PTR respLength)
{
	NTSTATUS status = CB_Check();
	if (!NT_SUCCESS(status)) {
		KdPrint(("YMC!CB_GetProcessNotificationCallbacks # CB_Check faield\n"));
		return status;
	}
	return CB_GetCallbacks(CB_P_PROCSNOTIFY_ARRAY, pReq, respLength);
}

NTSTATUS CB_GetThreadNotificationCallbacks(_In_ PYMCRES_CALLBACKS pReq, _Out_ PULONG_PTR respLength)
{
	NTSTATUS status = CB_Check();
	if (!NT_SUCCESS(status)) {
		KdPrint(("YMC!CB_GetThreadNotificationCallbacks # CB_Check faield\n"));
		return status;
	}
	return CB_GetCallbacks(CB_P_THREDNOTIFY_ARRAY, pReq, respLength);
}

NTSTATUS CB_GetImageNotificationCallbacks(_In_ PYMCRES_CALLBACKS pReq, _Out_ PULONG_PTR respLength)
{
	NTSTATUS status = CB_Check();
	if (!NT_SUCCESS(status)) {
		KdPrint(("YMC!CB_GetImageNotificationCallbacks # CB_Check faield\n"));
		return status;
	}
	return CB_GetCallbacks(CB_P_IMAGENOTIFY_ARRAY, pReq, respLength);
}

NTSTATUS CB_DelProcessNotificationCallbacks(_In_ PYMCREQ_CALLBACKS pReq)
{
	NTSTATUS status = CB_Check();
	if (!NT_SUCCESS(status)) {
		KdPrint(("YMC!CB_DelProcessNotificationCallbacks # CB_Check faield\n"));
		return status;
	}
	return CB_DelCallback(CB_P_PROCSNOTIFY_ARRAY, pReq);
}

NTSTATUS CB_DelThreadNotificationCallbacks(_In_ PYMCREQ_CALLBACKS pReq)
{
	NTSTATUS status = CB_Check();
	if (!NT_SUCCESS(status)) {
		KdPrint(("YMC!CB_DelThreadNotificationCallbacks # CB_Check faield\n"));
		return status;
	}
	return CB_DelCallback(CB_P_THREDNOTIFY_ARRAY, pReq);
}

NTSTATUS CB_DelImageNotificationCallbacks(_In_ PYMCREQ_CALLBACKS pReq)
{
	NTSTATUS status = CB_Check();
	if (!NT_SUCCESS(status)) {
		KdPrint(("YMC!CB_DelImageNotificationCallbacks # CB_Check faield\n"));
		return status;
	}
	return CB_DelCallback(CB_P_IMAGENOTIFY_ARRAY, pReq);
}