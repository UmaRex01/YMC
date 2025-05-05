#include <ntifs.h>
#include "YMC.h"
#include "Nt.h"

static const VERSION_SUPPORT supportedVersions[] = {
	{10, 0, 19045, 0x87A, 0, 0}
};
static int PP_STATUS = 0;
static ULONG PP_PROTECTION_OFFSET = 0;

static NTSTATUS PP_Check()
{
	if (PP_STATUS > 0)
		return STATUS_SUCCESS;
	if (PP_STATUS < 0)
		return STATUS_NOT_SUPPORTED;

	RTL_OSVERSIONINFOW osInfo;
	NTSTATUS status = GetWindowsVersion(&osInfo);
	if (!NT_SUCCESS(status)) {
		KdPrint(("YMC!PP_Check # RtlGetVersion faield: 0x%08X\n", status));
		return status;
	}

	for (int i = 0; i < (sizeof(supportedVersions) / sizeof(supportedVersions[0])); i++) {
		if (
			supportedVersions[i].MajorVersion == osInfo.dwMajorVersion &&
			supportedVersions[i].MinorVersion == osInfo.dwMinorVersion &&
			supportedVersions[i].BuildNumber == osInfo.dwBuildNumber
			) {
			PP_PROTECTION_OFFSET = supportedVersions[i].Offset1;
		}
	}

	if (PP_PROTECTION_OFFSET == 0) {
		status = STATUS_NOT_SUPPORTED;
		PP_STATUS = -1;
	}

	PP_STATUS = 1;
	return status;
}

static NTSTATUS PP_ApplyProtection(int TargetProcessId, UCHAR Type, UCHAR Audit, UCHAR Signer)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS pEprocess;

	status = PsLookupProcessByProcessId(
		(HANDLE)TargetProcessId,
		&pEprocess
	);
	if (status != STATUS_SUCCESS) {
		KdPrint(("YMC!PP_ApplyProtection # PsLookupProcessByProcessId faield: 0x%08X\n", status));
		return status;
	}

	PPS_PROTECTION pPsProtection = (PPS_PROTECTION)(((ULONG_PTR)pEprocess) + PP_PROTECTION_OFFSET);
	pPsProtection->ProtectionLevel.ProtectionFlags.Type = Type;
	pPsProtection->ProtectionLevel.ProtectionFlags.Audit = Audit;
	pPsProtection->ProtectionLevel.ProtectionFlags.Signer = Signer;

	ObDereferenceObject(pEprocess);
	return status;
}

NTSTATUS PP_UnprotectProcess(_In_ PYMCREQ_PROTECT_PROCESS pReq)
{
	NTSTATUS status = PP_Check();
	if (!NT_SUCCESS(status)) {
		KdPrint(("YMC!PP_UnprotectProcess # PP_Check faield\n"));
		return status;
	}
	return PP_ApplyProtection(pReq->TargetProcessId, 0, 0, 0);
}

NTSTATUS PP_ProtectProcess(_In_ PYMCREQ_PROTECT_PROCESS pReq)
{
	NTSTATUS status = PP_Check();
	if (!NT_SUCCESS(status)) {
		KdPrint(("YMC!PP_ProtectProcess # PP_Check faield\n"));
		return status;
	}
	if (pReq->Type < PsProtectedTypeNone || pReq->Type > PsProtectedTypeProtected) {
		KdPrint(("YMC!PP_ProtectProcess # Invalid input protected type\n"));
		return STATUS_INVALID_PARAMETER;
	}
	if (pReq->Signer < PsProtectedSignerNone || pReq->Signer > PsProtectedSignerMax) {
		KdPrint(("YMC!PP_ProtectProcess # Invalid input protected signer\n"));
		return STATUS_INVALID_PARAMETER;
	}
	return PP_ApplyProtection(pReq->TargetProcessId, pReq->Type, 0, pReq->Signer);
}