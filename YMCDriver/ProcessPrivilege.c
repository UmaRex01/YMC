#include <ntifs.h>
#include "YMC.h"
#include "Nt.h"

static const VERSION_SUPPORT supportedVersions[] = {
	{10, 0, 19045, 0x40, 0, 0}
};
static int PV_STATUS = 0;
static ULONG PV_PRIVS_OFFSET = 0;

static NTSTATUS PV_Check()
{
	if (PV_STATUS > 0)
		return STATUS_SUCCESS;
	if (PV_STATUS < 0)
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
			PV_PRIVS_OFFSET = supportedVersions[i].Offset1;
		}
	}

	if (PV_PRIVS_OFFSET == 0) {
		status = STATUS_NOT_SUPPORTED;
		PV_STATUS = -1;
	}

	PV_STATUS = 1;
	return status;
}

NTSTATUS PV_SetPrivileges(_In_ PYMCREQ_PROCESS_PRIVS pReq)
{
	NTSTATUS status = PV_Check();
	if (!NT_SUCCESS(status)) {
		KdPrint(("YMC!PV_SetPrivileges # PV_Check faield\n"));
		return status;
	}

	PEPROCESS pEprocess;
	status = PsLookupProcessByProcessId(
		(HANDLE)pReq->TargetProcessId,
		&pEprocess
	);
	if (status != STATUS_SUCCESS) {
		KdPrint(("YMC!PV_SetPrivileges # PsLookupProcessByProcessId faield: 0x%08X\n", status));
		return status;
	}

	PACCESS_TOKEN hToken = PsReferencePrimaryToken(pEprocess);
	PSEP_TOKEN_PRIVILEGES pTokenPrivs = (PSEP_TOKEN_PRIVILEGES)(((ULONG_PTR)hToken) + PV_PRIVS_OFFSET);

	ULONG64 bitmap = 0;
	for (int i = 0; i < SE_MAX_WELL_KNOWN_PRIVILEGE; i++) {
		if (pReq->NewPrivileges[i] < SE_MIN_WELL_KNOWN_PRIVILEGE || pReq->NewPrivileges[i] > SE_MAX_WELL_KNOWN_PRIVILEGE)
			continue;
		bitmap |= (1ULL << pReq->NewPrivileges[i]);
	}

	pTokenPrivs->Present = bitmap;
	pTokenPrivs->Enabled = bitmap;

	ObDereferenceObject(hToken);
	ObDereferenceObject(pEprocess);

	return status;
}