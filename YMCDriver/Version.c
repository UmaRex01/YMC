#include "YMC.h"

static RTL_OSVERSIONINFOW cachedOsInfo = { 0 };
static BOOLEAN isOsInfoCached = FALSE;

NTSTATUS GetWindowsVersion(_Out_ PRTL_OSVERSIONINFOW outOsInfo)
{
	if (!isOsInfoCached) {
		RTL_OSVERSIONINFOW osInfo = { 0 };
		osInfo.dwOSVersionInfoSize = sizeof(osInfo);
		NTSTATUS status = RtlGetVersion(&osInfo);
		if (!NT_SUCCESS(status)) {
			KdPrint(("YMC!GetWindowsVersion # RtlGetVersion failed: 0x%08X\n", status));
			return status;
		}
		cachedOsInfo = osInfo;
		isOsInfoCached = TRUE;
	}

	*outOsInfo = cachedOsInfo;
	return STATUS_SUCCESS;
}