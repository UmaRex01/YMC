#pragma once
#include <ntddk.h>
#include "Public.h"

#define YMC_TAG '1CMY'

typedef struct _VERSION_SUPPORT {
	ULONG MajorVersion;
	ULONG MinorVersion;
	ULONG BuildNumber;
	ULONG Offset1;
	ULONG Offset2;
	ULONG Offset3;
} VERSION_SUPPORT;

NTSTATUS GetWindowsVersion(_Out_ PRTL_OSVERSIONINFOW osInfo);

NTSTATUS PP_UnprotectProcess(_In_ PYMCREQ_PROTECT_PROCESS pReq);
NTSTATUS PP_ProtectProcess(_In_ PYMCREQ_PROTECT_PROCESS pReq);

NTSTATUS PV_SetPrivileges(_In_ PYMCREQ_PROCESS_PRIVS pReq);

NTSTATUS CB_GetProcessNotificationCallbacks(_In_ PYMCRES_CALLBACKS pReq, _Out_ PULONG_PTR respLength);
NTSTATUS CB_GetThreadNotificationCallbacks(_In_ PYMCRES_CALLBACKS pReq, _Out_ PULONG_PTR respLength);
NTSTATUS CB_GetImageNotificationCallbacks(_In_ PYMCRES_CALLBACKS pReq, _Out_ PULONG_PTR respLength);
NTSTATUS CB_DelProcessNotificationCallbacks(_In_ PYMCREQ_CALLBACKS pReq);
NTSTATUS CB_DelThreadNotificationCallbacks(_In_ PYMCREQ_CALLBACKS pReq);
NTSTATUS CB_DelImageNotificationCallbacks(_In_ PYMCREQ_CALLBACKS pReq);