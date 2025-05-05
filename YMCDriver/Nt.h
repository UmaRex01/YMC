#pragma once

/**
 * The PS_PROTECTION structure is used to define the protection level of a process.
 * https://ntdoc.m417z.com/ps_protection
 */
typedef struct _PS_PROTECTION
{
	union
	{
		UCHAR Level;
		struct
		{
			UCHAR Type : 3;
			UCHAR Audit : 1;	// Reserved
			UCHAR Signer : 4;
		} ProtectionFlags;
	} ProtectionLevel;
} PS_PROTECTION, * PPS_PROTECTION;

// https://learn.microsoft.com/en-us/windows/win32/procthread/zwqueryinformationprocess
typedef enum _PS_PROTECTED_TYPE {
	PsProtectedTypeNone = 0,
	PsProtectedTypeProtectedLight = 1,
	PsProtectedTypeProtected = 2
} PS_PROTECTED_TYPE, * PPS_PROTECTED_TYPE;

// https://learn.microsoft.com/en-us/windows/win32/procthread/zwqueryinformationprocess
typedef enum _PS_PROTECTED_SIGNER {
	PsProtectedSignerNone = 0,
	PsProtectedSignerAuthenticode,
	PsProtectedSignerCodeGen,
	PsProtectedSignerAntimalware,
	PsProtectedSignerLsa,
	PsProtectedSignerWindows,
	PsProtectedSignerWinTcb,
	PsProtectedSignerWinSystem,
	PsProtectedSignerApp,
	PsProtectedSignerMax
} PS_PROTECTED_SIGNER, * PPS_PROTECTED_SIGNER;

typedef struct _SEP_TOKEN_PRIVILEGES
{
	ULONG64 Present;
	ULONG64 Enabled;
	ULONG64 EnabledByDefault;
} SEP_TOKEN_PRIVILEGES, * PSEP_TOKEN_PRIVILEGES;