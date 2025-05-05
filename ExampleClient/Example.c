#include <Windows.h>
#include <stdio.h>
#include "../YMCDriver/public.h"

void DeleteCallback(HANDLE hDriver, int argc, char** argv)
{
	if (argc != 2) {
		printf("ERROR! Usage: del_callback <proc|thread|image> <target_callback_id>\n");
		return;
	}

	DWORD ioctl = 0;
	if (strcmp(argv[0], "proc") == 0) {
		printf("[+] Calling YMC_IOCTL_DEL_PROCESS_CALLBACKS...");
		ioctl = YMC_IOCTL_DEL_PROCESS_CALLBACKS;
	}
	else if (strcmp(argv[0], "thread") == 0) {
		printf("[+] Calling YMC_IOCTL_DEL_THREAD_CALLBACKS...");
		ioctl = YMC_IOCTL_DEL_THREAD_CALLBACKS;
	}
	else if (strcmp(argv[0], "image") == 0) {
		printf("[+] Calling YMC_IOCTL_DEL_IMAGE_CALLBACKS...");
		ioctl = YMC_IOCTL_DEL_IMAGE_CALLBACKS;
	}
	else {
		printf("ERROR! Usage: del_callback <proc|thread|image>\n");
		return;
	}

	YMCREQ_CALLBACKS pReq;
	pReq.TargetCallbackId = atoi(argv[1]);

	BOOL success = DeviceIoControl(
		hDriver,
		ioctl,
		&pReq,
		sizeof(YMCREQ_CALLBACKS),
		NULL,
		0,
		NULL,
		NULL
	);

	printf("Done!\n");
}

void GetCallback(HANDLE hDriver, int argc, char** argv)
{
	if (argc != 1) {
		printf("ERROR! Usage: get_callback <proc|thread|image>\n");
		return;
	}

	DWORD ioctl = 0;
	if (strcmp(argv[0], "proc") == 0) {
		printf("[+] Calling YMC_IOCTL_GET_PROCESS_CALLBACKS...");
		ioctl = YMC_IOCTL_GET_PROCESS_CALLBACKS;
	}
	else if (strcmp(argv[0], "thread") == 0) {
		printf("[+] Calling YMC_IOCTL_GET_THREAD_CALLBACKS...");
		ioctl = YMC_IOCTL_GET_THREAD_CALLBACKS;
	}
	else if (strcmp(argv[0], "image") == 0) {
		printf("[+] Calling YMC_IOCTL_GET_IMAGE_CALLBACKS...");
		ioctl = YMC_IOCTL_GET_IMAGE_CALLBACKS;
	}
	else {
		printf("ERROR! Usage: get_callback <proc|thread|image>\n");
		return;
	}

	YMCRES_CALLBACKS pReq[MAX_CALLBACKS] = { 0 };
	DWORD bytesReceived = 0;

	BOOL success = DeviceIoControl(
		hDriver,
		ioctl,
		NULL,
		0,
		&pReq,
		sizeof(pReq),
		&bytesReceived,
		NULL
	);

	if (success) {
		printf("Done! Data: %d\n", bytesReceived);
		for (int i = 0; i < MAX_CALLBACKS; i++) {
			if (pReq[i].Address > 0)
				printf("[+] Callback #%d\t0x%llx\t(%s)\n", i, pReq[i].Address, pReq[i].Module);
		}
	}
	else {
		printf("ERROR!\n");
	}
}

void ProtectProcess(HANDLE hDriver, int argc, char** argv)
{
	printf("[+] Calling YMC_IOCTL_PROTECT_PROCESS...");

	if (argc != 3) {
		printf("ERROR! Usage: protect_process <target_pid> <type> <signer>\n");
		return;
	}

	YMCREQ_PROTECT_PROCESS pReq;
	pReq.TargetProcessId = atoi(argv[0]);
	pReq.Type = atoi(argv[1]);
	pReq.Audit = 0;
	pReq.Signer = atoi(argv[2]);

	BOOL success = DeviceIoControl(
		hDriver,
		YMC_IOCTL_PROTECT_PROCESS,
		&pReq,
		sizeof(YMCREQ_PROCESS_PRIVS),
		NULL,
		0,
		NULL,
		NULL
	);

	printf("Done!\n");
}

void UnprotectProcess(HANDLE hDriver, int argc, char** argv)
{
	printf("[+] Calling YMC_IOCTL_UNPROTECT_PROCESS...");

	if (argc != 1) {
		printf("ERROR! Usage: unprotect_process <target_pid>\n");
		return;
	}

	YMCREQ_PROTECT_PROCESS pReq;
	pReq.TargetProcessId = atoi(argv[0]);

	BOOL success = DeviceIoControl(
		hDriver,
		YMC_IOCTL_UNPROTECT_PROCESS,
		&pReq,
		sizeof(YMCREQ_PROCESS_PRIVS),
		NULL,
		0,
		NULL,
		NULL
	);

	printf("Done!\n");
}

void SetPrivileges(HANDLE hDriver, int argc, char** argv)
{
	printf("[+] Calling YMC_IOCTL_SET_PROCESS_PRIVS...");

	if (argc - 1 > (SE_MAX_WELL_KNOWN_PRIVILEGE - SE_MIN_WELL_KNOWN_PRIVILEGE)) {
		printf("ERROR! Too many privs selected (max %d)\n", (SE_MAX_WELL_KNOWN_PRIVILEGE - SE_MIN_WELL_KNOWN_PRIVILEGE));
		return;
	}

	YMCREQ_PROCESS_PRIVS pReq;
	pReq.TargetProcessId = atoi(argv[0]);
	for (int i = 1; i < argc; i++) {
		pReq.NewPrivileges[i] = atoi(argv[i]);
	}

	BOOL success = DeviceIoControl(
		hDriver,
		YMC_IOCTL_SET_PROCESS_PRIVS,
		&pReq,
		sizeof(YMCREQ_PROCESS_PRIVS),
		NULL,
		0,
		NULL,
		NULL
	);

	printf("Done!\n");
}

int main(int argc, char** argv)
{
	if (argc < 2) {
		printf("Usage: %s <module> [arguments...]\n", argv[0]);
		return 1;
	}

	printf("[+] Opening handle to driver\n");
	HANDLE hDriver = CreateFile(
		L"\\\\.\\YMC",
		GENERIC_WRITE,
		FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
	);
	if (hDriver == INVALID_HANDLE_VALUE) {
		printf("[!] Failed to open handle: %d\n", GetLastError());
		return -1;
	}
	printf("[+] Opened!\n");

	char* command = argv[1];

	if (strcmp(command, "protect_process") == 0) {
		ProtectProcess(hDriver, argc - 2, &argv[2]);
	}
	else if (strcmp(command, "unprotect_process") == 0) {
		UnprotectProcess(hDriver, argc - 2, &argv[2]);
	}
	else if (strcmp(command, "set_privs") == 0) {
		SetPrivileges(hDriver, argc - 2, &argv[2]);
	}
	else if (strcmp(command, "get_callback") == 0) {
		GetCallback(hDriver, argc - 2, &argv[2]);
	}
	else if (strcmp(command, "del_callback") == 0) {
		DeleteCallback(hDriver, argc - 2, &argv[2]);
	}
	else {
		printf("[-] unknown command\n");
	}

	printf("[+] Closing handle\n");
	CloseHandle(hDriver);

	return 0;
}