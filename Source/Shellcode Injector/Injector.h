#ifndef INJECTOR_H
#define INJECTOR_H

#include <Windows.h>

class Injector
{
private:
	static HANDLE GetFileContent(LPSTR lpFilePath);
	static DWORD GetProcessByName(LPSTR lpProcessName);

public:
	static BOOL LocalInjectionFromFile(LPCSTR lpFileName);
	static BOOL LocalInjectionFromMemory(LPVOID lpShellcode, DWORD dShellcodeSize);
	static BOOL RemoteInjectionFromFile(LPCSTR lpFileName, LPCSTR lpProcessName);
	static BOOL RemoteInjectionFromMemory(LPVOID lpShellcode, DWORD dShellcodeSize, LPCSTR lpProcessName);

};

#endif
