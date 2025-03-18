// CallbackRemover.h
#pragma once

#include <Windows.h>
#include <aclapi.h>
#include <Psapi.h>
#include <cstdio>
#include <iostream>
#include <tchar.h>
#include <map>
#include "MemHandler.h"
#include <tlhelp32.h>

#define PRINT_ERROR_AUTO(func) (wprintf(L"ERROR " TEXT(__FUNCTION__) L" ; " func L" (0x%08x)\n", GetLastError()))

// Structure Definitions
struct Offsets {
    DWORD64 process;
    DWORD64 image;
    DWORD64 thread;
    DWORD64 registry;
};

class notifyRoutine
{
public:
	notifyRoutine(MemHandler* objMemHandler);
	~notifyRoutine();
	PVOID lpNtosBase = { 0 };
	DWORD64 GetFunctionAddress(LPCSTR function);
	std::map<DWORD64, std::pair<DWORD64, DWORD64>> patchCallbackMap;
	std::map<DWORD64, std::pair<DWORD64, DWORD64>> patchLinksMap;
	BOOL Restore();
	DWORD64 PatternSearch(DWORD64 start, DWORD64 end, DWORD64 pattern);
	void findregistrycallbackroutines(DWORD64 remove);
	void unlinkregistrycallbackroutines(DWORD64 remove);
	void findimgcallbackroutine(DWORD64 remove);
	void findthreadcallbackroutine(DWORD64 remove);
	void findprocesscallbackroutine(DWORD64 remove);
	void findprocesscallbackroutinestealth(DWORD64 remove);
	TCHAR* FindDriver(DWORD64 address);
private:
	ULONG ulNumFrames;
	PVOID ResolveDriverBase(const wchar_t* strDriverName);
	MemHandler* objMemHandler;
};