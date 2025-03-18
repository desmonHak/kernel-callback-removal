#pragma once
#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>
#include <vector>
#include <unordered_map>
#include "ETWTI.h"
#include "MemHandler.h"
#include <map>

// I can hear the OSR replies now... 
#define ProviderEnableInfo_OFFSET 0x60
#define GuidEntry_OFFSET 0x20

class ETWTI
{
public:
	ETWTI(MemHandler* objMemHandler);
	~ETWTI();
	PVOID lpNtosBase = { 0 };
	PVOID lpnetioBase = { 0 };
	std::map<DWORD64, std::pair<DWORD64, DWORD64>> patchCallbackMap;
	std::map<DWORD64, std::pair<DWORD64, DWORD64>> patchLinksMap;
	BOOL EnumerateETW(BOOLEAN REMOVE = false, wchar_t* DriverName = NULL);

private:
	ULONG ulNumFrames;
	PVOID ResolveDriverBase(const wchar_t* strDriverName);
	MemHandler* objMemHandler;
};
