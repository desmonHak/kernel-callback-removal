#pragma once
#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>
#include <vector>
#include <unordered_map>
#include "net.h"
#include "MemHandler.h"
#include <map>

// I can hear the OSR replies now... 
#define CALLOUT_STRUCTURE_SIZE 0x60

#define UNISTR_OFFSET_LEN 0
#define UNISTR_OFFSET_BUF 8

class NetworkManager
{
public:
	NetworkManager(MemHandler* objMemHandler);
	~NetworkManager();
	PVOID lpNtosBase = { 0 };
	PVOID lpnetioBase = { 0 };
	std::map<DWORD64, std::pair<DWORD64, DWORD64>> patchCallbackMap;
	std::map<DWORD64, std::pair<DWORD64, DWORD64>> patchLinksMap;
	BOOL Restore();
	TCHAR* FindDriver(DWORD64 address);
	BOOL EnumerateNetworkFilters(BOOLEAN REMOVE = false, wchar_t* DriverName = NULL, DWORD64 ADDRESS = NULL);
	wchar_t* ExtractDriverName(TCHAR* driverOutput);

private:
	ULONG ulNumFrames;
	PVOID ResolveDriverBase(const wchar_t* strDriverName);
	MemHandler* objMemHandler;
};
