#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <string>
#include "Logging\Logging.h"

namespace Hook
{
	FARPROC GetProcAddress(HMODULE hModule, LPCSTR FunctionName);
	std::string funcPtrToStr(const void* funcPtr);
	bool CheckExportAddress(HMODULE hModule, void* AddressCheck);
	HMODULE GetModuleHandle(char* ProcName);

	// HotPatch hooks
	void* HotPatch(void* apiproc, const char* apiname, void* hookproc);

	// IATPatch hooks
	void* IATPatch(HMODULE module, const char* apiname, void* hookproc);
}
