/**
* Copyright (C) 2024 Elisha Riedlinger
*
* This software is  provided 'as-is', without any express  or implied  warranty. In no event will the
* authors be held liable for any damages arising from the use of this software.
* Permission  is granted  to anyone  to use  this software  for  any  purpose,  including  commercial
* applications, and to alter it and redistribute it freely, subject to the following restrictions:
*
*   1. The origin of this software must not be misrepresented; you must not claim that you  wrote the
*      original  software. If you use this  software  in a product, an  acknowledgment in the product
*      documentation would be appreciated but is not required.
*   2. Altered source versions must  be plainly  marked as such, and  must not be  misrepresented  as
*      being the original software.
*   3. This notice may not be removed or altered from any source distribution.
*
* Created from source code found in DDrawCompat v0.5.4
* https://github.com/narzoul/DDrawCompat
*/

// return:
// 0 = patch failed
// addr = address of the original function

#include "Hook.h"

namespace Hook
{
	PIMAGE_NT_HEADERS getImageNtHeaders(HMODULE module);
	FARPROC* findProcAddressInIat(HMODULE module, const char* procName);
}

PIMAGE_NT_HEADERS Hook::getImageNtHeaders(HMODULE module)
{
	PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
	if (IMAGE_DOS_SIGNATURE != dosHeader->e_magic)
	{
		return nullptr;
	}

	PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
		reinterpret_cast<char*>(dosHeader) + dosHeader->e_lfanew);
	if (IMAGE_NT_SIGNATURE != ntHeaders->Signature)
	{
		return nullptr;
	}

	return ntHeaders;
}

FARPROC* Hook::findProcAddressInIat(HMODULE module, const char* procName)
{
	if (!module || !procName)
	{
		return nullptr;
	}

	PIMAGE_NT_HEADERS ntHeaders = getImageNtHeaders(module);
	if (!ntHeaders)
	{
		return nullptr;
	}

	char* moduleBase = reinterpret_cast<char*>(module);
	PIMAGE_IMPORT_DESCRIPTOR importDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(moduleBase +
		ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	for (PIMAGE_IMPORT_DESCRIPTOR desc = importDesc;
		0 != desc->Characteristics && 0xFFFF != desc->Name;
		++desc)
	{
		auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(moduleBase + desc->FirstThunk);
		auto origThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(moduleBase + desc->OriginalFirstThunk);
		while (0 != thunk->u1.AddressOfData && 0 != origThunk->u1.AddressOfData)
		{
			if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG))
			{
				auto origImport = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(moduleBase + origThunk->u1.AddressOfData);
				if (0 == strcmp(reinterpret_cast<char*>(origImport->Name), procName))
				{
					return reinterpret_cast<FARPROC*>(&thunk->u1.Function);
				}
			}

			++thunk;
			++origThunk;
		}
	}

	return nullptr;
}

void* Hook::IATPatch(HMODULE module, const char* apiname, void* hookproc)
{
	FARPROC* func = findProcAddressInIat(module, apiname);
	if (func)
	{
		LOG_DEBUG << "Hooking function via IAT: " << apiname << " (" << funcPtrToStr(*func) << ')';
		DWORD oldProtect = 0;
		VirtualProtect(func, sizeof(func), PAGE_READWRITE, &oldProtect);
		*func = static_cast<FARPROC>(hookproc);
		DWORD dummy = 0;
		VirtualProtect(func, sizeof(func), oldProtect, &dummy);
		return func;
	}
	return nullptr;
}
