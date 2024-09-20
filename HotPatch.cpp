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

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <sstream>
#include <string>
#include "Hook.h"
#include "Disasm.h"
#include "Disasm.cpp"

namespace Hook
{
	HMODULE GetCurrentDll();
	std::string getModulePath(HMODULE module);
	HMODULE getModuleHandleFromAddress(const void* address);
	std::string funcPtrToStr(const void* funcPtr);
}

HMODULE Hook::GetCurrentDll()
{
	static HMODULE hModule = nullptr;
	if (!hModule)
	{
		if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			reinterpret_cast<LPCWSTR>(&GetCurrentDll), &hModule))
		{
			return nullptr;
		}
	}
	return hModule;
}

std::string Hook::getModulePath(HMODULE module)
{
	char path[MAX_PATH];
	GetModuleFileNameA(module, path, MAX_PATH);
	return path;
}

HMODULE Hook::getModuleHandleFromAddress(const void* address)
{
	HMODULE module = nullptr;
	GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		static_cast<const char*>(address), &module);
	return module;
}

std::string Hook::funcPtrToStr(const void* funcPtr)
{
	std::ostringstream oss;
	HMODULE module = getModuleHandleFromAddress(funcPtr);
	if (module)
	{
		oss << getModulePath(module).c_str() << "+0x" << std::hex <<
			reinterpret_cast<DWORD>(funcPtr) - reinterpret_cast<DWORD>(module);
	}
	else
	{
		oss << funcPtr;
	}
	return oss.str();
}

void* Hook::HotPatch(void* apiproc, const char* apiname, void* hookproc)
{
	BYTE* targetFunc = static_cast<BYTE*>(apiproc);

	std::ostringstream oss;
	oss << funcPtrToStr(targetFunc) << ' ';

	char origFuncPtrStr[20] = {};
	if (!apiname)
	{
		sprintf_s(origFuncPtrStr, "%p", apiproc);
		apiname = origFuncPtrStr;
	}

	auto prevTargetFunc = targetFunc;
	while (true)
	{
		unsigned instructionSize = 0;
		if (0xE9 == targetFunc[0])
		{
			instructionSize = 5;
			targetFunc += instructionSize + *reinterpret_cast<int*>(targetFunc + 1);
		}
		else if (0xEB == targetFunc[0])
		{
			instructionSize = 2;
			targetFunc += instructionSize + *reinterpret_cast<signed char*>(targetFunc + 1);
		}
		else if (0xFF == targetFunc[0] && 0x25 == targetFunc[1])
		{
			instructionSize = 6;
			targetFunc = **reinterpret_cast<BYTE***>(targetFunc + 2);
			if (getModuleHandleFromAddress(targetFunc) == getModuleHandleFromAddress(prevTargetFunc))
			{
				targetFunc = prevTargetFunc;
				break;
			}
		}
		else
		{
			break;
		}

		Logging::LogDebug() << Logging::hexDump(prevTargetFunc, instructionSize) << " -> " << funcPtrToStr(targetFunc) << ' ';
		prevTargetFunc = targetFunc;
	}

	if (getModuleHandleFromAddress(targetFunc) == GetCurrentDll())
	{
		Logging::Log() << "Error: Target function is already hooked: " << apiname;
		return nullptr;
	}

	const DWORD trampolineSize = 32;
	BYTE* trampoline = static_cast<BYTE*>(
		VirtualAlloc(nullptr, trampolineSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	BYTE* src = targetFunc;
	BYTE* dst = trampoline;
	while (src - targetFunc < 5)
	{
		unsigned instructionSize = Disasm::getInstructionLength(src);
		if (0 == instructionSize)
		{
			Logging::Log() << "Error: Failed to get instruction size from target function: " << apiname;
			return nullptr;
		}

		memcpy(dst, src, instructionSize);
		if (0xE8 == *src && 5 == instructionSize)
		{
			*reinterpret_cast<int*>(dst + 1) += src - dst;
		}

		src += instructionSize;
		dst += instructionSize;
	}

	Logging::LogDebug() << "Hooking function: " << apiname << " (" << oss.str() << Logging::hexDump(targetFunc, src - targetFunc) << ')';

	*dst = 0xE9;
	*reinterpret_cast<int*>(dst + 1) = src - (dst + 5);
	DWORD oldProtect = 0;
	VirtualProtect(trampoline, trampolineSize, PAGE_EXECUTE_READ, &oldProtect);

	VirtualProtect(targetFunc, src - targetFunc, PAGE_EXECUTE_READWRITE, &oldProtect);
	targetFunc[0] = 0xE9;
	*reinterpret_cast<int*>(targetFunc + 1) = static_cast<BYTE*>(hookproc) - (targetFunc + 5);
	memset(targetFunc + 5, 0xCC, src - targetFunc - 5);
	VirtualProtect(targetFunc, src - targetFunc, PAGE_EXECUTE_READ, &oldProtect);

	HMODULE module = nullptr;
	GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
		reinterpret_cast<char*>(targetFunc), &module);

	return trampoline;
}
