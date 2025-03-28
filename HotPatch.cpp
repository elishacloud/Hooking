/**
* Copyright (C) 2025 Elisha Riedlinger
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
* Created from source code found in DxWnd v2.03.99
* https://sourceforge.net/projects/dxwnd/
*/

// return:
// 0 = patch failed
// addr = address of the original function

#include "Hook.h"
#include "Disasm.cpp"

namespace Hook
{
	constexpr DWORD buff_size = 21;

	struct HOTPATCH
	{
		BYTE lpOrgBuffer[buff_size] = { 0x90 };
		BYTE lpNewBuffer[buff_size] = { 0x90 };
		void* procaddr = nullptr;
		void* alocmemaddr = nullptr;
	};

	bool IsUnsupportedInstruction(BYTE* src);
	bool CheckPadding(BYTE* patch_address);
	void* OverwriteHeaderWithPadding(BYTE* patch_address, const char* apiname, void* hookproc, DWORD ByteNum);
	void* RewriteHeader(BYTE* patch_address, const char* apiname, void* hookproc, DWORD ByteNum);
}

inline bool Hook::IsUnsupportedInstruction(BYTE* src)
{
	/*
		Conditional Jumps (0x70 to 0x7F):
			* These are short conditional jumps, like JZ, JNZ, JL, JG, etc., that use an 8-bit signed offset (1-byte).
			* Example: 0x74 (JZ - Jump if Zero), 0x75 (JNZ - Jump if Not Zero).
		Loop Instructions (0xE0 to 0xE2):
			* These instructions are relative and use an 8-bit displacement.
			* LOOP, LOOPZ, LOOPNZ - They decrement ECX and jump if ECX is not zero.
	*/
	return (*src >= 0xE0 && *src <= 0xE2) || (*src >= 0x70 && *src <= 0x7F);
}

inline bool Hook::CheckPadding(BYTE* patch_address)
{
	return (memcmp("\x90\x90\x90\x90\x90", patch_address, 5) == S_OK ||		// Normal padding
		memcmp("\xCC\xCC\xCC\xCC\xCC", patch_address, 5) == S_OK ||			// Debug padding
		memcmp("\x00\x00\x00\x00\x00", patch_address, 5) == S_OK);			// Alternative padding
}

inline void* Hook::OverwriteHeaderWithPadding(BYTE* patch_address, const char* apiname, void* hookproc, DWORD ByteNum)
{
	if (!patch_address || !apiname || !hookproc || ByteNum < 2 || ByteNum + 2 > buff_size)
	{
		Logging::Log() << __FUNCTION__ " Error: Invalid input!";
		return nullptr;
	}

	// Entry point could be at the top of a page? so VirtualProtect first to make sure patch_address is readable
	DWORD dwPrevProtect = 0;
	if (VirtualProtect(patch_address, buff_size, PAGE_EXECUTE_WRITECOPY, &dwPrevProtect) == FALSE)
	{
		Logging::LogFormat(__FUNCTION__ " Error: access denied.  Cannot hook api=%s at addr=%p err=%x", apiname, patch_address - 5, GetLastError());
		return nullptr; // access denied
	}

	// Create new memory and prepare to patch
	DWORD mem_size = (((ByteNum + 5) / 8) + 2) * 8;
	BYTE* new_mem = (BYTE*)VirtualAlloc(nullptr, mem_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	DWORD dwNull = 0;
	if (!new_mem || VirtualProtect(new_mem, mem_size, PAGE_EXECUTE_READWRITE, &dwNull) == FALSE)
	{
		Logging::LogFormat(__FUNCTION__ " Error: access denied.  Cannot mark memory as executable api=%s at addr=%p err=%x", apiname, new_mem, GetLastError());

		if (new_mem)
		{
			VirtualFree(new_mem, 0, MEM_RELEASE);
		}

		// Restore protection
		VirtualProtect(patch_address, buff_size, dwPrevProtect, &dwPrevProtect);

		return nullptr; // access denied
	}
	memset(new_mem, 0x90, mem_size);

	// Special handling for 2-byte jmp header
	if (memcmp("\xEB", (patch_address + 5), 1) == S_OK)
	{
		*((BYTE*)new_mem) = 0xE9; // jmp (5-byte relative)
		BYTE* CallJmpAddress = (BYTE*)(*(BYTE*)(patch_address + 6) + (DWORD)patch_address + 7); // address to call/jmp
		*((DWORD*)(new_mem + 1)) = (DWORD)CallJmpAddress - (DWORD)new_mem - 5; // relative address
		*(new_mem + 6) = 0xE9; // jmp (5-byte relative)
		*((DWORD*)(new_mem + 6 + 1)) = (DWORD)patch_address - (DWORD)new_mem; // relative address
	}
	// Write old data to new memory before overwritting it
	else
	{
		memcpy(new_mem, patch_address + 5, ByteNum);
		*(new_mem + ByteNum) = 0xE9; // jmp (4-byte relative)
		*((DWORD*)(new_mem + ByteNum + 1)) = (DWORD)patch_address - (DWORD)new_mem; // relative address
	}

	// Backup memory
	HOTPATCH tmpMemory;
	tmpMemory.procaddr = patch_address;
	tmpMemory.alocmemaddr = new_mem;
	ReadProcessMemory(GetCurrentProcess(), patch_address, tmpMemory.lpOrgBuffer, buff_size, nullptr);

	// Overwrite with NOPs to align
	memset(patch_address + 5, 0x90, ByteNum); // Overwrite remaining bytes with NOPs to align

	// Set HotPatch hook
	*patch_address = 0xE9; // jmp (4-byte relative)
	*((DWORD*)(patch_address + 1)) = (DWORD)hookproc - (DWORD)patch_address - 5; // relative address
	*((WORD*)(patch_address + 5)) = 0xF9EB; // should be atomic write (jmp $-5)

	// Get memory after update
	ReadProcessMemory(GetCurrentProcess(), patch_address, tmpMemory.lpNewBuffer, buff_size, nullptr);

	// Restore protection
	VirtualProtect(patch_address, buff_size, dwPrevProtect, &dwPrevProtect);

	// Flush cache
	FlushInstructionCache(GetCurrentProcess(), patch_address, buff_size);

	// Pin module
	HMODULE module = nullptr;
	GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
		reinterpret_cast<char*>(hookproc), &module);
	GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
		reinterpret_cast<char*>(patch_address + 5), &module);

#ifdef _DEBUG
	Logging::LogFormat(__FUNCTION__ ": api=%s addr=%p headersize=%d hook=%p", apiname, (patch_address + 5), ByteNum, hookproc);
#endif
	return new_mem;
}

inline void* Hook::RewriteHeader(BYTE* patch_address, const char* apiname, void* hookproc, DWORD ByteNum)
{
	if (!patch_address || !apiname || !hookproc || ByteNum < 5 || ByteNum + 5 > buff_size)
	{
		Logging::Log() << __FUNCTION__ " Error: Invalid input!";
		return nullptr;
	}

	// Entry point could be at the top of a page? so VirtualProtect first to make sure patch_address is readable
	DWORD dwPrevProtect = 0;
	if (VirtualProtect(patch_address, buff_size, PAGE_EXECUTE_WRITECOPY, &dwPrevProtect) == FALSE)
	{
		Logging::LogFormat(__FUNCTION__ " Error: access denied.  Cannot hook api=%s at addr=%p err=%x", apiname, patch_address - 5, GetLastError());
		return nullptr; // access denied
	}

	// Create new memory and prepare to patch
	DWORD mem_size = (((ByteNum + 5) / 8) + 2) * 8;
	BYTE* new_mem = (BYTE*)VirtualAlloc(nullptr, mem_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	DWORD dwNull = 0;
	if (!new_mem || VirtualProtect(new_mem, mem_size, PAGE_EXECUTE_READWRITE, &dwNull) == FALSE)
	{
		Logging::LogFormat(__FUNCTION__ " Error: access denied.  Cannot mark memory as executable api=%s at addr=%p err=%x", apiname, new_mem, GetLastError());

		if (new_mem)
		{
			VirtualFree(new_mem, 0, MEM_RELEASE);
		}

		// Restore protection
		VirtualProtect(patch_address, buff_size, dwPrevProtect, &dwPrevProtect);

		return nullptr; // access denied
	}
	memset(new_mem, 0x90, mem_size);

	// Write old data to new memory before overwritting it
	memcpy(new_mem, patch_address + 5, ByteNum);
	*(new_mem + ByteNum) = 0xE9; // jmp (5-byte relative)
	*((DWORD*)(new_mem + ByteNum + 1)) = (DWORD)patch_address - (DWORD)new_mem; // relative address

	// Special handling for 5-byte assembly header (call/jmp)
	if (memcmp("\xE8", new_mem, 1) == S_OK || memcmp("\xE9", new_mem, 1) == S_OK)
	{
		BYTE* CallJmpAddress = (BYTE*)(*(DWORD*)(patch_address + 6) + (DWORD)patch_address + 10); // address to call/jmp
		*((DWORD*)(new_mem + 1)) = (DWORD)CallJmpAddress - (DWORD)new_mem - 5; // relative address
	}

	// Backup memory
	HOTPATCH tmpMemory;
	tmpMemory.procaddr = patch_address;
	tmpMemory.alocmemaddr = new_mem;
	ReadProcessMemory(GetCurrentProcess(), patch_address, tmpMemory.lpOrgBuffer, buff_size, nullptr);

	// Overwrite with NOPs to align
	memset(patch_address + 5, 0x90, ByteNum); // Overwrite bytes with NOPs to align

	// Set HotPatch hook
	*(patch_address + 5) = 0xE9; // jmp (4-byte relative)
	*((DWORD*)(patch_address + 6)) = (DWORD)hookproc - (DWORD)patch_address - 10; // relative address

	// Get memory after update
	ReadProcessMemory(GetCurrentProcess(), patch_address, tmpMemory.lpNewBuffer, buff_size, nullptr);

	// Restore protection
	VirtualProtect(patch_address, buff_size, dwPrevProtect, &dwPrevProtect);

	// Flush cache
	FlushInstructionCache(GetCurrentProcess(), patch_address, buff_size);

	// Pin modules
	HMODULE module = nullptr;
	GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
		reinterpret_cast<char*>(hookproc), &module);
	GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
		reinterpret_cast<char*>(patch_address + 5), &module);

#ifdef _DEBUG
	Logging::LogFormat(__FUNCTION__ ": api=%s addr=%p headersize=%d hook=%p", apiname, (patch_address + 5), ByteNum, hookproc);
#endif
	return new_mem;
}

void* Hook::HotPatch(void* apiproc, const char* apiname, void* hookproc)
{
#ifdef _DEBUG
	Logging::LogFormat(__FUNCTION__ ": api=%s addr=%p hook=%p", apiname, apiproc, hookproc);
#endif

	// Check API address
	if (!apiproc)
	{
		Logging::Log() << __FUNCTION__ << " Error: Failed to find '" << apiname << "' api";
		return nullptr;
	}

	// Check hook address
	if (!hookproc)
	{
		Logging::Log() << __FUNCTION__ << " Error: Invalid hook address for '" << apiname << "'";
		return nullptr;
	}

	// Get API addresses
	BYTE* patch_address = ((BYTE*)apiproc) - 5;
	BYTE* srcLocation = (BYTE*)apiproc;

	// Initual instruction size
	unsigned instructionSize = Disasm::getInstructionLength(srcLocation);

	LOG_DEBUG << Logging::hexDump(srcLocation, instructionSize) << " -> " << funcPtrToStr(srcLocation) << ' ';

	// Check if there is a padding
	bool IsPadding = instructionSize < 5 && CheckPadding(patch_address);	// No need for padding if the instruction size is large enough
	DWORD BytesNeeded = IsPadding ? 2 : 5;

	// Check for unsupported instructions
	if (instructionSize == 0 || IsUnsupportedInstruction(srcLocation) || (!IsPadding  && *srcLocation == 0xEB))	// Currently 0xEB is only supported with padding
	{
		Logging::Log() << __FUNCTION__ " Error: unsupported instruction found in '" << apiname << "'. Code: " << Logging::hexDump(srcLocation, instructionSize)
			<< " (" << funcPtrToStr(apiproc) << " " << Logging::hexDump(patch_address, buff_size) << ')';
		return nullptr;
	}

	// Loop through each instruction to get instruction set size
	srcLocation += instructionSize;
	while (instructionSize < BytesNeeded)
	{
		// New instruction size
		unsigned newInstructionSize = Disasm::getInstructionLength(srcLocation);

		LOG_DEBUG << Logging::hexDump(srcLocation, newInstructionSize) << " -> " << funcPtrToStr(srcLocation) << ' ';

		// Check for unsupported instructions, 0xE8, 0xE9 and 0xEB are only supported with the first instruction
		if (newInstructionSize == 0 || IsUnsupportedInstruction(srcLocation) || *srcLocation == 0xE8 || *srcLocation == 0xE9 || *srcLocation == 0xEB)
		{
			Logging::Log() << __FUNCTION__ " Error: unsupported instruction found in loop in '" << apiname << "'. Code: " << Logging::hexDump(srcLocation, 1)
				<< " (" << funcPtrToStr(apiproc) << " " << Logging::hexDump(patch_address, buff_size) << ')';
			return nullptr;
		}

		// Get new instruction location
		srcLocation += newInstructionSize;
		instructionSize += newInstructionSize;
	}

	// Check instruction size
	if (instructionSize > buff_size - 5)
	{
		Logging::Log() << __FUNCTION__ " Error: instructions are too long in '" << apiname << "'. Size: " << instructionSize
			<< " (" << funcPtrToStr(apiproc) << " " << Logging::hexDump(patch_address, buff_size) << ')';
		return nullptr;
	}

	LOG_DEBUG << __FUNCTION__ " Hooking '" << apiname << "'. Instruction Code: " << Logging::hexDump(apiproc, srcLocation - (BYTE*)apiproc)
		<< "'. Size: " << instructionSize << " (" << funcPtrToStr(apiproc) << " " << Logging::hexDump(patch_address, buff_size) << ')';

	// Overwrite API with padding
	if (IsPadding && instructionSize < 5)
	{
		return OverwriteHeaderWithPadding(patch_address, apiname, hookproc, instructionSize);
	}

	// Rewrite API header
	else
	{
		return RewriteHeader(patch_address, apiname, hookproc, instructionSize);
	}
}
