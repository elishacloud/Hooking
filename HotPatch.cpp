/**
* Copyright (C) 2021 Elisha Riedlinger
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
// 1 = already patched
// addr = address of the original function

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <vector>
#include "Hook.h"

constexpr DWORD buff_size = 12;

namespace Hook
{
	struct HOTPATCH
	{
		BYTE lpOrgBuffer[buff_size];
		BYTE lpNewBuffer[buff_size];
		void* procaddr = nullptr;
		void* alocmemaddr = nullptr;
	};

	std::vector<HOTPATCH> HotPatchProcs;

	void *RewriteHeader(BYTE *patch_address, DWORD dwPrevProtect, const char *apiname, void *hookproc, DWORD ByteNum);
}

void *Hook::RewriteHeader(BYTE *patch_address, DWORD dwPrevProtect, const char *apiname, void *hookproc, DWORD ByteNum)
{
	if (!patch_address || !dwPrevProtect || !apiname || !hookproc || ByteNum < 5)
	{
		Logging::Log() << __FUNCTION__ " Error: Invalid input!";
		return nullptr;
	}

	// Create new memory and prepare to patch
	DWORD mem_size = (((ByteNum + 5) / 8) + 1) * 8;
	BYTE *new_mem = (BYTE*)VirtualAlloc(nullptr, mem_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	DWORD dwNull = 0;
	if (!new_mem || !VirtualProtect(new_mem, mem_size, PAGE_EXECUTE_READWRITE, &dwNull))
	{
		Logging::LogFormat(__FUNCTION__ " Error: access denied.  Cannot mark memory as executable api=%s at addr=%p err=%x", apiname, new_mem, GetLastError());

		if (new_mem)
		{
			VirtualFree(new_mem, 0, MEM_RELEASE);
		}

		// Restore protection
		VirtualProtect(patch_address, buff_size, dwPrevProtect, &dwNull);

		return nullptr; // access denied
	}
	memset(new_mem, 0x90, mem_size);

	// Write old data to new memory before overwritting it
	memcpy(new_mem, patch_address + 5, ByteNum);
	*(new_mem + ByteNum) = 0xE9; // jmp (4-byte relative)
	*((DWORD *)(new_mem + ByteNum + 1)) = (DWORD)patch_address - (DWORD)new_mem; // relative address

	// Special handling for 5-byte assembly header (call/jmp)
	if (!memcmp("\xE8", new_mem, 1) || !memcmp("\xE9", new_mem, 1))
	{
		BYTE* CallJmpAddress = (BYTE*)(*(DWORD*)(patch_address + 6) + (DWORD)patch_address + 10); // address to call/jmp
		*((DWORD*)(new_mem + 1)) = (DWORD)CallJmpAddress - (DWORD)new_mem - 5; // relative address
	}

	// Backup memory
	HOTPATCH tmpMemory;
	tmpMemory.procaddr = patch_address;
	tmpMemory.alocmemaddr = new_mem;
	ReadProcessMemory(GetCurrentProcess(), patch_address, tmpMemory.lpOrgBuffer, buff_size, nullptr);

	// Set HotPatch hook
	*(patch_address + 5) = 0xE9; // jmp (4-byte relative)
	*((DWORD *)(patch_address + 6)) = (DWORD)hookproc - (DWORD)patch_address - 10; // relative address

	// Get memory after update
	ReadProcessMemory(GetCurrentProcess(), patch_address, tmpMemory.lpNewBuffer, buff_size, nullptr);

	// Save memory
	HotPatchProcs.push_back(tmpMemory);

	// Restore protection
	VirtualProtect(new_mem, mem_size, dwPrevProtect, &dwNull);
	VirtualProtect(patch_address, buff_size, dwPrevProtect, &dwNull);

	// Flush cache
	FlushInstructionCache(GetCurrentProcess(), new_mem, mem_size);
	FlushInstructionCache(GetCurrentProcess(), patch_address, buff_size);
#ifdef _DEBUG
	Logging::LogFormat(__FUNCTION__ ": api=%s addr=%p headersize=%d hook=%p", apiname, (patch_address + 5), ByteNum, hookproc);
#endif
	return new_mem;
}

// Hook API using hot patch
void *Hook::HotPatch(void *apiproc, const char *apiname, void *hookproc, bool forcepatch)
{
	DWORD dwPrevProtect;
	BYTE *patch_address;
	void *orig_address;

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

	patch_address = ((BYTE *)apiproc) - 5;
	orig_address = (BYTE *)apiproc + 2;

	// Entry point could be at the top of a page? so VirtualProtect first to make sure patch_address is readable
	if (!VirtualProtect(patch_address, buff_size, PAGE_EXECUTE_WRITECOPY, &dwPrevProtect))
	{
		Logging::LogFormat(__FUNCTION__ " Error: access denied.  Cannot hook api=%s at addr=%p err=%x", apiname, apiproc, GetLastError());
		return nullptr; // access denied
	}

	// Check if API can be patched
	if (!(memcmp("\x90\x90\x90\x90\x90\xEB\x05\x90\x90\x90\x90\x90", patch_address, 12) &&											// Some calls (QueryPerformanceCounter) are sort of hot patched already....
		memcmp("\xCC\xCC\xCC\xCC\xCC\xEB\x05\xCC\xCC\xCC\xCC\xCC", patch_address, 12) &&											// For debugging
		memcmp("\x90\x90\x90\x90\x90\x8B\xFF", patch_address, 7) && memcmp("\x90\x90\x90\x90\x90\x89\xFF", patch_address, 7) &&		// Make sure it is a hotpatchable image... check for 5 nops followed by mov edi,edi
		memcmp("\x00\x00\x00\x00\x00\x8B\xFF", patch_address, 7) &&																	// Some API's use 0x00 rather than 0x90
		memcmp("\xCC\xCC\xCC\xCC\xCC\x8B\xFF", patch_address, 7) && memcmp("\xCC\xCC\xCC\xCC\xCC\x89\xFF", patch_address, 7)) ||	// For debugging
		((forcepatch && (!memcmp("\x90\x90\x90\x90\x90", patch_address, 5) || !memcmp("\xCC\xCC\xCC\xCC\xCC", patch_address, 5)))))	// Force hook, overwrites data, patched function may not be usable
	{
		// Backup memory
		HOTPATCH tmpMemory;
		tmpMemory.procaddr = patch_address;
		ReadProcessMemory(GetCurrentProcess(), patch_address, tmpMemory.lpOrgBuffer, buff_size, nullptr);

		// Set HotPatch hook
		*patch_address = 0xE9; // jmp (4-byte relative)
		*((DWORD *)(patch_address + 1)) = (DWORD)hookproc - (DWORD)patch_address - 5; // relative address
		*((WORD *)apiproc) = 0xF9EB; // should be atomic write (jmp $-5)

		// Get memory after update
		ReadProcessMemory(GetCurrentProcess(), patch_address, tmpMemory.lpNewBuffer, buff_size, nullptr);

		// Save memory
		HotPatchProcs.push_back(tmpMemory);

		// Restore protection
		VirtualProtect(patch_address, buff_size, dwPrevProtect, &dwPrevProtect);

		// Flush cache
		FlushInstructionCache(GetCurrentProcess(), patch_address, buff_size);
#ifdef _DEBUG
		Logging::LogFormat(__FUNCTION__ ": api=%s addr=%p->%p hook=%p", apiname, apiproc, orig_address, hookproc);
#endif
		return orig_address;
	}

	// Check for common 8-byte assembly header
	else if (!memcmp("\x33\xC0\x39\x05", patch_address + 5, 4))
	{
		return RewriteHeader(patch_address, dwPrevProtect, apiname, hookproc, 8);
	}

	// Check for common 7-byte assembly header
	else if ((!memcmp("\x8D\x4C\x24", patch_address + 5, 3) && !memcmp("\x83\xE4", patch_address + 9, 2)) ||
		!memcmp("\xF6\x05", patch_address + 5, 2) || !memcmp("\x55\x8B\xEC\x6A\xFF\x68\xD0", patch_address + 5, 7))
	{
		return RewriteHeader(patch_address, dwPrevProtect, apiname, hookproc, 7);
	}

	// Check for common 5-byte assembly header
	else if (!memcmp("\x90\x90\x90\x90\x90", patch_address + 5, 5) ||
		!memcmp("\xCC\xCC\xCC\xCC\xCC", patch_address + 5, 5) ||
		!memcmp("\x8B\xFF\x55\x8B\xEC", patch_address + 5, 5) ||
		!memcmp("\x68", patch_address + 5, 1) ||
		!memcmp("\xB8", patch_address + 5, 1) ||
		!memcmp("\xB9", patch_address + 5, 1) ||
		!memcmp("\xE8", patch_address + 5, 1) ||
		!memcmp("\xE9", patch_address + 5, 1))
	{
		return RewriteHeader(patch_address, dwPrevProtect, apiname, hookproc, 5);
	}

	// Check if API is just a pointer to another API
	else if (!(memcmp("\x90\x90\x90\x90\x90\xFF\x25", patch_address, 7) && memcmp("\xCC\xCC\xCC\xCC\xCC\xFF\x25", patch_address, 7)))
	{
		// Get memory address to function
		DWORD *patchAddr;
		memcpy(&patchAddr, ((BYTE*)apiproc + 2), sizeof(DWORD));

		// Restore protection
		VirtualProtect(patch_address, buff_size, dwPrevProtect, &dwPrevProtect);

#ifdef _DEBUG
		Logging::LogFormat(__FUNCTION__ ": api=%s addr=%p->%p hook=%p", apiname, apiproc, orig_address, hookproc);
#endif

		return HotPatch((void*)(*patchAddr), apiname, hookproc);
	}

	// API cannot be patched
	else
	{
		// Restore protection
		VirtualProtect(patch_address, buff_size, dwPrevProtect, &dwPrevProtect);

		// check it wasn't patched already
		if ((*patch_address == 0xE9) && (*(WORD *)apiproc == 0xF9EB))
		{
			// should never go through here ...
			Logging::LogFormat(__FUNCTION__ " Error: '%s' patched already at addr=%p", apiname, apiproc);
			return (void *)1;
		}
		else
		{
			Logging::LogFormat(__FUNCTION__ " Error: '%s' is not patch aware at addr=%p", apiname, apiproc);

			// Log memory
			BYTE lpBuffer[buff_size];
			if (ReadProcessMemory(GetCurrentProcess(), patch_address, lpBuffer, buff_size, nullptr))
			{
				const size_t size = buff_size * 4 + 40;
				char buffer[size] = { '\0' };
				strcpy_s(buffer, size, "Bytes in memory are: ");
				char tmpbuffer[8] = { '\0' };
				for (int x = 0; x < buff_size; x++)
				{
					sprintf_s(tmpbuffer, "\\x%02X", lpBuffer[x]);
					strcat_s(buffer, size, tmpbuffer);
				}
				Logging::LogFormat(buffer);
			}

			return nullptr; // not hot patch "aware"
		}
	}
}

// Restore all addresses hooked
bool Hook::UnHotPatchAll()
{
	bool flag = true;
	BYTE lpBuffer[buff_size];
	while (HotPatchProcs.size() != 0)
	{
		// VirtualProtect first to make sure patch_address is readable
		DWORD dwPrevProtect;
		if (VirtualProtect(HotPatchProcs.back().procaddr, buff_size, PAGE_EXECUTE_WRITECOPY, &dwPrevProtect))
		{
			// Read memory
			if (ReadProcessMemory(GetCurrentProcess(), HotPatchProcs.back().procaddr, lpBuffer, buff_size, nullptr))
			{
				// Check if memory is as expected
				if (!memcmp(lpBuffer, HotPatchProcs.back().lpNewBuffer, buff_size))
				{
					// Write to memory
					memcpy(HotPatchProcs.back().procaddr, HotPatchProcs.back().lpOrgBuffer, buff_size);
				}
				else
				{
					// Memory different than expected
					flag = false;
					Logging::LogFormat(__FUNCTION__ " Error: Memory different than expected procaddr: %p", HotPatchProcs.back().procaddr);
				}
			}
			else
			{
				// Failed to read memory
				flag = false;
				Logging::LogFormat(__FUNCTION__ " Error: Failed to read memory procaddr: %p", HotPatchProcs.back().procaddr);
			}

			// Restore protection
			VirtualProtect(HotPatchProcs.back().procaddr, buff_size, dwPrevProtect, &dwPrevProtect);

			// Flush cache
			FlushInstructionCache(GetCurrentProcess(), HotPatchProcs.back().procaddr, buff_size);
		}
		else
		{
			// Access denied
			flag = false;
			Logging::LogFormat(__FUNCTION__ " Error: access denied. procaddr: %p", HotPatchProcs.back().procaddr);
		}
		// Free VirtualAlloc memory
		if (HotPatchProcs.back().alocmemaddr)
		{
			VirtualFree(HotPatchProcs.back().alocmemaddr, 0, MEM_RELEASE);
		}
		HotPatchProcs.pop_back();
	}
	HotPatchProcs.clear();
	return flag;
}

// Unhook hot patched API
bool Hook::UnhookHotPatch(void *apiproc, const char *apiname, void *hookproc)
{
	DWORD dwPrevProtect;
	BYTE *patch_address;
	void *orig_address;

#ifdef _DEBUG
	Logging::LogFormat(__FUNCTION__ ": api=%s addr=%p hook=%p", apiname, apiproc, hookproc);
#endif

	patch_address = ((BYTE *)apiproc) - 5;
	orig_address = (BYTE *)apiproc + 2;

	// Check if this address is stored in the vector and restore memory
	BYTE lpBuffer[buff_size];
	for (UINT x = 0; x < HotPatchProcs.size(); ++x)
	{
		// Check for address
		if (HotPatchProcs[x].procaddr == patch_address)
		{
			// VirtualProtect first to make sure patch_address is readable
			if (VirtualProtect(HotPatchProcs[x].procaddr, buff_size, PAGE_EXECUTE_WRITECOPY, &dwPrevProtect))
			{
				// Read memory
				if (ReadProcessMemory(GetCurrentProcess(), HotPatchProcs[x].procaddr, lpBuffer, buff_size, nullptr))
				{
					// Check if memory is as expected
					if (!memcmp(lpBuffer, HotPatchProcs[x].lpNewBuffer, buff_size))
					{
						// Write to memory
						memcpy(HotPatchProcs[x].procaddr, HotPatchProcs[x].lpOrgBuffer, buff_size);

						// If not at the end then move back to current loc and pop_back
						if (x + 1 != HotPatchProcs.size())
						{
							HotPatchProcs[x].procaddr = HotPatchProcs.back().procaddr;
							memcpy(HotPatchProcs[x].lpOrgBuffer, HotPatchProcs.back().lpOrgBuffer, buff_size);
							memcpy(HotPatchProcs[x].lpNewBuffer, HotPatchProcs.back().lpNewBuffer, buff_size);
						}
						// Free VirtualAlloc memory
						if (HotPatchProcs.back().alocmemaddr)
						{
							VirtualFree(HotPatchProcs.back().alocmemaddr, 0, MEM_RELEASE);
						}
						HotPatchProcs.pop_back();

						// Restore protection
						VirtualProtect(patch_address, buff_size, dwPrevProtect, &dwPrevProtect);

						// Flush cache
						FlushInstructionCache(GetCurrentProcess(), patch_address, buff_size);

						// Return
						return true;
					}
				}

				// Restore protection
				VirtualProtect(patch_address, buff_size, dwPrevProtect, &dwPrevProtect);
			}
		}
	}

	// Entry point could be at the top of a page? so VirtualProtect first to make sure patch_address is readable
	if (!VirtualProtect(patch_address, buff_size, PAGE_EXECUTE_WRITECOPY, &dwPrevProtect))
	{
		Logging::LogFormat(__FUNCTION__ " Error: access denied.  Cannot hook api=%s at addr=%p err=%x", apiname, apiproc, GetLastError());
		return false; // access denied
	}

	// Check if API is hot patched
	if ((*patch_address == 0xE9) && (*(WORD *)apiproc == 0xF9EB) &&
		*((DWORD *)(patch_address + 1)) == (DWORD)hookproc - (DWORD)patch_address - 5)
	{
		*patch_address = 0x90; // nop
		*((DWORD *)(patch_address + 1)) = 0x90909090; // 4 nops
		*((WORD *)(patch_address + 5)) = 0x9090; // 2 nops

		// Restore protection
		VirtualProtect(patch_address, buff_size, dwPrevProtect, &dwPrevProtect);

		// Flush cache
		FlushInstructionCache(GetCurrentProcess(), patch_address, buff_size);
#ifdef _DEBUG
		Logging::LogFormat(__FUNCTION__ ": api=%s addr=%p->%p hook=%p", apiname, apiproc, orig_address, hookproc);
#endif
		return true;
	}

	Logging::LogFormat(__FUNCTION__ " Error: failed to unhook '%s' at addr=%p", apiname, apiproc);

	// Restore protection
	VirtualProtect(patch_address, buff_size, dwPrevProtect, &dwPrevProtect);
#ifdef _DEBUG
	Logging::LogFormat(__FUNCTION__ ": api=%s addr=%p->%p hook=%p", apiname, apiproc, orig_address, hookproc);
#endif
	return false;
}
