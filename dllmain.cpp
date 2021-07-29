#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
//#include <dinput.h>

#include <cstdio>

static void* SetupHacks() {
//	static int idx = 0;
//	int i = idx++;
//	char tmp[20];
//	sprintf(tmp, "%d.txt", i);
//	FILE* f = fopen(tmp, "wb");

	DWORD tmpdword;

	// allocate extra page for code
	void* new_page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT, PAGE_READWRITE);
	if (!new_page)
		return nullptr;

	// remove write protection of relevant page
	void* message_pump_loop_page_addr = reinterpret_cast<char*>(0x1403bf000);
	DWORD message_pump_loop_page_old_attr;
	VirtualProtect(message_pump_loop_page_addr, 0x1000, PAGE_READWRITE, &message_pump_loop_page_old_attr);


	// modify code
	{
		char* overwrite_addr = reinterpret_cast<char*>(0x1403bf070);
		constexpr unsigned int replace_size = 0x13;
		char overwrite_bytes[replace_size];
		char expected_bytes[replace_size] = { 0x45, 0x33, 0xC9, 0xC7, 0x44, 0x24, 0x20, 0x01, 0x00, 0x00, 0x00, 0x45, 0x33, 0xC0, 0x48, 0x8D, 0x4C, 0x24, 0x30 };
		memcpy(overwrite_bytes, overwrite_addr, replace_size);
		if (memcmp(overwrite_bytes, expected_bytes, replace_size) == 0) {
			// rdx is free to use

			// we appear to have found the correct bytes
			char* writeptr = reinterpret_cast<char*>(new_page);

			// inject a call to Sleep() so this thread is not constantly busy
			// this isn't a good fix but it'll do for now...
			char* sleep_addr = reinterpret_cast<char*>(0x140954390);
			// mov rdx,sleep_addr
			*writeptr++ = 0x48;
			*writeptr++ = 0xba;
			memcpy(writeptr, &sleep_addr, 8);
			writeptr += 8;
			// mov rdx,qword ptr[rdx]
			*writeptr++ = 0x48;
			*writeptr++ = 0x8b;
			*writeptr++ = 0x12;
			// mov ecx,0x10
			*writeptr++ = 0xb9;
			*writeptr++ = 0x10;
			*writeptr++ = 0x00;
			*writeptr++ = 0x00;
			*writeptr++ = 0x00;
			// call rdx
			*writeptr++ = 0xff;
			*writeptr++ = 0xd2;

			// place the data we just replaced at the new page
			memcpy(writeptr, overwrite_bytes, replace_size);
			writeptr += replace_size;

			// jump back to original code
			// mov rdx,overwrite_end
			*writeptr++ = 0x48;
			*writeptr++ = 0xba;
			char* overwrite_end = overwrite_addr + replace_size;
			memcpy(writeptr, &overwrite_end, 8);
			writeptr += 8;
			// jmp rdx
			*writeptr++ = 0xff;
			*writeptr++ = 0xe2;

			// and finally, inject jump to our new page
			// mov rdx,new_page
			writeptr = overwrite_addr;
			*writeptr++ = 0x48;
			*writeptr++ = 0xba;
			memcpy(writeptr, &new_page, 8);
			writeptr += 8;
			// jmp rdx
			*writeptr++ = 0xff;
			*writeptr++ = 0xe2;
		}
	}

	// reset write protection of relevant page
	VirtualProtect(message_pump_loop_page_addr, 0x1000, message_pump_loop_page_old_attr, &tmpdword);

	// mark newly allocated page as executable
	VirtualProtect(new_page, 0x1000, PAGE_EXECUTE_READ, &tmpdword);

//	MEMORY_BASIC_INFORMATION info;
//	if (size_t result = VirtualQuery(reinterpret_cast<void*>(0x1403bf0b2), &info, sizeof(info)) > 0) {
//		if (info.State == MEM_COMMIT) {
//			//char* baseAddr = reinterpret_cast<char*>(info.BaseAddress);
//			//for (size_t i = 0; i < info.RegionSize; ++i) {
//			//	*(baseAddr + i);
//			//}
//
//			fwrite(info.BaseAddress, info.RegionSize, 1, f);
//		}
//	}
//
//	fclose(f);

	return new_page;
}
static void* dummy = SetupHacks();

extern "C" {
	using PDirectInput8Create = HRESULT(*)(HINSTANCE hinst,
		DWORD dwVersion,
		REFIID riidltf,
		LPVOID* ppvOut,
		void* punkOuter);

	PDirectInput8Create LoadForwarderAddress() {
		constexpr int total = 10000;
		WCHAR tmp[total];
		UINT count = GetSystemDirectoryW(tmp, sizeof(tmp) / sizeof(TCHAR));
		if (count == 0 || count > total - 16)
			return nullptr;
		memcpy(tmp + count, L"\\dinput8.dll\0", sizeof(L"\\dinput8.dll\0"));

		HMODULE dll = ::LoadLibraryW(tmp);
		if (!dll)
			return nullptr;
		void* addr = ::GetProcAddress(dll, "DirectInput8Create");
		return (PDirectInput8Create)addr;
	}
	static PDirectInput8Create addr_PDirectInput8Create = LoadForwarderAddress();

	HRESULT DirectInput8Create(
		HINSTANCE hinst,
		DWORD dwVersion,
		REFIID riidltf,
		LPVOID* ppvOut,
		void* punkOuter
	) {
		PDirectInput8Create addr = addr_PDirectInput8Create;
		if (!addr) {
			return 0x8007000EL; // DIERR_OUTOFMEMORY
		}
		return addr(hinst, dwVersion, riidltf, ppvOut, punkOuter);
	}
}
