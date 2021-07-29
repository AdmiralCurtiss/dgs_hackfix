#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
//#include <dinput.h>

#include <cstdio>

#include "INIReader.h"

static void WriteFloat(void* addr, float value) {
	void* fps_addr = reinterpret_cast<void*>(reinterpret_cast<unsigned long long>(addr) & 0xffff'ffff'ffff'f000);
	DWORD fps_attr;
	VirtualProtect(fps_addr, 0x1000, PAGE_READWRITE, &fps_attr);
	memcpy(addr, &value, 4);
	DWORD tmpdword;
	VirtualProtect(fps_addr, 0x1000, fps_attr, &tmpdword);
}

static void WriteByte(void* addr, char value) {
	void* fps_addr = reinterpret_cast<void*>(reinterpret_cast<unsigned long long>(addr) & 0xffff'ffff'ffff'f000);
	DWORD fps_attr;
	VirtualProtect(fps_addr, 0x1000, PAGE_READWRITE, &fps_attr);
	memcpy(addr, &value, 1);
	DWORD tmpdword;
	VirtualProtect(fps_addr, 0x1000, fps_attr, &tmpdword);
}

static void* InjectSleepInMainThread(void* new_page, int MainThreadSleepTime) {
	DWORD tmpdword;

	// remove write protection of relevant page
	void* message_pump_loop_page_addr = reinterpret_cast<char*>(0x1403bf000);
	DWORD message_pump_loop_page_old_attr;
	VirtualProtect(message_pump_loop_page_addr, 0x1000, PAGE_READWRITE, &message_pump_loop_page_old_attr);

	void* rv = new_page;

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
			// mov ecx,MainThreadSleepTime
			*writeptr++ = 0xb9;
			memcpy(writeptr, &MainThreadSleepTime, 4);
			writeptr += 4;
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

			rv = writeptr;

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

	return rv;
}

static void* InjectSleepInAudioDeviceCountCheckThread(void* new_page, int sleepTime) {
	DWORD tmpdword;

	// remove write protection of relevant page
	void* message_pump_loop_page_addr = reinterpret_cast<char*>(0x140588000);
	DWORD message_pump_loop_page_old_attr;
	VirtualProtect(message_pump_loop_page_addr, 0x1000, PAGE_READWRITE, &message_pump_loop_page_old_attr);

	void* rv = new_page;

	// modify code
	{
		char* overwrite_addr = reinterpret_cast<char*>(0x140588eb6);
		constexpr unsigned int replace_size = 0xc;
		char overwrite_bytes[replace_size];
		char expected_bytes[replace_size] = { 0x48, 0x8b, 0xcb, 0xe8, 0x02, 0xe2, 0xe2, 0xff, 0x84, 0xc0, 0x74, 0xe0 };
		memcpy(overwrite_bytes, overwrite_addr, replace_size);
		if (memcmp(overwrite_bytes, expected_bytes, replace_size) == 0) {
			// rax, rcx is free to use

			// we appear to have found the correct bytes
			char* writeptr = reinterpret_cast<char*>(new_page);

			// inject a call to Sleep() so this thread is not constantly busy
			// this isn't a good fix but it'll do for now...
			char* sleep_addr = reinterpret_cast<char*>(0x140954390);
			// mov rax,sleep_addr
			*writeptr++ = 0x48;
			*writeptr++ = 0xb8;
			memcpy(writeptr, &sleep_addr, 8);
			writeptr += 8;
			// mov rax,qword ptr[rax]
			*writeptr++ = 0x48;
			*writeptr++ = 0x8b;
			*writeptr++ = 0x00;
			// mov ecx,sleepTime
			*writeptr++ = 0xb9;
			memcpy(writeptr, &sleepTime, 4);
			writeptr += 4;
			// call rax
			*writeptr++ = 0xff;
			*writeptr++ = 0xd0;

			// replace code we overwrote with equivalent logic
			// mov rcx,rbx
			*writeptr++ = 0x48;
			*writeptr++ = 0x8b;
			*writeptr++ = 0xcb;
			// mov rax,some_function
			char* some_function = reinterpret_cast<char*>(0x1403b70c0);
			*writeptr++ = 0x48;
			*writeptr++ = 0xb8;
			memcpy(writeptr, &some_function, 8);
			writeptr += 8;
			// call rax
			*writeptr++ = 0xff;
			*writeptr++ = 0xd0;
			// test al,al
			*writeptr++ = 0x84;
			*writeptr++ = 0xc0;
			// jz continue_loop
			*writeptr++ = 0x74;
			*writeptr++ = 0x0c;
			// mov rcx,exit_loop_addr
			char* exit_loop_addr = reinterpret_cast<char*>(0x140588ec2);
			*writeptr++ = 0x48;
			*writeptr++ = 0xb9;
			memcpy(writeptr, &exit_loop_addr, 8);
			writeptr += 8;
			// jmp rcx
			*writeptr++ = 0xff;
			*writeptr++ = 0xe1;
			// continue_loop:
			// mov rcx,continue_loop_addr
			char* continue_loop_addr = reinterpret_cast<char*>(0x140588ea2);
			*writeptr++ = 0x48;
			*writeptr++ = 0xb9;
			memcpy(writeptr, &continue_loop_addr, 8);
			writeptr += 8;
			// jmp rcx
			*writeptr++ = 0xff;
			*writeptr++ = 0xe1;




			rv = writeptr;

			// inject jump to our new code
			// mov rcx,new_page
			writeptr = overwrite_addr;
			*writeptr++ = 0x48;
			*writeptr++ = 0xb9;
			memcpy(writeptr, &new_page, 8);
			writeptr += 8;
			// jmp rcx
			*writeptr++ = 0xff;
			*writeptr++ = 0xe1;
		}
	}

	// reset write protection of relevant page
	VirtualProtect(message_pump_loop_page_addr, 0x1000, message_pump_loop_page_old_attr, &tmpdword);

	return rv;
}

static void* SetupHacks() {
	INIReader ini("dgs.ini");

	if (ini.ParseError() != 0)
		return nullptr;

	// allocate extra page for code
	void* new_page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT, PAGE_READWRITE);
	if (!new_page)
		return nullptr;

	void* free_space_ptr = new_page;
	if (ini.GetBoolean("Main", "InjectSleepInMainThread", true)) {
		int ms = ini.GetInteger("Main", "MainThreadSleepTime", 10);
		free_space_ptr = InjectSleepInMainThread(free_space_ptr, ms);
	}
	if (ini.GetBoolean("Main", "InjectSleepInAudioDeviceCountCheckThread", true)) {
		int ms = ini.GetInteger("Main", "AudioDeviceCountCheckThreadSleepTime", 1000);
		free_space_ptr = InjectSleepInAudioDeviceCountCheckThread(free_space_ptr, ms);
	}

	// run at 60 fps or whatever
	float fps = ini.GetFloat("Main", "AnimationFps", 60.0f);
	if (fps != 30.0f) {
		//WriteFloat(reinterpret_cast<void*>(0x140058219), fps); // 3d model animation speed?
		WriteFloat(reinterpret_cast<void*>(0x140058227), fps); // 3d render update speed
	}

	if (ini.GetBoolean("Main", "DisplayAllRenderResolutions", true)) {
		WriteByte(reinterpret_cast<void*>(0x14005e2a6), 0xeb); // jz -> jmp
	}


	// mark newly allocated page as executable
	{
		DWORD tmpdword;
		VirtualProtect(new_page, 0x1000, PAGE_EXECUTE_READ, &tmpdword);
	}

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
