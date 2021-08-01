#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>

#include <cinttypes>
#include <cstdio>

#include "INIReader.h"
#include "crc32.h"

namespace {
struct Logger {
    FILE* f;

    Logger(const char* filename) {
        f = fopen(filename, "w");
    }

    ~Logger() {
        if (f) {
            fclose(f);
        }
    }

    Logger& Log(const char* text) {
        if (f) {
            fwrite(text, strlen(text), 1, f);
            fflush(f);
        }
        return *this;
    }

    Logger& LogPtr(const void* ptr) {
        if (f) {
            char buffer[32];
            int len = sprintf(buffer, "0x%016" PRIxPTR, reinterpret_cast<uintptr_t>(ptr));
            fwrite(buffer, len, 1, f);
            fflush(f);
        }
        return *this;
    }

    Logger& LogInt(unsigned long long v) {
        if (f) {
            char buffer[32];
            int len = sprintf(buffer, "%llu", v);
            fwrite(buffer, len, 1, f);
            fflush(f);
        }
        return *this;
    }

    Logger& LogHex(unsigned long long v) {
        if (f) {
            char buffer[32];
            int len = sprintf(buffer, "0x%llx", v);
            fwrite(buffer, len, 1, f);
            fflush(f);
        }
        return *this;
    }

    Logger& LogFloat(float v) {
        if (f) {
            char buffer[32];
            int len = sprintf(buffer, "%g", v);
            fwrite(buffer, len, 1, f);
            fflush(f);
        }
        return *this;
    }
};

struct PageUnprotect {
    Logger& Log;
    void* Address;
    size_t Length;
    DWORD Attributes;

    PageUnprotect(Logger& logger, void* addr, size_t length) : Log(logger) {
        // FIXME: check length/alignment, this might span multiple pages!
        Length = 0x1000;
        Address = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(addr) & (~(Length - 1)));
        Log.Log("Unprotecting ").LogHex(Length).Log(" bytes at ").LogPtr(Address);
        if (VirtualProtect(Address, Length, PAGE_READWRITE, &Attributes)) {
            Log.Log(" -> Success, previous attributes were ").LogHex(Attributes).Log(".\n");
        } else {
            Log.Log(" -> Failed.\n");
        }
    }

    ~PageUnprotect() {
        DWORD tmp;
        Log.Log("Reprotecting ").LogHex(Length).Log(" bytes at ").LogPtr(Address);
        if (VirtualProtect(Address, Length, Attributes, &tmp)) {
            Log.Log(" -> Success.\n");
        } else {
            Log.Log(" -> Failed.\n");
        }
    }
};
} // namespace

using PDirectInput8Create = HRESULT (*)(HINSTANCE hinst, DWORD dwVersion, REFIID riidltf,
                                        LPVOID* ppvOut, void* punkOuter);
static PDirectInput8Create LoadForwarderAddress(Logger& logger) {
    constexpr int total = 5000;
    WCHAR tmp[total];
    UINT count = GetSystemDirectoryW(tmp, sizeof(tmp) / sizeof(TCHAR));
    if (count == 0 || count > total - 16) {
        logger.Log("Failed constructing path for system dinput8.dll.\n");
        return nullptr;
    }
    memcpy(tmp + count, L"\\dinput8.dll\0", sizeof(L"\\dinput8.dll\0"));

    HMODULE dll = ::LoadLibraryW(tmp);
    if (!dll) {
        logger.Log("Failed loading system dinput8.dll.\n");
        return nullptr;
    }
    void* addr = ::GetProcAddress(dll, "DirectInput8Create");
    if (!addr) {
        logger.Log("Failed finding system DirectInput8Create.\n");
    } else {
        logger.Log("Found system DirectInput8Create at ").LogPtr(addr).Log(".\n");
    }
    return (PDirectInput8Create)addr;
}

static void WriteFloat(Logger& logger, void* addr, float value) {
    logger.Log("Writing float ").LogFloat(value).Log(" to ").LogPtr(addr).Log(".\n");
    PageUnprotect unprotect(logger, addr, 4);
    memcpy(addr, &value, 4);
}

static void WriteByte(Logger& logger, void* addr, char value) {
    logger.Log("Writing byte ").LogHex(value).Log(" to ").LogPtr(addr).Log(".\n");
    PageUnprotect unprotect(logger, addr, 1);
    memcpy(addr, &value, 1);
}

static char* Align16CodePage(Logger& logger, void* new_page) {
    logger.Log("Aligning ").LogPtr(new_page).Log(" to 16 bytes.\n");
    char* p = reinterpret_cast<char*>(new_page);
    *p++ = 0xcc;
    while ((reinterpret_cast<unsigned long long>(p) & 0xf) != 0) {
        *p++ = 0xcc;
    }
    return p;
}

static void FindImageBase(Logger& logger, void** code, void** rdata) {
    MEMORY_BASIC_INFORMATION info;
    memset(&info, 0, sizeof(info));
    *code = nullptr;
    *rdata = nullptr;
    for (unsigned long long address = 0; address < 0x80000000000; address += info.RegionSize) {
        if (VirtualQuery(reinterpret_cast<void*>(address), &info, sizeof(info)) == 0) {
            break;
        }

        if (info.State == MEM_COMMIT && info.Type == MEM_IMAGE) {
            logger.Log("Allocation at ")
                .LogPtr(info.AllocationBase)
                .Log(", base ptr ")
                .LogPtr(info.BaseAddress)
                .Log(", size ")
                .LogHex(info.RegionSize)
                .Log(", protection ")
                .LogHex(info.Protect)
                .Log(".\n");
            if (info.RegionSize == 0x953000 && info.Protect == PAGE_EXECUTE_READ) {
                // could be code section, verify checksum
                crc_t crc = crc_init();
                crc = crc_update(crc, info.BaseAddress, info.RegionSize);
                crc = crc_finalize(crc);
                if (crc == 0x21dbbfc0) {
                    logger.Log("Matches checksum, assuming ")
                        .LogPtr(info.BaseAddress)
                        .Log(" as code section.\n");
                    *code = info.BaseAddress;
                } else {
                    logger.Log("Mismatches checksum (").LogHex(crc).Log(")\n");
                }
            }
            if (info.RegionSize == 0x160000 && info.Protect == PAGE_READONLY) {
                // likely rdata section, can't really test this as the addresses have already been
                // fixed up, so just assume it's right...
                logger.Log("Assuming ").LogPtr(info.BaseAddress).Log(" as rdata section.\n");
                *rdata = info.BaseAddress;
            }

            // logger.Log("First 64 bytes are:");
            // for (int i = 0; i < (info.RegionSize < 64 ? info.RegionSize : 64); ++i) {
            //    logger.Log(" ").LogHex(*(reinterpret_cast<unsigned char*>(info.BaseAddress) + i));
            // }
            // logger.Log("\n");
        }
    }
}

static void* InjectSleepInMainThread(Logger& logger, void* new_page, int MainThreadSleepTime,
                                     void* codeBase, void* sleepFuncAddr) {
    char* overwrite_addr = reinterpret_cast<char*>(codeBase) + 0x3BE070;
    constexpr unsigned int replace_size = 0x13;
    PageUnprotect unprotect(logger, overwrite_addr, replace_size);

    void* rv = new_page;

    // modify code
    char overwrite_bytes[replace_size];
    char expected_bytes[replace_size] = {0x45, 0x33, 0xC9, 0xC7, 0x44, 0x24, 0x20, 0x01, 0x00, 0x00,
                                         0x00, 0x45, 0x33, 0xC0, 0x48, 0x8D, 0x4C, 0x24, 0x30};
    memcpy(overwrite_bytes, overwrite_addr, replace_size);
    if (memcmp(overwrite_bytes, expected_bytes, replace_size) == 0) {
        // rdx is free to use

        // we appear to have found the correct bytes
        char* writeptr = reinterpret_cast<char*>(new_page);

        // inject a call to Sleep() so this thread is not constantly busy
        // this isn't a good fix but it'll do for now...
        char* sleep_addr = reinterpret_cast<char*>(sleepFuncAddr);
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
    } else {
        logger.Log("Unexpected bytes found, not applying patch.\n");
    }

    return rv;
}

static void* InjectSleepInAudioDeviceCountCheckThread(Logger& logger, void* new_page, int sleepTime,
                                                      void* codeBase, void* sleepFuncAddr) {
    char* overwrite_addr = reinterpret_cast<char*>(codeBase) + 0x587EB6;
    constexpr unsigned int replace_size = 0xc;
    PageUnprotect unprotect(logger, overwrite_addr, replace_size);

    void* rv = new_page;

    // modify code
    char overwrite_bytes[replace_size];
    char expected_bytes[replace_size] = {0x48, 0x8b, 0xcb, 0xe8, 0x02, 0xe2,
                                         0xe2, 0xff, 0x84, 0xc0, 0x74, 0xe0};
    memcpy(overwrite_bytes, overwrite_addr, replace_size);
    if (memcmp(overwrite_bytes, expected_bytes, replace_size) == 0) {
        // rax, rcx is free to use

        // we appear to have found the correct bytes
        char* writeptr = reinterpret_cast<char*>(new_page);

        // inject a call to Sleep() so this thread is not constantly busy
        // this isn't a good fix but it'll do for now...
        char* sleep_addr = reinterpret_cast<char*>(sleepFuncAddr);
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
        char* some_function = reinterpret_cast<char*>(codeBase) + 0x3B60C0;
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
        char* exit_loop_addr = reinterpret_cast<char*>(codeBase) + 0x587EC2;
        *writeptr++ = 0x48;
        *writeptr++ = 0xb9;
        memcpy(writeptr, &exit_loop_addr, 8);
        writeptr += 8;
        // jmp rcx
        *writeptr++ = 0xff;
        *writeptr++ = 0xe1;
        // continue_loop:
        // mov rcx,continue_loop_addr
        char* continue_loop_addr = reinterpret_cast<char*>(codeBase) + 0x587EA2;
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
    } else {
        logger.Log("Unexpected bytes found, not applying patch.\n");
    }

    return rv;
}

static void* InjectInvestigationCursorSpeedAdjust(Logger& logger, void* new_page, float factor,
                                                  void* codeBase) {
    char* overwrite_addr = reinterpret_cast<char*>(codeBase) + 0x1D012F;
    constexpr unsigned int replace_size = 0xc;
    PageUnprotect unprotect(logger, overwrite_addr, replace_size);

    void* rv = new_page;

    // modify code
    char overwrite_bytes[replace_size];
    char expected_bytes[replace_size] = {0x48, 0x8b, 0x8b, 0xe8, 0x02, 0x00,
                                         0x00, 0xf3, 0x45, 0x0f, 0x59, 0xc4};
    memcpy(overwrite_bytes, overwrite_addr, replace_size);
    if (memcmp(overwrite_bytes, expected_bytes, replace_size) == 0) {
        // rax, rcx, xmm6, xmm7 are free to use

        // we appear to have found the correct bytes
        char* writeptr = reinterpret_cast<char*>(new_page);
        char* factor_literal_ptr = writeptr;
        memcpy(writeptr, &factor, 4);
        writeptr += 4;
        writeptr = Align16CodePage(logger, writeptr);


        char* code_start = writeptr;

        // multiply xmm12 with given factor
        // movss xmm7,factor
        char* factor_load_relative_to = writeptr + 8;
        int factor_load_diff = factor_literal_ptr - factor_load_relative_to;
        *writeptr++ = 0xf3;
        *writeptr++ = 0x0f;
        *writeptr++ = 0x10;
        *writeptr++ = 0x3d;
        memcpy(writeptr, &factor_load_diff, 4);
        writeptr += 4;
        // mulss xmm12,xmm7
        *writeptr++ = 0xf3;
        *writeptr++ = 0x44;
        *writeptr++ = 0x0f;
        *writeptr++ = 0x59;
        *writeptr++ = 0xe7;

        // replace code we overwrote
        memcpy(writeptr, overwrite_bytes, replace_size);
        writeptr += replace_size;

        // jump back
        // mov rax,overwrite_end
        *writeptr++ = 0x48;
        *writeptr++ = 0xb8;
        char* overwrite_end = overwrite_addr + replace_size;
        memcpy(writeptr, &overwrite_end, 8);
        writeptr += 8;
        // jmp rax
        *writeptr++ = 0xff;
        *writeptr++ = 0xe0;

        rv = writeptr;

        // inject jump to our new code
        // mov rcx,code_start
        writeptr = overwrite_addr;
        *writeptr++ = 0x48;
        *writeptr++ = 0xb9;
        memcpy(writeptr, &code_start, 8);
        writeptr += 8;
        // jmp rcx
        *writeptr++ = 0xff;
        *writeptr++ = 0xe1;
    } else {
        logger.Log("Unexpected bytes found, not applying patch.\n");
    }

    return rv;
}

static void FixJuryPitCrash(Logger& logger, void* codeBase) {
    char* code_start_addr = reinterpret_cast<char*>(codeBase) + 0x5C1036;
    char* target_start_addr = reinterpret_cast<char*>(codeBase) + 0x5C1076;
    PageUnprotect unprotect(logger, code_start_addr, 0x4a);

    // setup code in the between-function padding, barely enough space there...
    char* writeptr = reinterpret_cast<char*>(target_start_addr);
    memcpy(writeptr, code_start_addr, 3);
    writeptr += 3;

    // inject a nullptr test and skip the function if null
    // test rcx,rcx
    *writeptr++ = 0x48;
    *writeptr++ = 0x85;
    *writeptr++ = 0xc9;
    // jz exit_function
    *writeptr++ = 0x74;
    *writeptr++ = 0xf2;
    // jmp continue_function
    *writeptr++ = 0xeb;
    *writeptr++ = 0xb9;

    // inject jmp into the function padding
    writeptr = code_start_addr;
    *writeptr++ = 0xeb;
    *writeptr++ = 0x3e;
    *writeptr++ = 0x90;
}

static PDirectInput8Create addr_PDirectInput8Create = 0;
static void* SetupHacks() {
    Logger logger("dgsfix.log");

    addr_PDirectInput8Create = LoadForwarderAddress(logger);

    void* codeBase = nullptr;
    void* rdataBase = nullptr;
    FindImageBase(logger, &codeBase, &rdataBase);

    if (!codeBase || !rdataBase) {
        logger.Log("Failed finding executable in memory -- wrong game or version?\n");
        return nullptr;
    }

    INIReader ini("dgs.ini");

    if (ini.ParseError() != 0) {
        logger.Log("INI parsing failed.\n");
        return nullptr;
    }

    if (ini.GetBoolean("Main", "InjectNullCheckForJuryPit", true)) {
        logger.Log("Applying InjectNullCheckForJuryPit...\n");
        FixJuryPitCrash(logger, codeBase);
    }

    if (ini.GetBoolean("Main", "ReportAsHighDpiAware", true)) {
        logger.Log("Applying ReportAsHighDpiAware...\n");
        SetProcessDPIAware();
    }

    // run at 60 fps or whatever
    float fps = ini.GetFloat("Main", "AnimationFps", 60.0f);
    if (fps != 30.0f) {
        logger.Log("Applying AnimationFps...\n");
        // 3d render update speed
        WriteFloat(logger, reinterpret_cast<char*>(codeBase) + 0x57227, fps);
    }

    if (ini.GetBoolean("Main", "DisplayAllRenderResolutions", true)) {
        logger.Log("Applying DisplayAllRenderResolutions...\n");
        WriteByte(logger, reinterpret_cast<char*>(codeBase) + 0x5D2A6, 0xeb); // jz -> jmp
    }

    // allocate extra page for code
    void* new_page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    if (!new_page) {
        logger.Log("VirtualAlloc failed, skipping remaining patches.\n");
        return nullptr;
    }

    void* sleepAddr = reinterpret_cast<char*>(rdataBase) + 0x390;
    void* free_space_ptr = new_page;
    if (ini.GetBoolean("Main", "InjectSleepInMainThread", true)) {
        int ms = ini.GetInteger("Main", "MainThreadSleepTime", 10);
        logger.Log("Applying InjectSleepInMainThread...\n");
        free_space_ptr = InjectSleepInMainThread(logger, free_space_ptr, ms, codeBase, sleepAddr);
        free_space_ptr = Align16CodePage(logger, free_space_ptr);
    }
    if (ini.GetBoolean("Main", "InjectSleepInAudioDeviceCountCheckThread", true)) {
        int ms = ini.GetInteger("Main", "AudioDeviceCountCheckThreadSleepTime", 1000);
        logger.Log("Applying InjectSleepInAudioDeviceCountCheckThread...\n");
        free_space_ptr = InjectSleepInAudioDeviceCountCheckThread(logger, free_space_ptr, ms,
                                                                  codeBase, sleepAddr);
        free_space_ptr = Align16CodePage(logger, free_space_ptr);
    }

    // adjust cursor so it moves at correct speed (or faster/slower depending on user config)
    float rawCursorMoveSpeed = ini.GetFloat("Main", "InvestigationCursorMoveSpeed", 1.0f);
    float adjustedCursorMoveSpeed = rawCursorMoveSpeed / (fps / 30.0f);
    if (adjustedCursorMoveSpeed != 1.0f) {
        logger.Log("Applying InvestigationCursorMoveSpeed...\n");
        free_space_ptr = InjectInvestigationCursorSpeedAdjust(logger, free_space_ptr,
                                                              adjustedCursorMoveSpeed, codeBase);
        free_space_ptr = Align16CodePage(logger, free_space_ptr);
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
HRESULT DirectInput8Create(HINSTANCE hinst, DWORD dwVersion, REFIID riidltf, LPVOID* ppvOut,
                           void* punkOuter) {
    PDirectInput8Create addr = addr_PDirectInput8Create;
    if (!addr) {
        return 0x8007000EL; // DIERR_OUTOFMEMORY
    }
    return addr(hinst, dwVersion, riidltf, ppvOut, punkOuter);
}
}
