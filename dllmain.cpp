#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>

#include <array>
#include <cinttypes>
#include <cstdio>
#include <memory>
#include <thread>

#include "INIReader.h"
#include "crc32.h"

namespace {
enum class GameVersion {
    Unknown,
    English_v1,            // original release
    Japanese_v1,           // original release
    English_v1_encrypted,  // 2023-07-10 patch
    Japanese_v1_encrypted, // 2023-07-10 patch
};

struct Logger {
    FILE* f;

    Logger() {
        f = nullptr;
    }

    explicit Logger(const char* filename) {
        f = fopen(filename, "w");
    }

    Logger(const Logger& other) = delete;
    Logger(Logger&& other) {
        this->f = other.f;
        other.f = nullptr;
    }
    Logger& operator=(const Logger& other) = delete;
    Logger& operator=(Logger&& other) {
        this->f = other.f;
        other.f = nullptr;
        return *this;
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

    Logger& LogInt(int v) {
        if (f) {
            char buffer[32];
            int len = sprintf(buffer, "%d", v);
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
        Log.Log(" to attributes ").LogHex(Attributes);
        if (VirtualProtect(Address, Length, Attributes, &tmp)) {
            Log.Log(" -> Success.\n");
        } else {
            Log.Log(" -> Failed.\n");
        }
    }
};
} // namespace

template<size_t S>
static std::array<char, S> ReadInstruction(char*& ptr) {
    std::array<char, S> data;
    memcpy(data.data(), ptr, S);
    ptr += S;
    return data;
}

template<size_t S>
static void WriteInstruction(const std::array<char, S>& data, char*& ptr) {
    memcpy(ptr, data.data(), S);
    ptr += S;
}

static int SelectOffset(GameVersion version, int en, int jp) {
    switch (version) {
        case GameVersion::English_v1: return en;
        case GameVersion::Japanese_v1: return jp;
        default: return 0;
    }
}

#ifdef BUILD_AS_DINPUT8
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
#endif

static void WriteFloat(Logger& logger, void* addr, float value) {
    logger.Log("Writing float ").LogFloat(value).Log(" to ").LogPtr(addr).Log(".\n");
    PageUnprotect unprotect(logger, addr, 4);
    memcpy(addr, &value, 4);
}

static void WriteInt(Logger& logger, void* addr, int value) {
    logger.Log("Writing int ").LogInt(value).Log(" to ").LogPtr(addr).Log(".\n");
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

static GameVersion FindImageBase(Logger& logger, void** code, void** rdata,
                                 void** dataOverwrittenArray, void** steamdrmBase) {
    GameVersion gameVersionByCode = GameVersion::Unknown;
    GameVersion gameVersionByRData = GameVersion::Unknown;
#ifndef BUILD_AS_DINPUT8
    GameVersion gameVersionByOverwrittenArrayData = GameVersion::Unknown;
#endif
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
            if ((*code == 0) && (info.RegionSize == 0x953000 || info.RegionSize == 0x954000)
                && info.Protect == PAGE_EXECUTE_READ) {
                // could be code section, verify checksum of a known part
                constexpr int offset_english_v1 = 0x5C1030;
                constexpr int offset_japanese_v1 = 0x5C1A70;

                crc_t crc = crc_init();
                crc = crc_update(
                    crc,
                    ((const char*)info.BaseAddress)
                        + (info.RegionSize == 0x953000 ? offset_english_v1 : offset_japanese_v1),
                    0x50);
                crc = crc_finalize(crc);
                logger.Log("Checksum is ").LogHex(crc).Log(".\n");
                if (info.RegionSize == 0x953000 && crc == 0xb32acbf8) {
                    logger.Log("Appears to be the WW code. (original release, decrypted)\n");
                    *code = info.BaseAddress;
                    gameVersionByCode = GameVersion::English_v1;
                } else if (info.RegionSize == 0x954000 && crc == 0xb32acbf8) {
                    logger.Log("Appears to be the JP code. (original release, decrypted)\n");
                    *code = info.BaseAddress;
                    gameVersionByCode = GameVersion::Japanese_v1;
                } else if (info.RegionSize == 0x953000 && crc == 0xa9b1dc0f) {
                    logger.Log("Appears to be the WW code. (2023-07-10 patch, encrypted)\n");
                    *code = info.BaseAddress;
                    gameVersionByCode = GameVersion::English_v1_encrypted;
                } else if (info.RegionSize == 0x954000 && crc == 0x1a34f88) {
                    logger.Log("Appears to be the JP code. (2023-07-10 patch, encrypted)\n");
                    *code = info.BaseAddress;
                    gameVersionByCode = GameVersion::Japanese_v1_encrypted;
                } else {
                    logger.Log("Could not identify code section.\n");
                }
            }
            // if ((*steamdrmBase == 0) && (info.RegionSize == 0x33000)
            //     && info.Protect == PAGE_EXECUTE_READ) {
            //     // could be steam drm section, verify checksum of a known part
            //     constexpr int offset = 0x3900;
            //
            //     crc_t crc = crc_init();
            //     crc = crc_update(crc, ((const char*)info.BaseAddress) + offset, 0x80);
            //     crc = crc_finalize(crc);
            //     logger.Log("Checksum is ").LogHex(crc).Log(".\n");
            //     if (crc == 0x6c4e2e9) {
            //         logger.Log("Appears to be the steamdrm code.\n");
            //         *steamdrmBase = info.BaseAddress;
            //     } else {
            //         logger.Log("Could not identify steamdrm section.\n");
            //     }
            // }
            if ((*rdata == 0) && info.RegionSize == 0x160000 && info.Protect == PAGE_READONLY) {
                // likely rdata section
                constexpr std::array<const char, 0x1D> executable_name_ww = {
                    0x58, 0x50, 0x69, 0x70, 0x65, 0x4D, 0x61, 0x73, 0x74, 0x65,
                    0x72, 0x52, 0x65, 0x6C, 0x65, 0x61, 0x73, 0x65, 0x57, 0x57,
                    0x44, 0x58, 0x31, 0x31, 0x2E, 0x65, 0x78, 0x65, 0x00};
                constexpr std::array<const char, 0x1B> executable_name_jp = {
                    0x58, 0x50, 0x69, 0x70, 0x65, 0x4D, 0x61, 0x73, 0x74,
                    0x65, 0x72, 0x52, 0x65, 0x6C, 0x65, 0x61, 0x73, 0x65,
                    0x44, 0x58, 0x31, 0x31, 0x2E, 0x65, 0x78, 0x65, 0x00};
                const char* executable_name_ptr_ww = ((const char*)info.BaseAddress) + 0x15D7D2;
                const char* executable_name_ptr_jp = ((const char*)info.BaseAddress) + 0x15D7A2;
                if (std::memcmp(executable_name_ptr_ww, executable_name_ww.data(),
                                executable_name_ww.size())
                    == 0) {
                    logger.Log("Assuming ").LogPtr(info.BaseAddress).Log(" as WW rdata section.\n");
                    *rdata = info.BaseAddress;
                    gameVersionByRData = GameVersion::English_v1;
                } else if (std::memcmp(executable_name_ptr_jp, executable_name_jp.data(),
                                       executable_name_jp.size())
                           == 0) {
                    logger.Log("Assuming ").LogPtr(info.BaseAddress).Log(" as JP rdata section.\n");
                    *rdata = info.BaseAddress;
                    gameVersionByRData = GameVersion::Japanese_v1;
                }
            }
#ifndef BUILD_AS_DINPUT8
            if ((*dataOverwrittenArray == 0) && info.RegionSize >= 0x1000
                && (info.Protect == PAGE_READWRITE || info.Protect == PAGE_WRITECOPY)) {
                const char* array_ptr = ((const char*)info.BaseAddress) + 0xe90;
                constexpr std::array<const char, 8> value_ww = {0x18, 0x7f, 0x97, 0x40,
                                                                0x01, 0x00, 0x00, 0x00};
                constexpr std::array<const char, 8> value_jp = {0x18, 0x8f, 0x97, 0x40,
                                                                0x01, 0x00, 0x00, 0x00};
                const bool looks_like_ww = std::memcmp(array_ptr, value_ww.data(), 8) == 0;
                const bool looks_like_jp =
                    !looks_like_ww && std::memcmp(array_ptr, value_jp.data(), 8) == 0;

                if (looks_like_ww || looks_like_jp) {
                    const char* first_array_ptr =
                        ((const char*)info.BaseAddress) + (looks_like_jp ? 0xe90 : 0xe80);
                    bool matches = true;
                    for (size_t i = 0; i < 16; ++i) {
                        if (i >= 6 || i <= 10) {
                            continue;
                        }
                        if (std::memcmp(array_ptr, (looks_like_jp ? value_jp : value_ww).data(), 8)
                            != 0) {
                            matches = false;
                            break;
                        }
                    }
                    if (matches) {
                        if (looks_like_jp) {
                            logger.Log("Assuming ")
                                .LogPtr(info.BaseAddress)
                                .Log(" as JP array data section.\n");
                            *dataOverwrittenArray = info.BaseAddress;
                            gameVersionByOverwrittenArrayData = GameVersion::Japanese_v1;
                        } else {
                            logger.Log("Assuming ")
                                .LogPtr(info.BaseAddress)
                                .Log(" as WW array data section.\n");
                            *dataOverwrittenArray = info.BaseAddress;
                            gameVersionByOverwrittenArrayData = GameVersion::English_v1;
                        }
                    }
                }
            }
#endif

            // logger.Log("First 64 bytes are:");
            // for (int i = 0; i < (info.RegionSize < 64 ? info.RegionSize : 64); ++i) {
            //    logger.Log(" ").LogHex(*(reinterpret_cast<unsigned char*>(info.BaseAddress) + i));
            // }
            // logger.Log("\n");

            // logger.Log("Data is:");
            // for (int i = 0; i < info.RegionSize; ++i) {
            //    if ((i % 0x10) == 0) {
            //        logger.Log("\n").LogHex(i).Log(":");
            //    }
            //    logger.Log(" ").LogHex(*(reinterpret_cast<unsigned char*>(info.BaseAddress) + i));
            // }
            // logger.Log("\n");
        }
    }

#ifdef BUILD_AS_DINPUT8
    if (gameVersionByCode == GameVersion::English_v1
        && gameVersionByRData == GameVersion::English_v1) {
        return GameVersion::English_v1;
    }
    if (gameVersionByCode == GameVersion::Japanese_v1
        && gameVersionByRData == GameVersion::Japanese_v1) {
        return GameVersion::Japanese_v1;
    }
    if (gameVersionByCode == GameVersion::English_v1_encrypted
        && gameVersionByRData == GameVersion::English_v1) {
        return GameVersion::English_v1_encrypted;
    }
    if (gameVersionByCode == GameVersion::Japanese_v1_encrypted
        && gameVersionByRData == GameVersion::Japanese_v1) {
        return GameVersion::Japanese_v1_encrypted;
    }
#else
    if (gameVersionByCode == gameVersionByRData
        && gameVersionByCode == gameVersionByOverwrittenArrayData) {
        return gameVersionByCode;
    }
#endif

    return GameVersion::Unknown;
}

static void* InjectSleepInMainThread(GameVersion version, Logger& logger, void* new_page,
                                     int MainThreadSleepTime, void* codeBase, void* sleepFuncAddr) {
    constexpr int offset_english_v1 = 0x3BE070;
    constexpr int offset_japanese_v1 = 0x3BEB10;
    int offset = SelectOffset(version, offset_english_v1, offset_japanese_v1);
    char* overwrite_addr = reinterpret_cast<char*>(codeBase) + offset;
    constexpr unsigned int replace_size = 0x13;
    PageUnprotect unprotect(logger, overwrite_addr, replace_size);

    void* rv = new_page;

    char overwrite_bytes[replace_size];
    memcpy(overwrite_bytes, overwrite_addr, replace_size);

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

    return rv;
}

static void* InjectSleepInAudioDeviceCountCheckThread(GameVersion version, Logger& logger,
                                                      void* new_page, int sleepTime, void* codeBase,
                                                      void* sleepFuncAddr) {
    constexpr int offset_english_v1 = 0x587EB6;
    constexpr int offset_japanese_v1 = 0x5888F6;
    int offset = SelectOffset(version, offset_english_v1, offset_japanese_v1);
    char* overwrite_addr = reinterpret_cast<char*>(codeBase) + offset;
    constexpr unsigned int replace_size = 0xc;
    PageUnprotect unprotect(logger, overwrite_addr, replace_size);

    void* rv = new_page;

    int relative_replaced_function_offset;
    memcpy(&relative_replaced_function_offset, overwrite_addr + 4, 4);
    char* absolute_replaced_function_address =
        overwrite_addr + 8 + relative_replaced_function_offset;

    char overwrite_bytes[replace_size];
    memcpy(overwrite_bytes, overwrite_addr, replace_size);

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
    *writeptr++ = 0x48;
    *writeptr++ = 0xb8;
    memcpy(writeptr, &absolute_replaced_function_address, 8);
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
    char* exit_loop_addr = overwrite_addr + 0xC;
    *writeptr++ = 0x48;
    *writeptr++ = 0xb9;
    memcpy(writeptr, &exit_loop_addr, 8);
    writeptr += 8;
    // jmp rcx
    *writeptr++ = 0xff;
    *writeptr++ = 0xe1;
    // continue_loop:
    // mov rcx,continue_loop_addr
    char* continue_loop_addr = overwrite_addr - 0x14;
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

    return rv;
}

static void* InjectInvestigationCursorSpeedAdjust(GameVersion version, Logger& logger,
                                                  void* new_page, float factor, void* codeBase) {
    constexpr int offset_english_v1 = 0x1D012F;
    constexpr int offset_japanese_v1 = 0x1D0BDF;
    int offset = SelectOffset(version, offset_english_v1, offset_japanese_v1);
    char* overwrite_addr = reinterpret_cast<char*>(codeBase) + offset;
    constexpr unsigned int replace_size = 0xc;
    PageUnprotect unprotect(logger, overwrite_addr, replace_size);

    void* rv = new_page;

    // modify code
    char overwrite_bytes[replace_size];
    memcpy(overwrite_bytes, overwrite_addr, replace_size);

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

    return rv;
}

static void InjectInvestigationCameraSpeedAdjust(GameVersion version, Logger& logger, float factor,
                                                 void* codeBase) {
    constexpr int offset_english_v1 = 0x1E56E0;
    // educated guess based on cursor move speed address...
    constexpr int offset_japanese_v1 = offset_english_v1 + 0xAB0;
    int offset = SelectOffset(version, offset_english_v1, offset_japanese_v1);
    if (offset == 0) {
        logger.Log("No known address, skipping camera patch...\n");
    }

    char* function_addr = reinterpret_cast<char*>(codeBase) + offset;

    // all of these are addss xmm6,dword ptr[something], we'll just replace the relevant value with
    // a scaled one
    constexpr int count = 8;
    int addressOffsets[count] = {0x86, 0xA7, 0xE2, 0xEC, 0x147, 0x156, 0x17F, 0x189};

    // just some close function padding bytes...
    int valueOffsets[count] = {0x738, 0x73c, -0x4, -0x2F4, -0x2F8, -0xE04, -0xE08, -0xE0C};

    // verify stuff since we're guessing the JP, wouldn't want to write garbage...
    bool bad = false;
    for (int i = 0; i < count; ++i) {
        unsigned int tmp;
        char* addr = function_addr + valueOffsets[i];
        memcpy(&tmp, addr, 4);
        if (tmp != 0xccccccccu) {
            logger.Log("Bad padding bytes at offset ").LogPtr(addr).Log(".\n");
            bad = true;
        } else {
            logger.Log("Valid padding bytes at offset ").LogPtr(addr).Log(".\n");
        }

        char* addr_instr = function_addr + addressOffsets[i];
        memcpy(&tmp, addr_instr, 4);
        if (tmp != 0x35580ff3) {
            logger.Log("Bad instruction at offset ").LogPtr(addr_instr);
            logger.Log(" (").LogHex(tmp).Log(").\n");
            bad = true;
        } else {
            logger.Log("Valid instruction at offset ").LogPtr(addr_instr).Log(".\n");
        }
    }
    if (bad) {
        logger.Log("Found bad padding bytes, cancelling camera patch.\n");
        return;
    }

    // scale and replace values
    for (int i = 0; i < count; ++i) {
        int oldLiteralOffset;
        char* offsetAddress = function_addr + addressOffsets[i] + 4;
        memcpy(&oldLiteralOffset, offsetAddress, 4);
        char* oldLiteralAddress = (function_addr + addressOffsets[i] + 8) + oldLiteralOffset;
        float oldLiteral;
        memcpy(&oldLiteral, oldLiteralAddress, 4);
        float newLiteral = oldLiteral * factor;
        char* newLiteralAddress = function_addr + valueOffsets[i];
        WriteFloat(logger, newLiteralAddress, newLiteral);
        WriteInt(logger, offsetAddress, static_cast<int>(newLiteralAddress - (offsetAddress + 4)));
    }
}

static void MultiWitnessBarPositionAdjust(GameVersion version, Logger& logger, void* codeBase,
                                          float xpos, float ypos) {
    constexpr int offset_english_v1 = 0x140212c3a - 0x140001000;
    constexpr int offset_japanese_v1 = 0x1402136ea - 0x140001000;
    int offset = SelectOffset(version, offset_english_v1, offset_japanese_v1);

    char* function_addr = reinterpret_cast<char*>(codeBase) + offset;

    // all of these are movss xmm1,dword ptr[something], we'll just replace the values
    constexpr int count = 4;
    int addressOffsets[count] = {0x4, 0x11, 0x1b, 0x28};

    // padding bytes of previous function
    constexpr int valueCount = 2;
    int valueOffsets[valueCount] = {-0x6c2, -0x6be};
    float newValues[valueCount] = {xpos, ypos};

    // verify
    bool bad = false;
    for (int i = 0; i < count; ++i) {
        unsigned int tmp;
        char* addr = function_addr + valueOffsets[i % valueCount];
        memcpy(&tmp, addr, 4);
        if (tmp != 0xccccccccu) {
            logger.Log("Bad padding bytes at offset ").LogPtr(addr).Log(".\n");
            bad = true;
        } else {
            logger.Log("Valid padding bytes at offset ").LogPtr(addr).Log(".\n");
        }

        char* addr_instr = function_addr + addressOffsets[i];
        memcpy(&tmp, addr_instr, 4);
        if (tmp != 0x0d100ff3) {
            logger.Log("Bad instruction at offset ").LogPtr(addr_instr);
            logger.Log(" (").LogHex(tmp).Log(").\n");
            bad = true;
        } else {
            logger.Log("Valid instruction at offset ").LogPtr(addr_instr).Log(".\n");
        }
    }
    if (bad) {
        logger.Log("Found bad padding bytes, cancelling multi-witness-slider patch.\n");
        return;
    }

    // replace values
    for (int i = 0; i < count; ++i) {
        int oldLiteralOffset;
        char* offsetAddress = function_addr + addressOffsets[i] + 4;
        float newLiteral = newValues[i % valueCount];
        char* newLiteralAddress = function_addr + valueOffsets[i % valueCount];
        WriteFloat(logger, newLiteralAddress, newLiteral);
        WriteInt(logger, offsetAddress, static_cast<int>(newLiteralAddress - (offsetAddress + 4)));
    }
}

static void FixJuryPitCrash(GameVersion version, Logger& logger, void* codeBase) {
    constexpr int offset_english_v1 = 0x5C1036;
    constexpr int offset_japanese_v1 = 0x5C1A76;
    int offset = SelectOffset(version, offset_english_v1, offset_japanese_v1);
    char* code_start_addr = reinterpret_cast<char*>(codeBase) + offset;
    char* target_start_addr = code_start_addr + 0x40;
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

static void* MouseWheelBacklogScrollSpeedAdjust(GameVersion version, Logger& logger, void* new_page,
                                                float factor, void* codeBase) {
    constexpr int offset_english_v1 = 0x140199f60 - 0x140001000;
    constexpr int offset_japanese_v1 = offset_english_v1 + 0xAB0;
    int offset = SelectOffset(version, offset_english_v1, offset_japanese_v1);

    constexpr int replacementCount = 2;
    int replacementOffsets[replacementCount] = {0x38e, 0x3dd};

    char* writeptr = reinterpret_cast<char*>(new_page);
    char* factor_literal_ptr = writeptr;
    memcpy(writeptr, &factor, 4);
    writeptr += 4;

    for (int i = 0; i < replacementCount; ++i) {
        constexpr unsigned int replaceSize = 8 + 5;
        char oldData[replaceSize];
        char* code_start_addr = reinterpret_cast<char*>(codeBase) + offset + replacementOffsets[i];
        PageUnprotect unprotect(logger, code_start_addr, replaceSize);
        std::memcpy(oldData, code_start_addr, replaceSize);
        std::memset(code_start_addr, 0x90, replaceSize);

        writeptr = Align16CodePage(logger, writeptr);
        char* new_code_address = writeptr;
        std::memcpy(writeptr, oldData, replaceSize);
        writeptr += replaceSize;

        // multiply xmm12 with given factor
        // movss xmm1,factor
        char* factor_load_relative_to = writeptr + 8;
        int factor_load_diff = factor_literal_ptr - factor_load_relative_to;
        *writeptr++ = 0xf3;
        *writeptr++ = 0x0f;
        *writeptr++ = 0x10;
        *writeptr++ = 0x0d;
        memcpy(writeptr, &factor_load_diff, 4);
        writeptr += 4;
        // mulss xmm0,xmm1
        *writeptr++ = 0xf3;
        *writeptr++ = 0x0f;
        *writeptr++ = 0x59;
        *writeptr++ = 0xc1;

        // mov rax,backjump_address
        *writeptr++ = 0x48;
        *writeptr++ = 0xb8;
        char* backjump_address = code_start_addr + replaceSize;
        memcpy(writeptr, &backjump_address, 8);
        writeptr += 8;
        // jmp rax
        *writeptr++ = 0xff;
        *writeptr++ = 0xe0;

        // at injection location:
        // mov rax,new_code_address
        char* w = code_start_addr;
        *w++ = 0x48;
        *w++ = 0xb8;
        memcpy(w, &new_code_address, 8);
        w += 8;
        // jmp rax
        *w++ = 0xff;
        *w++ = 0xe0;
    }

    return writeptr;
}

static void* MouseEvidenceRotateSpeedAdjust(GameVersion version, Logger& logger, void* new_page,
                                            float factor, void* codeBase) {
    constexpr int offset_english_v1 = 0x1401a7f55 - 0x140001000;
    constexpr int offset_japanese_v1 = offset_english_v1 + 0xAB0;
    int offset = SelectOffset(version, offset_english_v1, offset_japanese_v1);

    char* writeptr = reinterpret_cast<char*>(new_page);
    char* factor_literal_ptr = writeptr;
    memcpy(writeptr, &factor, 4);
    writeptr += 4;

    char* code_start_addr = reinterpret_cast<char*>(codeBase) + offset;
    PageUnprotect unprotect(logger, code_start_addr, 0x2f);

    char* code = code_start_addr;
    auto instr_a0 = ReadInstruction<7>(code);
    auto instr_a1 = ReadInstruction<3>(code);
    auto instr_a2 = ReadInstruction<4>(code);
    auto instr_a3 = ReadInstruction<5>(code);
    char* call_address_a = code;
    code += 5;
    char* code_start_addr_2 = code;
    auto instr_b0 = ReadInstruction<7>(code);
    auto instr_b1 = ReadInstruction<3>(code); // this restores rcx to the correct value
    auto instr_b2 = ReadInstruction<5>(code);
    auto instr_b3 = ReadInstruction<3>(code);
    char* call_address_b = code;

    std::memset(code_start_addr, 0x90, 7 + 3 + 4 + 5);
    std::memset(code_start_addr_2, 0x90, 7 + 3 + 5 + 3);

    {
        writeptr = Align16CodePage(logger, writeptr);
        char* start = writeptr;
        WriteInstruction(instr_a0, writeptr);
        WriteInstruction(instr_a1, writeptr);
        WriteInstruction(instr_a2, writeptr);
        WriteInstruction(instr_a3, writeptr);

        // movss xmm0,factor
        char* factor_load_relative_to = writeptr + 8;
        int factor_load_diff = factor_literal_ptr - factor_load_relative_to;
        *writeptr++ = 0xf3;
        *writeptr++ = 0x0f;
        *writeptr++ = 0x10;
        *writeptr++ = 0x05;
        memcpy(writeptr, &factor_load_diff, 4);
        writeptr += 4;

        // mulss xmm1,xmm0
        *writeptr++ = 0xf3;
        *writeptr++ = 0x0f;
        *writeptr++ = 0x59;
        *writeptr++ = 0xc8;

        // mov rcx,backjump_addr
        char* backjump_addr = call_address_a - 3;
        *writeptr++ = 0x48;
        *writeptr++ = 0xb9;
        memcpy(writeptr, &backjump_addr, 8);
        writeptr += 8;
        // jmp rcx
        *writeptr++ = 0xff;
        *writeptr++ = 0xe1;
        char* end = writeptr;

        // restore rcx
        writeptr = backjump_addr;
        WriteInstruction(instr_b1, writeptr);

        // jump to code
        // mov rcx,start
        writeptr = code_start_addr;
        *writeptr++ = 0x48;
        *writeptr++ = 0xb9;
        memcpy(writeptr, &start, 8);
        writeptr += 8;
        // jmp rcx
        *writeptr++ = 0xff;
        *writeptr++ = 0xe1;

        writeptr = end;
    }

    {
        writeptr = Align16CodePage(logger, writeptr);
        char* start = writeptr;
        WriteInstruction(instr_b0, writeptr);
        WriteInstruction(instr_b2, writeptr);
        WriteInstruction(instr_b3, writeptr);

        // movss xmm0,factor
        char* factor_load_relative_to = writeptr + 8;
        int factor_load_diff = factor_literal_ptr - factor_load_relative_to;
        *writeptr++ = 0xf3;
        *writeptr++ = 0x0f;
        *writeptr++ = 0x10;
        *writeptr++ = 0x05;
        memcpy(writeptr, &factor_load_diff, 4);
        writeptr += 4;

        // mulss xmm1,xmm0
        *writeptr++ = 0xf3;
        *writeptr++ = 0x0f;
        *writeptr++ = 0x59;
        *writeptr++ = 0xc8;

        // mov rcx,backjump_addr
        char* backjump_addr = call_address_b - 3;
        *writeptr++ = 0x48;
        *writeptr++ = 0xb9;
        memcpy(writeptr, &backjump_addr, 8);
        writeptr += 8;
        // jmp rcx
        *writeptr++ = 0xff;
        *writeptr++ = 0xe1;
        char* end = writeptr;

        // restore rcx
        writeptr = backjump_addr;
        WriteInstruction(instr_b1, writeptr);

        // jump to code
        // mov rcx,start
        writeptr = code_start_addr_2;
        *writeptr++ = 0x48;
        *writeptr++ = 0xb9;
        memcpy(writeptr, &start, 8);
        writeptr += 8;
        // jmp rcx
        *writeptr++ = 0xff;
        *writeptr++ = 0xe1;

        writeptr = end;
    }

    return writeptr;
}

#ifdef BUILD_AS_DINPUT8
static PDirectInput8Create addr_PDirectInput8Create = 0;
#endif

struct HackInitData {
    Logger logger;
    void* codeBase = nullptr;
    void* rdataBase = nullptr;
    void* overwrittenArrayBase = nullptr;
    GameVersion version = GameVersion::Unknown;
    void* newPage1 = nullptr;
    void* newPage2 = nullptr;
};

static void* SetupHacks(HackInitData* hackInitData) {
    void* codeBase = hackInitData->codeBase;
    void* rdataBase = hackInitData->rdataBase;
    void* overwrittenArrayBase = hackInitData->overwrittenArrayBase;
    GameVersion version = hackInitData->version;
    Logger& logger = hackInitData->logger;

#ifndef BUILD_AS_DINPUT8
    if (overwrittenArrayBase) {
        logger.Log("Checking for clobbered array.\n");
        int clobbered_array_offset = SelectOffset(version, 0xe80, 0xe90);
        if (clobbered_array_offset) {
            char* first_array_ptr =
                ((char*)overwrittenArrayBase) + (uint32_t)(clobbered_array_offset);
            std::array<char, 8> array_value;
            std::array<char, 8> clobbered_value;
            std::memcpy(array_value.data(), first_array_ptr, 8);
            for (size_t i = 6; i < 8; ++i) {
                char* current_array_ptr = first_array_ptr + i * 8;
                std::memcpy(clobbered_value.data(), current_array_ptr, 8);
                if (std::memcmp(clobbered_value.data(), array_value.data(), 8) == 0) {
                    logger.Log("Clobbered array value at ").LogInt(i).Log(" already fixed.\n");
                } else {
                    logger.Log("Fixing clobbered array value at ").LogInt(i).Log(" from ");
                    {
                        uint64_t v = 0;
                        std::memcpy(&v, clobbered_value.data(), 8);
                        logger.LogHex(v);
                    }
                    logger.Log(" to ");
                    {
                        uint64_t v = 0;
                        std::memcpy(&v, array_value.data(), 8);
                        logger.LogHex(v);
                    }
                    logger.Log(".\n");
                    std::memcpy(current_array_ptr, array_value.data(), 8);
                }
            }
        } else {
            logger.Log("Version error.\n");
        }
    } else {
        logger.Log("Cannot check for clobbered array, continuing anyway.\n");
    }

#endif

    INIReader ini("dgs.ini");

    if (ini.ParseError() != 0) {
        logger.Log("INI parsing failed, patching with defaults.\n");
        ini.Clear();
    }

    if (ini.GetBoolean("Main", "InjectNullCheckForJuryPit", true)) {
        logger.Log("Applying InjectNullCheckForJuryPit...\n");
        FixJuryPitCrash(version, logger, codeBase);
    }

    if (ini.GetBoolean("Main", "ReportAsHighDpiAware", true)) {
        logger.Log("Applying ReportAsHighDpiAware...\n");
        SetProcessDPIAware();
    }

    // run at 60 fps or whatever
    float fps = ini.GetFloat("Main", "AnimationFps", 60.0f);
    if (fps != 30.0f) {
        constexpr int offset_english_v1 = 0x57227;
        constexpr int offset_japanese_v1 = 0x57227;
        int offset = SelectOffset(version, offset_english_v1, offset_japanese_v1);
        if (offset) {
            logger.Log("Applying AnimationFps...\n");
            // 3d render update speed
            WriteFloat(logger, reinterpret_cast<char*>(codeBase) + offset, fps);
        } else {
            logger.Log("No offset for AnimationFps.\n");
        }
    }

    if (ini.GetBoolean("Main", "DisplayAllRenderResolutions", true)) {
        constexpr int offset_english_v1 = 0x5D2A6;
        constexpr int offset_japanese_v1 = 0x5D2A6;
        int offset = SelectOffset(version, offset_english_v1, offset_japanese_v1);
        if (offset) {
            logger.Log("Applying DisplayAllRenderResolutions...\n");
            WriteByte(logger, reinterpret_cast<char*>(codeBase) + offset, 0xeb); // jz -> jmp
        } else {
            logger.Log("No offset for DisplayAllRenderResolutions.\n");
        }
    }

    void* new_page = hackInitData->newPage1;
    if (!new_page) {
        logger.Log("VirtualAlloc failed, skipping remaining patches.\n");
        return nullptr;
    }

    void* sleepAddr = reinterpret_cast<char*>(rdataBase) + 0x390;
    void* free_space_ptr = new_page;
    if (ini.GetBoolean("Main", "InjectSleepInMainThread", true)) {
        int ms = ini.GetInteger("Main", "MainThreadSleepTime", 10);
        logger.Log("Applying InjectSleepInMainThread...\n");
        free_space_ptr =
            InjectSleepInMainThread(version, logger, free_space_ptr, ms, codeBase, sleepAddr);
        free_space_ptr = Align16CodePage(logger, free_space_ptr);
    }
    if (ini.GetBoolean("Main", "InjectSleepInAudioDeviceCountCheckThread", true)) {
        int ms = ini.GetInteger("Main", "AudioDeviceCountCheckThreadSleepTime", 1000);
        logger.Log("Applying InjectSleepInAudioDeviceCountCheckThread...\n");
        free_space_ptr = InjectSleepInAudioDeviceCountCheckThread(version, logger, free_space_ptr,
                                                                  ms, codeBase, sleepAddr);
        free_space_ptr = Align16CodePage(logger, free_space_ptr);
    }

    // adjust cursor so it moves at correct speed (or faster/slower depending on user config)
    float rawCursorMoveSpeed = ini.GetFloat("Main", "InvestigationCursorMoveSpeed", 1.0f);
    float adjustedCursorMoveSpeed = rawCursorMoveSpeed / (fps / 30.0f);
    if (adjustedCursorMoveSpeed != 1.0f) {
        logger.Log("Applying InvestigationCursorMoveSpeed...\n");
        free_space_ptr = InjectInvestigationCursorSpeedAdjust(version, logger, free_space_ptr,
                                                              adjustedCursorMoveSpeed, codeBase);
        free_space_ptr = Align16CodePage(logger, free_space_ptr);
    }

    // adjust camera so it moves at correct speed (or faster/slower depending on user config)
    // this is specifically the back-and-forth scroll during some deductions
    float rawCameraMoveSpeed = ini.GetFloat("Main", "InvestigationCameraMoveSpeed", 1.0f);
    float adjustedCameraMoveSpeed = rawCameraMoveSpeed / (fps / 30.0f);
    if (adjustedCameraMoveSpeed != 1.0f) {
        logger.Log("Applying InvestigationCameraMoveSpeed...\n");
        InjectInvestigationCameraSpeedAdjust(version, logger, adjustedCameraMoveSpeed, codeBase);
    }

    float rawBacklogScrollSpeed = ini.GetFloat("Main", "BacklogMousewheelScrollSpeed", 1.0f);
    float adjustedBacklogScrollSpeed = rawBacklogScrollSpeed * (fps / 30.0f);
    if (adjustedBacklogScrollSpeed != 1.0f) {
        logger.Log("Applying MouseWheelBacklogScrollSpeedAdjust...\n");
        free_space_ptr = MouseWheelBacklogScrollSpeedAdjust(version, logger, free_space_ptr,
                                                            adjustedBacklogScrollSpeed, codeBase);
        free_space_ptr = Align16CodePage(logger, free_space_ptr);
    }

    float rawEvidenceRotateSpeed = ini.GetFloat("Main", "EvidenceMouseRotateSpeed", 1.0f);
    float adjustedEvidenceRotateSpeed = rawEvidenceRotateSpeed * (fps / 30.0f);
    if (adjustedEvidenceRotateSpeed != 1.0f) {
        logger.Log("Applying MouseEvidenceRotateSpeedAdjust...\n");
        free_space_ptr = MouseEvidenceRotateSpeedAdjust(version, logger, free_space_ptr,
                                                        adjustedEvidenceRotateSpeed, codeBase);
        free_space_ptr = Align16CodePage(logger, free_space_ptr);
    }

    if (ini.GetBoolean("Main", "AdjustMultiWitnessBarPosition", false)) {
        float x = ini.GetFloat("Main", "MultiWitnessBarPositionX", -435.0f);
        float y = ini.GetFloat("Main", "MultiWitnessBarPositionY", 951.0f);
        logger.Log("Applying MultiWitnessBarPositionAdjust...\n");
        MultiWitnessBarPositionAdjust(version, logger, codeBase, x, y);
    }

    // mark newly allocated page as executable
    {
        DWORD tmpdword;
        VirtualProtect(new_page, 0x1000, PAGE_EXECUTE_READ, &tmpdword);
        FlushInstructionCache(GetCurrentProcess(), new_page, 0x1000);
    }

    return new_page;
}

static HackInitData* InitHacks();
static HackInitData* dummy = InitHacks();

static void SetupHacksAfterDecrypt() {
    std::unique_ptr<HackInitData> hd(dummy);
    if (hd) {
        dummy = nullptr;
        void* codeBase = nullptr;
        void* rdataBase = nullptr;
        void* overwrittenArrayBase = nullptr;
        void* steamdrmBase = nullptr;
        GameVersion version =
            FindImageBase(hd->logger, &codeBase, &rdataBase, &overwrittenArrayBase, &steamdrmBase);

        hd->codeBase = codeBase;
        hd->rdataBase = rdataBase;
        hd->overwrittenArrayBase = overwrittenArrayBase;
        hd->version = version;
        SetupHacks(hd.get());
    }
}

static void InterceptDecryption(HackInitData* hd) {
    // extremely ugly... we're basically racing against the decryption thread and hope the timing
    // works out

    // spinloop here for a while and wait for the entry point to be decrypted
    volatile char* refpt =
        reinterpret_cast<char*>(hd->codeBase)
        + (hd->version == GameVersion::English_v1_encrypted ? 0x91283f : 0x91319f);
    while (*refpt != (char)0x84) {
        ;
    }

    // entry point decrypted, inject a call to our function
    char* jumptarget = reinterpret_cast<char*>(hd->newPage2);
    char* injectval = reinterpret_cast<char*>(hd->codeBase)
                      + (hd->version == GameVersion::English_v1_encrypted ? 0x912828 : 0x913188);
    char* writeptr = injectval;
    // mov rcx,jumptarget
    *writeptr++ = 0x48;
    *writeptr++ = 0xb9;
    memcpy(writeptr, &jumptarget, 8);
    writeptr += 8;
    // jmp rcx
    *writeptr++ = 0xff;
    *writeptr++ = 0xe1;

    *writeptr++ = 0xcc;
    *writeptr++ = 0xcc;
    *writeptr++ = 0xcc;

    FlushInstructionCache(GetCurrentProcess(), injectval, 0xf);
}

static HackInitData* InitHacks() {
    // Sleep(10000);
    // 0x1405aaffa
    // WriteByte(logger, reinterpret_cast<char*>(0x14040643e), 0xeb);

#ifdef BUILD_AS_DINPUT8
    Logger logger("dgsfix_dinput8.log");
#else
    Logger logger("dgsfix_standalone.log");
#endif

#ifdef BUILD_AS_DINPUT8
    addr_PDirectInput8Create = LoadForwarderAddress(logger);
#endif

    void* codeBase = nullptr;
    void* rdataBase = nullptr;
    void* overwrittenArrayBase = nullptr;
    void* steamdrmBase = nullptr;
    GameVersion version =
        FindImageBase(logger, &codeBase, &rdataBase, &overwrittenArrayBase, &steamdrmBase);

    if (version == GameVersion::Unknown || !codeBase || !rdataBase) {
        logger.Log("Failed finding executable in memory -- wrong game or version?\n");
        return nullptr;
    }

    // allocate extra pages for code
    void* new_page_1 = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT, PAGE_READWRITE);

    std::unique_ptr<HackInitData> hd = std::make_unique<HackInitData>();
    hd->codeBase = codeBase;
    hd->rdataBase = rdataBase;
    hd->overwrittenArrayBase = overwrittenArrayBase;
    hd->version = version;
    hd->logger = std::move(logger);
    hd->newPage1 = new_page_1;
    hd->newPage2 = nullptr;

    if (version == GameVersion::English_v1 || version == GameVersion::Japanese_v1) {
        hd->logger.Log("Patching v1.\n");
        SetupHacks(hd.get());
        return nullptr;
    }

    if (version == GameVersion::English_v1_encrypted
        || version == GameVersion::Japanese_v1_encrypted) {
        // if (steamdrmBase == nullptr) {
        //     hd->logger.Log("Didn't find DRM decryption code, cannot patch encrypted binary.\n");
        //     return nullptr;
        // }

        void* new_page_2 = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT, PAGE_READWRITE);
        hd->newPage2 = new_page_2;
        if (hd->newPage2 == nullptr) {
            hd->logger.Log("VirtualAlloc failed, cannot patch encrypted binary.\n");
            return nullptr;
        }
        hd->logger.Log("Delaying patch of encrypted code until after decryption.\n");

        // we need to hook ourselves after the game is decrypted, but before execution jumps to it
        char* writeptr = reinterpret_cast<char*>(hd->newPage2);

        // prepare injection code...

        // mov qword ptr[rsp+8],rbx
        *writeptr++ = 0x48;
        *writeptr++ = 0x89;
        *writeptr++ = 0x5c;
        *writeptr++ = 0x24;
        *writeptr++ = 0x08;
        // push rdi
        *writeptr++ = 0x57;
        // sub rsp,0x30
        *writeptr++ = 0x48;
        *writeptr++ = 0x83;
        *writeptr++ = 0xec;
        *writeptr++ = 0x30;

        // mov rcx,SetupHacksAfterDecrypt
        void* setuphacks = SetupHacksAfterDecrypt;
        *writeptr++ = 0x48;
        *writeptr++ = 0xb9;
        memcpy(writeptr, &setuphacks, 8);
        writeptr += 8;
        // call rcx
        *writeptr++ = 0xff;
        *writeptr++ = 0xd1;

        // mov ecx,1
        *writeptr++ = 0xb9;
        *writeptr++ = 0x01;
        *writeptr++ = 0x00;
        *writeptr++ = 0x00;
        *writeptr++ = 0x00;

        // jump back to original code
        // mov rax,codeback
        char* codeback = reinterpret_cast<char*>(hd->codeBase)
                         + (version == GameVersion::English_v1_encrypted ? 0x912837 : 0x913197);
        *writeptr++ = 0x48;
        *writeptr++ = 0xb8;
        memcpy(writeptr, &codeback, 8);
        writeptr += 8;
        // jmp rax
        *writeptr++ = 0xff;
        *writeptr++ = 0xe0;

        // mark as executable
        {
            DWORD tmpdword;
            VirtualProtect(hd->newPage2, 0x1000, PAGE_EXECUTE_READ, &tmpdword);
            FlushInstructionCache(GetCurrentProcess(), hd->newPage2, 0x1000);
        }

        std::thread decryptIntercept(InterceptDecryption, hd.get());
        decryptIntercept.detach();

        return hd.release();

        // stuff below doesn't work, steam drm apparently verifies its own code...

        // char* steamdrm = reinterpret_cast<char*>(steamdrmBase);

        // PageUnprotect unprotect(hd->logger, steamdrm + 0x396e, 0x2);
        // writeptr = steamdrm + 0x396e;
        // *writeptr++ = 0x31;

        /*
        PageUnprotect unprotect(hd->logger, steamdrm + 0x3949, 0x10);

        char* jumptarget = writeptr;

        // call the function that patches the game
        // mov rcx,SetupHacksAfterDecrypt
        void* setuphacks = SetupHacksAfterDecrypt;
        *writeptr++ = 0x48;
        *writeptr++ = 0xb9;
        memcpy(writeptr, &setuphacks, 8);
        writeptr += 8;
        // call rcx
        *writeptr++ = 0xff;
        *writeptr++ = 0xd1;

        // copy instructions we're gonna overwrite
        memcpy(writeptr, steamdrm + 0x3949, 0x10);
        writeptr += 0x10;

        // jump back to original code
        // mov rcx,codeback
        char* codeback = steamdrm + 0x3949 + 0x10;
        *writeptr++ = 0x48;
        *writeptr++ = 0xb9;
        memcpy(writeptr, &codeback, 8);
        writeptr += 8;
        // jmp rcx
        *writeptr++ = 0xff;
        *writeptr++ = 0xe1;

        hd->writeptr = Align16CodePage(hd->logger, writeptr);

        // jump to our construct here at original code location
        // mov rcx,jumptarget
        writeptr = steamdrm + 0x3949;
        *writeptr++ = 0x48;
        *writeptr++ = 0xb9;
        memcpy(writeptr, &jumptarget, 8);
        writeptr += 8;
        // jmp rcx
        *writeptr++ = 0xff;
        *writeptr++ = 0xe1;

        // fill up half leftover instruction with interrupt
        *writeptr++ = 0xcc;
        *writeptr++ = 0xcc;
        *writeptr++ = 0xcc;
        *writeptr++ = 0xcc;

        // mark newly allocated page as executable
        {
            DWORD tmpdword;
            VirtualProtect(new_page, 0x1000, PAGE_EXECUTE_READ, &tmpdword);
            FlushInstructionCache(GetCurrentProcess(), new_page, 0x1000);
        }
        */
    }

    hd->logger.Log("Invalid version enum?\n");
    return nullptr;
}

#ifdef BUILD_AS_DINPUT8
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
#else
extern "C" {
void DummyExport() {}
}
#endif
