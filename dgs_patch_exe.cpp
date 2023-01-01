#define _CRT_SECURE_NO_WARNINGS

#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "crc32.h"

uint32_t read_u32(char* data) {
    return ((uint32_t)(unsigned char)data[0]) | (((uint32_t)(unsigned char)data[1]) << 8)
           | (((uint32_t)(unsigned char)data[2]) << 16)
           | (((uint32_t)(unsigned char)data[3]) << 24);
}
void write_u32(uint32_t val, char* data) {
    data[0] = (char)(unsigned char)(val & 0xff);
    data[1] = (char)(unsigned char)((val >> 8) & 0xff);
    data[2] = (char)(unsigned char)((val >> 16) & 0xff);
    data[3] = (char)(unsigned char)((val >> 24) & 0xff);
}

int patch(const char* filename, std::FILE*& f) {
    f = fopen(filename, "r+b");
    if (!f) {
        printf("failed to open %s\n", filename);
        return -1;
    }

    constexpr uint32_t filesize_ww = 12006608;
    constexpr uint32_t filesize_jp = 12010232;
    constexpr uint32_t crc32_ww = 0x14C34E5E;
    constexpr uint32_t crc32_jp = 0x818E535B;

    if (_fseeki64(f, 0, SEEK_END) != 0) {
        printf("failed to seek to end in file %s\n", filename);
        return -1;
    }
    const auto filesize = _ftelli64(f);
    if (_fseeki64(f, 0, SEEK_SET) != 0) {
        printf("failed to seek to start in file %s\n", filename);
        return -1;
    }

    if (!(filesize == filesize_ww || filesize == filesize_jp)) {
        printf("file %s is not a supported executable (mismatching filesize)\n", filename);
        return -1;
    }

    std::array<char, 4 * 1024> buffer;
    crc_t checksum = crc_init();
    std::size_t total_bytes_read = 0;
    while (true) {
        std::size_t bytes_read = fread(buffer.data(), 1, buffer.size(), f);
        if (bytes_read > 0) {
            total_bytes_read += bytes_read;
            checksum = crc_update(checksum, buffer.data(), bytes_read);
            if (bytes_read < buffer.size()) {
                break;
            }
        } else {
            break;
        }
    }

    if (total_bytes_read != filesize) {
        printf("failed to read bytes of file %s (read %zd bytes, expected %zd bytes)\n", filename,
               total_bytes_read, filesize);
        return -1;
    }

    checksum = crc_finalize(checksum);

    if (!(checksum == crc32_jp || checksum == crc32_ww)) {
        printf("file %s is not a supported executable (mismatching checksum)\n", filename);
        return -1;
    }

    if (checksum == crc32_jp || checksum == crc32_ww) {
        // apply patch
        bool is_jp = checksum == crc32_jp;
        const uint32_t offset_export_buffer = is_jp ? 0xab0f70 : 0xab05a0;
        const uint32_t offset_free_space_near_imports = is_jp ? 0xab2d60 : 0xab2390;
        const uint32_t offset_nvidia_optimus_in_export_buffer = 0x64 - (is_jp ? 0x17 : 0x15);
        const uint32_t length_nvidia_optimus = 0x14;
        const uint32_t offset_imports_header = 0x1f8;

        if (fseek(f, offset_imports_header, SEEK_SET) != 0) {
            printf("failed to seek\n");
            return -1;
        }
        std::array<char, 0x8> header_buffer;
        if (fread(header_buffer.data(), 1, header_buffer.size(), f) != header_buffer.size()) {
            printf("failed to read\n");
            return -1;
        }
        // increase length of import data structure by 1 entry and shift back 1 entry
        write_u32(read_u32(header_buffer.data()) - 0x14, header_buffer.data());
        write_u32(read_u32(header_buffer.data() + 4) + 0x14, header_buffer.data() + 4);

        std::array<char, 0x60> new_dll_buffer{};
        new_dll_buffer[0x00] = 0x01; // first symbol by ordinal
        new_dll_buffer[0x07] = 0x80;
        // no second symbol
        const char* dll_name = "dgs_hackfix.dll";
        assert(std::strlen(dll_name) == 0x10 - 1);
        for (size_t i = 0; i < 0x10 - 1; ++i) {
            new_dll_buffer[i + 0x10] = dll_name[i];
        }
        std::size_t new_dll_buffer_free_pos = 0x20;

        // add new entry into dll import table
        if (fseek(f, offset_export_buffer, SEEK_SET) != 0) {
            printf("failed to seek\n");
            return -1;
        }
        std::array<char, 0x64> export_buffer;
        if (fread(export_buffer.data(), 1, export_buffer.size(), f) != export_buffer.size()) {
            printf("failed to read\n");
            return -1;
        }
        const uint32_t ref_address = read_u32(export_buffer.data() + 0x2c);
        const uint32_t base_address =
            ref_address - (offset_export_buffer + offset_nvidia_optimus_in_export_buffer);

        // copy nvidia optimus string to new_dll_buffer
        std::memcpy(&new_dll_buffer[new_dll_buffer_free_pos],
                    &export_buffer[offset_nvidia_optimus_in_export_buffer], length_nvidia_optimus);
        write_u32(
            (uint32_t)(offset_free_space_near_imports + base_address + new_dll_buffer_free_pos),
            export_buffer.data() + 0x2c);
        new_dll_buffer_free_pos += length_nvidia_optimus;

        // reuse that space for new dll table entry
        for (size_t i = offset_nvidia_optimus_in_export_buffer; i < export_buffer.size(); ++i) {
            export_buffer[i] = (char)0;
        }
        write_u32(offset_free_space_near_imports + base_address,
                  export_buffer.data() + export_buffer.size() - 0x14); // import lookup table
        write_u32(offset_free_space_near_imports + base_address + 0x10,
                  export_buffer.data() + export_buffer.size() - 0x8); // dll name

        // this is extremely ugly and overwrites valid and probably used data, the dll will fix it
        // up later
        write_u32(is_jp ? 0xab5ec0 : 0xab4eb0,
                  export_buffer.data() + export_buffer.size() - 0x4); // import address table

        // write result
        if (fseek(f, offset_imports_header, SEEK_SET) != 0) {
            printf("failed to seek\n");
            return -1;
        }
        if (fwrite(header_buffer.data(), 1, header_buffer.size(), f) != header_buffer.size()) {
            printf("failed to write\n");
            return -1;
        }
        if (fseek(f, offset_export_buffer, SEEK_SET) != 0) {
            printf("failed to seek\n");
            return -1;
        }
        if (fwrite(export_buffer.data(), 1, export_buffer.size(), f) != export_buffer.size()) {
            printf("failed to write\n");
            return -1;
        }
        if (fseek(f, offset_free_space_near_imports, SEEK_SET) != 0) {
            printf("failed to seek\n");
            return -1;
        }
        if (fwrite(new_dll_buffer.data(), 1, new_dll_buffer.size(), f) != new_dll_buffer.size()) {
            printf("failed to write\n");
            return -1;
        }
        if (fseek(f, is_jp ? 0xab3cc0 : 0xab32b0, SEEK_SET) != 0) {
            printf("failed to seek\n");
            return -1;
        }
        if (fwrite(new_dll_buffer.data(), 1, 0x10, f) != 0x10) {
            printf("failed to write\n");
            return -1;
        }

        return 0;
    }

    return -1;
}

int main(int argc, char** argv) {
    std::FILE* f = nullptr;
    int rv = patch(argc > 1 ? argv[1] : "TGAAC.exe", f);
    if (f) {
        fclose(f);
    }
    return rv;
}
