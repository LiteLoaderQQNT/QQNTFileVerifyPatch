#include "scanner.h"

std::uint8_t* sig(const HMODULE module, const std::string& byte_array) {
    if (!module)
        return nullptr;

    static const auto pattern_to_byte = [&](std::string pattern) {
        std::vector<int> bytes{};
        const auto start = const_cast<char*>(pattern.c_str());
        const auto end = const_cast<char*>(pattern.c_str()) + pattern.length();

        for (auto current = start; current < end; ++current) {
            if (*current == '?') {
                ++current;

                if (*current == '?')
                    ++current;

                bytes.push_back(-1);
            }
            else {
                bytes.push_back(std::strtoul(current, &current, 16));
            }
        }
        return bytes;
    };

    const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
    const auto nt_headers =
        reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<std::uint8_t*>(module) + dos_header->e_lfanew);

    const auto size_of_image = nt_headers->OptionalHeader.SizeOfImage;
    const auto pattern_bytes = pattern_to_byte(byte_array);
    const auto scan_bytes = reinterpret_cast<std::uint8_t*>(module);

    const auto pattern_size = pattern_bytes.size();
    const auto pattern_data = pattern_bytes.data();

    for (auto i = 0ul; i < size_of_image - pattern_size; ++i) {
        bool found = true;

        for (auto j = 0ul; j < pattern_size; ++j) {
            if (scan_bytes[i + j] != pattern_data[j] && pattern_data[j] != -1) {
                found = false;
                break;
            }
        }
        if (found)
            return &scan_bytes[i];
    }

    return nullptr;
}