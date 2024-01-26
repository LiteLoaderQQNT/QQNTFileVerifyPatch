#include "windows.h"
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <filesystem>

//#ifdef _WIN64
inline std::vector<uint8_t> x64_sig = { 0x48,0x89,0xCE,0x48,0x8B,0x11,0x4C,0x8B,0x41,0x08,0x49,0x29,0xD0,0x48,0x8B,0x49,0x18,0xE8 }; //x64
inline std::vector<uint8_t> x64_fixthisshit = { 0x48,0x89,0xCE,0x48,0x8B,0x11,0x4C,0x8B,0x41,0x08,0x49,0x29,0xD0,0x48,0x8B,0x49,0x18,0xB8,0x01,0x00,0x00,0x00 };
//#else
inline std::vector<uint8_t> x86_sig = { 0x89,0xCE,0x8B,0x01,0x8B,0x49,0x04,0x29,0xC1,0x51,0x50,0xFF,0x76,0x0C,0xE8 }; //x86
inline std::vector<uint8_t> x86_fixthisshit = { 0x89,0xCE,0x8B,0x01,0x8B,0x49,0x04,0x29,0xC1,0x51,0x50,0xFF,0x76,0x0C,0xB8,0x01,0x00,0x00,0x00 };
//#endif // !_WIN64

struct ImageOptionalHeader {
    uint16_t Magic;
};

bool Is64BitPE(const std::vector<uint8_t>& buffer)
{
    if (buffer.size() >= sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS32)) {
        const IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data());
        const IMAGE_NT_HEADERS32* ntHeader32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(buffer.data() + dosHeader->e_lfanew);
        if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE && ntHeader32->Signature == IMAGE_NT_SIGNATURE) {
            const ImageOptionalHeader* optionalHeader = reinterpret_cast<const ImageOptionalHeader*>(&ntHeader32->OptionalHeader);
            return (optionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC); //64bit
        }
    }
    return false; // 32bit
}

std::vector<uint8_t> ReadFile(const std::string& file_path) {
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw std::runtime_error("[-] Failed to open file");
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(size);
    if (file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        return buffer;
    }
    else {
        throw std::runtime_error("[-] Failed to read file");
    }
}

void ScanSigAReplace(std::vector<uint8_t>& buffer, const std::vector<uint8_t>& pattern, const std::vector<uint8_t>& replacement) {
    auto it = std::search(buffer.begin(), buffer.end(), pattern.begin(), pattern.end());
    if (it == buffer.end()) {
        printf("[-] Sig not Found!\n");
        system("pause");
        exit(1);
    }
    while (it != buffer.end()) {
        std::copy(replacement.begin(), replacement.end(), it);
        printf("[+] Found at 0x%08X\n", static_cast<int>(std::distance(buffer.begin(), it)));
        it = std::search(it + replacement.size(), buffer.end(), pattern.begin(), pattern.end());
    }
}

std::string SelectPEFile() {
    TCHAR szBuffer[MAX_PATH] = { 0 };
    OPENFILENAME file = { 0 };
    file.hwndOwner = NULL;
    file.lStructSize = sizeof(file);
    file.lpstrFilter = L"所有文件(*.*)\0*.*\0exe文件(*.exe)\0*.exe\0";
    file.lpstrInitialDir = L"";
    file.lpstrFile = szBuffer;
    file.nMaxFile = sizeof(szBuffer) / sizeof(*szBuffer);
    file.nFilterIndex = 0;
    file.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_EXPLORER;
    if (GetOpenFileName(&file)) {
        int size = WideCharToMultiByte(CP_ACP, 0, file.lpstrFile, -1, NULL, 0, NULL, NULL); //fuck you cpp
        if (size == 0) {
            return NULL;
        }
        std::string result(size-1, 0);
        WideCharToMultiByte(CP_ACP, 0, file.lpstrFile, -1, &result[0], size, NULL, NULL);
        return result;
    }
    else {
        return NULL;
    }
}

int main() {
    SetConsoleTitleA("QQNT Patcher | By sysR@M");
    try {
        std::string Filepath=SelectPEFile();
        std::string savePath = Filepath;
        printf("[*] PEFile Path: %s\n",Filepath.c_str());
        std::filesystem::rename(Filepath,Filepath+".bak");
        Filepath += ".bak";
        printf("[*] Backup At: %s\n", Filepath.c_str());
        std::vector<uint8_t> pe_file = ReadFile(Filepath);

        if (Is64BitPE(pe_file)) {
            printf("[+] PE file is 64bit!\n");
            ScanSigAReplace(pe_file, x64_sig, x64_fixthisshit);
        }
        else{
            printf("[+] PE file is 32bit!\n");
            ScanSigAReplace(pe_file, x86_sig, x86_fixthisshit);
        }
        std::ofstream output_file(savePath, std::ios::binary);
        output_file.write(reinterpret_cast<const char*>(pe_file.data()), pe_file.size());
        std::cout << "[+] Patched!\n" << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "[-] An error occurred: " << e.what() << std::endl;
        system("pause");
        return 1;
    }
    system("pause");
    return 0;
}
