#include "scanner.h"
#include <Psapi.h>
#define Sig_text "75 ?? e8 ?? ?? ?? ?? 84 c0 0f 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8"


void Exploit() {
    static auto JNEPointer = static_cast<void*>(sig(GetModuleHandleA(NULL), Sig_text));
    static auto JNEPointer2 = static_cast<char*>(JNEPointer);
    SIZE_T size = 1;
    DWORD oldProtection;
    if (!VirtualProtect(JNEPointer, size, PAGE_READWRITE, &oldProtection)) {
        MessageBoxA(nullptr, "Failed to change memory protection.", "ERROR", MB_ICONERROR | MB_OK);
        exit(1);
    }

    *JNEPointer2 = 0x74;

    DWORD oldProtection_;
    if (!VirtualProtect(JNEPointer, size, oldProtection, &oldProtection_)) {
        MessageBoxA(nullptr, "Failed to recovery memory protection.", "ERROR", MB_ICONERROR | MB_OK);
        exit(1);
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
    {
        HANDLE hProc = GetCurrentProcess();
        std::wstring processName(MAX_PATH, L'\0');
        GetModuleFileNameEx(hProc, nullptr, &processName[0], MAX_PATH);
        DisableThreadLibraryCalls(hinstDLL);
        if (processName.find(L"QQ.exe") != std::wstring::npos) {
            if (wcsstr(GetCommandLine(), L"--") != NULL) {
                return true;
            }
            Exploit();
            return true;
        }
        else
        {
            return true;
        }

        break;
    }
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}



//dbghelp.dll DLLHijack

extern "C" __declspec(dllexport) void StackWalk64() {}
extern "C" __declspec(dllexport) void SymCleanup() {}
extern "C" __declspec(dllexport) void SymFromAddr() {}
extern "C" __declspec(dllexport) void SymFunctionTableAccess64() {}
extern "C" __declspec(dllexport) void SymGetLineFromAddr64() {}
extern "C" __declspec(dllexport) void SymGetModuleBase64() {}
extern "C" __declspec(dllexport) void SymGetModuleInfo64() {}
extern "C" __declspec(dllexport) void SymGetSymFromAddr64() {}
extern "C" __declspec(dllexport) void SymGetSearchPathW() {}
extern "C" __declspec(dllexport) void SymInitialize() {}
extern "C" __declspec(dllexport) void SymSetOptions() {}
extern "C" __declspec(dllexport) void SymSetSearchPathW() {}
extern "C" __declspec(dllexport) void UnDecorateSymbolName() {}
extern "C" __declspec(dllexport) void MiniDumpWriteDump() {}