#include <MinHook.h>
#include <psapi.h>
#include "nt.h"
#include "scanner.h"
#define Sig_text "57 41 56 41 55 41 54 56 57 55 53 48 81 ec ?? ?? ?? ?? 0f 29 bc 24 ?? ?? ?? ?? 0f 29 b4 24 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 48 31 e0 48 89 84 24 ?? ?? ?? ?? b9"

typedef __int64(*def_sub7FF67F97A5A0)();
def_sub7FF67F97A5A0 Org_sub_7FF67F97A5A0 = NULL;

__int64 Hk_sub_7FF67F97A5A0() {
    return (unsigned int)"r.json";
}


void Exploit() {
    if (MH_Initialize() != MH_OK) {
        MessageBoxA(nullptr, "MH Init Error!", "ERROR", MB_ICONERROR | MB_OK);
        exit(1);
    }
    static const auto FileVerify_MainPointer = static_cast<void*>(sig(GetModuleHandleA(NULL), Sig_text));
    if (FileVerify_MainPointer != nullptr) {
        if (MH_CreateHook(FileVerify_MainPointer, &Hk_sub_7FF67F97A5A0, reinterpret_cast<LPVOID*>(&Org_sub_7FF67F97A5A0)) != MH_OK) {
            MessageBoxA(nullptr, "MH Hook Patch failed!", "ERROR", MB_ICONERROR | MB_OK);
            exit(1);
        }
        if (MH_EnableHook(FileVerify_MainPointer) != MH_OK) {
            MessageBoxA(nullptr, "MH Enable Hook Patch failed!", "ERROR", MB_ICONERROR | MB_OK);
            exit(1);
        }
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