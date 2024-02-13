#include <MinHook.h>
#include "nt.h"
#include "scanner.h"

inline FILE* m_file{ };
def_CreateFileW Org_CreateFileW = NULL;

/*
_BOOL8 __fastcall sub_7FF79DDD5B80(__int64 *a1, __int64 a2, __int64 a3)
{
  __int64 v4; // rcx
  __int64 v7; // rax
  __int64 v8; // r14
  __int64 v9; // rax
  __int64 v10; // r15
  __int64 v11; // r12
  __int64 v12; // r12
  BOOL v13; // esi
  __int64 v14; // rdi
  __int64 v16; // rax
  __int128 v17; // [rsp+30h] [rbp-98h] BYREF
  __int128 v18; // [rsp+40h] [rbp-88h]
  __int128 v19[4]; // [rsp+50h] [rbp-78h] BYREF

  Sig: 57 41 56 41 54 56 57 53 48 81 ec ? ? ? ? 48 89 cb 48 8b 05 ? ? ? ? 48 31 e0 48 89 84 24 ? ? ? ? 48 8b 49
*/

typedef BOOL(__fastcall* def_sub_7FF79DDD5B80)(__int64* a1, __int64 a2, __int64 a3);
def_sub_7FF79DDD5B80 Org_sub_7FF79DDD5B80 = NULL;

BOOL __fastcall Hk_sub_7FF79DDD5B80(__int64* a1, __int64 a2, __int64 a3) {
    return true; //return
}

HANDLE WINAPI Hk_CreateFileW(
    _In_           LPCWSTR                lpFileName,
    _In_           DWORD                 dwDesiredAccess,
    _In_           DWORD                 dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_           DWORD                 dwCreationDisposition,
    _In_           DWORD                 dwFlagsAndAttributes,
    _In_opt_ HANDLE                hTemplateFile
) {
    if (wcsstr(lpFileName,L"launcher.json")!=NULL) {
        static const auto FileVerify = static_cast<void*>(sig(GetModuleHandleA(NULL), "57 41 56 41 54 56 57 53 48 81 ec ?? ?? ?? ?? 48 89 cb 48 8b 05 ?? ?? ?? ?? 48 31 e0 48 89 84 24 ?? ?? ?? ?? 48 8b 49"));
        if (FileVerify != nullptr) {
            if (Org_sub_7FF79DDD5B80 == NULL) {
                if (MH_CreateHook(FileVerify, &Hk_sub_7FF79DDD5B80, reinterpret_cast<LPVOID*>(&Org_sub_7FF79DDD5B80)) != MH_OK) {
                    MessageBoxA(nullptr, "MH Hook Hk_sub_7FF79DDD5B80 Error!", "ERROR", MB_OK);
                    exit(1);
                }
                if (MH_EnableHook(FileVerify) != MH_OK) {
                    MessageBoxA(nullptr, "MH Enable Hk_sub_7FF79DDD5B80 Error!", "ERROR", MB_OK);
                    exit(1);
                }
            }
        }
    }
    return Org_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

void Exploit() {
    if (MH_Initialize() != MH_OK) {
        MessageBoxA(nullptr, "MH Init Error!", "ERROR", MB_OK);
        exit(1);
    }
    if (MH_CreateHook(&CreateFileW, &Hk_CreateFileW, reinterpret_cast<LPVOID*>(&Org_CreateFileW)) != MH_OK) {
        MessageBoxA(nullptr, "MH Hook CreateFileW failed!", "ERROR", MB_OK);
        exit(1);
    }
    if (MH_EnableHook(&CreateFileW) != MH_OK) {
        MessageBoxA(nullptr, "MH Enable Hook CreateFileW failed!", "ERROR", MB_OK);
        exit(1);
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        Exploit();
        break;
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