#include <MinHook.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <tchar.h>
#include <windows.h>
#include <aclapi.h>
#include <algorithm>
#include <iostream>
#include <fstream>
#include "nt.h"
#include "scanner.h"
#include "json.hpp"
#define Sig_text "57 41 56 41 55 41 54 56 57 55 53 48 81 ec ?? ?? ?? ?? 0f 29 bc 24 ?? ?? ?? ?? 0f 29 b4 24 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 48 31 e0 48 89 84 24 ?? ?? ?? ?? b9"

inline bool mulock1 = false;
inline bool mulock2 = false;

def_CreateFileW Org_CreateFileW = NULL;
def_ReadFile Org_ReadFile = NULL;
def_GetFileSize Org_GetFileSize = NULL;

typedef __int64(*def_sub7FF67F97A5A0)();
def_sub7FF67F97A5A0 Org_sub_7FF67F97A5A0 = NULL;

__int64 Hk_sub_7FF67F97A5A0() {
    return (unsigned int)"r.json";
}

bool IsRunAsAdmin()
{
    BOOL fIsRunAsAdmin = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    PSID pAdministratorsGroup = NULL;

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdministratorsGroup))
    {
        dwError = GetLastError();
    }
    else
    {
        if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin))
        {
            dwError = GetLastError();
        }

        FreeSid(pAdministratorsGroup);
    }

    return fIsRunAsAdmin != FALSE;
}

bool RestartAsAdmin()
{
    wchar_t szPath[MAX_PATH];
    if (GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath)))
    {
        SHELLEXECUTEINFO sei = { sizeof(sei) };
        sei.lpVerb = L"runas";
        sei.lpFile = szPath;
        sei.nShow = SW_NORMAL;
        if (!ShellExecuteEx(&sei))
        {
            DWORD dwError = GetLastError();
            if (dwError == ERROR_CANCELLED)
            {
                MessageBoxA(nullptr, "Elevation was canceled by the user.", "ERROR", MB_ICONERROR | MB_OK);
            }
            else
            {
                MessageBoxA(nullptr, "Failed to restart as administrator privileges.", "ERROR", MB_ICONERROR | MB_OK);
            }
            return false;
        }
        return true;
    }
    return false;
}

bool SetFileALLAccessPrems(const wchar_t* filePath)
{
    BOOL bSuccess = TRUE;
    EXPLICIT_ACCESS ea;
    PACL pNewDacl = NULL;
    PACL pOldDacl = NULL;
    const wchar_t UserAccount[MAX_PATH] = L"Users";
    do
    {
        if (ERROR_SUCCESS != GetNamedSecurityInfo((LPTSTR)filePath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pOldDacl, NULL, NULL))
        {
            bSuccess = FALSE;
            break;

        }
        ::BuildExplicitAccessWithName(&ea, (LPTSTR)UserAccount, GENERIC_ALL, GRANT_ACCESS, SUB_CONTAINERS_AND_OBJECTS_INHERIT);
        if (ERROR_SUCCESS != ::SetEntriesInAcl(1, &ea, pOldDacl, &pNewDacl))
        {
            bSuccess = FALSE;
            break;
        }

        if (ERROR_SUCCESS != ::SetNamedSecurityInfo((LPTSTR)filePath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDacl, NULL))
        {
            bSuccess = FALSE;
        }
    } while (FALSE);
    if (NULL != pNewDacl)
    {
        ::LocalFree(pNewDacl);
    }
    return bSuccess;
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

    if (wcsstr(lpFileName, L"\\resources\\app\\app_launcher\\index.js") != NULL&& mulock1 !=true&&mulock2!=true)
    {

        if (_taccess(L"PatchConfig.json", 0) != 0) {
            if (!IsRunAsAdmin()) {
                RestartAsAdmin();
                exit(0);
            }

            nlohmann::json data;
            data["LLPath"] = "NULL";
            std::ofstream file("PatchConfig.json");
            file << std::setw(4) << data << std::endl;
            file.close();
            SetFileALLAccessPrems(L"PatchConfig.json");

        }
        else
        {
            std::ifstream file("PatchConfig.json");
            nlohmann::json j;
            file >> j;
            file.close();
            std::string value = "";
            if (j.find("LLPath") != j.end()) {
                value = j["LLPath"];
            }
            else 
            {
                MessageBoxA(nullptr, "Cant find jsonkey \"LLPath\"", "ERROR", MB_ICONERROR | MB_OK);
                exit(1);
            }
            if (value != "NULL"&&value!="") {
                mulock1 = true;
                FILE* indexfile = _wfopen(lpFileName, L"r");
                if (indexfile == NULL) {
                    MessageBoxA(nullptr, "failed to open index.js", "ERROR", MB_ICONERROR | MB_OK);
                    exit(1);
                }
                char OrgConte[1024] = "";
                if (fgets(OrgConte, sizeof(OrgConte), indexfile) == NULL) {
                    OrgConte[0] = '\0';
                }
                size_t OrgSize = strlen(OrgConte);
                fclose(indexfile);
                if (strstr(OrgConte, "require(String.raw`") == NULL) {
                    indexfile = _wfopen(lpFileName, L"w+");
                    if (indexfile == NULL) {
                        if (!IsRunAsAdmin()) {
                            RestartAsAdmin();
                            exit(0);
                        }
                        MessageBoxA(nullptr, "failed to open index.js", "ERROR", MB_ICONERROR | MB_OK);
                        exit(1);
                    }
                    fputs("require(String.raw`",indexfile);
                    fputs(value.c_str(), indexfile);
                    fputs("`);\n", indexfile);
                    mulock2 = true;
                    if (OrgSize > 0) {
                        fputs(OrgConte, indexfile);
                    }
                    fclose(indexfile);
                    if (IsRunAsAdmin()) {
                        SetFileALLAccessPrems(lpFileName);
                    }
                }
            }
        }
    }

    return Org_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
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
    }

    if (MH_CreateHook(&CreateFileW, &Hk_CreateFileW, reinterpret_cast<LPVOID*>(&Org_CreateFileW)) != MH_OK) {
        MessageBoxA(nullptr, "MH Hook CreateFileW failed!", "ERROR", MB_ICONERROR | MB_OK);
        exit(1);
    }

    if (MH_EnableHook(MH_ALL_HOOKS)!=MH_OK) {
        MessageBoxA(nullptr, "MH enable all hooks failed!", "ERROR", MB_ICONERROR | MB_OK);
        exit(1);
    }
}

DWORD GetParentProcessID() {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    DWORD ppid = 0, pid = GetCurrentProcessId();

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == pid) {
                ppid = pe32.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return ppid;
}

bool IsParentQQ() {
    DWORD parentPID = GetParentProcessID();
    TCHAR szProcessName[MAX_PATH] = TEXT("U N K N O W N");
    bool IsQQ = false;

    HANDLE hParentProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, parentPID);
    if (hParentProcess) {
        HMODULE hMod;
        DWORD cbNeeded;
        if (EnumProcessModules(hParentProcess, &hMod, sizeof(hMod), &cbNeeded)) {
            GetModuleBaseName(hParentProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
            IsQQ = (_tcsicmp(szProcessName, TEXT("QQ.exe")) == 0);
        }
        CloseHandle(hParentProcess);
    }

    return IsQQ;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
    {
        //MessageBoxA(nullptr,"Enter Entry","DEBUG",MB_OK);
        HANDLE hProc = GetCurrentProcess();
        std::wstring processName(MAX_PATH, L'\0');
        GetModuleFileNameEx(hProc, nullptr, &processName[0], MAX_PATH);
        DisableThreadLibraryCalls(hinstDLL);
        if (IsParentQQ() != true || wcsstr(GetCommandLine(), L"--from-multiple-login") != NULL) {
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
extern "C" __declspec(dllexport) void SymGetOptions() {}
extern "C" __declspec(dllexport) void SymSetSearchPathW() {}
extern "C" __declspec(dllexport) void UnDecorateSymbolName() {}
extern "C" __declspec(dllexport) void MiniDumpWriteDump() {}