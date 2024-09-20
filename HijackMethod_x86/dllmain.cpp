#include "Minhook.h"
#include "scanner.h"
#include "nt.h"
#include "json.hpp"
#include <tlhelp32.h>
#include <windows.h>
#include <AccCtrl.h>
#include <AclAPI.h>
#include <psapi.h>
#include <tchar.h>
#include <iostream>
#include <fstream>
#define Sig_text "75 ?? e8 ?? ?? ?? ?? 84 c0 0f 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8"
#define Sig_text2 "75 ?? e8 ?? ?? ?? ?? 84 c0 8d 7d" // Ver <=9.9.12_25765
#define Sig_text3 "85 ?? ?? ?? ?? 80 3d ?? ?? ?? ?? ?? 75 ?? a0 ?? ?? ?? ?? 84 c0 74 ?? b9 ?? ?? ?? ?? 34 ?? 88 41 ?? 8a 01 41 84 c0 75 ?? c6 05 ?? ?? ?? ?? ?? bf ?? ?? ?? ?? 57 e8 ?? ?? ?? ?? 83 c4 ?? 50 57 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 ?? 89 c1 6a ?? e8 ?? ?? ?? ?? 89 46 ?? 8b 08 8b 49 ?? 01 c1 8d be ?? ?? ?? ?? 57 e8 ?? ?? ?? ?? 89 f9 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 c7" //Ver 28060

inline bool mulock1 = false;
inline bool mulock2 = false;

inline bool OldQQ = false;

def_CreateFileW Org_CreateFileW = NULL;
def_LdrRegisterDllNotification Org_LdrRegisterDllNotification = NULL;

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
    if (wcsstr(lpFileName, L"\\resources\\app\\app_launcher\\index.js") != NULL && mulock1 != true && mulock2 != true&&OldQQ==true)
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
            if (value != "NULL" && value != "") {
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
                    fputs("require(String.raw`", indexfile);
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
    void* JNEPointer = nullptr;

    if (OldQQ) 
    {
        JNEPointer = static_cast<void*>(sig(GetModuleHandleA(NULL), Sig_text));
        if (JNEPointer == nullptr) {
            JNEPointer = static_cast<void*>(sig(GetModuleHandleA(NULL), Sig_text2));
            if (JNEPointer == nullptr) {
                MessageBoxA(nullptr, "Sig outdated", "ERROR", MB_ICONERROR | MB_OK);
                exit(1);
            }
        }
    }
    else
    {
        JNEPointer = static_cast<void*>(sig(GetModuleHandleA("QQNT.dll"), Sig_text3));
    }

    HMODULE SelfModule = GetModuleHandleA("dbghelp.dll");
    MODULEINFO SelfModuleInfo = { 0 };
    GetModuleInformation(GetCurrentProcess(), SelfModule, &SelfModuleInfo, sizeof(SelfModuleInfo));

    if ((JNEPointer >= SelfModule && JNEPointer < SelfModule + SelfModuleInfo.SizeOfImage)) {
        MessageBoxA(nullptr, "Sig not found!", "ERROR", MB_ICONERROR | MB_OK);
        exit(1);
    }

    if (JNEPointer == nullptr) {
        MessageBoxA(nullptr, "Sig outdated", "ERROR", MB_ICONERROR | MB_OK);
        exit(1);
    }
    
    static auto JNEPointer2 = static_cast<char*>(JNEPointer);
    SIZE_T size = 1;
    DWORD oldProtection;
    if (!VirtualProtect(JNEPointer, size, PAGE_READWRITE, &oldProtection)) {
        MessageBoxA(nullptr, "Failed to change memory protection.", "ERROR", MB_ICONERROR | MB_OK);
        exit(1);
    }
    if (OldQQ) {
        *JNEPointer2 = 0x74;
    }
    else
    {
        *JNEPointer2 = 0x84;
    }
    

    DWORD oldProtection_;
    if (!VirtualProtect(JNEPointer, size, oldProtection, &oldProtection_)) {
        MessageBoxA(nullptr, "Failed to recovery memory protection.", "ERROR", MB_ICONERROR | MB_OK);
        exit(1);
    }

    if (MH_Initialize() != MH_OK) {
        MessageBoxA(nullptr, "MH Init Error!", "ERROR", MB_ICONERROR | MB_OK);
        exit(1);
    }


    if (MH_CreateHook(&CreateFileW, &Hk_CreateFileW, reinterpret_cast<LPVOID*>(&Org_CreateFileW)) != MH_OK) {
        MessageBoxA(nullptr, "MH Hook CreateFileW failed!", "ERROR", MB_ICONERROR | MB_OK);
        exit(1);
    }

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
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

void CALLBACK DLLNotification(ULONG Reason, PLDR_DLL_NOTIFICATION_DATA NotificationData, PVOID Context) {
    if (Reason == LDR_DLL_NOTIFICATION_REASON_LOADED) {

        wprintf(L"[LdrDllNotification] %s\n", NotificationData->Loaded.FullDllName->Buffer);
        if (wcsstr(NotificationData->Loaded.FullDllName->Buffer, L"QQNT.dll") != NULL) {
            Exploit();
        }
    }
    return;
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
    {
        //MessageBoxA(nullptr,"Enter Entry","DEBUG",MB_OK);


        PVOID Cookie;
        Org_LdrRegisterDllNotification = (def_LdrRegisterDllNotification)GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrRegisterDllNotification");

        HANDLE hProc = GetCurrentProcess();
        std::wstring processName(MAX_PATH, L'\0');
        GetModuleFileNameEx(hProc, nullptr, &processName[0], MAX_PATH);
        DisableThreadLibraryCalls(hinstDLL);
        if (IsParentQQ() != true || wcsstr(GetCommandLine(), L"--from-multiple-login") != NULL) {
            
            if (_taccess(L"ffmpeg.dll", 0) == 0) 
            {
                OldQQ = true;
                Exploit();
            }
            else
            {
                Org_LdrRegisterDllNotification(0, DLLNotification, NULL, &Cookie); //New Exploit
            }
            
            
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