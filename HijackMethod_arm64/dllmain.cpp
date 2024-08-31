#include <windows.h>
#include <tlhelp32.h>
#include <fstream>
#include <detours.h>
#include <Psapi.h>
#include <tchar.h>
#include "scanner.h"
#include "json.hpp"
#include "nt.h"
#include <AclAPI.h>
#pragma comment (lib,"detours.lib") //building by ur self 

#define Sig_text "F3 53 BA A9 F5 5B 01 A9 F7 63 02 A9 F9 6B 03 A9 FB 73 04 A9 FD 7B 05 A9 FD 43 01 91 FF C3 0F D1 48 D3 04 ?? C0 24 80 52 08 05 40 F9 A8 03 1A F8"


def_CreateFileW Org_CreateFileW = CreateFileW;
def_MessageBoxW Org_MessageBoxW = MessageBoxW;
inline bool mulock1 = false;
inline bool mulock2 = false;

typedef __int64(*def_sub14032B99)();
def_sub14032B99 Org_sub_14032B99C = NULL;


__int64 Hk_sub_14032B99C() {
    return 1;
}

void GetCallStack(std::string& callStack) {
    CONTEXT context;
    RtlCaptureContext(&context);

    DWORD64 imageBase;
    DWORD64 controlPc = context.Pc;
    DWORD64 frameBase = context.Fp;

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    MODULEINFO kernel32Info = { 0 };
    MODULEINFO ntdllInfo = { 0 };
    GetModuleInformation(GetCurrentProcess(), hKernel32, &kernel32Info, sizeof(kernel32Info));
    GetModuleInformation(GetCurrentProcess(), hNtdll, &ntdllInfo, sizeof(ntdllInfo));


    std::ostringstream oss;

    oss << "已触发QQ文件校验退出函数, 一般情况下有可能是LLQQNT框架/插件导致的问题\n有任何问题请到Repo开issue, 带上你的截图\nCallStack:\n";

    /*Skip self*/
    UNWIND_HISTORY_TABLE historyTable;
    ZeroMemory(&historyTable, sizeof(UNWIND_HISTORY_TABLE));
    PRUNTIME_FUNCTION pFunction = RtlLookupFunctionEntry(controlPc, &imageBase, &historyTable);
    if (pFunction != NULL) {
        PVOID handlerData;
        ULONG64 establisherFrame;
        RtlVirtualUnwind(UNW_FLAG_NHANDLER, imageBase, controlPc, pFunction, &context, &handlerData, &establisherFrame, NULL);
        controlPc = context.Pc;
        frameBase = context.Fp;
    }
    /*---------*/

    for (int i = 0; i < 16; ++i) {
        if (controlPc == 0) {
            break;
        }

        if ((controlPc >= (DWORD64)hKernel32 && controlPc < (DWORD64)hKernel32 + kernel32Info.SizeOfImage))
        {
            oss << "in module kernel32.dll | Maybe BaseThreadInitThunk\n";
        }
        else if ((controlPc >= (DWORD64)hNtdll && controlPc < (DWORD64)hNtdll + ntdllInfo.SizeOfImage))
        {
            oss << "in module ntdll.dll | Maybe RtlUserThreadStart\n";
        }

        oss << "Address: 0x" << std::hex << controlPc << std::endl;

        BYTE buffer[32];
        SIZE_T bytesRead;
        if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)controlPc, buffer, sizeof(buffer), &bytesRead))
        {
            oss << "Data: ";
            for (SIZE_T j = 0; j < bytesRead; ++j) {
                oss << std::setw(2) << std::setfill('0') << std::hex << (int)buffer[j] << " ";
            }
            oss << std::endl;
        }
        else
        {
            oss << "Failed to read memory.\n";
        }

        oss << "\n";

        UNWIND_HISTORY_TABLE historyTable;
        ZeroMemory(&historyTable, sizeof(UNWIND_HISTORY_TABLE));

        // Unwind to next frame
        PRUNTIME_FUNCTION pFunction = RtlLookupFunctionEntry(controlPc, &imageBase, &historyTable);
        if (pFunction == NULL)
        {
            controlPc = (DWORD64)(*(PULONG64)controlPc);
        }
        else
        {
            PVOID handlerData;
            ULONG64 establisherFrame;
            RtlVirtualUnwind(UNW_FLAG_NHANDLER, imageBase, controlPc, pFunction, &context, &handlerData, &establisherFrame, NULL);
            controlPc = context.Pc;
            frameBase = context.Fp;
        }
    }

    callStack = oss.str();
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

    if (wcsstr(lpFileName, L"\\resources\\app\\app_launcher\\index.js") != NULL && mulock1 != true && mulock2 != true)
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

int WINAPI Hk_MessageBoxW(
    _In_opt_ HWND    hWnd,
    _In_opt_ LPCWSTR lpText,
    _In_opt_ LPCWSTR lpCaption,
    _In_           UINT    uType
) {
    LPCWSTR text = L"退出";
    if (wcscmp(lpCaption, text) == 0) {
        std::string data;
        //GetCallStack(data);
        MessageBoxA(hWnd, data.c_str(), "Congratulation", MB_OK);
    }
    return Org_MessageBoxW(hWnd, lpText, lpCaption, uType);
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

void InitHookFramework() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)Org_CreateFileW, Hk_CreateFileW);
    DetourAttach(&(PVOID&)Org_MessageBoxW, Hk_MessageBoxW);
    DetourAttach(&(PVOID&)Org_sub_14032B99C, Hk_sub_14032B99C);
    if (DetourTransactionCommit()!=NO_ERROR) {
        MessageBoxA(nullptr, "failed to create hook", "ERROR", MB_OK | MB_ICONERROR);
        exit(1);
    }
}

void Exploit() {
    Org_sub_14032B99C = (def_sub14032B99)static_cast<void*>(sig(GetModuleHandleA(NULL), Sig_text));
    if (Org_sub_14032B99C == nullptr) {
        MessageBoxA(nullptr, "Sig not found!", "ERROR", MB_OK|MB_ICONERROR);
        exit(1);
    }
    InitHookFramework();
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        HANDLE hProc = GetCurrentProcess();
        std::wstring processName(MAX_PATH, L'\0');
        GetModuleFileNameEx(hProc, nullptr, &processName[0], MAX_PATH);
        DisableThreadLibraryCalls(hModule);
        if (IsParentQQ() != true || wcsstr(GetCommandLine(), L"--from-multiple-login") != NULL) {
            Exploit();
            return true;
        }
        else
        {
            return true;
        }
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
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
