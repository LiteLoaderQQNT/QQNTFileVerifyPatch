#pragma once
typedef HANDLE(WINAPI* def_CreateFileW)(
    _In_           LPCWSTR                lpFileName,
    _In_           DWORD                 dwDesiredAccess,
    _In_           DWORD                 dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_           DWORD                 dwCreationDisposition,
    _In_           DWORD                 dwFlagsAndAttributes,
    _In_opt_ HANDLE                hTemplateFile
    );

typedef BOOL(WINAPI* def_ReadFile)(
    _In_                HANDLE       hFile,
    _Out_               LPVOID       lpBuffer,
    _In_                DWORD        nNumberOfBytesToRead,
    _Out_opt_     LPDWORD      lpNumberOfBytesRead,
    _In_opt_ LPOVERLAPPED lpOverlapped
);

typedef DWORD(WINAPI* def_GetFileSize)(
    _In_            HANDLE  hFile,
    _Out_opt_ LPDWORD lpFileSizeHigh
);

typedef int(WINAPI* def_MessageBoxW)(
    _In_opt_ HWND    hWnd,
    _In_opt_ LPCWSTR lpText,
    _In_opt_ LPCWSTR lpCaption,
    _In_           UINT    uType
    );

typedef HMODULE(WINAPI* def_LoadLibraryExA)(
    _In_ LPCSTR lpLibFileName,
    _Reserved_ HANDLE hFile,
    _In_ DWORD dwFlags
    );

typedef HMODULE(WINAPI* def_LoadLibraryExW)(
    _In_ LPCWSTR lpLibFileName,
    _Reserved_ HANDLE hFile,
    _In_ DWORD dwFlags
    );


enum LDR_DLL_NOTIFICATION_REASON
{
    LDR_DLL_NOTIFICATION_REASON_LOADED = 1,
    LDR_DLL_NOTIFICATION_REASON_UNLOADED = 2,
};

typedef struct tag_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} __UNICODE_STRING, * PUNICODE_STRING, * PCUNICODE_STRING;

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
    ULONG Flags;                    //Reserved.
    PCUNICODE_STRING FullDllName;   //The full path name of the DLL module.
    PCUNICODE_STRING BaseDllName;   //The base file name of the DLL module.
    PVOID DllBase;                  //A pointer to the base address for the DLL in memory.
    ULONG SizeOfImage;              //The size of the DLL image, in bytes.
} LDR_DLL_LOADED_NOTIFICATION_DATA, * PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA {
    ULONG Flags;                    //Reserved.
    PCUNICODE_STRING FullDllName;   //The full path name of the DLL module.
    PCUNICODE_STRING BaseDllName;   //The base file name of the DLL module.
    PVOID DllBase;                  //A pointer to the base address for the DLL in memory.
    ULONG SizeOfImage;              //The size of the DLL image, in bytes.
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, * PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA {
    LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
    LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, * PLDR_DLL_NOTIFICATION_DATA;

typedef VOID(CALLBACK* PLDR_DLL_NOTIFICATION_FUNCTION)(
    _In_     ULONG                       NotificationReason,
    _In_     PLDR_DLL_NOTIFICATION_DATA NotificationData,
    _In_opt_ PVOID                       Context
    );

typedef NTSTATUS(NTAPI* def_LdrRegisterDllNotification)(
    _In_     ULONG                          Flags,
    _In_     PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
    _In_opt_ PVOID                          Context,
    _Out_    PVOID* Cookie
    );