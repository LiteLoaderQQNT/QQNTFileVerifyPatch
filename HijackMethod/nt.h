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