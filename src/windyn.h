/*
windows api function pointer define,
functions or macros for dynamic bindings
    v0.1.3, developed by devseed
*/

#ifndef _WINDYN_H
#define _WINDYN_H
#define WINDYN_VERSION 130

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>

#ifndef WINDYNDEF
#ifdef WINDYN_STATIC
#define WINDYNDEF static
#else
#define WINDYNDEF extern
#endif
#endif

#ifndef WINDYN_SHARED
#define WINDYN_EXPORT
#else
#ifdef _WIN32
#define WINDYN_EXPORT __declspec(dllexport)
#else
#define WINDYN_EXPORT __attribute__((visibility("default")))
#endif
#endif

#ifndef INLINE
#if defined(_MSC_VER)
#define INLINE __forceinline
#else  // tcc, gcc not support inline export ...
#define INLINE
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

// function pointer declear
typedef HMODULE (WINAPI* PFN_LoadLibraryA)(
    LPCSTR lpLibFileName
);

typedef FARPROC (WINAPI* PFN_GetProcAddress)(
    HMODULE hModule, 
    LPCSTR lpProcName
);

typedef HMODULE (WINAPI *PFN_GetModuleHandleA)(
    LPCSTR lpModuleName
);

typedef LPVOID (WINAPI *PFN_VirtualAllocEx)(
    HANDLE hProcess, 
    LPVOID lpAddress, 
    SIZE_T dwSize, 
    DWORD flAllocationType, 
    DWORD flProtect
);

typedef BOOL (WINAPI *PFN_VirtualFreeEx)(
    HANDLE hProcess, 
    LPVOID lpAddress, 
    SIZE_T dwSize, 
    DWORD dwFreeType
);

typedef BOOL (WINAPI *PFN_VirtualProtectEx)(
    HANDLE hProcess, 
    LPVOID lpAddress, 
    SIZE_T dwSize, 
    DWORD flNewProtect, 
    PDWORD lpflOldProtect
);

typedef BOOL (WINAPI *PFN_CreateProcessA)(
    LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);

typedef HANDLE (WINAPI *PFN_OpenProcess)(
    DWORD dwDesiredAccess, 
    BOOL bInheritHandle, 
    DWORD dwProcessId
);

typedef HANDLE (WINAPI *PFN_GetCurrentProcess)(
    VOID
);

typedef BOOL (WINAPI *PFN_ReadProcessMemory)(
    HANDLE hProcess, 
    LPCVOID lpBaseAddress, 
    LPVOID lpBuffer, 
    SIZE_T nSize, 
    SIZE_T* lpNumberOfBytesRead
);

typedef BOOL (WINAPI *PFN_WriteProcessMemory)(
    HANDLE hProcess, 
    LPVOID lpBaseAddress, 
    LPCVOID lpBuffer, 
    SIZE_T nSize, 
    SIZE_T* lpNumberOfBytesWritten
);

typedef HANDLE (WINAPI *PFN_CreateRemoteThread)(
    HANDLE hProcess, 
    LPSECURITY_ATTRIBUTES lpThreadAttributes, 
    SIZE_T dwStackSize, 
    LPTHREAD_START_ROUTINE lpStartAddress, 
    LPVOID lpParameter, 
    DWORD dwCreationFlags, 
    LPDWORD lpThreadId
);

typedef HANDLE (WINAPI *PFN_GetCurrentThread)(
    VOID
);

typedef DWORD (WINAPI *PFN_SuspendThread)(
    HANDLE hThread
);

typedef DWORD (WINAPI *PFN_ResumeThread)(
    HANDLE hThread
);

typedef BOOL (WINAPI *PFN_GetThreadContext)(
    HANDLE hThread, 
    LPCONTEXT lpContext
);

typedef BOOL (WINAPI *PFN_SetThreadContext)(
    HANDLE hThread, 
    CONST CONTEXT* lpContext
);

typedef DWORD (WINAPI *PFN_WaitForSingleObject)(
    HANDLE hHandle, 
    DWORD dwMilliseconds
);

typedef BOOL (WINAPI *PFN_CloseHandle)(
    HANDLE hObject
);

typedef HANDLE (WINAPI *PFN_CreateToolhelp32Snapshot)(
    DWORD dwFlags, 
    DWORD th32ProcessID
);

typedef BOOL (WINAPI *PFN_Process32First)(
    HANDLE hSnapshot,
    LPPROCESSENTRY32 lppe
);

typedef BOOL (WINAPI *PFN_Process32Next)(
    HANDLE hSnapshot,
    LPPROCESSENTRY32 lppe
);

typedef NTSTATUS (NTAPI * PFN_NtQueryInformationProcess)(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength
);

// util inline functions and macro declear
#define WINDYN_FINDEXP(mempe, funcname, exp)\
{\
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)mempe;\
    PIMAGE_NT_HEADERS  pNtHeader = (PIMAGE_NT_HEADERS)\
    ((uint8_t*)mempe + pDosHeader->e_lfanew);\
    PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;\
    PIMAGE_OPTIONAL_HEADER pOptHeader = &pNtHeader->OptionalHeader;\
    PIMAGE_DATA_DIRECTORY pDataDirectory = pOptHeader->DataDirectory;\
    PIMAGE_DATA_DIRECTORY pExpEntry =\
    &pDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];\
    PIMAGE_EXPORT_DIRECTORY  pExpDescriptor =\
    (PIMAGE_EXPORT_DIRECTORY)((uint8_t*)mempe + pExpEntry->VirtualAddress);\
    WORD* ordrva = (WORD*)((uint8_t*)mempe\
        + pExpDescriptor->AddressOfNameOrdinals);\
    DWORD* namerva = (DWORD*)((uint8_t*)mempe\
        + pExpDescriptor->AddressOfNames);\
    DWORD* funcrva = (DWORD*)((uint8_t*)mempe\
        + pExpDescriptor->AddressOfFunctions);\
    if ((size_t)funcname <= MAXWORD)\
    {\
        WORD ordbase = LOWORD(pExpDescriptor->Base) - 1;\
        WORD funcord = LOWORD(funcname);\
        exp = (void*)((uint8_t*)mempe + funcrva[ordrva[funcord - ordbase]]);\
    }\
    else\
    {\
        for (DWORD i = 0; i < pExpDescriptor->NumberOfNames; i++)\
        {\
            LPCSTR curname = (LPCSTR)((uint8_t*)mempe + namerva[i]);\
            if (windyn_stricmp(curname, funcname) == 0)\
            {\
                exp = (void*)((uint8_t*)mempe + funcrva[ordrva[i]]); \
                break;\
            }\
        }\
    }\
}

#define WINDYN_FINDMODULE(peb, modulename, hmod)\
{\
    typedef struct _LDR_ENTRY  \
    {\
        LIST_ENTRY InLoadOrderLinks; \
        LIST_ENTRY InMemoryOrderLinks;\
        LIST_ENTRY InInitializationOrderLinks;\
        PVOID DllBase;\
        PVOID EntryPoint;\
        ULONG SizeOfImage;\
        UNICODE_STRING FullDllName;\
        UNICODE_STRING BaseDllName;\
        ULONG Flags;\
        USHORT LoadCount;\
        USHORT TlsIndex;\
        union\
        {\
            LIST_ENTRY HashLinks;\
            struct\
            {\
                PVOID SectionPointer;\
                ULONG CheckSum;\
            };\
        };\
        ULONG TimeDateStamp;\
    } LDR_ENTRY, * PLDR_ENTRY; \
    PLDR_ENTRY ldrentry = NULL;\
    PPEB_LDR_DATA ldr = NULL;\
    if (!peb)\
    {\
        PTEB teb = NtCurrentTeb();\
        if(sizeof(size_t)>4) peb = *(PPEB*)((uint8_t*)teb + 0x60);\
        else peb = *(PPEB*)((uint8_t*)teb + 0x30);\
    }\
    if(sizeof(size_t)>4) ldr = *(PPEB_LDR_DATA*)((uint8_t*)peb + 0x18);\
    else ldr = *(PPEB_LDR_DATA*)((uint8_t*)peb + 0xC);\
    ldrentry = (PLDR_ENTRY)((size_t)\
        ldr->InMemoryOrderModuleList.Flink - 2 * sizeof(size_t));\
    if (!modulename)\
    {\
        hmod = ldrentry->DllBase;\
    }\
    else\
    {\
        while (ldrentry->InMemoryOrderLinks.Flink != \
            ldr->InMemoryOrderModuleList.Flink)\
        {\
            PUNICODE_STRING ustr = &ldrentry->FullDllName; \
            int i; \
            for (i = ustr->Length / 2 - 1; i > 0 && ustr->Buffer[i] != '\\'; i--); \
                if (ustr->Buffer[i] == '\\') i++; \
                    if (windyn_stricmp2(modulename, ustr->Buffer + i) == 0)\
                    {\
                        hmod = ldrentry->DllBase; \
                        break; \
                    }\
                        ldrentry = (PLDR_ENTRY)((size_t)\
                            ldrentry->InMemoryOrderLinks.Flink - 2 * sizeof(size_t)); \
        }\
    }\
}

#define WINDYN_FINDKERNEL32(kernel32)\
{\
    PPEB peb = NULL;\
    char name_kernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', '\0' }; \
    WINDYN_FINDMODULE(peb, name_kernel32, kernel32);\
}

#define WINDYN_FINDLOADLIBRARYA(kernel32, pfnLoadLibraryA)\
{\
    char name_LoadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0' };\
    WINDYN_FINDEXP((void*)kernel32, name_LoadLibraryA, pfnLoadLibraryA);\
}\

#define WINDYN_FINDGETPROCADDRESS(kernel32, pfnGetProcAddress)\
{\
    char name_GetProcAddress[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', '\0' }; \
    WINDYN_FINDEXP((void*)kernel32, name_GetProcAddress, pfnGetProcAddress);\
}

// stdc inline functions declear
WINDYNDEF WINDYN_EXPORT
int windyn_strlen(const char* str1);

WINDYNDEF WINDYN_EXPORT
int windyn_stricmp(const char* str1, const char* str2);

WINDYNDEF WINDYN_EXPORT
INLINE int windyn_stricmp2(const char* str1, const wchar_t* str2);

WINDYNDEF WINDYN_EXPORT
INLINE int windyn_wcsicmp(const wchar_t* str1, const wchar_t* str2);

WINDYNDEF WINDYN_EXPORT
INLINE void* windyn_memset(void* buf, int ch, size_t n);

WINDYNDEF WINDYN_EXPORT
INLINE void* windyn_memcpy(void* dst, const void* src, size_t n);

// winapi inline functions declear
WINDYNDEF WINDYN_EXPORT
INLINE HMODULE WINAPI windyn_GetModuleHandleA(
    LPCSTR lpModuleName
);

WINDYNDEF WINDYN_EXPORT
INLINE HMODULE WINAPI windyn_LoadLibraryA(
    LPCSTR lpLibFileName
);

WINDYNDEF WINDYN_EXPORT
INLINE FARPROC WINAPI windyn_GetProcAddress(
    HMODULE hModule,
    LPCSTR lpProcName
);

WINDYNDEF WINDYN_EXPORT 
INLINE LPVOID WINAPI windyn_VirtualAllocEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
);

WINDYNDEF WINDYN_EXPORT 
INLINE BOOL WINAPI windyn_VirtualFreeEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD dwFreeType
);

WINDYNDEF WINDYN_EXPORT 
INLINE BOOL WINAPI windyn_VirtualProtectEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect,
    PDWORD lpflOldProtect
);

WINDYNDEF WINDYN_EXPORT 
INLINE BOOL WINAPI windyn_CreateProcessA(
    LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);

WINDYNDEF WINDYN_EXPORT 
INLINE HANDLE WINAPI windyn_OpenProcess(
    DWORD dwDesiredAccess,
    BOOL bInheritHandle,
    DWORD dwProcessId
);

WINDYNDEF WINDYN_EXPORT 
INLINE HANDLE WINAPI windyn_GetCurrentProcess(
    VOID
);

WINDYNDEF WINDYN_EXPORT 
INLINE BOOL WINAPI windyn_ReadProcessMemory(
    HANDLE hProcess,
    LPCVOID lpBaseAddress,
    LPVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesRead
);

WINDYNDEF WINDYN_EXPORT 
INLINE BOOL WINAPI windyn_WriteProcessMemory(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesWritten
);

WINDYNDEF WINDYN_EXPORT 
INLINE HANDLE WINAPI windyn_CreateRemoteThread(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId
);

WINDYNDEF WINDYN_EXPORT
INLINE HANDLE WINAPI windyn_GetCurrentThread(
    VOID
);

WINDYNDEF WINDYN_EXPORT
INLINE DWORD WINAPI windyn_SuspendThread(
    HANDLE hThread
);

WINDYNDEF WINDYN_EXPORT
INLINE DWORD WINAPI windyn_ResumeThread(
    HANDLE hThread
);

WINDYNDEF WINDYN_EXPORT
INLINE BOOL WINAPI windyn_GetThreadContext(
    HANDLE hThread,
    LPCONTEXT lpContext
);

WINDYNDEF WINDYN_EXPORT
INLINE BOOL WINAPI windyn_SetThreadContext(
    HANDLE hThread,
    CONST CONTEXT* lpContext
);

WINDYNDEF WINDYN_EXPORT
INLINE DWORD WINAPI windyn_WaitForSingleObject(
    HANDLE hHandle,
    DWORD dwMilliseconds
);

WINDYNDEF WINDYN_EXPORT
INLINE BOOL WINAPI windyn_CloseHandle(
    HANDLE hObject
);

WINDYNDEF WINDYN_EXPORT
INLINE HANDLE WINAPI windyn_CreateToolhelp32Snapshot(
    DWORD dwFlags,
    DWORD th32ProcessID
);

WINDYNDEF WINDYN_EXPORT
INLINE BOOL WINAPI windyn_Process32First(
    HANDLE hSnapshot,
    LPPROCESSENTRY32 lppe
);

WINDYNDEF WINDYN_EXPORT
INLINE BOOL WINAPI windyn_Process32Next(
    HANDLE hSnapshot,
    LPPROCESSENTRY32 lppe
);

#ifdef WINDYN_IMPLEMENTATION
#include <windows.h>
#include <winternl.h>
// util functions

// stdc inline functions define
INLINE int windyn_strlen(const char* str1)
{
    const char* p = str1;
    while (*p) p++;
    return (int)(p - str1);
}

WINDYNDEF WINDYN_EXPORT
INLINE int windyn_stricmp(const char* str1, const char* str2)
{
    int i = 0;
    while (str1[i] != 0 && str2[i] != 0)
    {
        if (str1[i] == str2[i]
            || str1[i] + 0x20 == str2[i]
            || str2[i] + 0x20 == str1[i])
        {
            i++;
        }
        else
        {
            return (int)str1[i] - (int)str2[i];
        }
    }
    return (int)str1[i] - (int)str2[i];
}

WINDYNDEF WINDYN_EXPORT
INLINE int windyn_stricmp2(const char* str1, const wchar_t* str2)
{
    int i = 0;
    while (str1[i] != 0 && str2[i] != 0)
    {
        if ((wchar_t)str1[i] == str2[i]
            || (wchar_t)str1[i] + 0x20 == str2[i]
            || str2[i] + 0x20 == (wchar_t)str1[i])
        {
            i++;
        }
        else
        {
            return (int)str1[i] - (int)str2[i];
        }
    }
    return (int)str1[i] - (int)str2[i];
}

WINDYNDEF WINDYN_EXPORT
INLINE int windyn_wcsicmp(const wchar_t * str1, const wchar_t* str2)
{
    int i = 0;
    while (str1[i] != 0 && str2[i] != 0)
    {
        if (str1[i] == str2[i]
            || str1[i] + 0x20 == str2[i]
            || str2[i] + 0x20 == str1[i])
        {
            i++;
        }
        else
        {
            return (int)str1[i] - (int)str2[i];
        }
    }
    return (int)str1[i] - (int)str2[i];
}

WINDYNDEF WINDYN_EXPORT
INLINE void* windyn_memset(void* buf, int ch, size_t n)
{
    char* p = buf;
    for (size_t i = 0; i < n; i++) p[i] = (char)ch;
    return buf;
}

WINDYNDEF WINDYN_EXPORT
INLINE void* windyn_memcpy(void* dst, const void* src, size_t n)
{
    char* p1 = (char*)dst;
    char* p2 = (char*)src;
    for (size_t i = 0; i < n; i++) p1[i] = p2[i];
    return dst;
}

// winapi inline functions define
WINDYNDEF WINDYN_EXPORT
INLINE HMODULE WINAPI windyn_GetModuleHandleA(
    LPCSTR lpModuleName
)
{
    PPEB peb = NULL;
    HMODULE hmod = NULL;
    WINDYN_FINDMODULE(peb, lpModuleName, hmod);
    return hmod;
}

WINDYNDEF WINDYN_EXPORT
INLINE HMODULE WINAPI windyn_LoadLibraryA(
    LPCSTR lpLibFileName
)
{
    HMODULE kernel32 = NULL;
    WINDYN_FINDKERNEL32(kernel32);
    PFN_LoadLibraryA pfnLoadLibraryA = NULL;
    WINDYN_FINDLOADLIBRARYA(kernel32, pfnLoadLibraryA);
    return pfnLoadLibraryA(lpLibFileName);
}

WINDYNDEF WINDYN_EXPORT
INLINE FARPROC WINAPI windyn_GetProcAddress(
    HMODULE hModule,
    LPCSTR lpProcName
)
{
    HMODULE kernel32 = NULL;
    WINDYN_FINDKERNEL32(kernel32);
    PFN_GetProcAddress pfnGetProcAddress = NULL;
    WINDYN_FINDGETPROCADDRESS(kernel32, pfnGetProcAddress);
    return pfnGetProcAddress(hModule, lpProcName);
}

WINDYNDEF WINDYN_EXPORT 
INLINE LPVOID WINAPI windyn_VirtualAllocEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
)
{    
    HMODULE kernel32 = NULL;
    WINDYN_FINDKERNEL32(kernel32);
    PFN_GetProcAddress pfnGetProcAddress = NULL;
    WINDYN_FINDGETPROCADDRESS(kernel32, pfnGetProcAddress);

    char name_VirtualAllocEx[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 'E', 'x', '\0'};
    PFN_VirtualAllocEx pfnVirtualAllocEx = (PFN_VirtualAllocEx)
        pfnGetProcAddress(kernel32, name_VirtualAllocEx);
    return pfnVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

WINDYNDEF WINDYN_EXPORT 
INLINE BOOL WINAPI windyn_VirtualFreeEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD dwFreeType
);

WINDYNDEF WINDYN_EXPORT 
INLINE BOOL WINAPI windyn_VirtualProtectEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect,
    PDWORD lpflOldProtect
);

WINDYNDEF WINDYN_EXPORT 
INLINE BOOL WINAPI windyn_CreateProcessA(
    LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);

WINDYNDEF WINDYN_EXPORT 
INLINE HANDLE WINAPI windyn_OpenProcess(
    DWORD dwDesiredAccess,
    BOOL bInheritHandle,
    DWORD dwProcessId
);

WINDYNDEF WINDYN_EXPORT 
INLINE HANDLE WINAPI windyn_GetCurrentProcess(
    VOID
);

WINDYNDEF WINDYN_EXPORT 
INLINE BOOL WINAPI windyn_ReadProcessMemory(
    HANDLE hProcess,
    LPCVOID lpBaseAddress,
    LPVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesRead
);

WINDYNDEF WINDYN_EXPORT 
INLINE BOOL WINAPI windyn_WriteProcessMemory(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesWritten
);

WINDYNDEF WINDYN_EXPORT 
INLINE HANDLE WINAPI windyn_CreateRemoteThread(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId
);

WINDYNDEF WINDYN_EXPORT 
INLINE HANDLE WINAPI windyn_GetCurrentThread(
    VOID
);

WINDYNDEF WINDYN_EXPORT 
INLINE DWORD WINAPI windyn_SuspendThread(
    HANDLE hThread
);

WINDYNDEF WINDYN_EXPORT 
INLINE DWORD WINAPI windyn_ResumeThread(
    HANDLE hThread
);

WINDYNDEF WINDYN_EXPORT 
INLINE BOOL WINAPI windyn_GetThreadContext(
    HANDLE hThread,
    LPCONTEXT lpContext
);

WINDYNDEF WINDYN_EXPORT 
INLINE BOOL WINAPI windyn_SetThreadContext(
    HANDLE hThread,
    CONST CONTEXT* lpContext
);

WINDYNDEF WINDYN_EXPORT 
INLINE DWORD WINAPI windyn_WaitForSingleObject(
    HANDLE hHandle,
    DWORD dwMilliseconds
);

WINDYNDEF WINDYN_EXPORT 
INLINE BOOL WINAPI windyn_CloseHandle(
    HANDLE hObject
);

WINDYNDEF WINDYN_EXPORT 
INLINE HANDLE WINAPI windyn_CreateToolhelp32Snapshot(
    DWORD dwFlags,
    DWORD th32ProcessID
);

WINDYNDEF WINDYN_EXPORT 
INLINE BOOL WINAPI windyn_Process32First(
    HANDLE hSnapshot,
    LPPROCESSENTRY32 lppe
);

WINDYNDEF WINDYN_EXPORT 
INLINE BOOL WINAPI windyn_Process32Next(
    HANDLE hSnapshot,
    LPPROCESSENTRY32 lppe
);

#endif

#ifdef __cplusplus
}
#endif

#endif

/*
* history
* v0.1, initial version
* v0.1.1, add some function pointer
* v0.1.2, add some inline stdc function
* v0.1.3, add some inline windows api 
*/