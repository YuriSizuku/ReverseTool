/** windows api function pointer define,
 *  functions or macros for dynamic bindings
 *    v0.1.4, developed by devseed
 * 
 * macros:
 *    WINDYN_IMPLEMENT, include defines of each function
 *    WINDYN_SHARED, make function export
 *    WINDYN_STATIC, make function static
 *    WINDYN_NOINLINE, don't use inline function
*/

#ifndef _WINDYN_H
#define _WINDYN_H
#define WINDYN_VERSION 140

// define general macro
#if defined(_MSC_VER) || defined(__TINYC__)
#ifndef STDCALL
#define STDCALL __stdcall
#endif
#ifndef NAKED
#define NAKED __declspec(naked)
#endif
#ifndef INLINE
#define INLINE __forceinline
#endif
#ifndef EXPORT
#define EXPORT __declspec(dllexport)
#endif
#else
#ifndef STDCALL
#define STDCALL __attribute__((stdcall))
#endif
#ifndef NAKED
#define NAKED __attribute__((naked))
#endif
#ifndef INLINE
#define INLINE __attribute__((always_inline)) inline
#endif
#ifndef EXPORT 
#define EXPORT __attribute__((visibility("default")))
#endif
#endif // _MSC_VER

// define specific macro
#ifdef WINDYN_API
#undef WINDYN_API
#endif
#ifdef WINDYN_API_DEF
#undef WINDYN_API_DEF
#endif
#ifdef WINDYN_API_EXPORT
#undef WINDYN_API_EXPORT
#endif
#ifdef WINDYN_API_INLINE
#undef WINDYN_API_INLINE
#endif
#ifdef WINDYN_STATIC
#define WINDYN_API_DEF static
#else
#define WINDYN_API_DEF extern
#endif // WINDYN_STATIC
#ifdef WINDYN_SHARED
#define WINDYN_API_EXPORT EXPORT
#else
#define WINDYN_API_EXPORT
#endif // WINDYN_SHARED
#ifdef WINDYN_NOINLINE
#define WINDYN_API_INLINE
#else
#define WINDYN_API_INLINE INLINE
#endif // WINDYN_NOINLINE
#define WINDYN_API WINDYN_API_DEF WINDYN_API_EXPORT WINDYN_API_INLINE

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>

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
WINDYN_API
int windyn_strlen(const char* str1);

WINDYN_API
int windyn_stricmp(const char* str1, const char* str2);

WINDYN_API
int windyn_stricmp2(const char* str1, const wchar_t* str2);

WINDYN_API
int windyn_wcsicmp(const wchar_t* str1, const wchar_t* str2);

WINDYN_API
void* windyn_memset(void* buf, int ch, size_t n);

WINDYN_API
void* windyn_memcpy(void* dst, const void* src, size_t n);

// winapi inline functions declear
WINDYN_API
HMODULE WINAPI windyn_GetModuleHandleA(
    LPCSTR lpModuleName);

WINDYN_API
HMODULE WINAPI windyn_LoadLibraryA(
    LPCSTR lpLibFileName);

WINDYN_API
FARPROC WINAPI windyn_GetProcAddress(
    HMODULE hModule,
    LPCSTR lpProcName);

WINDYN_API
LPVOID WINAPI windyn_VirtualAllocEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect);

WINDYN_API
BOOL WINAPI windyn_VirtualFreeEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD dwFreeType);

WINDYN_API
BOOL WINAPI windyn_VirtualProtectEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect,
    PDWORD lpflOldProtect);

WINDYN_API
BOOL WINAPI windyn_CreateProcessA(
    LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation);

WINDYN_API
HANDLE WINAPI windyn_OpenProcess(
    DWORD dwDesiredAccess,
    BOOL bInheritHandle,
    DWORD dwProcessId);

WINDYN_API
HANDLE WINAPI windyn_GetCurrentProcess(
    VOID);

WINDYN_API
BOOL WINAPI windyn_ReadProcessMemory(
    HANDLE hProcess,
    LPCVOID lpBaseAddress,
    LPVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesRead);

WINDYN_API
BOOL WINAPI windyn_WriteProcessMemory(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesWritten);

WINDYN_API 
HANDLE WINAPI windyn_CreateRemoteThread(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId);

WINDYN_API
HANDLE WINAPI windyn_GetCurrentThread(
    VOID);

WINDYN_API
DWORD WINAPI windyn_SuspendThread(
    HANDLE hThread);

WINDYN_API
DWORD WINAPI windyn_ResumeThread(
    HANDLE hThread);

WINDYN_API
BOOL WINAPI windyn_GetThreadContext(
    HANDLE hThread,
    LPCONTEXT lpContext);

WINDYN_API
BOOL WINAPI windyn_SetThreadContext(
    HANDLE hThread,
    CONST CONTEXT* lpContext);

WINDYN_API
DWORD WINAPI windyn_WaitForSingleObject(
    HANDLE hHandle,
    DWORD dwMilliseconds);

WINDYN_API
BOOL WINAPI windyn_CloseHandle(
    HANDLE hObject);

WINDYN_API
HANDLE WINAPI windyn_CreateToolhelp32Snapshot(
    DWORD dwFlags,
    DWORD th32ProcessID);

WINDYN_API
BOOL WINAPI windyn_Process32First(
    HANDLE hSnapshot,
    LPPROCESSENTRY32 lppe);

WINDYN_API
BOOL WINAPI windyn_Process32Next(
    HANDLE hSnapshot,
    LPPROCESSENTRY32 lppe);

#ifdef WINDYN_IMPLEMENTATION
#include <windows.h>
#include <winternl.h>
// util functions

// stdc inline functions define
int windyn_strlen(const char* str1)
{
    const char* p = str1;
    while (*p) p++;
    return (int)(p - str1);
}

int windyn_stricmp(const char* str1, const char* str2)
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

int windyn_stricmp2(const char* str1, const wchar_t* str2)
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

int windyn_wcsicmp(const wchar_t * str1, const wchar_t* str2)
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

void* windyn_memset(void* buf, int ch, size_t n)
{
    char* p = buf;
    for (size_t i = 0; i < n; i++) p[i] = (char)ch;
    return buf;
}

void* windyn_memcpy(void* dst, const void* src, size_t n)
{
    char* p1 = (char*)dst;
    char* p2 = (char*)src;
    for (size_t i = 0; i < n; i++) p1[i] = p2[i];
    return dst;
}

// winapi inline functions define
HMODULE WINAPI windyn_GetModuleHandleA(
    LPCSTR lpModuleName)
{
    PPEB peb = NULL;
    HMODULE hmod = NULL;
    WINDYN_FINDMODULE(peb, lpModuleName, hmod);
    return hmod;
}

HMODULE WINAPI windyn_LoadLibraryA(
    LPCSTR lpLibFileName)
{
    HMODULE kernel32 = NULL;
    WINDYN_FINDKERNEL32(kernel32);
    PFN_LoadLibraryA pfnLoadLibraryA = NULL;
    WINDYN_FINDLOADLIBRARYA(kernel32, pfnLoadLibraryA);
    return pfnLoadLibraryA(lpLibFileName);
}

FARPROC WINAPI windyn_GetProcAddress(
    HMODULE hModule,
    LPCSTR lpProcName)
{
    HMODULE kernel32 = NULL;
    WINDYN_FINDKERNEL32(kernel32);
    PFN_GetProcAddress pfnGetProcAddress = NULL;
    WINDYN_FINDGETPROCADDRESS(kernel32, pfnGetProcAddress);
    return pfnGetProcAddress(hModule, lpProcName);
}

LPVOID WINAPI windyn_VirtualAllocEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect)
{    
    HMODULE kernel32 = NULL;
    WINDYN_FINDKERNEL32(kernel32);
    PFN_GetProcAddress pfnGetProcAddress = NULL;
    WINDYN_FINDGETPROCADDRESS(kernel32, pfnGetProcAddress);
    char name_VirtualAllocEx[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 'E', 'x', '\0'};
    PFN_VirtualAllocEx pfnVirtualAllocEx = (PFN_VirtualAllocEx)pfnGetProcAddress(kernel32, name_VirtualAllocEx);
    return pfnVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

// todo
BOOL WINAPI windyn_VirtualFreeEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD dwFreeType);

BOOL WINAPI windyn_VirtualProtectEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect,
    PDWORD lpflOldProtect);

BOOL WINAPI windyn_CreateProcessA(
    LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation);

HANDLE WINAPI windyn_OpenProcess(
    DWORD dwDesiredAccess,
    BOOL bInheritHandle,
    DWORD dwProcessId);

HANDLE WINAPI windyn_GetCurrentProcess(
    VOID);

BOOL WINAPI windyn_ReadProcessMemory(
    HANDLE hProcess,
    LPCVOID lpBaseAddress,
    LPVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesRead);

BOOL WINAPI windyn_WriteProcessMemory(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesWritten);

HANDLE WINAPI windyn_CreateRemoteThread(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId);

HANDLE WINAPI windyn_GetCurrentThread(
    VOID);

DWORD WINAPI windyn_SuspendThread(
    HANDLE hThread);

DWORD WINAPI windyn_ResumeThread(
    HANDLE hThread);

BOOL WINAPI windyn_GetThreadContext(
    HANDLE hThread,
    LPCONTEXT lpContext);

BOOL WINAPI windyn_SetThreadContext(
    HANDLE hThread,
    CONST CONTEXT* lpContext);

DWORD WINAPI windyn_WaitForSingleObject(
    HANDLE hHandle,
    DWORD dwMilliseconds);

BOOL WINAPI windyn_CloseHandle(
    HANDLE hObject);

HANDLE WINAPI windyn_CreateToolhelp32Snapshot(
    DWORD dwFlags,
    DWORD th32ProcessID);

BOOL WINAPI windyn_Process32First(
    HANDLE hSnapshot,
    LPPROCESSENTRY32 lppe);

BOOL WINAPI windyn_Process32Next(
    HANDLE hSnapshot,
    LPPROCESSENTRY32 lppe);

#endif

#ifdef __cplusplus
}
#endif

#endif

/**
* history
* v0.1, initial version
* v0.1.1, add some function pointer
* v0.1.2, add some inline stdc function
* v0.1.3, add some inline windows api
* v0.1.4, improve macro style
*/