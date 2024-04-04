#include <stdio.h>
#include <assert.h>
#if defined (_MSC_VER) 
#define WINPE_IMPLEMENTATION
#define WINPE_NOASM
#endif
#include "winpe.h"

void test_findkernel32()
{
    void *kerenl32 = winpe_findkernel32();
    assert(kerenl32==GetModuleHandleA("kernel32"));
    printf("[test_findkernel32] kernel32=%p\n", kerenl32);
}

void test_findmodulea(const char *modname)
{
    void* hmod = (void*)GetModuleHandleA(modname);
    void* hmod2 = (void*)winpe_findmodulea(modname);
    assert(hmod==hmod2);
    printf("[test_findmodulea] modname=%s hmod=%p\n", modname, hmod2);
}

void test_memforwardexp(HMODULE hmod, const char *funcname)
{
    size_t expva = (size_t)GetProcAddress(hmod, funcname);
    size_t exprva = (size_t)winpe_memfindexp(hmod, funcname) - (size_t)hmod;
    void *func = winpe_memforwardexp(hmod, exprva, 
                    LoadLibraryA, (PFN_GetProcAddress)winpe_memfindexp);
    void *func2 = winpe_memGetProcAddress(hmod, funcname);
    assert(exprva!=0 && (size_t)func==expva  && func!=NULL && func2==func);
    printf("[test_memforwardexp] hmod=%p funcname=%s func=%p\n", hmod, funcname, func2);
}

void test_memGetProcAddress(HMODULE hmod, const char *funcname)
{
    void* func = (void*)GetProcAddress(hmod, funcname);
    void *func2 = (void*)winpe_memGetProcAddress(hmod, funcname);
    assert(func==func2);
    printf("[test_memGetProcAddress] hmod=%p funcname=%s func=%p\n", hmod, funcname, func2);
}

int main(int argc, char *argv[])
{
    test_findkernel32();
    test_findmodulea("kernel32.dll");
    HMODULE hkernel32 = LoadLibraryA("kernel32.dll");
    test_memforwardexp(hkernel32, "LoadLibraryA");
    test_memforwardexp(hkernel32, "InitializeSListHead");
    test_memforwardexp(hkernel32, "GetSystemTimeAsFileTime");
    test_memGetProcAddress(hkernel32, "GetProcessMitigationPolicy");
    return 0;
}