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
    printf("[test_findkernel32] kernel32=%p\n", kerenl32);
    assert(kerenl32==GetModuleHandleA("kernel32"));
}

void test_findloadlibrarya()
{

    void *func = (void*)LoadLibraryA;
    void *func2 = winpe_findloadlibrarya();
    printf("[test_findloadlibrarya] LoadLibraryA=%p\n", func2);
    assert(func==func2);
}

void test_findgetprocaddress()
{
    void *func = (void*)GetProcAddress;
    void *func2 = winpe_findgetprocaddress();
    printf("[test_findgetprocaddress] GetProcAddress=%p\n", func2);
    assert(func==func2);
}

void test_findmodulea(const char *modname)
{
    void* hmod = (void*)GetModuleHandleA(modname);
    void* hmod2 = (void*)winpe_findmodulea(modname);
    printf("[test_findmodulea] modname=%s hmod=%p\n", modname, hmod2);
    assert(hmod==hmod2);
}

void test_memforwardexp(HMODULE hmod, const char *funcname)
{
    size_t expva = (size_t)GetProcAddress(hmod, funcname);
    size_t exprva = (size_t)winpe_memfindexp(hmod, funcname) - (size_t)hmod;
    printf("%x\n", exprva);
    void *func = winpe_memforwardexp(hmod, exprva, 
        (PFN_LoadLibraryA)winpe_findloadlibrarya(), 
        (PFN_GetProcAddress)winpe_memfindexp);
    void *func2 = winpe_memGetProcAddress(hmod, funcname);
    printf("[test_memforwardexp] hmod=%p funcname=%s func=%p func2=%p\n", 
                hmod, funcname, func, func2);
    assert(exprva!=0);
    assert((size_t)func==expva);
    assert(func2==func);
}

void test_memGetProcAddress(HMODULE hmod, const char *funcname)
{
    void* func = (void*)GetProcAddress(hmod, funcname);
    void *func2 = (void*)winpe_memGetProcAddress(hmod, funcname);
    printf("[test_memGetProcAddress] hmod=%p funcname=%s func=%p func2=%p\n", 
                hmod, funcname, func, func2);
    assert(func==func2);
}

int main(int argc, char *argv[])
{
    test_findkernel32();
    test_findloadlibrarya();
    test_findgetprocaddress();
    test_findmodulea("kernel32.dll");
    HMODULE hkernel32 = LoadLibraryA("kernel32.dll");
    test_memforwardexp(hkernel32, "LoadLibraryA");
    test_memforwardexp(hkernel32, "InitializeSListHead");
    test_memforwardexp(hkernel32, "GetSystemTimeAsFileTime");
    test_memGetProcAddress(hkernel32, "GetProcessMitigationPolicy");
    printf("%s finish!\n", argv[0]);
    return 0;
}