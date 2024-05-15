#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <TlHelp32.h>
#include <Psapi.h>

#define qassert(cond, msg) if (!(cond)) { printf("%s\nExiting in 5 seconds...\n", msg); Sleep(5000); exit(1); }

uintptr_t get_process_base(HANDLE proc)
{
    HMODULE base;
    DWORD cb;
    EnumProcessModules(proc, &base, 8, &cb);
    return (uintptr_t)base;
}

uintptr_t aob = 0x8D4800000002B941;

uintptr_t offset_cached = 0;
uintptr_t look_for_that_thing(HANDLE proc, uintptr_t base)
{
    if (offset_cached)
        return base + offset_cached;
    
    uintptr_t address = base + 0x1000000;

    char sbuffer[23] = {};
    
    MEMORY_BASIC_INFORMATION mbi = {};
    while (VirtualQueryEx(proc, (LPVOID)base, &mbi, sizeof(mbi)))
    {
        if (mbi.State & MEM_COMMIT)
        {
            char* buffer = (char*)malloc(mbi.RegionSize);
            if (ReadProcessMemory(proc, (LPVOID)address, buffer, mbi.RegionSize, 0))
            {
                for (uintptr_t i = 0; i < mbi.RegionSize; i++)
                {
                    if (*reinterpret_cast<uintptr_t*>(&buffer[i]) == aob)
                    {
                        uintptr_t addr = address + i;
                        DWORD offset;
                        ReadProcessMemory(proc, (LPVOID)(addr + 9), &offset, 4, 0);
                        uintptr_t string_address = addr + offset + 13;
                        if (ReadProcessMemory(proc, (LPVOID)string_address, sbuffer, sizeof(sbuffer), 0) && strcmp(sbuffer, "TaskSchedulerTargetFps") == 0)
                        {
                            ReadProcessMemory(proc, (LPVOID)(addr - 4), &offset, 4, 0);
                            offset_cached = addr + offset - base;
                            return addr + offset;
                        }
                    }
                }
            }
            free(buffer);
        }
        address += mbi.RegionSize;
    }
}

std::vector<DWORD> get_roblox_pids()
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    qassert(snap != INVALID_HANDLE_VALUE, "Failed to create process snapshot");

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    qassert(Process32First(snap, &pe), "Failed to get first process");

    std::vector<DWORD> pids = {};
    do
    {
        if (strcmp(pe.szExeFile, "RobloxPlayerBeta.exe") == 0)
            pids.push_back(pe.th32ProcessID);
    } while (Process32Next(snap, &pe));

    CloseHandle(snap);

    return pids;
}

int main(int argc, char** argv)
{
    int fpscap = 0;

    if (argc == 2)
        fpscap = std::stoi(argv[1]);

    if (fpscap == 0)
    {
        printf("Please enter fps cap: ");
        std::cin >> fpscap;
    }

    for (DWORD pid : get_roblox_pids())
    {
        HANDLE proc = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);

        uintptr_t base = get_process_base(proc);
        printf("Got roblox: pid = %d, base = %llX\n", pid, base);

        WriteProcessMemory(proc, (LPVOID)look_for_that_thing(proc, base), &fpscap, 4, 0);

        CloseHandle(proc);
    }
}