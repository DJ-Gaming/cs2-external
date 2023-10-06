#include <iostream>
#include "include/eris.h"
#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h> 
#include <iostream> 
#include <thread>

uintptr_t get_module_base(uint32_t process_id, const char* module_name)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id);

    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 ModuleEntry32 = { 0 };
        ModuleEntry32.dwSize = sizeof(MODULEENTRY32);

        if (Module32First(hSnapshot, &ModuleEntry32))
        {
            do
            {
                if (strcmp(ModuleEntry32.szModule, module_name) == 0)
                {
                    return reinterpret_cast<uintptr_t>(ModuleEntry32.modBaseAddr);
                }
            } while (Module32Next(hSnapshot, &ModuleEntry32));
        }
        CloseHandle(hSnapshot);
    }

    CloseHandle(hSnapshot);
    return 0;
}

template<typename T>
T memory_read(HANDLE cs2_handle, uintptr_t address)
{
    T val = T();
    ReadProcessMemory(cs2_handle, (LPCVOID)address, &val, sizeof(T), NULL);
    return val;
}

template<typename T>
void memory_write(HANDLE cs2_handle, uintptr_t address, T value)
{
    WriteProcessMemory(cs2_handle, (LPVOID)address, &value, sizeof(T), NULL);
}

namespace offsets
{
    ptrdiff_t p_entity_list = 0x178D8E8;
    ptrdiff_t m_h_player_pawn = 0x7FC;
    ptrdiff_t m_fl_detected_by_enemy_sensor_time = 0x13C8;
}

int main() {
    SetConsoleTitleA("dooogeware");

    DWORD pid = Eris::GetPID("cs2.exe");

    std::cout <<
        (pid == 0 ? "Process not found" : "Process found") << std::endl;

    HANDLE Handle = Eris::Hijack(pid);

    if (Handle != nullptr) {
        std::cout << "Successfully hijacked handle: " << Handle << std::endl;
    }
    else {
        std::cerr << "Failed to hijack handle" << std::endl;
    }

    HANDLE cs2_process_handle = Handle;
    printf("cs2.exe process handle: 0x%lx\n", cs2_process_handle);

    if (!cs2_process_handle)
        printf("cs2.exe process handle is null!\n");

    uintptr_t cs2_module_client = get_module_base(Eris::GetPID("cs2.exe"), "client.dll");
    printf("client.dll base address: 0x%llx\n", cs2_module_client);

    if (!cs2_module_client)
        printf("client.dll not found in cs2.exe!\n");

    while (true)
    {
        static bool glow_enabled = false;
        static bool noflash_enabled = false;

        if (GetAsyncKeyState(VK_F1))
        {
            glow_enabled = !glow_enabled;
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
            printf("status enabled: %s\n", glow_enabled ? "true" : "false");
        }

        if (GetAsyncKeyState(VK_F2))
        {
            noflash_enabled = !noflash_enabled;
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
            printf("status enabled: %s\n", noflash_enabled ? "true" : "false");
        }

        for (int i = 1; i < 64; i++)
        {
            uintptr_t entity_list = memory_read<uintptr_t>(cs2_process_handle, cs2_module_client + offsets::p_entity_list);
            if (!entity_list)
                continue;

            uintptr_t list_entry = memory_read<uintptr_t>(cs2_process_handle, entity_list + (8 * (i & 0x7FFF) >> 9) + 16);
            if (!list_entry)
                continue;

            uintptr_t player = memory_read<uintptr_t>(cs2_process_handle, list_entry + 120 * (i & 0x1FF));
            if (!player)
                continue;

            uint32_t player_pawn = memory_read<uint32_t>(cs2_process_handle, player + offsets::m_h_player_pawn);

            uintptr_t list_entry2 = memory_read<uintptr_t>(cs2_process_handle, entity_list + 0x8 * ((player_pawn & 0x7FFF) >> 9) + 16);
            if (!list_entry2)
                continue;

            uintptr_t p_cs_player_pawn = memory_read<uintptr_t>(cs2_process_handle, list_entry2 + 120 * (player_pawn & 0x1FF));
            if (!p_cs_player_pawn)
                continue;

            int health = memory_read<int>(cs2_process_handle, player + 0x808);

            uintptr_t local_player = memory_read<uintptr_t>(cs2_process_handle, cs2_module_client + 0x187AC48);
            if (!local_player)
                continue;

            if (!glow_enabled)
                memory_write<float>(cs2_process_handle, p_cs_player_pawn + offsets::m_fl_detected_by_enemy_sensor_time, 0.f); // off
            else {
                memory_write<float>(cs2_process_handle, p_cs_player_pawn + offsets::m_fl_detected_by_enemy_sensor_time, 86400.f); // on
            }

            if (!noflash_enabled)
                memory_write<float>(cs2_process_handle, local_player + 0x1450, 255.f); // on remember to make this default flash alpha
            else {
                memory_write<float>(cs2_process_handle, local_player + 0x1450, 0.f); // on
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    getchar();
    return 0;
}

/*
bool DoesFileExist(const char* name) {
    if (FILE* file = fopen(name, "r")) {
        fclose(file);
        return true;
    }

    return false;
}

bool LoadLibraryInject(HANDLE handle, const char* Dll)
{

    char CustomDLL[MAX_PATH];
    GetFullPathName(Dll, MAX_PATH, CustomDLL, 0);

    LPVOID allocatedMem = VirtualAllocEx(handle, NULL, sizeof(CustomDLL), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (!WriteProcessMemory(handle, allocatedMem, CustomDLL, sizeof(CustomDLL), NULL))
        return FALSE;

    CreateRemoteThread(handle, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, allocatedMem, 0, 0);

    if (handle)
        CloseHandle(handle);

    return TRUE;
}


if (DoesFileExist("cheat.dll"))
    LoadLibraryInject(Handle, "cheat.dll");
*/
