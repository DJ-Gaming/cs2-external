#include "eris.h"
#include <iostream>
#include <tlhelp32.h>

namespace Eris {
    DWORD GetPID(const std::string& ProcessName) {
        DWORD ProcId = 0;
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe;
            pe.dwSize = sizeof(pe);

            if (Process32First(hSnap, &pe)) {
                if (!pe.th32ProcessID)
                    Process32Next(hSnap, &pe);
                do {
                    if (!_stricmp(pe.szExeFile, ProcessName.c_str())) {
                        ProcId = pe.th32ProcessID;
                        break;
                    }
                } while (Process32Next(hSnap, &pe));
            }
        }
        CloseHandle(hSnap);
        return ProcId;
    }

    bool Valid(HANDLE Handle) {
        return Handle && Handle != INVALID_HANDLE_VALUE;
    }

    HANDLE Hijack(DWORD TargetProcessId) {
        HMODULE Ntdll = GetModuleHandleA("ntdll");
        auto RtlAdjustPrivilege = (NTSTATUS(WINAPI*)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN)) GetProcAddress(Ntdll, "RtlAdjustPrivilege");
        BOOLEAN OldPriv;
        RtlAdjustPrivilege(20, TRUE, FALSE, &OldPriv);

        auto NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(Ntdll, "NtQuerySystemInformation");
        auto NtDuplicateObject = (_NtDuplicateObject)GetProcAddress(Ntdll, "NtDuplicateObject");
        auto NtOpenProcess = (_NtOpenProcess)GetProcAddress(Ntdll, "NtOpenProcess");

        OBJECT_ATTRIBUTES Obj_Attribute = { sizeof(OBJECT_ATTRIBUTES) };
        CLIENT_ID clientID = { 0 };
        DWORD size = sizeof(SYSTEM_HANDLE_INFORMATION);
        auto hInfo = std::make_unique<BYTE[]>(size);
        ZeroMemory(hInfo.get(), size);
        NTSTATUS NtRet;

        do {
            hInfo.reset(new BYTE[size *= 2]);
        } while ((NtRet = NtQuerySystemInformation(kSystemHandleInformation,
            reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(hInfo.get()), size,
            nullptr)) == kStatusInfoLengthMismatch);

        if (!NT_SUCCESS(NtRet))
            return nullptr;

        for (unsigned int i = 0; i < reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(hInfo.get())->HandleCount; ++i)
        {
            auto handle = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(hInfo.get())->Handles[i];
            if (!Valid((HANDLE)handle.Handle))
                continue; 
            if (handle.ObjectTypeNumber != kProcessHandleType)
                continue;
            clientID.UniqueProcess = (HANDLE)handle.ProcessId;
            HANDLE procHandle;
            NtRet = NtOpenProcess(&procHandle, PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                &Obj_Attribute,
                &clientID);
            if (!Valid(procHandle) || !NT_SUCCESS(NtRet))
                continue;

            HANDLE HHandle; // hijacked
            NtRet = NtDuplicateObject(procHandle,
                (HANDLE)handle.Handle,
                kNtCurrentProcess,
                &HHandle,
                PROCESS_ALL_ACCESS,
                0,
                0);
            if (!Valid(HHandle) || !NT_SUCCESS(NtRet))
                continue;

            if (GetProcessId(HHandle) != TargetProcessId)
            {
                CloseHandle(HHandle);
                continue;
            }
            return HHandle;
        }
        return nullptr;
    }
}
