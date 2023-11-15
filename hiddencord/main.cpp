#include "pch.h"
#include "helper/helper.h"

int main()
{
    unsigned char shellcode[] = {
    0x55, //push ebp
    0x8B, 0xEC, //mov ebp, esp
    0x6A, 0x11, //push 11
    0x8B, 0x45, 0x08, //mov eax, [ebp+8]
    0x50, //push eax
    0xE8, 0x00, 0x00, 0x00, 0x00, //call SetWindowDisplayAffinity
    //0xB8, 0x04, 0x00, 0x00, 0x00, //mov eax, 4
    0x5D, //pop ebp
    0xC2, 0x04, 0x00 //ret 4
    };

    std::cout << "[-] Initializing.." << std::endl;

    DWORD proc_id = 0;
    while (!proc_id)
    {
        proc_id = helper::get_process_id("Discord.exe");
        Sleep(30);
    }

    std::cout << "[-] Found Discord. PID: " << proc_id << std::endl;

    HANDLE h_proc = OpenProcess(PROCESS_ALL_ACCESS, 0, proc_id);

    if (h_proc && h_proc != INVALID_HANDLE_VALUE)
    {
        std::cout << "[-] Opened handle to Discord" << std::endl;
        std::cout << "[-] Allocating memory in process" << std::endl;

        // Allocate memory for shellcode
        void* loc = VirtualAllocEx(h_proc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (loc == NULL)
        {
            std::cout << "[!] Failed to allocate memory in process!" << std::endl;
            return 1;
        }

        std::cout << "[-] Calculating relative offset to SetWindowDisplayAffinity" << std::endl;

        HMODULE h_user32 = GetModuleHandle("user32.dll");
        if (h_user32 == NULL)
        {
            std::cout << "[!] Failed to get handle to user32.dll!" << std::endl;
            return 1;
        }

        DWORD swda_addr = (DWORD)GetProcAddress(h_user32, "SetWindowDisplayAffinity");
        if (swda_addr == NULL)
        {
            std::cout << "[!] Failed to find SetWindowDisplayAffinity!" << std::endl;
            return 1;
        }

        HWND hwnd_discord = NULL;
        EnumWindows(helper::EnumWindowsProc, (LPARAM)&hwnd_discord);
        if (hwnd_discord == NULL)
        {
            std::cout << "[!] Failed to find Discord window!" << std::endl;
            return 1;
        }

        std::cout << "[-] Found Discord window: " << hwnd_discord << std::endl;

        // Put offset in little endian in our byte
        DWORD offset = swda_addr - (DWORD)loc + 9 - 23;
        memcpy(&shellcode[10], &offset, 4);


        std::cout << "[-] Writing shellcode to process memory" << std::endl;
        if (!WriteProcessMemory(h_proc, loc, shellcode, sizeof(shellcode), 0))
        {
            std::cout << "[!] Failed to write to process memory!" << std::endl;
            return 1;
        }

        std::cout << "[-] Creating remote thread at " << (DWORD)loc << std::endl;
        system("pause");
        HANDLE h_thread = CreateRemoteThread(h_proc, 0, 0, (LPTHREAD_START_ROUTINE)loc, hwnd_discord, 0, 0);
        if (h_thread == NULL)
        {
            std::cout << "[!] Failed to create remote thread!" << std::endl;
            return 1;
        }
        std::cout << "[-] Waiting for thread to finish" << std::endl;
        WaitForSingleObject(h_thread, INFINITE);
        std::cout << "[-] Cleaning up" << std::endl;
        VirtualFreeEx(h_proc, loc, 0, MEM_RELEASE);
        CloseHandle(h_thread);
        CloseHandle(h_proc);
    }
    else
    {
        std::cout << "[!] Failed to open handle to process!" << std::endl;
        return 1;
    }
    std::cout << "[-] Done!" << std::endl;
    return 0;
}