#include "pch.h"
#include "helper/helper.h"

int main()
{
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
        void* loc = VirtualAllocEx(h_proc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (loc == NULL)
        {
            std::cout << "[!] Failed to allocate memory in process!" << std::endl;
            return 1;
        }

        unsigned char shellcode[] = {
            0x6A, 0x11, 0x8B, 0x44, 0x24, 0x08, 0x50, 0xE8, 0x0, 0x0, 0x0, 0x0, 0x31, 0xC0, 0xC2, 0x04, 0x00
        };

        std::cout << "[-] Calculating relative offset to SetWindowDisplayAffinity" << std::endl;

        HMODULE h_user32 = GetModuleHandle("user32.dll");
        if (h_user32 == NULL)
        {
            std::cout << "[!] Failed to get handle to user32.dll!" << std::endl;
            return 1;
        }

        uintptr_t swda_addr = (uintptr_t)GetProcAddress(h_user32, "SetWindowDisplayAffinity");
        if (swda_addr == NULL)
        {
            std::cout << "[!] Failed to find SetWindowDisplayAffinity!" << std::endl;
            return 1;
        }

        // Get relative offset from call instruction to function address
        uintptr_t call = (uintptr_t)loc + 7;
        DWORD relative = (DWORD)swda_addr - (DWORD)call - 5;

        std::cout << "[-] Getting shellcode ready.." << std::endl;

        // Patch shellcode with relative
        *(DWORD*)(shellcode + 8) = relative;

        // Write shellcode to allocated memory
        WriteProcessMemory(h_proc, loc, shellcode, sizeof(shellcode), 0);

        // Fetch window handle of Discord
        HWND hwnd_discord = NULL;
        EnumWindows(helper::EnumWindowsProc, (LPARAM)&hwnd_discord);
        if (hwnd_discord == NULL)
        {
            std::cout << "[!] Failed to find Discord window!" << std::endl;
            return 1;
        }

        // Create remote thread and call shellcode pushing window handle onto stack
        std::cout << "[-] Starting remote thread.." << std::endl;
        HANDLE h_thread = CreateRemoteThread(h_proc, 0, 0, (LPTHREAD_START_ROUTINE)loc, hwnd_discord, 0, 0);
        Sleep(100);

        std::cout << "[-] Success! Cleaning up.." << std::endl;
        if (h_thread)
        {
            CloseHandle(h_thread);
        }
    }

    if (h_proc)
    {
        CloseHandle(h_proc);
    };

    std::cout << "[-] Finished! Press enter to close the window!" << std::endl;
    std::cin.get();

    return 0;
}