#include "pch.h"
#include "helper/helper.h"

typedef BOOL(WINAPI* LPFN_SWDA)(HWND, DWORD);
LPFN_SWDA pSetWindowDisplayAffinity;

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
        std::cout << "[-] Trying to hook Discord.." << std::endl;

        // Allocate memory for code
        void* loc = VirtualAllocEx(h_proc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (loc == NULL)
        {
            std::cout << "[!] Failed to allocate memory in process!" << std::endl;
            return 1;
        }

        // Handle to user32 to fetch address of SWDA
        HMODULE h_user32 = GetModuleHandle("user32.dll");
        if (h_user32 == NULL)
        {
            std::cout << "[!] Failed to get handle to user32.dll!" << std::endl;
            return 1;
        }

        // Fetch address of SWDA
        pSetWindowDisplayAffinity = (LPFN_SWDA)GetProcAddress(h_user32, "SetWindowDisplayAffinity");
        if (pSetWindowDisplayAffinity == NULL)
        {
            std::cout << "[!] Failed to find SetWindowDisplayAffinity!" << std::endl;
            return 1;
        }
       
        HWND hwnd_discord = NULL;
        DWORD affinity = WDA_EXCLUDEFROMCAPTURE;

        // Fetch window handle of Discord
        EnumWindows(helper::EnumWindowsProc, (LPARAM)&hwnd_discord);
        if (hwnd_discord == NULL)
        {
            std::cout << "[!] Failed to find Discord window!" << std::endl;
            return 1;
        }

        // Write window handle to memory
        if (!WriteProcessMemory(h_proc, loc, &hwnd_discord, sizeof(hwnd_discord), NULL))
        {
            std::cout << "[!] Failed to write window handle to memory!" << std::endl;
            return 1;
        }

        // Write affinity value to memory
        if (!WriteProcessMemory(h_proc, (BYTE*)loc + sizeof(hwnd_discord), &affinity, sizeof(affinity), NULL))
        {
            std::cout << "[!] Failed to write affinity value to memory!" << std::endl;
            return 1;
        }

        // Execute SWDA and point it to allocated memory for arguments
        DWORD thread_id;
        HANDLE h_thread = CreateRemoteThread(h_proc, NULL, 0, (LPTHREAD_START_ROUTINE)pSetWindowDisplayAffinity, loc, 0, &thread_id);
        if (h_thread == INVALID_HANDLE_VALUE)
        {
            std::cout << "[!] Couldn't create thread to Discord!" << std::endl;
            return 1;
        }

        std::cout << "[-] Finalizing.." << std::endl;
        WaitForSingleObject(h_thread, INFINITE);

        std::cout << "[-] Success! Cleaning up.." << std::endl;
        CloseHandle(h_thread);
        VirtualFreeEx(h_proc, loc, 0, MEM_RELEASE);
        CloseHandle(h_proc);

        std::cout << "[-] Execution complete, close window when you are ready..";
        std::cin.get();
    }

    return 0;
}