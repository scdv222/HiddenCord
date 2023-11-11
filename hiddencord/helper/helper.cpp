#include "pch.h"
#include "helper.h"

DWORD helper::get_process_id(const char* process_name)
{
	DWORD proc_id = 0;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (snapshot != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 proc_entry;
		proc_entry.dwSize = sizeof(proc_entry);

		if (Process32First(snapshot, &proc_entry))
		{
			do
			{
				if (!_stricmp(proc_entry.szExeFile, process_name))
				{
					proc_id = proc_entry.th32ProcessID;
					break;
				}
			} while (Process32Next(snapshot, &proc_entry));
		}
	}
	CloseHandle(snapshot);
	return proc_id;
}

BOOL CALLBACK helper::EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
	const DWORD title_size = 256;
	WCHAR window_title[title_size];

	GetWindowTextW(hwnd, window_title, title_size);

	if (wcsstr(window_title, L"- Discord"))
	{
		*((HWND*)lParam) = hwnd;
		return FALSE;
	}

	return TRUE;
}