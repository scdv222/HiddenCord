#pragma once

namespace helper
{
	DWORD get_process_id(const char* process_name);
	BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam);
	HWND GetProcessWindow();
	const char* get_dll_path();
}
