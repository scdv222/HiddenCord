#pragma once

#define NOMINMAX

#pragma warning(push, 0)
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Psapi.h>
#include <DbgHelp.h>
#include <tlhelp32.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iostream>
#undef  WIN32_LEAN_AND_MEAN