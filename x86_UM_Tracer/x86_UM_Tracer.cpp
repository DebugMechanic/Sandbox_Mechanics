// dllmain.cpp : Defines the entry point for the DLL application.

#include <SDKDDKVer.h>
#define WIN32_LEAN_AND_MEAN  // Exclude rarely-used stuff from Windows headers
#include <windows.h>
#include <stdio.h>
#include <cstdio>
#include <TlHelp32.h>
#include "Log.h"


#pragma warning( disable: 4996 )


// Prototypes
DWORD suspend_all_threads(DWORD processId);
void resume_all_threads(DWORD processId);
void EnableDebugPriv();
void WINAPI MainThread(void);


// Global
DWORD ThreadId;


DWORD suspend_all_threads(DWORD processId)
{
	DWORD  retval = 0;
	HANDLE hThread;

	THREADENTRY32 te = { te.dwSize = sizeof(THREADENTRY32) };

	HANDLE g_SnapShot_Handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
	if (INVALID_HANDLE_VALUE == g_SnapShot_Handle) {
		Log("Invalid Snap Handle\n");
	}

	if (Thread32First(g_SnapShot_Handle, &te)) {
		do
		{
			if (te.th32OwnerProcessID == processId)
			{
				if (0 == retval)
				{
					retval = (DWORD)te.th32ThreadID;
				}

				hThread = OpenThread(THREAD_ALL_ACCESS | THREAD_GET_CONTEXT, FALSE, te.th32ThreadID);
				if (NULL != hThread)
				{
					if ((DWORD)te.th32ThreadID != GetThreadId(GetCurrentThread()))
					{
						Log("\tsuspending thread %016llX\n", (DWORD)te.th32ThreadID);
						SuspendThread(hThread);
						CloseHandle(hThread);
					}

				}
				else {
					Log("\tfailed to open thread %016llX\n", (DWORD)te.th32ThreadID);
				}

			}
			else {
				Log("OwnerProcessID Not Found\n");
			}

		} while (Thread32Next(g_SnapShot_Handle, &te));

	}
	else {
		Log("Failed to Thread32First! %016llX\n", (DWORD)GetLastError());
	}
	CloseHandle(g_SnapShot_Handle);

	return retval;
}


void resume_all_threads(DWORD processId)
{
	HANDLE hThread;
	THREADENTRY32 te = { te.dwSize = sizeof(THREADENTRY32) };

	HANDLE g_SnapShot_Handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
	if (INVALID_HANDLE_VALUE == g_SnapShot_Handle) {
		Log("Invalid Snap Handle\n");
	}

	if (Thread32First(g_SnapShot_Handle, &te))
	{
		do
		{
			if (te.th32OwnerProcessID == processId)
			{
				hThread = OpenThread(THREAD_ALL_ACCESS | THREAD_GET_CONTEXT, FALSE, te.th32ThreadID);
				if (NULL != hThread)
				{
					if ((DWORD)te.th32ThreadID != GetThreadId(GetCurrentThread()))
					{
						Log("\tresuming thread %X\n", (DWORD)te.th32ThreadID);
						ResumeThread(hThread);
						CloseHandle(hThread);
					}

				}
				else {
					Log("\tfailed to open thread %X\n", (DWORD)te.th32ThreadID);
				}

			}
			else {
				Log("OwnerProcessID Not Found\n");
			}

		} while (Thread32Next(g_SnapShot_Handle, &te));

	}
	else {
		Log("Failed to Thread32First! %016llX\n", (DWORD)GetLastError());
	}
	CloseHandle(g_SnapShot_Handle);
}


void EnableDebugPriv()
{
	HANDLE              hToken;
	LUID                SeDebugNameValue;
	TOKEN_PRIVILEGES    TokenPrivileges;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &SeDebugNameValue))
		{
			TokenPrivileges.PrivilegeCount = 1;
			TokenPrivileges.Privileges[0].Luid = SeDebugNameValue;
			TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			if (AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
			{
				Log("Adjustment Of Privileges Completed...\n");
				CloseHandle(hToken);

			}
			else {
				CloseHandle(hToken);
				Log("AdjustTokenPrivileges() Failed!\n");
			}

		}
		else {
			CloseHandle(hToken);
			Log("LookupPrivilegeValue() Failed!\n");
		}

	}
	else {
		Log("OpenProcessToken() Failed!, Error: %08X\n", GetLastError());
	}
}


void WINAPI MainThread(void)
{
	SYSTEMTIME SystemTime;

	EnableDebugPriv();

	Log("\n\n[MainThread]: Version Compiled On [%s][%s]...\n", __DATE__, __TIME__);
	Log("[MainThread]: Hello From Thread:[%d][%X], The x86 UserMode Tracer .dll... \n", ThreadId, ThreadId);

	GetLocalTime(&SystemTime);
	Log("[MainThread]: LocalTime: [%d:%d:%d]\n", SystemTime.wHour, SystemTime.wMinute, SystemTime.wSecond);
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
			CreateThread(0, 0, (LPTHREAD_START_ROUTINE)MainThread, 0, 0, &ThreadId);
			break;

		case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}

