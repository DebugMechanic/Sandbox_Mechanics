// x86_Injector.cpp : Defines the entry point for the console application.

/*
* Property Pages:
*
*   x64 Active(Debug) Compiler Settings:
*		Character Set:              Use Multi-Byte Character Set
*		Warning Level:              Level3 (/W3)
*		Optimization:               Disabled (/Od)
*       Favor Size Or Speed:        Neither
*		Whole Program Optimization: No
*		Enable C++ Exceptions:      No
*		Security Check:             Disable Security Check (/GS-)
*		Precompiled Header:         Not Using Precompiled Headers
*
*   Project->Build Dependencies->Build Customizations...
*		check & apply "masm(.targets, .props)
*
*   x64 Active(Debug) Microsoft Macro Assembler
*		Generate Debug Information:  No
*		Use Safe Exception Handlers: No
*		Pack Alignment Boundary:     One Byte Boundary (/Zp1)(/Zp1)
*       Calling Convention:          Default
*       Error Reporting:             Do not send report (/errorReport:none)(/errorReport:none)
*
*/

// test parameters for x86 ( 32 bit )
// --exe "C:\Program Files (x86)\HxD\HxD.exe" --dll "C:\Users\Administrator\Documents\visual studio 2013\Projects\Sandbox_Mechanics\Debug\x86_UM_Tracer.dll"


#include "x86_Injector.h"


int main(int argc, const char* argv[])
{
	PARGINFO pArgValues;

#if DEBUGLOG
	Log("\n\n[main]: Starting On [%s][%s]...\n", __DATE__, __TIME__);
#endif

	pArgValues = Init_ArgvInfo();
	if (!pArgValues)
		return 1;

	Arg_Handler(pArgValues, argv);

	/* Injection Handler */
	Inject_Handler(pArgValues);

	free(pArgValues);
	//_getch(); For Debugging

	return 0;
}


int x86_CodeCave_Setup(PARGINFO pArgv_Values, PSETUP pSetup)
{
	/* Gathering ShellCode() Information & Creating Code Cave */
	pSetup->TotalSize = sizeof(BYTE) * (X86SHELLCODESIZE + pArgv_Values->dll_path_length);
	pSetup->CodeCave  = (BYTE*)malloc(pSetup->TotalSize); // TODO: Caller Must Free
	if (pSetup->CodeCave != NULL)
	{
		memset(pSetup->CodeCave, 0x00, pSetup->TotalSize);

		/* Jump Table Fixup */
		DWORD   JmpVA = (DWORD)&x86ShellCode;
		DWORD   JmpOffset = *(DWORD*)((BYTE*)JmpVA + 1);
		BYTE*   pShellCode = (BYTE*)(JmpVA + JmpOffset + 5);

		/* Copy ShellCode() Assembly Instructions(Bytes) To Code Cave */
		memcpy(pSetup->CodeCave, pShellCode, (sizeof(BYTE) * pSetup->TotalSize));

		/* Copy LoadLibraryA() Address */
		memcpy((pSetup->CodeCave + X86SHELLCODESIZE) - MINUS4, &pSetup->LoadLibraryA, sizeof(DWORD));

		/* Copy Dll Name To Code Cave */
		memcpy(pSetup->CodeCave + X86SHELLCODESIZE, pArgv_Values->dll_path, pArgv_Values->dll_path_length);

		return 1;
	}

	return 0;
}

int x86_Injection(PREMOTE pRemote, PSETUP pSetup, PARGINFO argv_values, PROCESS_INFORMATION tmpProcessInfo)
{
	BOOL bValid;
	DWORD dwThreadId = 0, RtnResult = 0, VA_of_Fixup = 0;
	SIZE_T BytesWritten;
	unsigned char Return[5] = { 0 };
	BOOL code_cave = 0;

	/* Setup x64 Code Cave */
	if (pRemote != NULL && pSetup != NULL)
	{		
		code_cave = x86_CodeCave_Setup(argv_values, pSetup);
		if (code_cave != NULL)
		{
			/* Allocate Space In Victim Process For Code Cave */
			pRemote->pRemoteMemory = VirtualAllocEx(pRemote->hVictimProcess, NULL, pSetup->TotalSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (!pRemote->pRemoteMemory) 
			{

#if DEBUGLOG
				Log("Couldn't Allocate Memory In Victim Process\n");
#endif

				return 0;
			}

#if DEBUGLOG
			Log("VA Of Code Cave Inside Victim Process:\n\t[0x%p]\n", pRemote->pRemoteMemory);
#endif

			/* Copy Code Cave To Remote Allocated Memory */
			WriteProcessMemory(pRemote->hVictimProcess, pRemote->pRemoteMemory, pSetup->CodeCave, pSetup->TotalSize, &BytesWritten);

			/* Grab Victim Thread Handle */
			pRemote->hVictimThread = OpenThread(
				THREAD_GET_CONTEXT |
				THREAD_SET_CONTEXT |
				THREAD_SUSPEND_RESUME |
				THREAD_QUERY_INFORMATION, FALSE, tmpProcessInfo.dwThreadId);

			if (pRemote->hVictimThread != NULL)
			{
				/* Grab Victim Contex */
				bValid = GetThreadContext(pRemote->hVictimThread, &pRemote->ctx);
				if (!bValid)
				{

#if DEBUGLOG
					Log("GetThreadContext() Failed: %d\n", GetLastError());
#endif
					return 0;
				}

#if DEBUGLOG
				Log("Original Victim [EIP]: 0x%08X\n", pRemote->ctx.Eip);
#endif

				/* Set Returning Rip */
				ReturnEip = pRemote->ctx.Eip;

				/* Realign Stack and Instruction Pointer */
				WriteProcessMemory(pRemote->hVictimProcess, &pRemote->ctx.Esp, &pRemote->ctx.Eip, sizeof(DWORD), &BytesWritten);
				pRemote->ctx.Eip = (DWORD)pRemote->pRemoteMemory;

				/* Set New Victim Context */
				bValid = SetThreadContext(pRemote->hVictimThread, &pRemote->ctx);
				if (!bValid)
				{

#if DEBUGLOG
					Log("SetThreadContext() Failed: %d\n", GetLastError());
#endif

					return 0;
				}

#if DEBUGLOG
				Log("Reset Victim [EIP]: 0x%08X\n", pRemote->ctx.Eip);
#endif

				/* Copy Returning Eip To Code Cave In Remote Process */
				// E9 Jmp Formula:
				// ( Return Address, You Want To Go To ) - ( Virtual Address of current EIP ) - 5 = Bytes To Be Placed.
				// --- Fix --- E9 8A 01 14 77 | jmp <ntdll.RtlUserThreadStart>
				VA_of_Fixup = (DWORD)(((BYTE*)pRemote->ctx.Eip + X86SHELLCODESIZE) - MINUS10);
				RtnResult = ReturnEip - VA_of_Fixup - 5;
				memcpy(Return, &RtnResult, 4);
				memmove(Return + 1, Return, 4); // Shift Bytes Over By 1.
				Return[0] = 0xE9;
				WriteProcessMemory(pRemote->hVictimProcess, ((BYTE*)pRemote->ctx.Eip + X86SHELLCODESIZE) - MINUS10, &Return, 5, &BytesWritten);

				return 1;
			}
		}
	}

	return 0;
}


PREMOTE Init_Remote()
{
	PREMOTE pTemp = (PREMOTE)malloc(sizeof(REMOTE)); // TODO: Caller Needs To Free
	if (pTemp != NULL)
	{
		memset(pTemp, 0, sizeof(REMOTE));
		pTemp->ctx.ContextFlags = CONTEXT_FULL;
		return pTemp;
	}
	return NULL;
}


PSETUP Init_Setup()
{
	PSETUP pTemp = (PSETUP)malloc(sizeof(SETUP)); // TODO: Caller Needs To Free
	if (pTemp != NULL)
	{
		memset(pTemp, 0, sizeof(SETUP));
		return pTemp;
	}
	return NULL;
}


LPVOID MapFile(const char * file)
{
	BOOL bCheck = FALSE;
	HANDLE hFile, hMap;
	LPVOID pBase = NULL;

	if (file == NULL)
		return pBase;

	bCheck = MapFile_From_HardDisk(file, &hFile, &hMap, &pBase);
	if (bCheck != TRUE)
		return pBase; // :) Having a good day

	return pBase;
}


bool Is_MZ(LPVOID pBase)
{
	PIMAGE_DOS_HEADER dos_h;
	dos_h = (PIMAGE_DOS_HEADER)pBase;

	if (dos_h->e_magic == IMAGE_DOS_SIGNATURE)
		return 1;

	return 0;
}


int Is_32_or_64(LPVOID pBase)
{
	int result = 0;
	int index = 0;

	if (pBase != NULL)
	{
		WORD* temp = (WORD*)pBase;

		for (index = 0; index < 500; index++)
		{
			if (temp[index] == IMAGE_FILE_MACHINE_I386)
			{
				result = 1;    // 32 bit found.
				return result;

			}
			else if (temp[index] == IMAGE_FILE_MACHINE_IA64)
			{
				result = 2;    // 64 bit found.
				return result;

			}
			else if (temp[index] == IMAGE_FILE_MACHINE_AMD64)
			{
				result = 2;    // 64 bit found.
				return result;
			}
		}
	}

	return 0;
}


bool Is_32(LPVOID pBase)
{
	PIMAGE_DOS_HEADER dos_h;
	PIMAGE_NT_HEADERS32 nt_h;
	IMAGE_OPTIONAL_HEADER32 op_h;

	dos_h = (PIMAGE_DOS_HEADER)pBase;
	nt_h = (PIMAGE_NT_HEADERS32)((DWORD)pBase + dos_h->e_lfanew);
	op_h = (IMAGE_OPTIONAL_HEADER32)nt_h->OptionalHeader;

	if (op_h.Magic == 0x10B)
		return 1;

	return 0;
}


bool Is_64(LPVOID pBase)
{
	PIMAGE_DOS_HEADER dos_h;
	PIMAGE_NT_HEADERS64 nt_h;
	IMAGE_OPTIONAL_HEADER64 op_h;

	dos_h = (PIMAGE_DOS_HEADER)pBase;
	nt_h = (PIMAGE_NT_HEADERS64)((uint64_t)pBase + dos_h->e_lfanew);
	op_h = (IMAGE_OPTIONAL_HEADER64)nt_h->OptionalHeader;

	if (op_h.Magic == 0x20B)
		return 1;

	return 0;
}


int Inject_Handler(PARGINFO argv_values)
{
	BOOL  bVictim, bMZ = FALSE, b32 = FALSE, b64 = FALSE;
	DWORD dwThreadId = 0;
	HANDLE hVictim;
	HMODULE hModule;
	PSETUP pSetup;
	PREMOTE pRemote;
	STARTUPINFO          tmpStartupInfo;
	PROCESS_INFORMATION	 tmpProcessInfo;
	LPVOID pBase = NULL;
	int arch = 0;

	if (argv_values != NULL)
	{
		/* Init Structures */
		pRemote = Init_Remote();
		pSetup = Init_Setup();
		if (pRemote != NULL && pSetup != NULL)
		{

			ZeroMemory(&tmpProcessInfo, sizeof(tmpProcessInfo));
			ZeroMemory(&tmpStartupInfo, sizeof(tmpStartupInfo));
			tmpStartupInfo.cb = sizeof(tmpStartupInfo);

			if (argv_values->victim_path != NULL)
			{
				// Check Victim Path Static Information...
				pBase = MapFile(argv_values->victim_path);
				if (pBase != NULL)
				{
					// Check MZ Header...
					bMZ = Is_MZ(pBase);
					if (bMZ != NULL)
					{

#if DEBUGLOG
						Log("[Injector_Controller]: Successfully Passed MZ Header Check\n");
#endif
						arch = Is_32_or_64(pBase);

#if DEBUGLOG
						Log("[Injector_Controller]: Arch: [%d]\n", arch);
#endif
						switch (arch)
						{
							case 0:
							{

#if DEBUGLOG
								Log("[Injector_Controller]: 32 bit, 64 bit check failed...\n");
#endif

								return 0;
							}

							case 1:
							{
								b32 = Is_32(pBase);
								break;
							}

							case 2:
							{
								b64 = Is_64(pBase);
								break;
							}
						}
						UnmapViewOfFile(pBase);
					}
				}
				else{

#if DEBUGLOG
					Log("[Injector_Controller]: MapFile Failed... {%s}\n", argv_values->victim_path);
#endif

				}

#if DEBUGLOG
				Log("[Injector_Controller]: b32: [%d], b64: [%d]\n", b32, b64);
#endif

				if ( (b32 == 0 && b64 == 1) || (b32 == 1 && b64 == 0) )
				{

					/* Create Victim Process Suspended */
					bVictim = CreateProcessA(
						(LPSTR)argv_values->victim_path,
						NULL,
						NULL,
						NULL,
						NULL,
						CREATE_SUSPENDED,
						NULL,
						NULL,
						&tmpStartupInfo,
						&tmpProcessInfo
					);
					if (!bVictim)
					{

#if DEBUGLOG
						Log("Couldn't Create Victim Process '%.64s': %d", argv_values->victim_path, GetLastError());
#endif

						return 0;
					}

					/* Suspend All Threads Of Victim Process */
					dwThreadId = suspend_all_threads(tmpProcessInfo.dwProcessId);
					if (!dwThreadId)
					{

#if DEBUGLOG
						Log("Suspending Victim Threads Failed\n");
#endif

						return 0;
					}

					/* Standard Handle For Privilege Adjustment */
					hVictim = tmpProcessInfo.hProcess;

#if DEBUGLOG
					Log("\nVictim Information:\n\t[PID]: [%d] [0x%08X]\n\t[TID]: [%d] [0x%08X]\n\t[Process Handle]: 0x%p\n\t[Thread Handle]: 0x%p\n",
						tmpProcessInfo.dwProcessId, tmpProcessInfo.dwProcessId,
						tmpProcessInfo.dwThreadId, tmpProcessInfo.dwThreadId,
						tmpProcessInfo.hProcess, tmpProcessInfo.hThread);
#endif

					/* Set SeDebugPrivilege Privilege. */
					EnableDebugPriv(hVictim);

					/* Grab Process All Access Handle */
					pRemote->hVictimProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, tmpProcessInfo.dwProcessId);
					if (!pRemote->hVictimProcess)
						return 0;

#if DEBUGLOG
					Log("Victim All Access Handle Acquired...\n\t[%p]\n", pRemote->hVictimProcess);
#endif

					/* Grab LoadLibraryA Address */
					hModule = GetModuleHandle("Kernel32");
					if (hModule != NULL)
					{
						pSetup->LoadLibraryA = GetProcAddress(hModule, "LoadLibraryA");
						if (pSetup->LoadLibraryA != NULL)
						{
							if (b32)
								x86_Injection(pRemote, pSetup, argv_values, tmpProcessInfo);

							/*	Resume Victim Threads */
#if DEBUGLOG
							Log("Resuming Victim Threads:\n");
#endif

							resume_all_threads(tmpProcessInfo.dwProcessId);

							return 1;
						}
					}
				}
			}
		}
	}

	return 0;
}


void EnableDebugPriv(HANDLE hProcess)
{
	HANDLE              hToken;
	LUID                SeDebugNameValue;
	TOKEN_PRIVILEGES    TokenPrivileges;

	if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &SeDebugNameValue))
		{
			// New State Privileges, used in AdjustTokenPrivileges().. See MSDN...
			TokenPrivileges.PrivilegeCount = 1;
			TokenPrivileges.Privileges[0].Luid = SeDebugNameValue;
			TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			if (AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
			{

#if DEBUGLOG
				Log("Victim Debug Privileges Granted...\n");
#endif

				CloseHandle(hToken);

			}
			else {
				CloseHandle(hToken);

#if DEBUGLOG
				Log("Victim AdjustTokenPrivileges() Failed!\n");
#endif

			}

		}
		else {
			CloseHandle(hToken);

#if DEBUGLOG
			Log("Victim LookupPrivilegeValue() Failed!\n");
#endif

		}

	}
	else {

#if DEBUGLOG
		Log("OpenProcessToken() Failed!, Error: %08X\n", GetLastError());
#endif

	}
}


void resume_all_threads(DWORD processId)
{
	DWORD dwSuspendCount = 0;
	HANDLE hThread, hSnapShot;
	THREADENTRY32 te = { 0 };
	te.dwSize = sizeof(THREADENTRY32);

	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, processId);
	if (INVALID_HANDLE_VALUE == hSnapShot) 
	{

#if DEBUGLOG
		Log("Invalid Snap Handle\n");
#endif

	}

	if (Thread32First(hSnapShot, &te)) {

		do
		{
			if (te.th32OwnerProcessID == processId) {
				hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
				if (NULL != hThread)
				{

#if DEBUGLOG
					Log("Resuming Victim Thread %d\n", (DWORD)te.th32ThreadID);
#endif

					do{
						dwSuspendCount = ResumeThread(hThread);

#if DEBUGLOG
						Log("Suspend Count: %d\n", dwSuspendCount);
#endif

						if (dwSuspendCount == 1)
						{

#if DEBUGLOG
							Log("Thread Restarted\n");
#endif

						}
					} while (dwSuspendCount != 0);
					CloseHandle(hThread);

				}
				else {

#if DEBUGLOG
					Log("Failed To Open Victim Thread %d\n", (DWORD)te.th32ThreadID);
#endif

				}
			}
		} while (Thread32Next(hSnapShot, &te));

	}
	else {

#if DEBUGLOG
		Log("Thread32First Failed! %d\n", (DWORD)GetLastError());
#endif

	}
	CloseHandle(hSnapShot);
}


DWORD suspend_all_threads(DWORD processId)
{
	DWORD dwSuspendCount = 0;
	DWORD retval = 0;
	HANDLE hSnapShot;
	HANDLE hThread;
	THREADENTRY32 te = { 0 };
	te.dwSize = sizeof(THREADENTRY32);

	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, processId);
	if (INVALID_HANDLE_VALUE == hSnapShot) 
	{

#if DEBUGLOG
		Log("Invalid Snap Handle\n");
#endif

	}

	if (Thread32First(hSnapShot, &te)) {

		do
		{
			if (te.th32OwnerProcessID == processId) {

				if (0 == retval) {
					retval = (DWORD)te.th32ThreadID;
				}

				hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
				if (NULL != hThread)
				{

#if DEBUGLOG
					Log("Suspending Victim Thread %d\n", (DWORD)te.th32ThreadID);
#endif

					dwSuspendCount = SuspendThread(hThread);

#if DEBUGLOG
					Log("Suspend Count: %d\n", dwSuspendCount);
#endif

					CloseHandle(hThread);
				}
				else {

#if DEBUGLOG
					Log("Failed To Open Victim Thread %d\n", (DWORD)te.th32ThreadID);
#endif

				}
			}
		} while (Thread32Next(hSnapShot, &te));

	}
	else {

#if DEBUGLOG
		Log("Thread32First() Failed! %d\n", (DWORD)GetLastError());
#endif

	}
	CloseHandle(hSnapShot);

	return retval;
}

