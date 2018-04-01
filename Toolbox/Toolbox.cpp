// Toolbox.cpp : Defines the entry point for the console application.


/*

Debug:

x64 Test :
--exe "C:\Windows\notepad.exe" --dll "C:\Users\Administrator\Documents\visual studio 2013\Projects\Sandbox_Mechanics\x64\Debug\x64_UM_Tracer.dll"

x86 Test :
--exe "C:\Program Files (x86)\HxD\HxD.exe" --dll "C:\Users\Administrator\Documents\visual studio 2013\Projects\Sandbox_Mechanics\Debug\x86_UM_Tracer.dll"

Release:

x64 Test :
--exe "C:\Windows\notepad.exe" --dll "C:\Users\Administrator\Documents\visual studio 2013\Projects\Sandbox_Mechanics\x64\Release\x64_UM_Tracer.dll"
--exe "C:\Program Files (x86)\Steam\steamapps\common\DayZ\BattlEye\BEService_x64.exe" --dll "C:\Users\Administrator\Documents\visual studio 2013\Projects\Sandbox_Mechanics\x64\Release\x64_UM_Tracer.dll"

x86 Test :
--exe "C:\Program Files (x86)\HxD\HxD.exe" --dll "C:\Users\Administrator\Documents\visual studio 2013\Projects\Sandbox_Mechanics\Release\x86_UM_Tracer.dll"

*/


#include <SDKDDKVer.h>
#include <stdio.h>
#include <tchar.h>
#include <Windows.h>
#include <conio.h>
#include <stdint.h>

#include "resource.h"
#include "Usage.h"
#include "HardDiskPE.h"
#include "Log.h"

#pragma warning( disable: 4996)

// Prototypes
BOOL BuildParameters(PARGINFO pArgValues, char* Params);
char* ExtractResource(int id);
int Injector_Controller(PARGINFO pArgValues, const char* argv[]);
LPVOID MapFile(const char * file);
bool Is_MZ(LPVOID pBase);
bool Is_32(LPVOID pBase);
bool Is_64(LPVOID pBase);
int Is_32_or_64(LPVOID pBase);


int main(int argc, const char* argv[])
{
	PARGINFO pArgValues;
	int result = 0;

#if DEBUGLOG
	Log("\n\n[main]: Version Compiled On [%s][%s]...\n", __DATE__, __TIME__);
#endif

	pArgValues = Init_ArgvInfo();
	if (!pArgValues)
		return 1;

	Arg_Handler(pArgValues, argv);

#if DEBUGLOG
	Log("[main]: Successfully Parsed Command Line...\n");
#endif

	if (argc > 1)
	{
		/* Injector Controller */
		result = Injector_Controller(pArgValues, argv);
		if (result)
		{

#if DEBUGLOG
			Log("[main]: PE File Format Does Not Exist, Exiting...\n");
#endif

			free(pArgValues);
			return 1;
		}
	}
	else{
		Print_Usage();
	}

#if DEBUGLOG
	Log("[main]: Exiting Toolbox...\n");
#endif

	free(pArgValues);
	//_getch(); // For Debugging	
	return 0;
}


char* AddDoubleQuotes(const char* string)
{
	size_t len = strlen(string);
	char* NewString = (char*)malloc(len + 1 + 1 + 1); // adding 3 characters
	if (NewString != NULL)
	{
		strcpy(NewString, string);
		memmove(NewString + 1, NewString, len);
		NewString[0] = '\"';
		NewString[len + 1] = '\"';
		NewString[len + 1 + 1] = '\0';
		return NewString;
	}
	return NULL;
}


BOOL BuildParameters(PARGINFO pArgValues, char* Params)
{
	// " --exe "
	char* ExeFlag = " --exe ", *ExeTemp = NULL;
	char* ExeString = (char*)malloc(strlen(ExeFlag) + pArgValues->victim_path_length);
	if (ExeString != NULL)
	{
		strcpy(ExeString, ExeFlag); // str 1
		ExeTemp = AddDoubleQuotes(pArgValues->victim_path);
		strcat(ExeString, ExeTemp); // str 2

		// " --dll "
		char* DllFlag = " --dll ", *DllTemp = NULL;
		char* DllString = (char*)malloc(strlen(DllFlag) + pArgValues->dll_path_length);
		if (DllString != NULL)
		{
			strcpy(DllString, DllFlag); // str 1
			DllTemp = AddDoubleQuotes(pArgValues->dll_path);
			strcat(DllString, DllTemp); // str 2

			// Concatenate New Additions
			strcpy(Params, ExeString);
			strcat(Params, DllString);
			return TRUE;
		}
		return FALSE;
	}
	return FALSE;
}



char* ExtractResource(int id)
{		
	char* hashname = "XXXXXX.exe";             // TODO: Implement hash function for creating filename.
	BOOL is_ok = FALSE;
	HANDLE hFile;
	HRSRC hRes;
	HGLOBAL hGlob;
	LPVOID data_ptr = NULL;
	DWORD data_size = 0, bytes_written = 0;

	char* temp_path = (char*)malloc(MAX_PATH); // TODO: Caller Must Free
	if (temp_path != NULL)
	{
		memset(temp_path, 0x00, MAX_PATH);
		GetTempPath(MAX_PATH, temp_path);                // Path where resource will be placed.
		strcpy(temp_path + strlen(temp_path), hashname); // filename added to path

		hRes = FindResource(NULL, MAKEINTRESOURCE(id), "BIN");
		if (hRes != NULL) {

			hGlob = LoadResource(NULL, hRes);
			if (hGlob != NULL) {

				data_ptr = LockResource(hGlob);
				if (data_ptr != NULL) {

					data_size = SizeofResource(NULL, hRes);
					if (data_size != NULL) {

						hFile = CreateFile(
							temp_path,                     // _In_ LPCTSTR lpFileName,
							GENERIC_READ | GENERIC_WRITE,  // _In_ DWORD dwDesiredAccess,
							0,                             // _In_ DWORD dwShareMode,
							NULL,                          // _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
							CREATE_ALWAYS,                 // _In_ DWORD dwCreationDisposition,
							FILE_ATTRIBUTE_NORMAL,         // _In_ DWORD dwFlagsAndAttributes,
							NULL                           // _In_opt_ HANDLE hTemplateFile
							);
						if (hFile != INVALID_HANDLE_VALUE) {

							is_ok = WriteFile(hFile, data_ptr, data_size, &bytes_written, NULL);
							if (is_ok != FALSE)
								if (bytes_written == data_size){
									CloseHandle(hFile);
									return temp_path; // :) I'm Having a good day...
								}
						}
					}
				}
			}
		}
	}
	return NULL; // :( I'm Having a bad day...
}



int Injector_Controller(PARGINFO pArgValues, const char* argv[])
{
	BOOL bMZ = FALSE, b32 = FALSE, b64 = FALSE, bTest = FALSE;
	LPVOID pBase = NULL;
	char Params[1024] = { 0 };
	PROCESS_INFORMATION ePI = {0};
	STARTUPINFO         rSI = {0};
	int arch = 0;

#if DEBUGLOG
	Log("[Injector_Controller]: Starting Injector_Controller\n");
#endif
	
	ZeroMemory(&rSI, sizeof(rSI));
	rSI.cb = sizeof(rSI);
	ZeroMemory(&ePI, sizeof(ePI));

	rSI.dwFlags = STARTF_USESHOWWINDOW; // A bitfield that determines whether certain STARTUPINFO members are used when the process creates a window.
	rSI.wShowWindow = SW_SHOWNORMAL;

	if (pArgValues != NULL)
	{
		if (pArgValues->victim_path != NULL)
		{
			// Check Victim Path Static Information...
			pBase = MapFile(pArgValues->victim_path);
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

							return 1;
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
				Log("[Injector_Controller]: MapFile Failed... {%s}\n", pArgValues->victim_path);
#endif

			}

#if DEBUGLOG
			Log("[Injector_Controller]: b32: [%d], b64: [%d]\n", b32, b64);
#endif

			if (!b32 && !b64)
				return 1;

#if DEBUGLOG
			Log("[Injector_Controller]: Successfully Passed 32 bit and 64 bit verification...\n");
#endif

			// Build Commandline Parameters For CreateProcess.
			bTest = BuildParameters(pArgValues, Params);
			if (bTest == FALSE)
				return 1;

			// Execute 32 Bit Injector: "x86_Injector"
			if (b32)
			{
				/* Extract Resource */
				char* x86Inj = ExtractResource(x86_INJECTOR);
				if (x86Inj == NULL)
					return 1;

#if DEBUGLOG
				Log("[Injector_Controller]: Extracted 32 Bit Resource Successfully...\n");
#endif

				//char* x86Inj = "C:\\Users\\Administrator\\Documents\\visual studio 2013\\Projects\\Sandbox_Mechanics\\Debug\\x86_Injector.exe";

				BOOL fRet = CreateProcess(
					x86Inj,             // _In_opt_ LPCTSTR lpApplicationName,
					Params,             // _Inout_opt_ LPTSTR lpCommandLine,
					NULL,               // _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
					NULL,               // _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
					TRUE,               // _In_ BOOL bInheritHandles,
					CREATE_NEW_CONSOLE, // _In_ DWORD dwCreationFlags,
					NULL,               // _In_opt_ LPVOID lpEnvironment,
					NULL,               // _In_opt_ LPCTSTR lpCurrentDirectory,
					&rSI,               // where we set up the ShowWIndow setting
					&ePI                // gets populated with handle info
					);

				if (!fRet)
				{

#if DEBUGLOG
					Log("[Injector_Controller]: x86 CreateProcess Failed (%d).\n", GetLastError());
#endif

					return 1;
				}

#if DEBUGLOG
				Log("[Injector_Controller]: Created 32 Bit Process Successfully...\n");
#endif

			}

			// Execute 64 Bit Injector: "x64_Injector"
			if (b64)
			{
				/* Extract Resource */
				char* x64Inj = ExtractResource(x64_INJECTOR);
				if (x64Inj == NULL)
					return 1;

#if DEBUGLOG
				Log("[Injector_Controller]: Extracted 64 Bit Resource Successfully...\n");
#endif

				// char* x64Inj = "C:\\Users\\Administrator\\Documents\\visual studio 2013\\Projects\\Sandbox_Mechanics\\x64\\Debug\\x64_Injector.exe";

				BOOL fRet = CreateProcess(
					x64Inj,             // _In_opt_ LPCTSTR lpApplicationName,
					Params,             // _Inout_opt_ LPTSTR lpCommandLine,
					NULL,               // _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
					NULL,               // _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
					FALSE,              // _In_ BOOL bInheritHandles,
					CREATE_NEW_CONSOLE, // _In_ DWORD dwCreationFlags,
					NULL,               // _In_opt_ LPVOID lpEnvironment,
					NULL,               // _In_opt_ LPCTSTR lpCurrentDirectory,
					&rSI,               // _In_ LPSTARTUPINFO lpStartupInfo,
					&ePI                // _Out_ LPPROCESS_INFORMATION lpProcessInformation
					);

				if (!fRet)
				{

#if DEBUGLOG
					Log("[Injector_Controller]: x64 CreateProcess Failed (%d).\n", GetLastError());
#endif

					return 1;
				}

#if DEBUGLOG
				Log("[Injector_Controller]: Created 64 Bit Process Successfully...\n");
#endif

			}

			CloseHandle(ePI.hProcess);
			CloseHandle(ePI.hThread);
			return 0;
		}
	}	

	return 1;
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
	int index  = 0;
	
	if (pBase != NULL)
	{
		WORD* temp = (WORD*)pBase;

		for (index = 0; index < 500; index++)
		{

#if DEBUGLOG
			Log("[Is_32_or_64]: Check [0x%04X]\n", temp[index]);
#endif

			if (temp[index] == IMAGE_FILE_MACHINE_I386)
			{

#if DEBUGLOG
				Log("[Is_32_or_64]: Found I386\n");
#endif

				result = 1;    // 32 bit found.
				return result;

			}
			else if (temp[index] == IMAGE_FILE_MACHINE_IA64)
			{

#if DEBUGLOG
				Log("[Is_32_or_64]: Found IA64\n");
#endif

				result = 2;    // 64 bit found.
				return result;

			}
			else if (temp[index] == IMAGE_FILE_MACHINE_AMD64)
			{

#if DEBUGLOG
				Log("[Is_32_or_64]: Found AMD64\n");
#endif

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
	nt_h  = (PIMAGE_NT_HEADERS32)( (BYTE*)pBase + dos_h->e_lfanew );
	op_h  = (IMAGE_OPTIONAL_HEADER32)nt_h->OptionalHeader;

#if DEBUGLOG
	Log("[Is_32]: Magic: [0x%04X]\n", op_h.Magic);
#endif

	if (op_h.Magic == 0x010B)
		return 1;

	return 0;
}


bool Is_64(LPVOID pBase)
{
	PIMAGE_DOS_HEADER dos_h;
	PIMAGE_NT_HEADERS64 nt_h;
	IMAGE_OPTIONAL_HEADER64 op_h;

	dos_h = (PIMAGE_DOS_HEADER)pBase;
	nt_h = (PIMAGE_NT_HEADERS64)( (BYTE*)pBase + dos_h->e_lfanew );
	op_h = (IMAGE_OPTIONAL_HEADER64)nt_h->OptionalHeader;

#if DEBUGLOG
	Log("[Is_64]: Magic: [0x%04X]\n", op_h.Magic);
#endif

	if (op_h.Magic == 0x020B)
		return 1;

	return 0;
}


LPVOID MapFile(const char * file)
{
	BOOL bCheck = FALSE;
	HANDLE hFile, hMap;
	LPVOID pBase = NULL;

#if DEBUGLOG
	Log("[MapFile]: Starting MapFile\n");
#endif

	if (file == NULL)
		return pBase;

	bCheck = MapFile_From_HardDisk(file, &hFile, &hMap, &pBase);
	if (bCheck != TRUE)
		return pBase;

	return pBase;
}

