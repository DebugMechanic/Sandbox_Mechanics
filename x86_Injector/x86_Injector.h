#ifndef X86_INJECTOR_H
#define X86_INJECTOR_H


#include <SDKDDKVer.h>
#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <conio.h>
#include <stdint.h>

#include "Usage.h"
#include "HardDiskPE.h"
#include "StringParsing.h"
#include "Log.h"


#define X86SHELLCODESIZE 47

// Helps with creating shellcode
#define MINUS1   1
#define MINUS2   2
#define MINUS3   3
#define MINUS4   4
#define MINUS5   5
#define MINUS6   6
#define MINUS7   7
#define MINUS8   8
#define MINUS9   9
#define MINUS10 10
#define MINUS11 11
#define MINUS12 12
#define MINUS13 13
#define MINUS14 14
#define MINUS15 15
#define MINUS16 16
#define MINUS19 19


/* .ASM Page Prototypes */
extern "C" {
	void x86ShellCode();
	DWORD ReturnEip;
}


/* Prototypes & Types */
typedef struct _Setup{
	int     TotalSize;
	int     CodeSize;
	BYTE*   CodeCave;
	FARPROC LoadLibraryA;
}SETUP, *PSETUP;


typedef struct _Remote{
	HANDLE  hVictimProcess;
	HANDLE  hVictimThread;
	DWORD   dwThreadId;
	CONTEXT	ctx;
	LPVOID  pRemoteMemory;
	DWORD   RtnOffset;
	DWORD   RtnJmpOffset;
}REMOTE, *PREMOTE;


// Prototypes
void EnableDebugPriv(HANDLE hProcess);
void resume_all_threads(DWORD processId);
DWORD suspend_all_threads(DWORD processId);
int MapFile(char * file);
bool Is_MZ(LPVOID pBase);
bool Is_32(LPVOID pBase);
bool Is_64(LPVOID pBase);
int Is_32_or_64(LPVOID pBase);
PREMOTE Init_Remote();
PSETUP Init_Setup();


extern "C"{
	int Inject_Handler(PARGINFO argv_values);
	int x86_CodeCave_Setup(PARGINFO pArgv_Values, PSETUP pSetup);
	int x86_Injection(PREMOTE pRemote, PSETUP pSetup, PARGINFO argv_values, PROCESS_INFORMATION	 tmpProcessInfo);
}


#endif