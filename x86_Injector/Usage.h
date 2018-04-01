#ifndef UTRACE_H
#define UTRACE_H

#include <stdio.h>
#include <Windows.h>
#include "Log.h"

typedef struct tagArgInfo{
	const char * victim_path;
	const char * dll_path;
	int dll_path_length;
	int victim_path_length;
} ARGINFO, *PARGINFO;

/* Prototypes */
PARGINFO Init_ArgvInfo();
void Print_Usage();
int ArgvInfoGetInteger(PARGINFO argv_values, const char * value_string);
const char ** Arg_Interpreter(PARGINFO argv_values, const char * curarg, const char ** argv);
const char ** Arg_Handler(PARGINFO argv_values, const char ** argv);
void EnableDebugPriv(HANDLE hProcess);

#endif