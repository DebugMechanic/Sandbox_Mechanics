#include "Usage.h"


PARGINFO Init_ArgvInfo()
{
	PARGINFO pTemp = (PARGINFO)malloc(sizeof(ARGINFO)); // Caller Needs To Free
	if (pTemp != NULL)
	{
		memset(pTemp, 0, sizeof(ARGINFO));
		return pTemp;
	}
	return NULL;
}


void Print_Usage()
{
	fprintf(stderr, "\nToolbox Build v1.0 -- By DebugMechanic\n");
	fprintf(stderr, "\nUsage:\n");
	fprintf(stderr, "\t--help    : Print Usage...\n");
	fprintf(stderr, "\t--exe     : (Exe To Trace) -- Ex. C:\\Victim_EXE_Location\\Victim.exe\n");
	fprintf(stderr, "\t--dll     : (Tracer Dll)   -- Ex. C:\\Custom_DLL_Location\\Custom.dll\n");
	fprintf(stderr, "\n");
	exit(1);
}


int ArgvInfoGetInteger(PARGINFO argv_values, const char * value_string)
{
	int i;
	int	value;

	value = atoi(value_string);
	if (value == 0)
	{
		for (i = 0; value_string[i] != 0; i++)
		{
			if (value_string[i] != '0')
			{

#if DEBUGLOG
				Log("Bad Integer Value '%s'\n", value_string);
#endif

				Print_Usage();
			}
		}
	}

	return value;
}


const char ** Arg_Interpreter(PARGINFO argv_values, const char * curarg, const char ** argv)
{
	const char * arg_name;
	int arg_length;

	/* --dll */
	arg_name = "--dll";
	arg_length = (int)strlen(arg_name);
	if (strncmp(curarg, arg_name, arg_length) == 0 && curarg[arg_length] == 0)
	{
		argv++;
		argv_values->dll_path = *argv;
		argv_values->dll_path_length = (int)strlen(argv_values->dll_path) + 1;
		return argv;
	}

	/* --exe */
	arg_name = "--exe";
	arg_length = (int)strlen(arg_name);
	if (strncmp(curarg, arg_name, arg_length) == 0 && curarg[arg_length] == 0)
	{
		argv++;
		argv_values->victim_path = *argv;
		argv_values->victim_path_length = (int)strlen(argv_values->victim_path) + 1;
		return argv;
	}

	/* --help */
	arg_name = "--help";
	arg_length = (int)strlen(arg_name);
	if (strncmp(curarg, arg_name, arg_length) == 0 && curarg[arg_length] == 0)
	{
		Print_Usage();
	}

	return argv;
}


const char ** Arg_Handler(PARGINFO argv_values, const char ** argv)
{
	const char * curarg;
	for (argv++; *argv; argv++) {
		curarg = *argv;
		if (curarg[0] != '-' || curarg[1] == '\0')
			break;
		argv = Arg_Interpreter(argv_values, curarg, argv);
	}
	return argv;
}

