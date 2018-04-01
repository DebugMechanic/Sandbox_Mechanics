#include "Log.h"

VOID WINAPIV Log( CHAR* szFormat, ... )
{
	//CRITICAL_SECTION cs;
	//InitializeCriticalSection(&cs);

	//EnterCriticalSection(&cs);
	FILE *fp;
	CHAR szBuf[1024]; 

	// Clear Buffer
	memset(szBuf, 0x0, sizeof(szBuf));

	va_list list; 
	va_start( list, szFormat );
	vsprintf_s( szBuf, szFormat, list ); 
	va_end( list ); 
		
	fp = fopen("c://Toolbox.log", "a+");
	if (fp == NULL)
		return;

	fprintf(fp, szBuf);
		
	fclose(fp);
	

	//LeaveCriticalSection(&cs);
}

