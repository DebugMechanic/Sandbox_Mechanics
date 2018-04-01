
#include "Log.h"

VOID WINAPIV Log( CHAR* szFormat, ... )
{	
	FILE *fp;
	CHAR szBuf[1024]; 
	memset(szBuf, 0x0, sizeof(szBuf));

	va_list list; 
	va_start( list, szFormat );
	vsprintf_s( szBuf, szFormat, list ); 
	va_end( list ); 
		
	fp = fopen("c://x64_UM_Tracer.log", "a+");
	if (fp == NULL)
		return;

	fprintf(fp, szBuf);		
	fclose(fp);	
}

