#ifndef LOG_H
#define LOG_H

#include <Windows.h>
#include <cstdio>
#include <fstream>

#pragma warning( disable: 4996 )

VOID WINAPIV Log( CHAR* szFormat, ... );

#endif