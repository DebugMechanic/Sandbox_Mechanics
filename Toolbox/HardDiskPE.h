#ifndef HARDDISKPE_H
#define HARDDISKPE_H

#include <Windows.h>
#include <stdio.h>
#include "Log.h"

BOOL MapFile_From_HardDisk(const char * fileName, HANDLE * hfile, HANDLE * hfileMapping, LPVOID * baseAddress);


#endif