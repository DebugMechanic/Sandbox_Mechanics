#include "HardDiskPE.h"


BOOL MapFile_From_HardDisk(const char * fileName, HANDLE * hfile, HANDLE * hfileMapping, LPVOID * baseAddress)
{

#if DEBUGLOG
	Log("[MapFile_From_HardDisk]: Starting MapFile_From_HardDisk\n");
#endif

	if (fileName == NULL)
		return 1;

#if DEBUGLOG
	Log("[MapPE_From_HardDisk]: Opening %s\n", fileName);
#endif

	// Open file for read access
	(*hfile) = CreateFileA(
		fileName,                  //LPCTSTR lpfileName
		GENERIC_READ,              //DWORD dwDesiredAccess
		FILE_SHARE_READ,           //DWORD dwShareMode		
		NULL,                      //LPSECURITY_ATIRIBUTES (if NULL, handle cannot be inherited)
		OPEN_EXISTING,             //DWORD dWCreationDisposition
		FILE_ATTRIBUTE_NORMAL,     //WORD dwFlagsAndAttributes
		NULL                       //HANOLE hTemplatefile (if NULL, ignored)		
	);
	if ((*hfile) != INVALID_HANDLE_VALUE)
	{

#if DEBUGLOG
		Log("[MapPE_From_HardDisk]: Acquired Read Access...\n");
#endif

		// Create mapping handle.
		(*hfileMapping) = CreateFileMapping(
			*hfile,           //HANDLE hFile
			NULL,             //LPSECURITY_ATIRIBUTES (if NULL, handle cannot be inherited)
			PAGE_READONLY,    //DWORD flProtect
			0,                //DWORD dwMaximumSizeHigh
			0,                //DWORD dwMaximumSizeLow
			NULL              //LPCTSTR lpName (NULL, mapped object unnamed)	
		);
		if ((*hfileMapping) != NULL)
		{

#if DEBUGLOG
			Log("[MapPE_From_HardDisk]: Acquired File Mapping Handle...\n");
#endif

			// Create map of file to acquire base address of mapping.
			(*baseAddress) = MapViewOfFile(
				*hfileMapping,   //HANDLE hFileMappingObject
				FILE_MAP_READ,   //DWORD dwDesiredAccess
				0,               //DWORD dwFileOffsetHigh
				0,               //DWORD dwFileOffsetLow
				0                //SIZE_T dwNumberOfBytesToMap (if a, from offset to the end of section)
			);
			if ((*baseAddress) != NULL)
			{

#if DEBUGLOG
				Log("[MapPE_From_HardDisk]: Successfully Mapped File...\n");
#endif

				return 0; // :) I'm having a good day
			}
			else{
		
				CloseHandle(*hfileMapping);
				CloseHandle(*hfile);

#if DEBUGLOG
				Log("MapViewOfFile() Failed: [%d]\n", GetLastError());
#endif

				return 1;
			}

		}
		else{

			CloseHandle(*hfile);

#if DEBUGLOG
			Log("[MapPE_From_HardDisk]: CreateFileMapping() Failed: [%d]\n", GetLastError());
#endif

			return 1;
		}

	}

#if DEBUGLOG
	Log("[MapPE_From_HardDisk]: Createfile() Failed: [%d]\n", GetLastError());
#endif

	return 1;
}

