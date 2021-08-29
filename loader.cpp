#include <windows.h>
#include <winnt.h>
#include <stdio.h>




// Loads a PE file from disk to memory and performs relocations and JMP's to start exec
// Think of it like system(), except you do everything yourself
// Mostly from this:
// https://programmer.help/blogs/pe-file-loading-process.html
// With some insight from here:
// https://blog.kowalczyk.info/articles/pefileformat.html


// Putting into the hacks git file, but really I just want to make an exe interpreter eventually
// Running from a memory image that has relocations resolved is easier I think


#define IMAGE_SIZEOF_FILE_HEADER             20
#define IMAGE_DOS_SIGNATURE             0x5A4D      // MZ
#define IMAGE_OS2_SIGNATURE             0x454E      // NE
#define IMAGE_OS2_SIGNATURE_LE          0x454C      // LE
#define IMAGE_NT_SIGNATURE              0x00004550  // PE00

#define SIZE_OF_NT_SIGNATURE sizeof(IMAGE_NT_SIGNATURE)

#define OPTHDROFFSET(a) ((LPVOID)((BYTE *)a                 + \
    ((PIMAGE_DOS_HEADER)a)->e_lfanew + SIZE_OF_NT_SIGNATURE + \
    sizeof (IMAGE_FILE_HEADER)))

DWORD   GetSizeOfImage(void *file)
{
	IMAGE_OPTIONAL_HEADER * oe = (IMAGE_OPTIONAL_HEADER *)OPTHDROFFSET(file);

	return oe->SizeOfImage;
}

int RunExe(char *szFileName)
{
	//Open the file, set the property to be readable and writable
	HANDLE hFile = CreateFileA(szFileName,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_ARCHIVE,
		NULL);

	if (INVALID_HANDLE_VALUE == hFile)
	{
		printf("File open failed\n");
		return 1;
	}

	//Get file size
	DWORD dwFileSize = GetFileSize(hFile, NULL);

	//Request space to read exe into memory
	char *pData = new char[dwFileSize];
	if (NULL == pData)
	{
		printf("Space request failed\n");
		return 2;
	}

	DWORD dwRet = 0;
	ReadFile(hFile, pData, dwFileSize, &dwRet, NULL);
	CloseHandle(hFile);


	char* chBaseAddress = NULL;

	//Get image size
	DWORD dwSizeOfImage = GetSizeOfImage(pData);

	//Create a memory space in the process
	chBaseAddress = (char*)VirtualAlloc(NULL,
		dwSizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	if (NULL == chBaseAddress)
	{
		printf("Failed to request process space\n");
		return NULL;
	}


	RtlZeroMemory(chBaseAddress, dwSizeOfImage);




	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pData;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pData + pDos->e_lfanew);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	//Size of all headers + knot headers
	DWORD dwSizeOfHeaders = pNt->OptionalHeader.SizeOfHeaders;
	//Get the number of sections
	int nNumerOfSections = pNt->FileHeader.NumberOfSections;

	// Copy the previous part
	RtlCopyMemory(chBaseAddress, pData, dwSizeOfHeaders);

	char* chSrcMem = NULL;
	char* chDestMem = NULL;
	DWORD dwSizeOfRawData = 0;
	for (int i = 0; i < nNumerOfSections; i++)
	{
		if ((0 == pSection->VirtualAddress) ||
			(0 == pSection->SizeOfRawData))
		{
			pSection++;
			continue;
		}

		chSrcMem = (char*)((DWORD)pData + pSection->PointerToRawData);
		chDestMem = (char*)((DWORD)chBaseAddress + pSection->VirtualAddress);
		dwSizeOfRawData = pSection->SizeOfRawData;
		RtlCopyMemory(chDestMem, chSrcMem, dwSizeOfRawData);

		pSection++;
	}



	PIMAGE_DOS_HEADER pDosMem = (PIMAGE_DOS_HEADER)chBaseAddress;
	PIMAGE_NT_HEADERS pNtMem = (PIMAGE_NT_HEADERS)(chBaseAddress + pDosMem->e_lfanew);
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pDosMem +
		pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	PIMAGE_BASE_RELOCATION pLoc = (PIMAGE_BASE_RELOCATION)(chBaseAddress + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	//Determine whether there is relocation table
	if ((char*)pLoc == (char*)pDosMem)
	{
		return TRUE;
	}

	while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0) //Start scanning relocation table
	{
		WORD *pLocData = (WORD *)((PBYTE)pLoc + sizeof(IMAGE_BASE_RELOCATION));
		//Calculate the number of relocation items (addresses) to be corrected
		int nNumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		for (int i = 0; i < nNumberOfReloc; i++)
		{
			// Each WORD consists of two parts. The high 4 bits indicate the type of relocation, and a series of images in WINNT.H define the value of relocation type.
			// The lower 12 bits are offset from the VirtualAddress domain, indicating where relocation must occur.

			if ((DWORD)(pLocData[i] & 0x0000F000) == 0x00003000) //This is an address that needs to be fixed
			{
				DWORD* pAddress = (DWORD *)((PBYTE)pDosMem + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
				DWORD dwDelta = (DWORD)pDosMem - pNt->OptionalHeader.ImageBase;
				*pAddress += dwDelta;
			}
		}

		//Move to next section for processing
		pLoc = (PIMAGE_BASE_RELOCATION)((PBYTE)pLoc + pLoc->SizeOfBlock);
	}



	// Loop through DLL in DLL import table and get function address in import table
	char *lpDllName = NULL;
	HMODULE hDll = NULL;
	PIMAGE_THUNK_DATA lpImportNameArray = NULL;
	PIMAGE_IMPORT_BY_NAME lpImportByName = NULL;
	PIMAGE_THUNK_DATA lpImportFuncAddrArray = NULL;
	FARPROC lpFuncAddress = NULL;
	DWORD i = 0;

	while (TRUE)
	{
		if (0 == pImportTable->OriginalFirstThunk)
		{
			break;
		}

		// Get the name of the DLL in the import table and load the DLL
		lpDllName = (char *)((DWORD)pDosMem + pImportTable->Name);
		hDll = GetModuleHandleA(lpDllName);
		if (NULL == hDll)
		{
			hDll = LoadLibraryA(lpDllName);
			if (NULL == hDll)
			{
				pImportTable++;
				continue;
			}
		}

		i = 0;
		// Get OriginalFirstThunk and the first address of the corresponding import function name table
		lpImportNameArray = (PIMAGE_THUNK_DATA)((DWORD)pDosMem + pImportTable->OriginalFirstThunk);
		// Get FirstThunk and the first address of the corresponding import function address table
		lpImportFuncAddrArray = (PIMAGE_THUNK_DATA)((DWORD)pDosMem + pImportTable->FirstThunk);
		while (TRUE)
		{
			if (0 == lpImportNameArray[i].u1.AddressOfData)
			{
				break;
			}

			// Get the image? Import? By? Name structure
			lpImportByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)pDosMem + lpImportNameArray[i].u1.AddressOfData);


			// Determine whether to export function by sequence number or by function name
			if (0x80000000 & lpImportNameArray[i].u1.Ordinal)
			{
				// Serial number export
				lpFuncAddress = GetProcAddress(hDll, (LPCSTR)(lpImportNameArray[i].u1.Ordinal & 0x0000FFFF));
			}
			else
			{
				// Name export
				printf("Importing function %s from DLL %s\r\n", lpImportByName->Name, lpDllName);
				lpFuncAddress = GetProcAddress(hDll, (LPCSTR)lpImportByName->Name);
			}
			lpImportFuncAddrArray[i].u1.Function = (DWORD)lpFuncAddress;
			i++;
		}

		pImportTable++;
	}


	pNt->OptionalHeader.ImageBase = (ULONG32)chBaseAddress;

	char* ExeEntry = (char*)(chBaseAddress + pNt->OptionalHeader.AddressOfEntryPoint);
	// Jump to entry point to execute
	__asm
	{
		mov eax, ExeEntry
		jmp eax
	}

}



int main()
{
	printf("Running exe...\r\n");
	SetCurrentDirectory("c:\\altEngine2\\");
	RunExe("altEngine2.exe");
	return 0;
}