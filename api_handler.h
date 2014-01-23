#ifndef APIH_H
#define APIH_H
// our API name enumeration table
enum pApiHashes{
	nWriteProcessMemory,
	nOpenProcess,
};

// our API name hash table...
static const DWORD dwAPIHashTable[] = { 
	0xd83d6aa1, // WriteProcessMemory
	0xefe297c0, // OpenProcess
}; 

// our API pointers...
static FARPROC pWriteProcessMemory;
static FARPROC pOpenProcess;

// our API prototypes list...
BOOL 	sWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
HANDLE	sOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);

// global return value storage
DWORD dwReturnValue;
LPVOID lpK32Base;
#endif
