// generates hash of API names...
#include <windows.h>
#include <stdio.h>

DWORD MakeApiNameHash(char *szApiName)
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


int main(int argc, char **argv)
{
	char *format = "Hash: %s:%x\n";
	if(argc == 2)
		printf(format, argv[1], MakeApiNameHash(argv[1])); 
	else printf("Enter API name to hash\n");
	return 0;
}
