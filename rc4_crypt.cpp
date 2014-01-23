#include <windows.h>
#include <stdio.h>

void RC4(LPBYTE lpBuf, LPBYTE lpKey, DWORD dwBufLen, DWORD dwKeyLen)
{
	int a, b = 0, s[256];
	BYTE swap;
	DWORD dwCount;
	for(a = 0; a < 256; a++)
		s[a] = a;
	
	for(a = 0; a < 256; a++){
		b = (b + s[a] + lpKey[a % dwKeyLen]) % 256;
		swap = s[a];
		s[a] = s[b];
		s[b] = swap;
	}

	for(dwCount = 0; dwCount < dwBufLen; dwCount++){
		a = (a + 1) % 256;
		b = (b + s[a]) % 256;
		swap = s[a];
		s[a] = s[b];
		s[b] = swap;
		lpBuf[dwCount] ^= s[(s[a] + s[b]) % 256];
	}
}

void dump_buffer(FILE *fd, unsigned char *buffer, unsigned int size)
{
	unsigned int index, offset, pos;
	
	for(index = 0; index < size; index += 16){
		for(offset = 0; offset < 16; offset++){
			pos = index + offset;
			if(pos < size)
				fprintf(fd, "\\x%02X", buffer[pos]);
			else
				fprintf(fd, "");
		}
		fprintf(fd, " ");
		for(offset = 0; offset < 16; offset++){
			pos = index + offset;
			if(pos < size)
				fprintf(fd, "%c", isprint(buffer[pos]) ? buffer[pos] : '.');
			else
				break;
		}
		fprintf(fd, "\n");
	}
}

int main(int argc, char **argv)
{
	int nSize;
	printf("RC4 Cipher encrypter/decrypter\n");
	if(argc != 3){
		printf("Usage: [string to en/de/crypt] [key]\n");
		return 0;
	}
	
	printf("Plaintext: %s\n", argv[1]);
	RC4((unsigned char *)argv[1], (unsigned char *)argv[2], strlen(argv[1]), strlen(argv[2]));
	printf("Ciphertext: ");
	dump_buffer(stdout, (unsigned char *)argv[1], strlen(argv[1]));
	RC4((unsigned char *)argv[1], (unsigned char *)argv[2], strlen(argv[1]), strlen(argv[2]));
	printf("Plaintext: %s\n", argv[1]);
	printf("Key: %s\n", argv[2]);
	return 0;
}
