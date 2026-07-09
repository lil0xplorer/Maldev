#include <stdio.h>
#include <windows.h>
#include "resource.h"

#define IDR_RCDATA1 101

int main() {

	HRSRC hRsrc = NULL;
	HGLOBAL hGlobal = NULL;
	PVOID pPayloadAddress = NULL;
	SIZE_T sPayloadSize = NULL;

	hRsrc = FindResourceA(NULL,MAKEINTRESOURCE(IDR_RCDATA1),RT_RCDATA); //finds our resource that is calc.ico

	hGlobal = LoadResource(NULL,hRsrc); //load it 

	pPayloadAddress  = LockResource(hGlobal); //lock in

	sPayloadSize = SizeofResource(NULL,hRsrc); //size calculation of resource

	printf("shellcode address: 0x%p \n",pPayloadAddress); //shellcode address in the .rsrc section

	printf("shellcode size: %ld \n",sPayloadSize); //shellcode size

	LPVOID tempspace = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sPayloadSize); //making a tempspace to move shellcode
	if (tempspace != NULL) {
		memcpy(tempspace,pPayloadAddress,sPayloadSize); //copying the shellcode to that new tempspace
	}

	printf("new allocated shellcode space: 0x%p \n",tempspace);
	getchar();
}
