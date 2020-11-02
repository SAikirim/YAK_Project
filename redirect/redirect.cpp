// redirect.cpp

#include "windows.h"
#include "stdio.h"
#include "tchar.h"
#include "tlhelp32.h"
#include "WinNT.h"
#include <Python.h>


#define STR_MODULE_NAME					    (L"redirect.dll")
#define STATUS_SUCCESS						(0x00000000L) 

typedef LONG NTSTATUS;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PVOID TebBaseAddress;
	CLIENT_ID ClientId;
	ULONG AffinityMask;
	LONG Priority;
	LONG BasePriority;
} THREAD_BASIC_INFORMATION;

typedef NTSTATUS (WINAPI *PFZWRESUMETHREAD)
(
    HANDLE ThreadHandle, 
    PULONG SuspendCount
);

typedef NTSTATUS (WINAPI *PFZWQUERYINFORMATIONTHREAD)
(
    HANDLE ThreadHandle, 
    ULONG ThreadInformationClass, 
    PVOID ThreadInformation, 
    ULONG ThreadInformationLength, 
    PULONG ReturnLength
);


BYTE g_pZWRT[5] = {0,};

void DebugLog(const char *format, ...)
{
	va_list vl;
	FILE *pf = NULL;
	char szLog[512] = {0,};

	va_start(vl, format);
	wsprintfA(szLog, format, vl);
	va_end(vl);

    OutputDebugStringA(szLog);
}

BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) 
{
    TOKEN_PRIVILEGES tp;
    HANDLE hToken;
    LUID luid;

    if( !OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, 
			              &hToken) )
    {
        DebugLog("OpenProcessToken error: %u\n", GetLastError());
        return FALSE;
    }

    if( !LookupPrivilegeValue(NULL,             // lookup privilege on local system
                              lpszPrivilege,    // privilege to lookup 
                              &luid) )          // receives LUID of privilege
    {
        DebugLog("LookupPrivilegeValue error: %u\n", GetLastError() ); 
        return FALSE; 
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if( bEnablePrivilege )
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.
    if( !AdjustTokenPrivileges(hToken, 
                               FALSE, 
                               &tp, 
                               sizeof(TOKEN_PRIVILEGES), 
                               (PTOKEN_PRIVILEGES) NULL, 
                               (PDWORD) NULL) )
    { 
        DebugLog("AdjustTokenPrivileges error: %u\n", GetLastError() ); 
        return FALSE; 
    } 

    if( GetLastError() == ERROR_NOT_ALL_ASSIGNED )
    {
        DebugLog("The token does not have the specified privilege. \n");
        return FALSE;
    } 

    return TRUE;
}

BOOL hook_by_code(LPCSTR szDllName, LPCSTR szFuncName, PROC pfnNew, PBYTE pOrgBytes)
{
	FARPROC pFunc = NULL;
	DWORD dwOldProtect = 0, dwAddress = 0;
	BYTE pBuf[5] = {0xE9, 0, };
	PBYTE pByte = NULL;
    HMODULE hMod = NULL;

    hMod = GetModuleHandleA(szDllName);
    if( hMod == NULL )
    {
        DebugLog("hook_by_code() : GetModuleHandle(\"%s\") failed!!! [%d]\n",
                  szDllName, GetLastError());
        return FALSE;
    }

	pFunc = (FARPROC)GetProcAddress(hMod, szFuncName);
    if( pFunc == NULL )
    {
        DebugLog("hook_by_code() : GetProcAddress(\"%s\") failed!!! [%d]\n",
                  szFuncName, GetLastError());
        return FALSE;
    }

	pByte = (PBYTE)pFunc;
	if( pByte[0] == 0xE9 )
    {
        DebugLog("hook_by_code() : The API is hooked already!!!\n");
		return FALSE;
    }

	if( !VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect) )
    {
        DebugLog("hook_by_code() : VirtualProtect(#1) failed!!! [%d]\n", GetLastError());
        return FALSE;
    }

	memcpy(pOrgBytes, pFunc, 5);

	dwAddress = (DWORD)pfnNew - (DWORD)pFunc - 5;
	memcpy(&pBuf[1], &dwAddress, 4);

	memcpy(pFunc, pBuf, 5);

	if( !VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect) )
    {
        DebugLog("hook_by_code() : VirtualProtect(#2) failed!!! [%d]\n", GetLastError());
        return FALSE;
    }

	return TRUE;
}

BOOL unhook_by_code(LPCSTR szDllName, LPCSTR szFuncName, PBYTE pOrgBytes)
{
	FARPROC pFunc = NULL;
	DWORD dwOldProtect = 0;
	PBYTE pByte = NULL;
    HMODULE hMod = NULL;

    hMod = GetModuleHandleA(szDllName);
    if( hMod == NULL )
    {
        DebugLog("unhook_by_code() : GetModuleHandle(\"%s\") failed!!! [%d]\n",
                  szDllName, GetLastError());
        return FALSE;
    }

	pFunc = (FARPROC)GetProcAddress(hMod, szFuncName);
    if( pFunc == NULL )
    {
        DebugLog("unhook_by_code() : GetProcAddress(\"%s\") failed!!! [%d]\n",
                  szFuncName, GetLastError());
        return FALSE;
    }

	pByte = (PBYTE)pFunc;
	if( pByte[0] != 0xE9 )
    {
        DebugLog("unhook_by_code() : The API is unhooked already!!!");
        return FALSE;
    }

	if( !VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect) )
    {
        DebugLog("unhook_by_code() : VirtualProtect(#1) failed!!! [%d]\n", GetLastError());
        return FALSE;
    }

	memcpy(pFunc, pOrgBytes, 5);

	if( !VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect) )
    {
        DebugLog("unhook_by_code() : VirtualProtect(#2) failed!!! [%d]\n", GetLastError());
        return FALSE;
    }

	return TRUE;
}

BOOL IsVistaLater()
{
    OSVERSIONINFO osvi;

    ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

    GetVersionEx(&osvi);

    if( osvi.dwMajorVersion >= 6 )
        return TRUE;

    return FALSE;
}

typedef DWORD (WINAPI *PFNTCREATETHREADEX)
( 
    PHANDLE                 ThreadHandle,	
    ACCESS_MASK             DesiredAccess,	
    LPVOID                  ObjectAttributes,	
    HANDLE                  ProcessHandle,	
    LPTHREAD_START_ROUTINE  lpStartAddress,	
    LPVOID                  lpParameter,	
    BOOL	                CreateSuspended,	
    DWORD                   dwStackSize,	
    DWORD                   dw1, 
    DWORD                   dw2, 
    LPVOID                  Unknown 
); 

BOOL MyCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pThreadProc, LPVOID pRemoteBuf)
{
    HANDLE      hThread = NULL;
    FARPROC     pFunc = NULL;

    if( IsVistaLater() )    // Vista, 7, Server2008
    {
        pFunc = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
        if( pFunc == NULL )
        {
            DebugLog("MyCreateRemoteThread() : GetProcAddress() failed!!! [%d]\n",
                   GetLastError());
            return FALSE;
        }

        ((PFNTCREATETHREADEX)pFunc)(&hThread,       // pFunc : NtCreateThreadEx
                                    0x1FFFFF,
                                    NULL,
                                    hProcess,
                                    pThreadProc,
                                    pRemoteBuf,
                                    FALSE,
                                    NULL,
                                    NULL,
                                    NULL,
                                    NULL);
        if( hThread == NULL )
        {
            DebugLog("MyCreateRemoteThread() : NtCreateThreadEx() failed!!! [%d]\n", GetLastError());
            return FALSE;
        }
    }
    else                    // 2000, XP, Server2003
    {
        hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                     pThreadProc, pRemoteBuf, 0, NULL);
        if( hThread == NULL )
        {
            DebugLog("MyCreateRemoteThread() : CreateRemoteThread() failed!!! [%d]\n", GetLastError());
            return FALSE;
        }
    }

	if( WAIT_FAILED == WaitForSingleObject(hThread, INFINITE) )
    {
        DebugLog("MyCreateRemoteThread() : WaitForSingleObject() failed!!! [%d]\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath)
{
	HANDLE                  hProcess = NULL;
    HANDLE                  hThread = NULL;
	LPVOID                  pRemoteBuf = NULL;
    DWORD                   dwBufSize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);
	LPTHREAD_START_ROUTINE  pThreadProc = NULL;
    BOOL                    bRet = FALSE;
    HMODULE                 hMod = NULL;

	if ( !(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)) )
    {
        DebugLog("InjectDll() : OpenProcess(%d) failed!!! [%d]\n", dwPID, GetLastError());
		goto INJECTDLL_EXIT;
    }

	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, 
                                MEM_COMMIT, PAGE_READWRITE);
    if( pRemoteBuf == NULL )
    {
        DebugLog("InjectDll() : VirtualAllocEx() failed!!! [%d]\n", GetLastError());
        goto INJECTDLL_EXIT;
    }

	if( !WriteProcessMemory(hProcess, pRemoteBuf, 
                           (LPVOID)szDllPath, dwBufSize, NULL) )
    {
        DebugLog("InjectDll() : WriteProcessMemory() failed!!! [%d]\n", GetLastError());
        goto INJECTDLL_EXIT;
    }

    hMod = GetModuleHandle(L"kernel32.dll");
    if( hMod == NULL )
    {
        DebugLog("InjectDll() : GetModuleHandle() failed!!! [%d]\n", GetLastError());
        goto INJECTDLL_EXIT;
    }

	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryW");
    if( pThreadProc == NULL )
    {
        DebugLog("InjectDll() : GetProcAddress() failed!!! [%d]\n", GetLastError());
        goto INJECTDLL_EXIT;
    }

    if( !MyCreateRemoteThread(hProcess, pThreadProc, pRemoteBuf) )  // LoadLibraryW를 실행
    {
        DebugLog("InjectDll() : MyCreateRemoteThread() failed!!!\n");
        goto INJECTDLL_EXIT;
    }

    bRet = TRUE;

INJECTDLL_EXIT:

    if( pRemoteBuf )
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);

    if( hThread )
	    CloseHandle(hThread);

    if( hProcess )
	    CloseHandle(hProcess);

	return bRet;
}

//typedef struct MY_IMAGE_DOS_HEADER {
//    WORD   e_magic;          // DOS signature : 4D5A ("MZ")
//    WORD   e_cblp;
//    WORD   e_cp;
//    WORD   e_crlc;
//    WORD   e_cparhdr;
//    WORD   e_minalloc;
//    WORD   e_maxalloc;
//    WORD   e_ss;
//    WORD   e_sp;
//    WORD   e_csum;
//    WORD   e_ip;
//    WORD   e_cs;
//    WORD   e_lfarlc;
//    WORD   e_ovno;
//    WORD   e_res[4];
//    WORD   e_oemid;
//    WORD   e_oeminfo;
//    WORD   e_res2[10];
//    LONG   e_lfanew;         // offset to NT header 
//}IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

bool CheckPE(HANDLE hFile)
{
    IMAGE_DOS_HEADER* pDos;
    IMAGE_NT_HEADERS* pNt;
    IMAGE_FILE_HEADER* pFile;
    IMAGE_OPTIONAL_HEADER* pOption;
    IMAGE_DATA_DIRECTORY* pDataDir;
    IMAGE_SECTION_HEADER* pSection;
    DWORD NumberofSections;
    DWORD NumberofData;
    DWORD PointertoRawdata;
    DWORD SizeofRawdata;
    DWORD dwSize;

    HANDLE hMap = CreateFileMapping(hFile, 0, PAGE_READONLY, 0, 0, 0);
    void* pBase = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);


    /* (BYTE *)는 그 주소와 상수를 더하기 위해 필요함 */
    pDos = (IMAGE_DOS_HEADER*)pBase;
    pNt = (IMAGE_NT_HEADERS*)(pDos->e_lfanew + (BYTE*)pDos);
    pFile = (IMAGE_FILE_HEADER*)((BYTE*)pNt + 4);
    pOption = (IMAGE_OPTIONAL_HEADER*)((BYTE*)pNt + 0x18);

    if (pDos->e_magic != 0x5a4d || pNt->Signature != 0x4550)
    {
        return FALSE;
    }

    NumberofSections = pFile->NumberOfSections;
    NumberofData = pOption->NumberOfRvaAndSizes;

    pDataDir = (IMAGE_DATA_DIRECTORY*)((BYTE*)pOption + 0x60);
    pSection = (IMAGE_SECTION_HEADER*)((BYTE*)pDataDir + (NumberofData * 8));

    for (int i = 0; i < NumberofSections - 1; i++)
    {
        pSection++; // 마지막 섹션으로 이동
    }

    PointertoRawdata = pSection->PointerToRawData;
    SizeofRawdata = pSection->SizeOfRawData;
    dwSize = GetFileSize(hFile, &dwSize);

    UnmapViewOfFile(pBase);
    CloseHandle(hMap);

    /* 실제 파일의 사이즈가 PE 구조에 나타난 크기 보다 작을 경우 FALSE 반환 */
    if (PointertoRawdata + SizeofRawdata > dwSize)
    {
        return FALSE;
    }

    return TRUE;
}

int Python()
{
    Py_Initialize();
    PyRun_SimpleString("import sys; sys.path.append('C:\\Users\\user\\source\\repos\\Yak_project')");
    PyRun_SimpleString("import callme;");
    PyRun_SimpleString("callme.messageBox('test', 'hell', 0)");
    Py_Finalize();

    return 0;
}

BOOL CheckMalware(HANDLE hProcess)
{
    IMAGE_DOS_HEADER idh ;
    TCHAR                   szProc[MAX_PATH] = L"iexplore.exe";
    DWORD                   dwPID = 0;
    HANDLE                  hSnapShot = INVALID_HANDLE_VALUE;
    PROCESSENTRY32          pe;
    BOOL                    bMore = FALSE;
    TCHAR text[256];
    MEMORY_BASIC_INFORMATION info = {};
    
    
    //printf("Alloc = %p, base = %p, size = %d, protect = %d\n",
    //    info.AllocationBase, info.BaseAddress, info.RegionSize, info.Protect);

    // 메모리에서 PE 추출
    VirtualQueryEx(hProcess, (LPCVOID)0x00000000, &info, sizeof info);
    ReadProcessMemory(hProcess, info.BaseAddress, &idh, sizeof(IMAGE_DOS_HEADER),NULL);
    wsprintf(text, L"idh.e_magic: %8x\n idh.e_lfanew: %x\n Python: %8d\n base = %p\n", idh.e_magic, idh.e_lfanew, Python(), info.BaseAddress);
    MessageBox(NULL, text, _T("악성코드 발견!"), NULL);
 

     // Get the snapshot of the system
    pe.dwSize = sizeof(PROCESSENTRY32);
    hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
    if (hSnapShot == INVALID_HANDLE_VALUE)
    {
        _tprintf(L"CheckMalware() : CreateToolhelp32Snapshot() failed!!! [%d]",
            GetLastError());
        return FALSE;
    }

    // find process
    bMore = Process32First(hSnapShot, &pe);
    for (; bMore; bMore = Process32Next(hSnapShot, &pe))
    {
        dwPID = pe.th32ProcessID;

        // 시스템의 안정성을 위해서
        // PID 가 100 보다 작은 시스템 프로세스에 대해서는
        // DLL Injection 을 수행하지 않는다.
        if (dwPID < 100)
            continue;

        if (!_tcsicmp(pe.szExeFile, szProc))
        {
            CloseHandle(hSnapShot);
            return TRUE;
        }
    }

    CloseHandle(hSnapShot);
    return FALSE;
}

NTSTATUS WINAPI NewZwResumeThread(HANDLE ThreadHandle, PULONG SuspendCount)
{
    HANDLE  hProcess = NULL;
    NTSTATUS status, statusThread;
    FARPROC pFunc = NULL, pFuncThread = NULL;
    DWORD dwPID = 0;
	static DWORD dwPrevPID = 0;
    THREAD_BASIC_INFORMATION tbi;
    HMODULE hMod = NULL;
    TCHAR szModPath[MAX_PATH] = {0,};
    TCHAR text[MAX_PATH];

    DebugLog("NewZwResumeThread() : start!!!\n");

    hMod = GetModuleHandle(L"ntdll.dll");
    if( hMod == NULL )
    {
        DebugLog("NewZwResumeThread() : GetModuleHandle() failed!!! [%d]\n",
                  GetLastError());
        return NULL;
    }


    // call ntdll!ZwQueryInformationThread()
    pFuncThread = GetProcAddress(hMod, "ZwQueryInformationThread");
    if( pFuncThread == NULL )
    {
        DebugLog("NewZwResumeThread() : GetProcAddress() failed!!! [%d]\n",
                  GetLastError());
        return NULL;
    }

    statusThread = ((PFZWQUERYINFORMATIONTHREAD)pFuncThread)
                   (ThreadHandle, 0, &tbi, sizeof(tbi), NULL);
    if( statusThread != STATUS_SUCCESS )
    {
        DebugLog("NewZwResumeThread() : pFuncThread() failed!!! [%d]\n", 
                 GetLastError());
        return NULL;
    }

    dwPID = (DWORD)tbi.ClientId.UniqueProcess;
    if ( (dwPID != GetCurrentProcessId()) && (dwPID != dwPrevPID) )
    {
        DebugLog("NewZwResumeThread() => call InjectDll()\n");

        dwPrevPID = dwPID;

        // change privilege
       	if( !SetPrivilege(SE_DEBUG_NAME, TRUE) )
            DebugLog("NewZwResumeThread() : SetPrivilege() failed!!!\n");

        // get injection dll path
        GetModuleFileName(GetModuleHandle(STR_MODULE_NAME), 
                          szModPath, 
                          MAX_PATH);

        if( !InjectDll(dwPID, szModPath) )
            DebugLog("NewZwResumeThread() : InjectDll(%d) failed!!!\n", dwPID);

        // check malware
        DebugLog("NewZwResumeThread() -> CheckMalware() : start!!!\n");
        if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
        {
            DebugLog("InjectDll() : OpenProcess(%d) failed!!! [%d]\n", dwPID, GetLastError());
            return NULL;
        }

        if (CheckMalware(hProcess))
        {
            wsprintf(text, L"악성코드로 의심되는 프로세스(%d)가 실행되었습니다.\n 종료하시겠습니까??\n", dwPID);
            if (MessageBox(NULL, text, _T("악성코드 발견!"), MB_ICONASTERISK | MB_YESNO) == IDYES)
            {
                if (!TerminateProcess(hProcess, 0))
                {
                    DebugLog("CheckMalware() : ExitProcess() failed!!!\n");
                    return NULL;
                }
            }
            else
            {
                DebugLog("CheckMalware() : ExitProcess() No!!!\n");
            }
        }
        if (hProcess)
            CloseHandle(hProcess);
    }



    // call ntdll!ZwResumeThread()
    if( !unhook_by_code("ntdll.dll", "ZwResumeThread", g_pZWRT) )
    {
        DebugLog("NewZwResumeThread() : unhook_by_code() failed!!!\n");
        return NULL;
    }

    pFunc = GetProcAddress(hMod, "ZwResumeThread");
    if( pFunc == NULL )
    {
        DebugLog("NewZwResumeThread() : GetProcAddress() failed!!! [%d]\n",
                  GetLastError());
        goto __NTRESUMETHREAD_END;
    }

    status = ((PFZWRESUMETHREAD)pFunc)(ThreadHandle, SuspendCount);
    if( status != STATUS_SUCCESS )
    {
        DebugLog("NewZwResumeThread() : pFunc() failed!!! [%d]\n", GetLastError());
        goto __NTRESUMETHREAD_END;
    }


__NTRESUMETHREAD_END:

    if( !hook_by_code("ntdll.dll", "ZwResumeThread", 
                      (PROC)NewZwResumeThread, g_pZWRT) )
    {
        DebugLog("NewZwResumeThread() : hook_by_code() failed!!!\n");
    }
    
    DebugLog("NewZwResumeThread() : end!!!\n");

    return status;
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch( fdwReason )
    {
        case DLL_PROCESS_ATTACH : 
            DebugLog("DllMain() : DLL_PROCESS_ATTACH\n");

            // hook
            hook_by_code("ntdll.dll", "ZwResumeThread", 
                         (PROC)NewZwResumeThread, g_pZWRT);
            break;

        case DLL_PROCESS_DETACH :
            DebugLog("DllMain() : DLL_PROCESS_DETACH\n");

            // unhook
            unhook_by_code("ntdll.dll", "ZwResumeThread", 
                           g_pZWRT);
            break;
    }

    return TRUE;
}
