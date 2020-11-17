// MalDetecter.cpp
// YAK_Project
// https://github.com/SAikirim/YAK_Project.git

#include "windows.h"
#include "stdio.h"
#include "tchar.h"
#include "tlhelp32.h"
#include <Python.h>



#define STR_MODULE_NAME					    (L"MalDetecter.dll")
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
    
    // 로컬 시스템에 대한 LUID를 가져옴.
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




int WhiteListCheck(TCHAR* file_name) {
    int result = 2;
    TCHAR text[256];    // 디버깅 출력용

    PyObject* whitelist = PyImport_ImportModule("whitelist");
    if (whitelist) {
        PyObject* check = PyObject_GetAttrString(whitelist, "whiteListCheck");
        if (check) {
            PyObject* r = PyObject_CallFunction(check, "u", file_name);
            if (r) {
                PyArg_Parse(r, "i", &result);
                Py_XDECREF(r);
            }
            Py_XDECREF(check);
        }
        Py_XDECREF(whitelist);
    }
    if (result == 3)
    {
        wsprintf(text, L"WhiteListCheck() : %d\n", result);
        MessageBox(NULL, text, _T("모델서버 에러"), NULL);
        DebugLog("WhiteListCheck() : whiteListCheck() failed!!! [%d]\n",
            GetLastError());
        return NULL;
    }
    if (result == 4)
    {
        wsprintf(text, L"WhiteListCheck() : %d\n", result);
        MessageBox(NULL, text, _T("whitelist 에러"), NULL);
        DebugLog("WhiteListCheck() : whiteListCheck() failed!!! [%d]\n",
            GetLastError());
        return NULL;
    }

    return result;
}


int Python2(HANDLE  hProcess)
{
    TCHAR   sProcessName[MAX_PATH] = { 0, };
    DWORD   nSize = sizeof(CHAR) * MAX_PATH;;
    DWORD   nLen = 0;
    TCHAR text[256];    // 디버거 출력용

    ZeroMemory(sProcessName, nSize);
    if ( !QueryFullProcessImageName(hProcess, 0, (LPWSTR)sProcessName, &nSize)) {
        wsprintf(text, L"QueryFullProcessImageName: %s\n", sProcessName);
        MessageBox(NULL, text, _T("Current_process2"), NULL);
        DebugLog("CheckMalware() : Python2() failed!!! [%d]\n",
            GetLastError());
        return NULL;
    }

    Py_Initialize();
    int check = 0;
    if (Py_IsInitialized())
    {
        PyRun_SimpleString("import sys\n sys.path.append('.')");
        // WhiteListCheck체크
        check = WhiteListCheck(sProcessName);
        
    }
    return check;
   
}


BOOL CheckMalware(HANDLE hProcess, DWORD dwPid)
{
    int result; // 디버거 체크옹
    TCHAR text[256];    // 디버거 출력용
    
    // 파일에서 추출
    result = Python2(hProcess);
    if (result == 2)
    {
        wsprintf(text, L"Python2() : %d\n", result);
        MessageBox(NULL, text, _T("전처리 에러"), NULL);
        DebugLog("CheckMalware() : Python2() failed!!! [%d]\n",
            GetLastError());
        return NULL;
    }

    return result;

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
    TCHAR text[320];

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
            if (CheckMalware(hProcess, dwPID))
            {
                wsprintf(text, L"악성코드로 의심되는 프로세스(%d)가 실행되었습니다.\n(악성코드가 아니면 whitelist에 직접 추가해 주세요(소문자사용))\n 종료하시겠습니까??\n", dwPID);
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
