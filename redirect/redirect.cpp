// redirect.cpp


#include "windows.h"
#include "stdio.h"
#include "tchar.h"
#include "tlhelp32.h"
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

bool PE_Extraction(HANDLE hFile)
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

int CheckWList_Python()
{
    return 1;
}

int All_Check(TCHAR* path) {
    TCHAR text[256];    // 디버깅 출력용
    BYTE test[1130] = { 0, };
    int result = 0;

    /*PyObject* pModule = PyImport_Import(PyUnicode_DecodeFSDefault("lief"));
    if (pModule) {
        MessageBox(NULL, L"PyImport_ImportModulestart : lief", _T("All_Check"), NULL);
    }*/
    MessageBox(NULL, L"text:start", _T("All_Check"), NULL);
    PyObject* mydef = PyImport_ImportModule("preprocessing_v1_4");  // preprocessing_v1_4
        if (mydef) {
            MessageBox(NULL, L"text:PyImport_ImportModule", _T("All_Check"), NULL);
        PyObject* allcheck = PyObject_GetAttrString(mydef, "All_Check");    // All_Check
        if (allcheck) {
            //MessageBox(NULL, L"text: PyObject_GetAttrString", _T("All_Check"), NULL);
            PyObject* r = PyObject_CallFunction(allcheck, "u", path);   // path
            if (r) {
                //MessageBox(NULL, L"text: PyObject_CallFunction ", _T("All_Check"), NULL);
                PyArg_Parse(r, "i", &result);  // &result
 
                Py_XDECREF(r);
            }
            Py_XDECREF(allcheck);
        }
        Py_XDECREF(mydef);
        //Py_XDECREF(pModule);
    }
    wsprintf(text, L" test: 0x%08x\n result: 0x%08x\n path: %s\n *path: 0x%08x\n",
        *test, result, path, (DWORD)path);
    MessageBox(NULL, text, _T("All_Check"), NULL);
    return result;
}

int Python(PVOID pImage, HANDLE hProcess)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNtHeaders;
    PIMAGE_FILE_HEADER pFile;
    PIMAGE_OPTIONAL_HEADER pOption;
    PVOID pEntry;
    PIMAGE_DATA_DIRECTORY pDataDir;
    PIMAGE_SECTION_HEADER pSection;
    DWORD NumberofSections;
    DWORD NumberofData;
    DWORD PointertoRawdata;
    DWORD SizeofRawdata;


    TCHAR text[256];    // 디버거 출력용

    DWORD test[286] = { 0, };  // 1144
    ReadProcessMemory(hProcess, (LPCVOID)pImage, (LPVOID)&test, sizeof(test), NULL);

    pDos = (PIMAGE_DOS_HEADER)pImage;
    pNtHeaders = (PIMAGE_NT_HEADERS)((PCHAR)pImage + pDos->e_lfanew); //((PCHAR)pImage + pDos->e_lfanew);   //((PCHAR)pImage + ((PIMAGE_DOS_HEADER)pImage)->e_lfanew);
    pFile = (PIMAGE_FILE_HEADER)((BYTE*)pNtHeaders + 4);
    pOption = (PIMAGE_OPTIONAL_HEADER)((BYTE*)pNtHeaders + 0x18);
    pEntry = (PVOID)((PCHAR)pImage + pNtHeaders->OptionalHeader.AddressOfEntryPoint);

    NumberofSections = pFile->NumberOfSections;
    NumberofData = pOption->NumberOfRvaAndSizes;

    pDataDir = (PIMAGE_DATA_DIRECTORY)((BYTE*)pOption + 0x60);
    pSection = (PIMAGE_SECTION_HEADER)((BYTE*)pDataDir + (NumberofData * 8));

    for (int i = 0; i < NumberofSections - 1; i++)
    {
        pSection++; // 마지막 섹션으로 이동
    }

    PointertoRawdata = pSection->PointerToRawData;
    SizeofRawdata = pSection->SizeOfRawData;

    wsprintf(text, L"Image base: 0x%08x\n e_magic: 0x%x\n Signature: 0x%08X\n TimeDateStamp: 0x%08x\n sizeof(test): %d\n",
         pImage, pDos->e_magic, pNtHeaders->Signature, pNtHeaders->FileHeader.TimeDateStamp, sizeof(test));
    MessageBox(NULL, text, _T("Current_process"), NULL);

    wsprintf(text, L"Characteristics: 0x%08x\n Characteristics: 0x%08x\n Image entry point: 0x%p\n test: 0x%x\n *test: %x %x %x %x\n",
        pNtHeaders->FileHeader.Characteristics, pFile->Characteristics, pEntry, test, test[0], test[1], test[2], test[3]);
    MessageBox(NULL, text, _T("Current_process2"), NULL);

    wsprintf(text, L"NumberofSections: 0x%08d\n Name: 0x%08s\n PointertoRawdata: 0x%x\n SizeofRawdata: 0x%x\n",
        NumberofSections, pSection->Name, PointertoRawdata, SizeofRawdata);
    MessageBox(NULL, text, _T("Current_process2"), NULL);

    Py_Initialize();
    PyRun_SimpleString("import sys");
    //PyRun_SimpleString("import sys; sys.path.append('C:\\Users\\user\\source\\repos\\Yak_project')");
    //PyRun_SimpleString("import preprocessing_v1_3"); // callme 
    //PyRun_SimpleString("callme.messageBox('test', 'hell', 0)");
    /*wsprintf(text, L"Py_GetPath(): %s\n",
        Py_GetPath());
    MessageBox(NULL, text, _T("Current_process2"), NULL);*/
    Py_Finalize();

    //int check = All_Check();
    return 0; // check;
}

int Python2(HANDLE  hProcess)
{
    TCHAR    sProcessName[MAX_PATH] = { 0, };
    DWORD   nSize = sizeof(CHAR) * MAX_PATH;;
    DWORD   nLen = 0;
    //HANDLE  hProcess = GetCurrentProcess();
    TCHAR text[256];    // 디버거 출력용

    ZeroMemory(sProcessName, nSize);
    if (QueryFullProcessImageName(hProcess, 0, (LPWSTR)sProcessName, &nSize)) {
        wsprintf(text, L"QueryFullProcessImageName: %s\n", sProcessName);
        MessageBox(NULL, text, _T("Current_process2"), NULL);
    }

   /* WCHAR    s1[MAX_PATH] = L"r'";
    WCHAR    s2[MAX_PATH] = L"'";

    wcscat(s1, sProcessName);
    wcscat(s1, s2);*/

    /*wsprintf(text, L"test1: %s\n sProcessName: %08x", s1, sProcessName);
    MessageBox(NULL, text, _T("s2"), NULL);*/


    Py_Initialize();
    PyRun_SimpleString("import sys");
    //PyRun_SimpleString("import lief");
    //PyRun_SimpleString("import sys; sys.path.append('C:\\Users\\user\\source\\repos\\Yak_project')");
    //PyRun_SimpleString("sys.path.append('C:\\Python37\\Lib\\site-packages')");
    //PyRun_SimpleString("import preprocessing_v1_3"); // callme 
    //PyRun_SimpleString("callme.messageBox('test', 'hell', 0)");
    wsprintf(text, L"Py_GetPath(): %s\n",
        Py_GetPath());
    MessageBox(NULL, text, _T("Current_process2"), NULL);

    int check = All_Check(sProcessName);
    Py_Finalize();
    return check;

}

typedef struct _PEB
{
    BYTE                          Reserved1[2];
    BYTE                          BeingDebugged;
    BYTE                          Reserved2[1];
    PVOID                         Reserved3[2]; // Reserved3[1] points to PEB
    //PPEB_LDR_DATA                 Ldr;
    //PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
    //BYTE                          Reserved4[104];
    //PVOID                         Reserved5[52];
    //PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    //BYTE                          Reserved6[128];
    //PVOID                         Reserved7[1];
    //ULONG                         SessionId;
} PEB, * PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
    LONG ExitStatus;    
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

//typedef struct _PROCESS_BASIC_INFORMATION {
//    PVOID Reserved1;
//    PPEB PebBaseAddress;
//    PVOID Reserved2[2];
//    ULONG_PTR UniqueProcessId;
//    PVOID Reserved3;
//} PROCESS_BASIC_INFORMATION;

typedef enum _PROCESSINFOCLASS
{
    ProcessBasicInformation = 0,
} PROCESSINFOCLASS, * PPROCESSINFOCLASS;


typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)
(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
);


//extern NTSTATUS(NTAPI* pNtQueryInformationProcess)(
//    HANDLE ProcessHandle,
//    PROCESSINFOCLASS ProcessInformationClass,
//    PVOID ProcessInformation,
//    ULONG ProcessInformationLength,
//    PULONG ReturnLength);

//

BOOL CheckMalware(HANDLE hProcess, DWORD dwPid)
{
  /*  PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNtHeaders;
    PIMAGE_FILE_HEADER pFile;
    IMAGE_NT_HEADERS pNt;
    IMAGE_FILE_HEADER pFile;
    IMAGE_OPTIONAL_HEADER pOption;
    IMAGE_DATA_DIRECTORY pDataDir;
    IMAGE_SECTION_HEADER pSection;
    DWORD NumberofSections;
    DWORD NumberofData;
    DWORD PointertoRawdata;
    DWORD SizeofRawdata;
    DWORD dwSize;*/

    NTSTATUS status;
    PROCESS_BASIC_INFORMATION pbi;

    PPEB pPeb;
    PVOID pImage;// , pEntry;
    //LONG e_lfanew;
    //SIZE_T NumberOfBytesRead;

    TCHAR text[256];    // 디버거 출력용
    int result; // 디버거 체크옹

    // tset용 나중에 제거
    //DWORD pBase;
    MEMORY_BASIC_INFORMATION info = {};
    DWORD nMem = 0x00000000; 

    

    // tset용 나중에 제거
    PROCESSENTRY32          pe;
    TCHAR                   szProc[MAX_PATH] = L"iexplore.exe";
    DWORD                   dwPID = 0;
    HANDLE                  hSnapShot = INVALID_HANDLE_VALUE;
    BOOL                    bMore = FALSE;

    
    // 멘토님 공유 링크 코드 참조/////////////////////////////////////////////////////////////////////////
    NTSTATUS(NTAPI * pNtQueryInformationProcess)(HANDLE, /*enum _PROCESSINFOCLASS*/DWORD, PVOID, ULONG, PULONG) = NULL;
    
    //extern PVOID GetPeb(HANDLE ProcessHandle);
    
    // PEB definition comes from winternl.h. This is a 32-bit PEB.

    // tset용 나중에 제거
    //STARTUPINFO StartupInfo;
    //PROCESS_INFORMATION ProcessInfo;

    
    pNtQueryInformationProcess = (NTSTATUS(NTAPI*)(HANDLE, /*enum _PROCESSINFOCLASS*/DWORD, PVOID, ULONG, PULONG))
        GetProcAddress(
            GetModuleHandle(TEXT("ntdll.dll")),
            ("NtQueryInformationProcess"));

    if (pNtQueryInformationProcess == NULL)
    {
        DebugLog("GetProcAddress(ntdll.dll, NtQueryInformationProcess) failed with error 0x%08X\n",
            GetLastError());
        return -1;
    }

    
    //PVOID pPeb_t;
    //FARPROC pFunc = NULL;


    memset(&pbi, 0, sizeof(pbi));
    //MessageBox(NULL, L"text1", _T("Current_process"), NULL);
    status = pNtQueryInformationProcess(
        hProcess, // hProcess : calc.exe,   // GetCurrentProcess() : explorer.exe
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        NULL);
    //MessageBox(NULL, L"text2", _T("Current_process"), NULL);
    pPeb = pbi.PebBaseAddress;

    if (status != STATUS_SUCCESS) //if(NT_SUCCESS(status))
    {
        MessageBox(NULL, _T("STATUS_NOT_SUCCESS"), _T("STATUS_SUCCESS"), NULL);
        pPeb = NULL;
    }

    //pPeb = (PPEB)GetPeb(hProcess);    // GetCurrentProcess() // hProcess
    pImage = pPeb->Reserved3[1];
    //pDos = (PIMAGE_DOS_HEADER)pImage;
    /*char test[10000] = { 0, };
    ReadProcessMemory(hProcess, (LPCVOID)(pImage), &test, sizeof(test), NULL);*/
    //pNtHeaders = (PIMAGE_NT_HEADERS)((PCHAR)pImage + pDos->e_lfanew); //((PCHAR)pImage + pDos->e_lfanew);   //((PCHAR)pImage + ((PIMAGE_DOS_HEADER)pImage)->e_lfanew);
    //pFile = (PIMAGE_FILE_HEADER)(pNtHeaders + 4);
    //pEntry = (PVOID)((PCHAR)pImage + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
    
    // 파일에서 추출
    result = Python2(hProcess);

    // 데이터 전달
    //result = Python(pImage, hProcess);

    wsprintf(text, L"Python2: %d\n  PID: %d\n",
        result, dwPid);
    MessageBox(NULL, text, _T("Last Check"), NULL);

     /*wsprintf(text, L"PEB: 0x%08X\n Image base: 0x%08p\n e_lfanew: 0x%x\n Signature: 0x%08X\n TimeDateStamp: 0x%08x\n",
         pPeb, pImage, pDos->e_lfanew, pNtHeaders->Signature, pNtHeaders->FileHeader.TimeDateStamp);
    MessageBox(NULL, text, _T("Current_process"), NULL);

    wsprintf(text, L"Characteristics: 0x%08x\n Characteristics: 0x%08x\n Python: %d\n Image entry point: 0x%p\n PID: %d\n",
         pNtHeaders->FileHeader.Characteristics, pFile->Characteristics, Python(), pEntry, dwPid);
    MessageBox(NULL, text, _T("Current_process2"), NULL);*/


    //-----------------------------------------------------------------

    //printf("Alloc = %p, base = %p, size = %d, protect = %d\n",
    //    info.AllocationBase, info.BaseAddress, info.RegionSize, info.Protect);
    //GetSystemInfo(&si);
    //nMem = (DWORD)si.lpMinimumApplicationAddress; //메모리 주소의 최소값을 구한다.

    // 메모리에서 '0x5a4d' 찾기
    //int test_num = 0;
    //while (nMem < 0x02000000)
    //{
    //    nMem += 2;
    //    VirtualQueryEx(hProcess, (LPCVOID)nMem, &info, sizeof info); // (LPCVOID)0x008d0400
    //    ReadProcessMemory(hProcess, (LPCVOID)info.AllocationBase, &pBase, sizeof(DWORD), NULL); // info.AllocationBase
    //    //wsprintf(text, L"Python: %8d\n base = %p\n, Allocationbase = %p\n, nMem: %p\n, pBase: %p",
    //    //    Python(), info.BaseAddress, info.AllocationBase, nMem, (DWORD)pBase);
    //    //MessageBox(NULL, text, _T("test"), NULL);
    //    
    //    if ((WORD)pBase == 0x5a4d )    // 0x00905a4d
    //    {
    //        test_num++;
    //        wsprintf(text, L"Python: %8d\n base = %p\n, Allocationbase = %p\n, nMem: %p\n, pBase: %p\n",
    //            Python(), info.BaseAddress, info.AllocationBase, (nMem), (DWORD)pBase);
    //        MessageBox(NULL, text, _T("test"), NULL);
    //        if (test_num == 1)
    //        {
    //            //wsprintf(text, L"num: %8d\n  nMem: %p\n, pBase: %p\n",
    //            //    test_num, (nMem), (DWORD)pBase);
    //            //MessageBox(NULL, text, _T("test"), NULL);
    //            break;
    //        }
    //       
    //    }
    //}

    //PE 추출
   // ReadProcessMemory(hProcess, (LPCVOID)nMem, &pDos, sizeof(IMAGE_DOS_HEADER), NULL);
   // LPCVOID Char = ((BYTE*)nMem + pDos.e_lfanew + 0x16);
   // WORD pChar;
   // ReadProcessMemory(hProcess, (LPCVOID)Char, &pChar, sizeof(WORD), NULL);
   ////pDos = (IMAGE_DOS_HEADER*)pBase;
   // wsprintf(text, L"idh.e_magic: %p\n idh.e_lfanew: %p\n Python: %8d\n base = %p\n, Allocationbase = %p\n, nMem: %p\n nMem_v:%p\n Characteristics:%lx\n",
   //     pDos.e_magic, pDos.e_lfanew, Python(), info.BaseAddress, info.AllocationBase, nMem, &nMem, (WORD)pChar);
   // MessageBox(NULL, text, _T("IMAGE_DOS_HEADER"), NULL);
   // 
   // 
   // //pNt = (IMAGE_NT_HEADERS*)(pDos.e_lfanew + nMem);
   // LPCVOID Nt = (LPCVOID)(pDos.e_lfanew + nMem);
   // ReadProcessMemory(hProcess, Nt, &pNt, sizeof(IMAGE_NT_HEADERS), NULL); // (LPCVOID)(pDos.e_lfanew + nMem)
   // wsprintf(text, L"pNt.Signature: %x\n pNt.OptionalHeader: %p\n pNt: %p\n Nt: %p\n nMem: %p\n",
   //     pNt.Signature, pNt.OptionalHeader, (LPCVOID)&pNt, Nt, nMem);
   // MessageBox(NULL, text, _T("IMAGE_NT_HEADERS"), NULL);
   // 
   // //pFile = (IMAGE_FILE_HEADER*)((BYTE*)Nt + 4);
   // LPCVOID File = (BYTE*)Nt + 4;
   // ReadProcessMemory(hProcess, (LPCVOID)File, &pFile, sizeof(IMAGE_FILE_HEADER), NULL);
   // wsprintf(text, L"idh.Signature: %x\n TimeDateStamp: %x\n Characteristics: %p\n &pFile: %p\n File:%p\n Nt: %p\n nMem: %p\n",
   //     pFile.Machine, pFile.TimeDateStamp, pFile.Characteristics, &pFile, File, (DWORD)Nt, (DWORD)nMem) ;
   // MessageBox(NULL, text, _T("IMAGE_FILE_HEADER"), NULL);

   // //pOption = (IMAGE_OPTIONAL_HEADER*)((BYTE*)pNt + 0x18);
   // LPCVOID Option = (BYTE*)Nt + 0x18;
   // ReadProcessMemory(hProcess, (LPCVOID)Option, &pOption, sizeof(IMAGE_OPTIONAL_HEADER), NULL);
   // wsprintf(text, L"idh.Magic: %p\n ImageBase: %p\n DllCharacteristics: %p\n idh.NumberOfRvaAndSizes: %p\n pOption: %p\n Option:%p\n File:%p\n Nt: %p\n nMem: %p\n",
   //     pOption.Magic, pOption.ImageBase, pOption.DllCharacteristics, pOption.NumberOfRvaAndSizes, &pOption, Option, File, (DWORD)Nt, (DWORD)nMem);
   // MessageBox(NULL, text, _T("IMAGE_OPTIONAL_HEADER"), NULL);

   // NumberofSections = pFile.NumberOfSections;
   // NumberofData = pOption.NumberOfRvaAndSizes;
   // LPCVOID DataDir = (IMAGE_DATA_DIRECTORY*)((BYTE*)Option + 0x60);   // 일반적으로 EXPORT table부터 시작
   // ReadProcessMemory(hPro cess, (LPCVOID)DataDir, &pDataDir, sizeof(IMAGE_DATA_DIRECTORY), NULL);

   // LPCVOID Section = (IMAGE_SECTION_HEADER*)((BYTE*)DataDir + (NumberofData * 8));   // Section 헤더 시작
   // ReadProcessMemory(hProcess, (LPCVOID)Section, &pSection, sizeof(IMAGE_SECTION_HEADER), NULL);

   // wsprintf(text, L"NumberofSections: %p\n NumberofData: %p\n pDataDir: %p\n pSection: %p\n",
   //     NumberofSections, NumberofData, DataDir, Section);
   // MessageBox(NULL, text, _T("IMAGE_OPTIONAL_HEADER"), NULL);

   // //for (int i = 0; i < NumberofSections - 1; i++)
   // //{
   // //    pSection++; // 마지막 섹션으로 이동
   // //}

   // PointertoRawdata = pSection.PointerToRawData;
   // SizeofRawdata = pSection.SizeOfRawData;
   // DWORD SectionAddr = pOption.ImageBase + pSection.VirtualAddress;
   // wsprintf(text, L"Name: %s\n, PointertoRawdata: %p\n SizeofRawdata: %p\n SetionAddr: %p\n",
   //     pSection.Name, PointertoRawdata, SizeofRawdata, SectionAddr);
   // MessageBox(NULL, text, _T("IMAGE_SECTION_HEADER"), NULL);

   // // .text section dump
   // // SectionAddr -> SizeofRawdata
   // void* TestSection;
   // ReadProcessMemory(hProcess, (LPCVOID)SectionAddr, &TestSection, SizeofRawdata, NULL);
   // wsprintf(text, L"TestSection: %d\n, &TestSection: %p\n ",
   //     sizeof(TestSection), TestSection);
   // MessageBox(NULL, text, _T("IMAGE_SECTION_HEADER"), NULL);

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
        if(CheckWList_Python())
        { 
            if (CheckMalware(hProcess, dwPID))
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
