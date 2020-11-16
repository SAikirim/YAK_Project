#!/usr/bin/env python
# coding: utf-8


#get_ipython().system('pip install setuptools --upgrade')
#get_ipython().system('pip install lief')



test = 0
try:
    import lief
except:
    test = 11

#import subprocess
import datetime
import datetime as pydatetime
import string
import re
import requests
import pickle



## dos header check
def isDosHeader(binary):
    dos_header = [binary.dos_header.magic,
              binary.dos_header.used_bytes_in_the_last_page,
              binary.dos_header.file_size_in_pages,
              binary.dos_header.numberof_relocation,
              binary.dos_header.header_size_in_paragraphs,
              binary.dos_header.minimum_extra_paragraphs,
              binary.dos_header.maximum_extra_paragraphs,
              binary.dos_header.initial_relative_ss,
              binary.dos_header.initial_sp,
              binary.dos_header.checksum,
              binary.dos_header.initial_ip,
              binary.dos_header.initial_relative_cs,
              binary.dos_header.addressof_relocation_table,
              binary.dos_header.overlay_number,
              binary.dos_header.oem_id,
              binary.dos_header.oem_info]
    dos_header_list=[23117,144,3,0,4,0,65535,0,184,0,0,0,64,0,0,0]
    if dos_header != dos_header_list:
        return True
    else:
        return False



# section name check
def isSectionName(binary):
    section_name_list = ['.00cfg','.AAWEBS','.apiset','.arch','.autoload_text','.bindat','.bootdat','.bss','.buildid','.CLR_UEF','.code','.cormeta','.complua','.CRT','.cygwin_dll_common','.data','.data1','.data2','.data3', '.debug', '.debug$F', '.debug$P', '.debug$S', '.debug$T',  '.drectve', '.didat', '.didata', '.edata', '.eh_fram', '.export', '.fasm', '.flat', '.gfids', '.giats', '.gljmp', '.glue_7t', '.glue_7','.idata' ,'.idlsym', '.impdata', '.import', '.itext', '.ndata', '.orpc', '.pdata', '.rdata', '.reloc', '.rodata', '.rsrc', '.sbss', '.script', '.shared', '.sdata', '.srdata', '.stab', '.stabstr', '.sxdata', '.text', '.text0', '.text1', '.text2', '.text3', '.textbss', '.tls', '.udata', '.vsdata', '.xdata', '.wixburn', '.wpp_sf', '._winzip_', '.adata']

    section_name=[]
    for section in binary.sections:
        section_name.append(section.name)
    section_name_lower=[]
    section_name_list_lower=[]
    for i in section_name:
        section_name_lower.append(i.lower())
    for i in section_name_list:
        section_name_list_lower.append(i.lower())
    for name1 in section_name_lower:
        if name1 not in section_name_list_lower:
            return True
            break
        else:
            return False





# time date stamp check
# .exe에서 time data stamp를 추출하여 시간으로 변환 (ver. 경로 저장)

def isTimeDate(binary):
    t = binary.header.time_date_stamps
    date = datetime.datetime.fromtimestamp(int(t)).strftime('%Y-%m-%d %H:%M:%S')

    # 현재시간을 timestamp형식으로 변환
    # 얻은 값을 int형으로 변환

    def get_now():
        return pydatetime.datetime.now()

    def get_now_timestamp():
        return get_now().timestamp()

    ts = get_now_timestamp()
    date2=int(t)
    ts2=int(ts)

    # 현재 시간보다 큰 값에서 1을 츨력. (아닌 값은 0)
    if (date2 > ts2) | (date2 < ts2 - 631152000):
        return True
    else:
        return False


# dll characteristics check
def isDllCha(binary):
    dll_list = list(binary.optional_header.dll_characteristics_lists)
    for i in range(len(dll_list)):
        if str(dll_list[i]) == 'DLL_CHARACTERISTICS.WDM_DRIVER':
            return True
        else:
            continue
    return False




# packing 유무
def isPacking(binary):
    raw_size=[]
    for section in binary.sections:
        raw_size.append(section.sizeof_raw_data)
    virtual_size=[]
    for section in binary.sections:
        virtual_size.append(section.virtual_size)
    if (raw_size[0] == 0 | ((virtual_size[0]-raw_size[0])> (raw_size[0] * 2)) ):
        return True
    else:
        return False


# section 갯수
def isSectionNum(binary):
    section_name=[]
    for section in binary.sections:
        section_name.append(section.name)
    if len(section_name) > 4:
        return True
    else:
        return False


# IP, URL check
printable = set(string.printable)
def process(stream):
    found_str = ""
    while True:
        data = stream.read(1024*4)
        i = 0
        if not data:
            break  
        for char in data:
            char = chr(char)
            if i > 4:
                break
            if char in printable:
                found_str += char
            elif len(found_str) >= 4:
                #if len bigger than 4 return found_str
                yield found_str       
                found_str = ""
            else:
                found_str = ""
              
def ip_URL_search(path):
    is_ip = 0
    is_dns = 0
    PEtoStr = open(path, 'rb')
    for found_str in process(PEtoStr):
        print()
        #search ip address
        m = re.search('(\d{1,3}\.){3}\d{1,3}', found_str)
        if m:
            if m.group(0) != '127.0.0.1' and m.group(0) !='6.0.0.0':
                is_ip = 1
        #search http or https address
        n = re.search('h\D{3,4}\:\/\/.{0,30}', found_str)
        if n:
            is_dns = 1
    PEtoStr.close()
    return is_ip, is_dns




# xor 처리후 문자열 출력
import string
printable = set(string.printable)
def Bytearray(stream, num):
    found_str = ""
    while True:
        data = stream.read(1024*4)
        i = 0
        if not data:
            break
        for char in data:
            char ^= num
            char = chr(char)
            if i > 4:
                break
            if char in printable:
                found_str += char
            elif len(found_str) >= 4:
                #if len bigger than 4 return found_str
                yield found_str       
                found_str = ""
            else:
                found_str = ""


# ip, url 검출
def check_ip_url(string):
    #search ip address
    m = re.search('(\d{1,3}\.){3}\d{1,3}', string)
    if m:
        if m.group(0) != '127.0.0.1' and m.group(0) !='6.0.0.0':
            return 1
    #search http or https address
    n = re.search('h\D{3,4}\:\/\/.{0,30}', string)
    if n:
        return 1




# xor check
#
def isXor(path, mal_api_list):

    is_xor = 0
    count = 0
    f = open(path,'rb')
    for num in range(1, 256):
        if(count==1):
            break
        for found_str in Bytearray(f, num):
            if (found_str in mal_api_list or check_ip_url(found_str)) and count==0:
                    count = 1
                    is_xor = 1
    f.close()
    return is_xor



# binary.optional_header.sizeof_uninitialized_data
def isUninit(binary):
    if binary.optional_header.sizeof_uninitialized_data > 0:
        return True
    else:
        return False




# dll check
def isDll(binary):
    mal_dll_list=['KERNEL32.DLL','USER32.DLL','GDI32.DLL','ADVAPI32.DLL','OLEAUT32.DLL','MSVBVM60.DLL','OLE32.DLL','COMCTL32.DLL','MSVCRT.DLL','SHELL32.DLL','QT5CORE.DLL','WS2_32.DLL','WININET.DLL','GDIPLUS.DLL','SHLWAPI.DLL','WSOCK32.DLL']
    dll_name=[]
    for dll in binary.libraries:
        dll_name.append(dll)

    dll_name_lower=[]
    mal_dll_list_lower=[]
    for i in dll_name:
        dll_name_lower.append(i.lower())
    for i in mal_dll_list:
        mal_dll_list_lower.append(i.lower())

    check_dll=[0 for i in range(len(mal_dll_list))]
    for mal_dll in mal_dll_list_lower:
        if mal_dll in dll_name_lower:
            check_dll_index=mal_dll_list_lower.index(mal_dll)
            check_dll[check_dll_index]=1

    return check_dll



# API check
def isApi(binary, mal_api_list):

    function_name=[]
    for function in binary.imported_functions:
        function_name.append(function.name)

    function_name_lower=[]
    mal_api_list_lower=[]
    for i in function_name:
        function_name_lower.append(i.lower())
    for i in mal_api_list:
        mal_api_list_lower.append(i.lower())

    check_api=[0 for i in range(len(mal_api_list))]
    for mal_api in mal_api_list_lower:
        if mal_api in function_name_lower:
            check_index=mal_api_list_lower.index(mal_api)
            check_api[check_index]=1

    return check_api



mal_api_list=['Accept',
'AdjustTokenPrivileges',
'AttachThreadInput',
'Bind',
'BitBlt',
'CertOpenSystemStore',
'Connect',
'ConnectNamedpipe',
'ControlService',
'CreateFile',
'CreateFileMapping',
'CreateMutex',
'CreateProcess',
'CreateRemoteThread',
'CreateService',
'CreateToolgelp32Snapshot',
'CryptAcuireContext',
'DeviceloControl',
'DispatchMessage',
'EnableExecuteProtectionSupport',
'EnumProcesses',
'EnumProcessModules',
'FindFirstFile',
'FindResource',
'FindWindow',
'FtpPutFile',
'GetAdapterInfo',
'GetAsyncKeyState',
'GetDC',
'GetForeGroundWindow',
'Gethostbyname',
'Gethostname',
'GetKeyState',
'GetMessage',
'GetModuleFilename',
'GetModuleHandle',
'GetProcAddress',
'GetStartupInfo',
'GetSystemDefaultLangId',
'GetTempPath',
'GetThreadContext',
'GetVersionEx',
'GetWindowsDirectory',
'GetWindowsThreadProcessId',
'HttpOpenRequest',
'HttpAddRequestHeaders',
'HTTPSendRequest',
'ioctlsocket',
'IsNTAdmin',
'InternetReadFile',
'InternetOpen',
'InternetConnect',
'LdrLoadDll',
'LoadResource',
'LockResource',
'LsaEnumerateLogonSessions',
'MapViewOfFile',
'MapVirtualKey',
'Module32First',
'Module32Next',
'NetScheduleJobAdd',
'OpenMutex',
'OpenProcess',
'OutputDebugString',
'PeekNamedPipe',
'Process32First',
'QueueUserAPC',
'ReadProcessMemory',
'Recv',
'RegisterHotKey',
'RegOpenKey',
'RegSetValue',
'RegCreateKey',
'ResumeThread',
'RtlCreateRegistryKey',
'RtlWriteRegistryValue',
'Send',
'SetFileTime',
'SetThreadContext',
'SetWindowsHookEx',
'SetWindowsHookExA',
'SfcTerminateWatcherThread',
'ShellExecute',
'SizeOfResource',
'socket',
'StartServiceCtrlDispatcher',
'SuspendThread',
'System',
'Thread32First',
'Toolhelp32ReadProcessMemory',
'VirtualAllocEx',
'VirtualProtectEx',
'WideCharToMultiByte',
'WinExec',
'WriteProcessMemory',
'WSAIoctl',
'WSAStartup',
'WSASocket',
'URLDownloadToFile',
'DeleteCriticalSection',
'LeaveCriticalSection',
'EnterCriticalSection',
'InitializeCriticalSection',
'Virtualfree',
'Virtualalloc',
'VirtualProtect',
'VirtualQuery',
'LocalFree',
'LocalAlloc',
'GetCurrentThreadld',
'GetStartupInfoA',
'CloseHandle',
'CreateFileA',
'RaiseException',
'ExitProcess',
'CreateThread',
'GetCommandLineA',
'GetModuleFileNameA',
'CreateEventW',
'CreateFileMappingW',
'CreateFileW',
'CreateMutexW',
'CreateSemaphoreW',
'WriteConsoleW',
'UnhandledExceptionFilter',
'Sleep',
'SleepEx',
'SetEvent',
'DeleteUrlCacheEntry',
'FindFirstUrlCacheEntryA',
'FindNextUrlCacheEntryA',
'DuplicateTokenEx',
'GetTokenInformation',
'GetFileType',
'GetSystemTime',
'GetFileSize',
'GetStdHandle',
'ReadFile',
'WriteFile',
'DuplicateTokenEx',
'GetTokenInformation',
'ShellExecuteExW',
'RegOpenKeyExW',
'RegQueryValueExW',
'ExitProcess',
'GetConsoleCP',
'GetConsoleMode',
'GetCurrentProcess',
'GetCurrentProcessId',
'GetEnvironmentStringsW',
'GetEnvironmentVariableW',
'GetFileAttributesExW',
'GetFileAttributesW',
'CreateDirectoryW',
'DeleteFileW',
'EnterCriticalSection',
'GetCommandLineW',
'GetCurrentDirectoryW',
'GetModuleHandleA',
'GetModuleHandleW',
'GetProcAddress',
'InitializeCriticalSection',
'HeapAlloc',
'HeapDestroy',
'HeapFree',
'HeapReAlloc',
'HeapSize',
'ReadConsoleW',
'TlsAlloc',
'TlsFree',
'TlsGetValue',
'TlsSetValue',
'TryEnterCriticalSection',
'LoadLibraryA',
'RegCloseKey',
'TerminateProcess',
'OpenEventA',
'OpenEventW',
'OpenProcess',
'GetProcessId',
'ExitThread',
'RegCreateKeyExW',
'RegDeleteKeyW',
'RegDeleteValueW',
'RegEnumKeyExW',
'RegOpenKeyExW',
'RegQueryInfoKeyW',
'RegSetValueExW',
'RegQueryValueExW',
'RegSetValueExA',
'RegCreateKeyExA',
'ShellExecuteW',
'ShellExecuteA',
'InternetCrackUrlW',
'InternetCloseHandle',
'LoadLibraryExA',
'LoadLibraryExW',
'LoadLibraryW',
'ReleaseMutex',
'OpenServiceA',
'StartServiceA',
'FreeEnvironmentStringsA',
'FreeEnvironmentStringsW',
'_adj_fdiv_m32',
'__vbaChkstk',
'EVENT_SINK_Release'
'__vbaEnd'
'EVENT_SINK_QueryInterface',
'_allmul',
'_adj_fdivr_m64', 
'_adj_fprem',
'_adj_fpatan', 
'EVENT_SINK_AddRef',
'__vbaInStr', 
'_adj_fdiv_m32i', 
'__vbaLenVarB', 
'__vbaExceptHandler', 
'__vbaSetSystemError', 
'__vbaFreeVarList', 
'DllFunctionCall', 
'__vbaFPException', 
'__vbaStrVarMove', 
'_adj_fdivr_m16i', 
'__vbaUbound', 
'__vbaVarAdd', 
'_adj_fdiv_r',  
'__vbaFreeVar',  
'__vbaObjSetAddref', 
'_adj_fdiv_m64', 
'__vbaFreeObj', 
'_CIsin', 
'_CIsqrt', 
'__vbaHresultCheckObj', 
'_CIlog', 
'__vbaLenBstrB', 
'__vbaVarTstGt',  
'_CIcos', 
'__vbaVarTstEq', 
'_adj_fptan', 
'__vbaVarMove', 
'__vbaErrorOverflow', 
'_CIatan', 
'__vbaNew2', 
'_adj_fdivr_m32i', 
'_CIexp', 
'__vbaStrMove', 
'_adj_fprem1', 
'_adj_fdivr_m32', 
'_CItan', 
'__vbaFpI4', 
'__vbaFreeStr', 
'_adj_fdiv_m16i',
'URLDownloadToFileA',
'WriteConsoleA',
'RegDeleteKeyA',
'RegDeleteValueA',
'RegOpenKeyExA',
'RegQueryValueExA'
]




#path = r"C:\Users\user\source\repos\Yak_project\nc.exe"
#path = "C:\Windows\System32\calc.exe"
#path = "nc.exe"
path = 'infected.vir'

# preprocessing PE file data of list
def All_Check(path):
    tmp = [0 for i in range(13)] #14
    binary = lief.parse(path)
    
    # Dos Header 
    if isDosHeader(binary):
        tmp[0] = 1
        
    # section name 
    if isSectionName(binary):
        tmp[1] = 1
        
    # time_date
    if isTimeDate(binary):
        tmp[2] = 1
        tmp[3] = 1
        tmp[4] = 1
        tmp[5] = 1
        tmp[6] = 1
        
    # dll character
    if isDllCha(binary):
        tmp[7] = 1
        
    # packing 
    if isPacking(binary):
        tmp[8] = 1
        
    # section_num(binary)
    if isSectionNum(binary):
        tmp[9] = 1
        
    # string IP, URL
    tmp[10], tmp[11] = ip_URL_search(path)

        
    # XOR 
    if isXor(path, mal_api_list):
        tmp[12] =1

    # sizeof_uninitialized_data
##    if isUninit(binary):
##        tmp[13] =1
    
    # dll
    dll_tmp = isDll(binary)
    tmp += dll_tmp
    
    # api 
    api_tmp = isApi(binary, mal_api_list)
    tmp += api_tmp

    print(tmp)
    print(len(tmp))
    
    myurl = 'http://192.168.10.140:5000/predict'
    content_type = 'application/json'
    headers = {'content-type': content_type}

    response = requests.post(myurl, data=pickle.dumps(tmp), headers=headers)
    resurlt = response.json()['result']

    if len(tmp) == 286:
        return 7
    
    if test == 11:
        return 5

##    if tmp[12] == 1:
##        return 4
##    
##    if tmp[0] == 1:
##        return 2
##        
##    if tmp[0] == 0:
##        return 3
    
    return resurlt

# if all process's done, tmp should be appended at result

print(All_Check(path))


