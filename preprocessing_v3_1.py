## YAK_Project
##  https://github.com/SAikirim/YAK_Project.git


test = 0
try:
    import lief
    import datetime
    import datetime as pydatetime
    import string
    import re
    import requests
    import pickle
    import ctypes
except Exception as e:
    excep = str(e)
    ctypes.windll.user32.MessageBoxW(None, excep, "제목", 0)
    return 4


## dos header check
def isDosHeader(binary):
    dos_header = []
    dos_header_list=[23117,144,3,0,4,0,65535,0,184,0,0,0,64,0,0,0]
    try:
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
    except:
        pass
    if dos_header != dos_header_list:
        return True
    else:
        return False

# section name check
def isSectionName(binary):
    section_name_list = ['.00cfg','.AAWEBS','.apiset','.arch','.autoload_text','.bindat','.bootdat','.bss','.buildid','.CLR_UEF','.code','.cormeta','.complua','.CRT','.cygwin_dll_common','.data','.data1','.data2','.data3', '.debug', '.debug$F', '.debug$P', '.debug$S', '.debug$T',  '.drectve', '.didat', '.didata', '.edata', '.eh_fram', '.export', '.fasm', '.flat', '.gfids', '.giats', '.gljmp', '.glue_7t', '.glue_7','.idata' ,'.idlsym', '.impdata', '.import', '.itext', '.ndata', '.orpc', '.pdata', '.rdata', '.reloc', '.rodata', '.rsrc', '.sbss', '.script', '.shared', '.sdata', '.srdata', '.stab', '.stabstr', '.sxdata', '.text', '.text0', '.text1', '.text2', '.text3', '.textbss', '.tls', '.udata', '.vsdata', '.xdata', '.wixburn', '.wpp_sf', '._winzip_', '.adata']
    section_name=[]
    section_name_lower=[]
    section_name_list_lower=[]
    try: 
        for section in binary.sections:
            section_name.append(section.name)
        for i in section_name:
            section_name_lower.append(i.lower())
        for i in section_name_list:
            section_name_list_lower.append(i.lower())
    except:
        pass
    for name1 in section_name_lower:
        if name1 not in section_name_list_lower:
            return True
            break
        else:
            return False


# time date stamp check
# .exe에서 time data stamp를 추출하여 시간으로 변환 (ver. 경로 저장)
import datetime
import datetime as pydatetime

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
                is_ip = 0.8
        #search http or https address
        n = re.search('h\D{3,4}\:\/\/.{0,30}', found_str)
        if n:
            is_dns = 0.8
    PEtoStr.close()
    return is_ip, is_dns



# xor 처리후 문자열 출력
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
        if mal_api in mal_1:
            check_index=mal_api_list_lower.index(mal_api)
            check_api[check_index]=1
        if mal_api in mal_0_8:
            check_index=mal_api_list_lower.index(mal_api)
            check_api[check_index]=0.8
        if mal_api in mal_0_6:
            check_index=mal_api_list_lower.index(mal_api)
            check_api[check_index]=0.6
        if mal_api in mal_0_5:
            check_index=mal_api_list_lower.index(mal_api)
            check_api[check_index]=0.5

    return check_api


mal_api_list=[
'__vbaChkstk',
'__vbaEnd',
'__vbaErrorOverflow',
'__vbaExceptHandler',
'__vbaFPException',
'__vbaFpI4',
'__vbaFreeObj',
'__vbaFreeStr',
'__vbaFreeVar',
'__vbaFreeVarList',
'__vbaHresultCheckObj',
'__vbaInStr',
'__vbaLenBstrB',
'__vbaLenVarB',
'__vbaNew2',
'__vbaObjSetAddref',
'__vbaSetSystemError',
'__vbaStrMove',
'__vbaStrVarMove',
'__vbaUbound',
'__vbaVarAdd',
'__vbaVarMove',
'__vbaVarTstEq',
'__vbaVarTstGt',
'_adj_fdiv_m16i',
'_adj_fdiv_m32',
'_adj_fdiv_m32i',
'_adj_fdiv_m64',
'_adj_fdiv_r',
'_adj_fdivr_m16i',
'_adj_fdivr_m32',
'_adj_fdivr_m32i',
'_adj_fdivr_m64',
'_adj_fpatan',
'_adj_fprem',
'_adj_fprem1',
'_adj_fptan',
'_allmul',
'_CIatan',
'_CIcos',
'_CIexp',
'_CIlog',
'_CIsin',
'_CIsqrt',
'_CItan',
'Accept',
'AdjustTokenPrivileges',
'AttachThreadInput',
'Bind',
'CertOpenSystemStore',
'CloseHandle',
'Connect',
'ConnectNamedpipe',
'ControlService',
'CreateDirectoryW',
'CreateEventW',
'CreateFile',
'CreateFileA',
'CreateFileMapping',
'CreateFileMappingW',
'CreateFileW',
'CreateMutex',
'CreateMutexA',
'CreateMutexW',
'CreateProcess',
'CreateRemoteThread',
'CreateSemaphoreW',
'CreateService',
'CreateThread',
'CreateToolgelp32Snapshot',
'CryptAcuireContext',
'DeleteCriticalSection',
'DeleteFileW',
'DeleteUrlCacheEntry',
'DeviceloControl',
'DispatchMessage',
'DllFunctionCall',
'DuplicateTokenEx',
'EnableExecuteProtectionSupport',
'EnterCriticalSection',
'EnumProcesses',
'EnumProcessModules',
'EVENT_SINK_AddRef',
'EVENT_SINK_QueryInterface',
'EVENT_SINK_Release',
'ExitProcess',
'ExitThread',
'FindFirstFile',
'FindFirstUrlCacheEntryA',
'FindNextUrlCacheEntryA',
'FindResource',
'FindWindow',
'FreeEnvironmentStringsA',
'FreeEnvironmentStringsW',
'FtpPutFile',
'GetAdapterInfo',
'GetAsyncKeyState',
'GetCommandLineA',
'GetCommandLineW',
'GetConsoleCP',
'GetConsoleMode',
'GetCurrentDirectoryW',
'GetCurrentProcess',
'GetCurrentProcessId',
'GetCurrentThreadId',
'GetCurrentThreadld',
'GetDeviceCaps',
'GetEnvironmentStringsW',
'GetEnvironmentVariableW',
'GetFileAttributesExW',
'GetFileAttributesW',
'GetFileSize',
'GetFileType',
'GetForeGroundWindow',
'Gethostbyname',
'Gethostname',
'GetKeyState',
'GetMessage',
'GetModuleFilename',
'GetModuleFileNameA',
'GetModuleFileNameW',
'GetModuleHandle',
'GetModuleHandleA',
'GetModuleHandleW',
'GetProcAddress',
'GetProcessId',
'GetSecurityInfo',
'GetStartupInfo',
'GetStartupInfoA',
'GetStdHandle',
'GetSystemDefaultLangId',
'GetSystemTime',
'GetTempPath',
'GetThreadContext',
'GetTickCount',
'GetTokenInformation',
'GetUserNameA',
'GetVersion',
'GetVersionEx',
'GetVersionExA',
'GetVersionExW',
'GetWindowsDirectory',
'GetWindowsThreadProcessId',
'HeapAlloc',
'HeapDestroy',
'HeapFree',
'HeapReAlloc',
'HeapSize',
'HttpAddRequestHeaders',
'HttpOpenRequest',
'HTTPSendRequest',
'InitializeCriticalSection',
'InternetCloseHandle',
'InternetConnect',
'InternetCrackUrlW',
'InternetOpen',
'InternetOpenA',
'InternetReadFile',
'ioctlsocket',
'IsDebuggerPresent',
'IsNTAdmin',
'LdrLoadDll',
'LeaveCriticalSection',
'LoadLibraryA',
'LoadLibraryExA',
'LoadLibraryExW',
'LoadLibraryW',
'LoadResource',
'LocalAlloc',
'LocalFree',
'LockResource',
'LsaEnumerateLogonSessions',
'MapViewOfFile',
'MapVirtualKey',
'Module32First',
'Module32Next',
'NetScheduleJobAdd',
'OpenEventA',
'OpenEventW',
'OpenMutex',
'OpenProcess',
'OpenServiceA',
'OutputDebugString',
'PeekNamedPipe',
'Process32First',
'Process32FirstW',
'Process32Next',
'Process32NextW',
'QueueUserAPC',
'RaiseException',
'ReadConsoleW',
'ReadProcessMemory',
'Recv',
'RegCloseKey',
'RegCreateKey',
'RegCreateKeyExA',
'RegCreateKeyExW',
'RegDeleteKeyA',
'RegDeleteKeyW',
'RegDeleteValueA',
'RegDeleteValueW',
'RegisterHotKey',
'RegOpenKey',
'RegOpenKeyExA',
'RegOpenKeyExW',
'RegQueryValueExA',
'RegQueryValueExW',
'RegSetValue',
'RegSetValueExA',
'RegSetValueExW',
'ReleaseMutex',
'ResumeThread',
'RtlCreateRegistryKey',
'RtlWriteRegistryValue',
'Send',
'SetEvent',
'SetFileTime',
'SetThreadContext',
'SetWindowsHookEx',
'SetWindowsHookExA',
'SfcTerminateWatcherThread',
'SHBrowseForFolderA',
'ShellExecute',
'ShellExecuteA',
'ShellExecuteExW',
'ShellExecuteW',
'SHFileOperationA',
'SHFileOperationW',
'SHGetFileInfoA',
'SHGetFolderPathW',
'SHGetPathFromIDListA',
'SizeOfResource',
'socket',
'StartServiceA',
'StartServiceCtrlDispatcher',
'SuspendThread',
'System',
'TerminateProcess',
'Thread32First',
'TlsAlloc',
'TlsFree',
'TlsGetValue',
'TlsSetValue',
'Toolhelp32ReadProcessMemory',
'TryEnterCriticalSection',
'UnhandledExceptionFilter',
'UnhookWindowsHookEx',
'URLDownloadToFile',
'URLDownloadToFileA',
'Virtualalloc',
'VirtualAllocEx',
'Virtualfree',
'VirtualProtect',
'VirtualProtectEx',
'VirtualQuery',
'WideCharToMultiByte',
'WinExec',
'WriteConsoleA',
'WriteConsoleW',
'WriteProcessMemory',
'WSAIoctl',
'WSASocket',
'WSAStartup'
]
mal_1 = [
 'accept',
 'shellexecute',
 'shellexecutea',
 'shellexecuteexw',
 'shellexecutew',
 'unhookwindowshookex',
 'urldownloadtofile',
 'urldownloadtofilea',
 'createmutex',
 'createmutexa',
 'createmutexw',
 'createprocess',
 'createremotethread',
 'getcurrentprocess',
 'getcurrentprocessid',
 'getcurrentthreadid',
 'getcurrentthreadld',
 'exitprocess',
 'exitthread',
 'createthread',
 'writeconsolea',
 'writeconsolew',
 'writeprocessmemory',
 'getcommandlinea',
 'getcommandlinew',
 'getconsolecp',
 'getconsolemode',
 'getprocaddress',
 'getprocessid',
 'process32first',
 'process32firstw',
 'process32next',
 'process32nextw',
 'readconsolew',
 'readprocessmemory',
 'openprocess',
 'enumprocesses',
 'suspendthread',
 'system',
 'terminateprocess',
 'thread32first',
  'connect',
 'adjusttokenprivileges',
 'attachthreadinput',
 'bind',
 'certopensystemstore',
 'connectnamedpipe',
 'controlservice',
 'createfilemapping',
 'createfilemappingw',
 'devicelocontrol',
 'enumprocessmodules',
 'findfirstfile',
 'findresource',
 'findwindow',
 'ftpputfile',
 'getadapterinfo',
 'getasynckeystate',
 'getforegroundwindow',
 'gethostbyname',
 'gethostname',
 'getmodulefilename',
 'getmodulefilenamea',
 'getmodulefilenamew',
 'getmodulehandle',
 'getmodulehandlea',
 'getmodulehandlew',
 'getstartupinfo',
 'getsystemdefaultlangid',
 'gettemppath',
 'getthreadcontext',
 'getversionex',
 'getversionexa',
 'getversionexw',
 'getwindowsdirectory',
 'isntadmin',
 'ldrloaddll',
 'loadresource',
 'lsaenumeratelogonsessions',
 'mapviewoffile',
 'mapvirtualkey',
 'module32first',
 'module32next',
 'netschedulejobadd',
 'openmutex',
 'peeknamedpipe',
 'queueuserapc',
 'recv',
 'resumethread',
 'rtlcreateregistrykey',
 'rtlwriteregistryvalue',
 'send',
 'setfiletime',
 'setthreadcontext',
 'setwindowshookex',
 'setwindowshookexa',
 'sfcterminatewatcherthread',
 'toolhelp32readprocessmemory',
 'virtualalloc',
 'virtualallocex',
 'virtualprotect',
 'virtualprotectex',
 'widechartomultibyte',
 'winexec',
 'wsastartup']
 
mal_0_8 = ['regclosekey',
 'regcreatekey',
 'regcreatekeyexa',
 'regcreatekeyexw',
 'regdeletekeya',
 'regdeletekeyw',
 'regdeletevaluea',
 'regdeletevaluew',
 'registerhotkey',
 'regopenkey',
 'regopenkeyexa',
 'regopenkeyexw',
 'regqueryvalueexa',
 'regqueryvalueexw',
 'regsetvalue',
 'regsetvalueexa',
 'regsetvalueexw',
 'httpaddrequestheaders',
 'httpopenrequest',
 'httpsendrequest',
 'initializecriticalsection',
 'internetclosehandle',
 'internetconnect',
 'internetcrackurlw',
 'internetopen',
 'internetopena',
 'internetreadfile',
 'closehandle',
 'createdirectoryw',
 'createeventw',
 'createfile',
 'createfilea',
 'createfilew',
 'createsemaphorew',
 'createservice',
 'createtoolgelp32snapshot',
 'cryptacuirecontext',
 'deletecriticalsection',
 'deletefilew',
 'deleteurlcacheentry',
 'dispatchmessage',
 'dllfunctioncall',
 'duplicatetokenex',
 'enableexecuteprotectionsupport',
 'entercriticalsection',
 'event_sink_addref',
 'event_sink_queryinterface',
 'event_sink_release',
 'findfirsturlcacheentrya',
 'findnexturlcacheentrya',
 'freeenvironmentstringsa',
 'freeenvironmentstringsw',
 'getcurrentdirectoryw',
 'getdevicecaps',
 'getenvironmentstringsw',
 'getenvironmentvariablew',
 'getfileattributesexw',
 'getfileattributesw',
 'getfilesize',
 'getfiletype',
 'getkeystate',
 'getmessage',
 'getsecurityinfo',
 'getstartupinfoa',
 'getstdhandle',
 'getsystemtime',
 'gettickcount',
 'gettokeninformation',
 'getusernamea',
 'getversion',
 'getwindowsthreadprocessid',
 'ioctlsocket',
 'isdebuggerpresent',
 'leavecriticalsection',
 'loadlibrarya',
 'loadlibraryexa',
 'loadlibraryexw',
 'loadlibraryw',
 'localalloc',
 'localfree',
 'lockresource',
 'openeventa',
 'openeventw',
 'openservicea',
 'outputdebugstring',
 'raiseexception',
 'releasemutex',
 'setevent',
 'shbrowseforfoldera',
 'shfileoperationa',
 'shfileoperationw',
 'shgetfileinfoa',
 'shgetfolderpathw',
 'shgetpathfromidlista',
 'sizeofresource',
 'socket',
 'startservicea',
 'startservicectrldispatcher',
 'tryentercriticalsection',
 'unhandledexceptionfilter',
 'wsaioctl',
 'wsasocket',
]
 
mal_0_6 = ['heapalloc',
 'heapdestroy',
 'heapfree',
 'heaprealloc',
 'heapsize',
 'virtualfree',
 'virtualquery',
 'tlsalloc',
 'tlsfree',
 'tlsgetvalue',
 'tlssetvalue']

mal_0_5 = [
'__vbachkstk',
 '__vbaend',
 '__vbaerroroverflow',
 '__vbaexcepthandler',
 '__vbafpexception',
 '__vbafpi4',
 '__vbafreeobj',
 '__vbafreestr',
 '__vbafreevar',
 '__vbafreevarlist',
 '__vbahresultcheckobj',
 '__vbainstr',
 '__vbalenbstrb',
 '__vbalenvarb',
 '__vbanew2',
 '__vbaobjsetaddref',
 '__vbasetsystemerror',
 '__vbastrmove',
 '__vbastrvarmove',
 '__vbaubound',
 '__vbavaradd',
 '__vbavarmove',
 '__vbavartsteq',
 '__vbavartstgt',
 '_adj_fdiv_m16i',
 '_adj_fdiv_m32',
 '_adj_fdiv_m32i',
 '_adj_fdiv_m64',
 '_adj_fdiv_r',
 '_adj_fdivr_m16i',
 '_adj_fdivr_m32',
 '_adj_fdivr_m32i',
 '_adj_fdivr_m64',
 '_adj_fpatan',
 '_adj_fprem',
 '_adj_fprem1',
 '_adj_fptan',
 '_allmul',
 '_ciatan',
 '_cicos',
 '_ciexp',
 '_cilog',
 '_cisin',
 '_cisqrt',
 '_citan']


def All_Check(path):
    tmp = [0 for i in range(10)]
    #ctypes.windll.user32.MessageBoxW(None, path, "제목", 0)
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
        
    # dll character
    if isDllCha(binary):
        tmp[3] = 0.6
        
    # packing 
    if isPacking(binary):
        tmp[4] = 1
        
    # section_num(binary)
    if isSectionNum(binary):
        tmp[5] = 0.4
        
    # string IP, URL
    tmp[6], tmp[7] = ip_URL_search(path)
        
    # XOR 
    if isXor(path, mal_api_list):
        tmp[8] =0.8

    # sizeof_uninitialized_data
    if isUninit(binary):
        tmp[9] =0.5

    # dll
    dll_tmp = isDll(binary)
    tmp += dll_tmp

    # api 
    api_tmp = isApi(binary, mal_api_list)
    tmp += api_tmp

    print(len(tmp))

    # Model Deliver
    try:
        myurl = 'http://192.168.10.140:5000/predict'
        content_type = 'application/json'
        headers = {'content-type': content_type}

        response = requests.post(myurl, data=pickle.dumps(tmp), headers=headers)
        result = response.json()['result']
    except Exception as e:
        return 3

    return result

## test
if __name__ == "__main__":
    #path = r"C:\Users\user\source\repos\Yak_project\nomal.vir"
    #path = r"C:\Windows\System32\calc.exe"
    #path = "nc.exe"
    path = 'C:/Users/user/source/repos/Yak_project/infected2.vir'
    print(All_Check(path))
