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
    ctypes.windll.user32.MessageBoxW(None, excep, "Exception", 0)
    test = 4

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
    if len(section_name) > 6:
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
    mal_dll_list=['ADVAPI32.DLL','OLEAUT32.DLL','MSVBVM60.DLL','OLE32.DLL','COMCTL32.DLL','MSVCRT.DLL','SHELL32.DLL','QT5CORE.DLL','WS2_32.DLL','WININET.DLL','GDIPLUS.DLL','SHLWAPI.DLL','WSOCK32.DLL']
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
'GetCurrentThreadld',
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
'GetModuleHandle',
'GetProcessId',
'GetSecurityInfo',
'GetStartupInfo',
'GetStartupInfoA',
'GetSystemDefaultLangId',
'GetSystemTime',
'GetTempPath',
'GetThreadContext',
'GetTokenInformation',
'GetUserNameA',
'GetVersion',
'GetVersionEx',
'GetVersionExA',
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
'InternetConnect',
'InternetCrackUrlW',
'InternetOpen',
'InternetOpenA',
'InternetReadFile',
'ioctlsocket',
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
'SHFileOperationA',
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
'WSAStartup',
'_CorDllMain',
'ZP',
'AnyPopup',
'DnsValidateName_W',
'AccessCheckAndAuditAlarmA',
'DnsApiFree',
'DnsNameCompare_W',
'EnumPropsExA',
'AccessCheckByTypeResultListAndAuditAlarmW',
'BroadcastSystemMessage',
'CreateDesktopA',
'BRUSHOBJ_ulGetBrushColor',
'LZSeek',
'CoInstall',
'CoSetState',
'BaseQueryModuleData',
'WSApSetPostRoutine',
'lstrcpyn',
'GetInterfaceInfo',
'DeleteColorSpace',
'SetSystemMenu',
'GetAltTabInfoW',
'TileChildWindows',
'PaintDesktop',
'SetDeskWallpaper',
'MessageBoxTimeoutA',
'midiStreamProperty',
'DragObject',
'DrawCaptionTempA',
'SetUserObjectInformationA',
'BroadcastSystemMessageExW',
'FoldStringA',
'EngCreateClip',
'DrawFrame',
'MenuWindowProcW',
'WriteProfileSectionW',
'EraseTape',
'ChangeMenuW',
'GetAltTabInfoA',
'LoadKeyboardLayoutEx',
'OemKeyScan',
'GetInternalWindowPos',
'EnumPropsW',
'SetInternalWindowPos',
'OpenWaitableTimerA',
'MessageBoxTimeoutW',
'SetProgmanWindow',
'GetInputDesktop',
'AllowForegroundActivation',
'BroadcastSystemMessageExA',
'IsDialogMessage',
'SetDefaultCommConfigW',
'MenuWindowProcA',
'LZRead',
'TranslateMessageEx',
'DeleteVolumeMountPointA',
'EnumDateFormatsExA',
'LoadAlterBitmap',
'AlignRects',
'AccessCheckByTypeResultListAndAuditAlarmA',
'GetProgmanWindow',
'PrivateExtractIconExA',
'PrivilegedServiceAuditAlarmW',
'EditWndProc',
'SetComputerNameExA',
'ShowStartGlass',
'IsGUIThread',
'AddRefActCtx',
'WantArrows',
'CopyLZFile',
'dwLBSubclass',
'GetListBoxInfo',
'ResetWriteWatch',
'AccessCheckByTypeResultListAndAuditAlarmByHandleA',
'_sleep',
'DrawMenuBarTemp',
'EnumPropsExW',
'SetProcessPriorityBoost',
'dwOKSubclass',
'GetTapeParameters',
'SetCursorContents',
'CascadeChildWindows',
'GetVolumePathNameA',
'SetWindowsHookW',
'_ctype',
'CancelDC',
'PrepareTape',
'GetMUILanguage',
'ImageList_GetFlags',
'MoveFileWithProgressA',
'SetMessageExtraInfo',
'ConvertToAutoInheritPrivateObjectSecurity',
'ScrollChildren',
'AddAuditAccessAce',
'GetTapeStatus',
'BRUSHOBJ_pvAllocRbrush',
'DllCanUnloadNow',
'GetProfileSectionW',
'WSAEnumNameSpaceProvidersA',
'SetColorSpace']


def All_Check(path):
    tmp = [0 for i in range(10)]
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
        tmp[3] = 1
        
    # packing 
    if isPacking(binary):
        tmp[4] = 1
        
    # section_num(binary)
    if isSectionNum(binary):
        tmp[5] = 1
        
    # string IP, URL 
    tmp[6], tmp[7] = ip_URL_search(path)
        
    # XOR 
    if isXor(path, mal_api_list):
        tmp[8] = 1

    # sizeof_uninitialized_data
    if isUninit(binary):
        tmp[6] = 1
    
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
        excep = str(e)
        ctypes.windll.user32.MessageBoxW(None, excep, "Exception", 0)
        return 3

    if test == 4:
        return 2
    
    return result

## test
if __name__ == "__main__":
    #path = r"C:\Users\user\source\repos\Yak_project\nomal1.vir"
    path = r"C:\Users\user\source\repos\Yak_project\nomal2.vir"
    #path = r"C:\Windows\System32\calc.exe"
    #path = 'C:/Users/user/source/repos/Yak_project/infected.vir'
    #path = 'C:/Users/user/source/repos/Yak_project/infected2.vir'
    #path = 'C:/Users/user/source/repos/Yak_project/infected3.vir'
    print(All_Check(path))
