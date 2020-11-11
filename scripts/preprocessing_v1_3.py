# -*- coding: utf-8 -*-
"""Preprocessing_v1_3.ipynb

Automatically generated by Colaboratory.

Original file is located at
    https://colab.research.google.com/drive/159mxBTicO7HGiVCfbRBwomR5AvkjPhvR
"""

##!pip install setuptools --upgrade
##!pip install lief

import lief
import subprocess

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
    if (date2> ts2) | (date2 > ts2 + 631152000):
        return True
    else:
        return False

# dll characteristics check
def isDllCha(binary):
    dll_list = list(binary.optional_header.dll_characteristics_lists)
    dll_list2=[]
    for i in range(len(dll_list)):
        dll_list2.append(str(dll_list[i]))
    if 'DLL_CHARACTERISTICS.WDM_DRIVER' in dll_list:
        return True
    else:
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
def isValidURL(data):
    urls = ['www', 'http://', 'https://', 'com', '.com', '.net', '.kr', '.org', '.io']    
    for string in data:
        try:
            string = string.decode('utf-8')
            for url in urls:
                if url in string :
                    return True
                else:
                    continue
        except:
            pass

def isValidIP(data):
    for address in data:
        try:
            address = address.decode('utf-8')
            parts = address.split(".")
            if len(parts) != 4:
                continue
            for item in parts:
                if not 0 <= int(item) <= 255:
                    continue
                return True
        except:
            pass


def binary_string(path):
    cmd = ['./strings.exe', path ]
    fd_popen = subprocess.Popen(cmd, stdout = subprocess.PIPE).stdout
    data = fd_popen.read().split()
    fd_popen.close()
    return data

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

import re
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
    for num in range(0, 256):
        if(count==1):
            break
        for found_str in Bytearray(f, num):
            if (found_str in mal_api_list or check_ip_url(found_str)) and count==0:
                    count = 1
                    is_xor = 1
    f.close()
    return is_xor

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
'GetFileAttributesW'
]

##len(mal_api_list)
##
### reading a file list
##cmd_dir = ['dir', 'KISA-CISC2017-Malware-1st', '/b']
##fd_popen_list = subprocess.Popen(cmd_dir, stdout = subprocess.PIPE, shell=True).stdout
##dic_list = fd_popen_list.read().split()

# result format would be a list of lists

# preprocessing PE file data of list
##for file_name in dic_list[:100]:
##    
##    file_name = file_name.decode('utf-8')
##    tmp[0] = file_name

test_dos_header = '4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D8 00 00 00'
test_dos_stub = ' 0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68 69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F 74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20 6D 6F 64 65 2E 0D 0D 0A 24 00 00 00 00 00 00 00'
signature = ' 50 45 00 00'
image_file_header = ' 4C 01 07 00 BA D1 73 4E 00 00 00 00 00 00 00 00 E0 00 0F 03'
image_optional_header = ' 0B 01 02 15 00 54 00 00 00 78 00 00 00 02 00 00 90 12 00 00 00 10 00 00 00 70 00 00 00 00 40 00 00 10 00 00 00 02 00 00 04 00 00 00 01 00 00 00 04 00 00 00 00 00 00 00 00 E0 00 00 00 04 00 00 6D 8A 01 00 03 00 00 00 00 00 20 00 00 10 00 00 00 00 10 00 00 10 00 00 00 00 00 00 10 00 00 00'
table_list = ' 00 00 00 00 00 00 00 00 00 B0 00 00 50 0B 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 7C 00 00 D8 1A 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D0 00 00 18 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 28 B2 00 00 C4 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'

testt = '4D 5A 90 00 04 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68 69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F 74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20 6D 6F 64 65 2E 0D 0D 0A 24 00 00 00 00 00 00 00 50 45 00 00 4C 01 07 00 BA D1 73 4E 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 02 15 00 54 00 00 00 78 00 00 00 02 00 00 90 12 00 00 00 10 00 00 00 70 00 00 00 00 40 00 00 10 00 00 00 02 00 00 04 00 00 00 01 00 00 00 04 00 00 00 00 00 00 00 00 E0 00 00 00 04 00 00 6D 8A 01 00 03 00 00 00 00 00 20 00 00 10 00 00 00 00 10 00 00 10 00 00 00 00 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 B0 00 00 50 0B 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 7C 00 00 D8 1A 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D0 00 00 18 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 28 B2 00 00 C4 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
sum_pe = test_dos_header + test_dos_stub + signature + image_file_header + image_optional_header + table_list

x = [int(x,16) for x in testt.split()]
bins = [bin(int(x,16))[2:].zfill(8) for x in testt.split()]

##print(bins,type(bins), len(bins))
##print(sum_pe, type(sum_pe), len(sum_pe))
##print(testt, type(testt),len(sum_pe))
##print(x, type(x),len(sum_pe))

path = 9 #0x5A4d #x #'nc.exe'
##result = []

import ctypes

def All_Check(path):
    tmp = [0 for i in range(13)]

    
##    binary = lief.parse(path)
##    print(binary)   
##    # 1.Dos Header 
##    if isDosHeader(binary):
##        tmp[0] = 1
        
##    # 2.section name 
##    if isSectionName(binary):
##        tmp[1] = 1
##        
##    # 3.time_date
##    if isTimeDate(binary):
##        tmp[2] = 1
##        tmp[3] = 1
##        tmp[4] = 1
##        tmp[5] = 1
##        tmp[6] = 1
##        
##    # 4.dll character
##    if isDllCha(binary):
##        tmp[7] = 1
##        
##    # 5.packing 
##    if isPacking(binary):
##        tmp[8] = 1
##        
##    # 6.section_num(binary)
##    if isSectionNum(binary):
##        tmp[9] = 1
##        
##    # 7.string IP 
##    data = binary_string(path)
##    if isValidIP(data):
##        tmp[10] = 1
##        
##    # 8.string URL
##    if isValidURL(data):
##        tmp[11] =1
##        
##    # 9.XOR 
##    if isXor(path, mal_api_list):
##        tmp[12] =1
##
##    # 10.dll
##    dll_tmp = isDll(binary)
##    tmp += dll_tmp
##
##    # 11.api 
##    api_tmp = isApi(binary, mal_api_list)
##    tmp += api_tmp
    
    if path == 0x5a4d:
        return 2

    if path == 0x4d5a:
        return 3

    if path == "4d5a":
        return 4
    
    if path == "5a4d":
        return 5

    msgbox = ctypes.windll.user32.MessageBoxA
    msg = msgbox(None, 'Hello world', 'hello', 0)
    print(msg)
    
    return 1 #tmp

# if all process's done, tmp should be appended at result
##result.append(tmp)

## 배열화된 'tmp'를 모델에 집어넣는다.
tmp = All_Check(path)
##print(tmp)


