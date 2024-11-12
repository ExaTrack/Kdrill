'''
@author: ExaTrack & Stefan Le Berre
@license: BSD-3-Clause license
@contact: stefan.le-berre@exatrack[.]com
'''

import struct
import datetime
import os
import re
import sys
import zipfile
import ctypes
import socket

import ms_infos


ctypes.windll.kernel32.Wow64DisableWow64FsRedirection(ctypes.byref(ctypes.c_long()))

bitness = 64
force_cr3 = False
is_gdb = False
is_live = False
cr3_self_offset = None
va_address_from = 0
va_address_to = 0xffffffffffffffff
dump_type = None
struct_MmCa = None
struct_VACB_ListEntry_Offset = None
struct_SHARED_CACHE_MAP = None
vacbAddress = None
vacbSize = None
kiWaitAlways = None
kiWaitNever = None
obj_header_types = {}
rootDirectoryObject_list = {}
obHeaderCookie = None
obpRootDirectoryObject = None
kpcr_address = None
pfnDatabase = None
psLoadedModuleList = None
psActiveProcessHead = None
kernel_mapping = None
modules_eat = {}
image_base_to_file = {}
offline_mode = 0
dev_handle = None
kprcb_list = None
kprocess_struct = None
KTHREAD_List_Struct = None
kiBalanceSetManagerPeriodicDpc = None
pgctx_base = None
gKiInterruptThunk = None
share_cache_offset = None
seValidateImageHeader_callback = None
seValidateImageData_callback = None
seValidateImageHeader_callback_addr = None
seValidateImageData_callback_addr = None
addr_IopNotifyLastChanceShutdownQueueHead = None
addr_IopNotifyShutdownQueueHead = None
addr_PspLoadImageNotifyRoutine = None
addr_PspCreateProcessNotifyRoutine = None
addr_PspCreateThreadNotifyRoutine = None
addr_CallbackListHead = None


phys_to_file = []
mem_to_phys = []
sdmp_map = {}

hdOffset = 0

cm_Callback_struct = {}
ndisCbIo_struct = {}
ndisCbIo_struct['NDfv_ptr'] = {}
ndisCbIo_struct['NDpb_ptr'] = {}
ndisCbIo_struct['ndisMiniportList_addr'] = []
Drivers_list = None
driver_object_struct = None
device_node_struct = None
file_object_struct = None
iopRootNodeDevice = None
pPoolBigPageTable = None
struct_FltmgrFrame = None
struct_FltmgrInstance = None
struct_FltmgrFltFilter = None
struct_Pfn = None
struct_PsProcessType = None
struct_ObFl = None

Driver_list_Struct = None
Drivers_list_addr = None


irp_mj_list = ["IRP_MJ_CREATE", "IRP_MJ_CREATE_NAMED_PIPE", "IRP_MJ_CLOSE", "IRP_MJ_READ", "IRP_MJ_WRITE", "IRP_MJ_QUERY_INFORMATION", "IRP_MJ_SET_INFORMATION", "IRP_MJ_QUERY_EA", "IRP_MJ_SET_EA", "IRP_MJ_FLUSH_BUFFERS", "IRP_MJ_QUERY_VOLUME_INFORMATION", "IRP_MJ_SET_VOLUME_INFORMATION", "IRP_MJ_DIRECTORY_CONTROL", "IRP_MJ_FILE_SYSTEM_CONTROL", "IRP_MJ_DEVICE_CONTROL", "IRP_MJ_INTERNAL_DEVICE_CONTROL", "IRP_MJ_SHUTDOWN", "IRP_MJ_LOCK_CONTROL", "IRP_MJ_CLEANUP", "IRP_MJ_CREATE_MAILSLOT", "IRP_MJ_QUERY_SECURITY", "IRP_MJ_SET_SECURITY", "IRP_MJ_POWER", "IRP_MJ_SYSTEM_CONTROL", "IRP_MJ_DEVICE_CHANGE", "IRP_MJ_QUERY_QUOTA", "IRP_MJ_SET_QUOTA", "IRP_MJ_PNP"]

PXE_analyzed = []
PPE_analyzed = []
PDE_analyzed = []
PTE_analyzed = []

EPROCESS_Struct = {}
EPROCESS_List = {}
EPROCESS_List_addr = {}
Process_List = {}

cr3 = None
cr3_system = None

cache_pages = {}
cache_pages_file = {}

debug = False

total_buffer = None


def hexprint(string, base=0, word_size=1, no_print=False):
    result = b""
    if len(string) == 0:
        return
    ascii = bytearray(b"."*256)
    for i in range(0x20, 0x7f):
        ascii[i] = i
    ascii[0x0] = 0x2e
    ascii[0x7] = 0x2e
    ascii[0x8] = 0x2e
    ascii[0x9] = 0x2e
    ascii[0xa] = 0x2e
    ascii[0x1b] = 0x2e
    ascii[0xd] = 0x2e
    ascii[0xff] = 0x23
    offset = 0
    while (offset+0x10) <= len(string):
        line = string[offset:(offset+0x10)]
        linebuf = b" %016X  " % (offset+base)
        if word_size == 1:
            for i in range(0, 16):
                if i == 8:
                    linebuf += b" "
                linebuf += b"%02X " % line[i]
            linebuf += b" "
            for i in range(0, 16):
                linebuf += b"%c" % ascii[line[i]]
            if no_print:
                result += linebuf+b"\n"
            else:
                print("%s" % linebuf.decode())
        elif word_size == 4:
            for i in [0, 4, 8, 0xc]:
                linebuf += b"%08X " % struct.unpack('I', line[i:i+4])[0]
            for i in range(0, 16):
                linebuf += b"%c" % ascii[line[i]]
            if no_print:
                result += linebuf+b"\n"
            else:
                print("%s" % linebuf.decode())
        elif word_size == 8:
            for i in [0, 8]:
                linebuf += b"%016X " % struct.unpack('Q', line[i:i+8])[0]
            linebuf += b" "
            for i in range(0, 16):
                linebuf += b"%c" % ascii[line[i]]
            if no_print:
                result += linebuf+b"\n"
            else:
                print("%s" % linebuf.decode())
        offset += 0x10
    if (len(string) % 0x10) > 0:
        linebuf = b" %016X  " % (offset+base)
        if word_size == 1:
            for i in range((len(string)-(len(string) % 0x10)), (len(string))):
                if i == 8:
                    linebuf += b" "
                linebuf += b"%02X " % string[i]
            linebuf += b"   "*(0x10-(len(string) % 0x10))
            linebuf += b" "
            if (len(string) % 0x10) < 8:
                linebuf += b" "
            for i in range((len(string)-(len(string) % 0x10)), (len(string))):
                linebuf += b"%c" % ascii[string[i]]
            if no_print:
                result += linebuf+b"\n"
            else:
                print("%s" % linebuf.decode())
        elif word_size == 4:
            linebuf = b" %08X  " % (offset+base)
            for i in range(len(string)-(len(string) % 0x10), len(string)):
                if (i % 4) != 0:
                    continue
                linebuf += b"%08X " % struct.unpack('I', string[i:i+4])[0]
            linebuf += b"  "*(0x11-(len(string) % 0x10))
            for i in range((len(string)-(len(string) % 0x10)), (len(string))):
                linebuf += b"%c" % ascii[string[i]]
            if no_print:
                result += linebuf+b"\n"
            else:
                print("%s" % linebuf.decode())
        elif word_size == 8:
            linebuf = b" %016X  " % (offset+base)
            if (len(string) % 0x10) == 8:
                linebuf += b"%016X " % struct.unpack('Q', string[len(string)-8:])[0]
            linebuf += b"  "*(0x11-(len(string) % 0x10))
            for i in range((len(string)-(len(string) % 0x10)), (len(string))):
                linebuf += b"%c" % ascii[string[i]]
            if no_print:
                result += linebuf+b"\n"
            else:
                print("%s" % linebuf.decode())
    return result.decode("cp1252")


def raw_to_int(strNumber):
    sz = len(strNumber)
    if sz == 1:
        return struct.unpack('B', strNumber)[0]
    elif sz == 2:
        return struct.unpack('H', strNumber)[0]
    elif sz == 4:
        return struct.unpack('I', strNumber)[0]
    elif sz == 8:
        return struct.unpack('Q', strNumber)[0]
    return None


def int_to_raw(decimal, size=8):
    result = ""
    while (size > 0):
        result += chr(decimal & 0xff)
        decimal = decimal >> 8
        size -= 1
    return result


def writeFile_autoname(datas):
    global fileDmp
    global cr3
    fd = open("%s_%x_Mem" % (fileDmp, cr3), "ab")
    if fd is not None:
        datas = fd.write(datas)
        fd.close()
    return None


def writeFile(filename, datas):
    fd = open(filename, "wb")
    if fd is not None:
        datas = fd.write(datas)
        fd.close()
    return None


if (len(sys.argv) < 2):
    print("+---------------------------+")
    print("|          Kdrill           |")
    print("+---------------------------+")

    print("Usage : %s -l/file.dmp" % sys.argv[0])
    print("        -l : load Winpmem for live analysis")
    print("        -gdb [IP PORT] : connect to remote GDB server")
    sys.exit()


def readFromFile_file(offset, length):
    global cache_pages_file
    global file_fd
    global dev_handle
    global phys_to_file

    if length == 0:
        return b''

    if len(cache_pages_file) > 0x20000:
        cache_pages_file = {}

    read_offset = offset & 0xfffffffffffff000
    read_size = (offset+length)-read_offset

    if len(phys_to_file) > 0:
        max_offset = phys_to_file[-1][2] + phys_to_file[-1][1]
        if max_offset < (offset + length):
            return None

    read_offset = offset & 0xfffffffffffff000
    read_size = (offset+length)-read_offset
    if (read_size % 0x1000) != 0:
        read_size = (read_size & 0xfffffffffffff000) + 0x1000

    readed_tb = []
    for i_page in range(read_size >> 12):
        coffset = read_offset+(i_page << 12)
        if coffset in cache_pages_file:
            readed_tb.append(cache_pages_file[coffset])
        else:
            tsize = read_size-(i_page << 12)
            if dev_handle is not None and phys_to_file != []:
                ctypes.windll.kernel32.SetFilePointer(dev_handle, coffset & 0xffffffff, ctypes.create_string_buffer(struct.pack("I", coffset >> 32)), 0)
                len_write = ctypes.create_string_buffer(b"\x00"*8)
                buffer = ctypes.create_string_buffer(b"\x00"*tsize)
                ctypes.windll.kernel32.ReadFile(dev_handle, buffer, tsize, len_write, None)
                if struct.unpack('I', len_write[:4])[0] == 0:
                    return None
                readed_post = bytes(buffer.raw)
            elif file_fd is not None:
                file_fd.seek(coffset, 0)
                readed_post = file_fd.read(tsize)
            if coffset not in cache_pages_file and tsize == 0x1000 and len(readed_post) == 0x1000:
                cache_pages_file[coffset] = readed_post
            readed = b''.join(readed_tb)+readed_post
            return readed[offset-read_offset:(offset-read_offset)+length]
    readed = b''.join(readed_tb)
    return readed[offset-read_offset:(offset-read_offset)+length]


def readFromPhys(offset, length):
    global phys_to_file

    datas = b""

    if dump_type == 2 or dump_type == 6:
        read_offset = offset & 0xfffffffffffff000
        read_size = (offset+length)-read_offset
        datas_tb = []
        if (length & 0xfff) != 0:
            read_size += 0x1000
        for i_page in range(read_size >> 12):
            i_page = i_page << 12
            if (read_offset+i_page) in sdmp_map:
                datas = readFromFile(sdmp_map[read_offset+i_page], 0x1000)
            datas_tb.append(datas)
        return bytearray(b''.join(datas_tb)[offset-read_offset:(offset-read_offset)+length])

    if phys_to_file != []:
        for base_page, size, file_offset in phys_to_file:
            if base_page <= offset and offset <= (base_page+size):
                offset_chunk = offset-base_page
                if (offset+length) > (base_page+size):
                    read_size = size-offset_chunk
                elif (offset+length) <= (base_page+size):
                    read_size = length
                else:
                    print("WTFFFFF")
                    sys.exit()
                ndatas = readFromFile(file_offset+offset_chunk, read_size)
                if ndatas is None:
                    return None
                datas += ndatas

    else:
        datas = readFromFile(offset, length)
    return bytearray(datas)


readFromFile = readFromFile_file


def get_file_offset_from_phys(offset):
    global phys_to_file
    global dump_type
    length = 1

    if dump_type == 2 or dump_type == 6:
        for sdmp_map_phys, sdmp_map_off in sdmp_map.items():
            if sdmp_map_phys <= offset and offset < (sdmp_map_phys+0x1000):
                return sdmp_map_off

    if phys_to_file != []:
        for base_page, size, file_offset in phys_to_file:
            if base_page <= offset and offset <= (base_page+size):
                if (offset+length) >= (base_page+size) and offset < base_page:
                    return file_offset
                elif (offset+length) >= (base_page+size) and offset >= base_page:
                    offset_chunk = offset-base_page
                    return file_offset+offset_chunk
                elif (offset+length) <= (base_page+size) and offset >= base_page:
                    offset_chunk = offset-base_page
                    return file_offset+offset_chunk
    else:
        return offset
    return None


def get_phys_from_file_offset(offset):
    global dump_type

    if dump_type == 2 or dump_type == 6:
        for sdmp_map_phys, sdmp_map_off in sdmp_map.items():
            if sdmp_map_off <= offset and offset < (sdmp_map_off+0x1000):
                return sdmp_map_phys

    if phys_to_file != []:
        for base_page, size, file_offset in phys_to_file:
            if file_offset <= offset and offset < (file_offset+size):
                return (base_page+(offset-file_offset))
    else:
        return offset
    return None


def download_from_ms(driver_name=None, image_base=None):
    global Drivers_list
    global image_base_to_file
    global offline_mode
    global debug
    try:
        import urllib2
        openurl = urllib2.urlopen
    except Exception:
        import urllib
        import urllib.request
        openurl = urllib.request.urlopen
    import os
    import os.path

    if offline_mode == 0:
        return
    if image_base is None and driver_name is None:
        return

    if driver_name is not None and type(driver_name) is not str:
        driver_name = driver_name.decode()

    multi_names = {'ntoskrnl.exe': ['ntoskrnl.exe', 'ntkrnlmp.exe', 'ntkrnlpa.exe', 'ntkrpamp.exe'], 'hal.dll': ['hal.dll', 'halmacpi.dll']}
    if image_base is None and driver_name is not None:
        image_base = resolve_symbol(driver_name)
    dvr_name = Drivers_list[image_base]['Name']
    end_name = dvr_name.decode().split('\\')[-1].lower()
    decode_pe(image_base)
    if 'PE' in Drivers_list[image_base] and 'Optional_Header' in Drivers_list[image_base]['PE']:
        timestamp = Drivers_list[image_base]['PE']['Optional_Header']['timestamp']
        size_of_image = Drivers_list[image_base]['PE']['Optional_Header']['size_of_image']
        identifier = "%08x%x" % (timestamp, size_of_image)
        path_file = "c:\\symbols\\%s\\%s\\%s" % (end_name, identifier, end_name)
        if os.path.isfile(path_file):
            image_base_to_file[image_base] = path_file
            if debug >= 1:
                print(" File : %s" % path_file)
            return

        if end_name in multi_names:
            for cname in multi_names[end_name]:
                if os.path.isfile("c:\\symbols\\%s\\%s\\%s" % (cname, identifier, cname)):
                    image_base_to_file[image_base] = "c:\\symbols\\%s\\%s\\%s" % (cname, identifier, cname)
                    if debug >= 1:
                        print(" File : %s" % image_base_to_file[image_base])
                    return

        if end_name in multi_names:
            received = False
            for cname in multi_names[end_name]:
                dl_link = "http://msdl.microsoft.com/download/symbols/%s/%s/%s" % (cname, identifier, cname)
                try:
                    response = openurl(dl_link)
                    datas = response.read()
                    received = True
                    path_file = "c:\\symbols\\%s\\%s\\%s" % (cname, identifier, cname)
                    end_name = cname
                except Exception as e:
                    print(e)
                    pass
            if not received:
                return
        else:
            dl_link = "http://msdl.microsoft.com/download/symbols/%s/%s/%s" % (end_name, identifier, end_name)
            try:
                response = openurl(dl_link)
                datas = response.read()
            except Exception:
                return
        try:
            os.stat("c:\\symbols")
        except Exception:
            os.mkdir("c:\\symbols")
        try:
            os.stat("c:\\symbols\\%s" % end_name)
        except Exception:
            os.mkdir("c:\\symbols\\%s" % end_name)
        try:
            os.stat("c:\\symbols\\%s\\%s" % (end_name, identifier))
        except Exception:
            os.mkdir("c:\\symbols\\%s\\%s" % (end_name, identifier))
        open("c:\\symbols\\%s\\%s\\%s" % (end_name, identifier, end_name), "wb").write(datas)
        image_base_to_file[image_base] = path_file
        if debug >= 1:
            print(" File : %s" % path_file)


def check_dump(dump):
    global regex
    regex_result = regex.search(dump)
    if regex_result is not None:
        found = regex_result.group(0)
        return found
    return None


def get_NtBuildNumber():
    try:
        import _winreg
    except Exception:
        import winreg as _winreg
    reg_path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
    try:
        _winreg.CreateKey(_winreg.HKEY_LOCAL_MACHINE, reg_path)
        registry_key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, reg_path, 0, _winreg.KEY_READ)
        build_number = _winreg.QueryValueEx(registry_key, 'CurrentBuild')
        return int(build_number[0])
    except Exception:
        print("Error, can't get build number :-(")
        return None


def get_RAM_mapping():
    try:
        import _winreg
    except Exception:
        import winreg as _winreg
    global phys_to_file
    global end_of_physmem
    reg_path = r"HARDWARE\RESOURCEMAP\System Resources\Physical Memory"
    map = {}
    try:
        _winreg.CreateKey(_winreg.HKEY_LOCAL_MACHINE, reg_path)
        registry_key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, reg_path, 0, _winreg.KEY_READ)
        datas = _winreg.QueryValueEx(registry_key, '.Translated')
        datas = datas[0]
        offset = 0x14
        total_size = 0
        while offset < (len(datas)):
            phys_rights = struct.unpack('I', datas[offset:offset+0x4])[0]
            phys_addr = struct.unpack('Q', datas[offset+0x4:offset+0xc])[0]
            phys_size = struct.unpack('Q', datas[offset+0xc:offset+0x14])[0]
            if ((phys_rights >> 16) & 0xffff) == 0x200:
                phys_size = phys_size << 8
            map[phys_addr] = phys_size
            total_size += phys_size
            phys_to_file.append([phys_addr, phys_size, phys_addr])
            end_of_physmem = phys_addr+phys_size
            offset += 0x14

        return map
    except Exception:
        print("Error, can't get build number :-(")
        return None


def get_local_drivers_mapping():
    cbsize = ctypes.c_ulonglong()
    SystemModuleInformation = 0xb
    ctypes.windll.ntdll.NtQuerySystemInformation(SystemModuleInformation, None, 0, ctypes.byref(cbsize))
    raw_buffer = (cbsize.value * ctypes.c_char)()
    ctypes.windll.ntdll.NtQuerySystemInformation(SystemModuleInformation, ctypes.byref(raw_buffer), len(raw_buffer), ctypes.byref(cbsize))
    nb_drivers = struct.unpack('I', raw_buffer[:4])[0]
    drivers = {}
    for i in range(nb_drivers):
        if (0x14+0x1c+(0x128*i)) > len(raw_buffer):
            break
        cimagebase = struct.unpack('Q', raw_buffer[0x14+4+(0x128*i):0x14+0xc+(0x128*i)])[0]
        cname = raw_buffer[0x14+0x1c+(0x128*i):0x14+0x128+(0x128*i)].split(b"\x00")[0]
        drivers[cimagebase] = cname
    return drivers


def get_se_rights(se_privs):
    word_size = struct.calcsize('P')
    lpLuid = ctypes.create_string_buffer(0x10)
    htoken = ctypes.create_string_buffer(0x8)
    seStr = ctypes.create_string_buffer(bytes(bytearray(se_privs, 'ascii'))+b"\x00")
    if word_size == 8:
        ctypes.windll.advapi32.OpenProcessToken(ctypes.c_ulonglong(0xffffffffffffffff), ctypes.c_uint(0x28), htoken)
    else:
        ctypes.windll.advapi32.OpenProcessToken(ctypes.c_ulong(0xffffffff), ctypes.c_uint(0x28), htoken)
    ctypes.windll.advapi32.LookupPrivilegeValueA(0, seStr, lpLuid)
    newPrivileges = ctypes.create_string_buffer(b"\x01\x00\x00\x00"+lpLuid.raw[:8]+b"\x02\x00\x00\x00")
    ui_htoken = struct.unpack('I', htoken.raw[:4])[0]
    ctypes.windll.advapi32.AdjustTokenPrivileges(ui_htoken, 0, newPrivileges, 0x10, 0, 0)


def decode_executable_from_file(path):
    driver_fd = open(path, "rb")
    if not (driver_fd):
        return None
    driver_file = driver_fd.read()
    driver_fd.close()
    result_pe = {}
    dos_header = pe_decode_dos_header(driver_file[:0x400])
    result_pe['DOS'] = dos_header
    pe_opt_header = pe_decode_pe_header(driver_file[dos_header['e_lfanew']:dos_header['e_lfanew']+0x200])
    result_pe['PE'] = pe_opt_header
    pe_sections = pe_decode_sections(driver_file[dos_header['e_lfanew']:dos_header['e_lfanew']+0x800])
    result_pe['Sections'] = pe_sections
    eat_addr = pe_opt_header['export_address_table_address']
    eat_dump = None
    for fcsection in pe_sections:
        if pe_opt_header['export_address_table_address'] >= fcsection['virtual_address'] and pe_opt_header['export_address_table_address'] < fcsection['virtual_address']+fcsection['virtual_size']:
            eat_file_offset = pe_opt_header['export_address_table_address'] - fcsection['virtual_address'] + fcsection['raw_address']
            eat_dump = driver_file[eat_file_offset:eat_file_offset+pe_opt_header['export_address_table_size']]
    if eat_dump is None:
        return None
    eat_header = pe_decode_eat_header(eat_dump)
    eat = {}
    for i in range(0, eat_header['number_of_names']):
        ceat_func_str_addr = struct.unpack('I', eat_dump[eat_header['address_of_names']-eat_addr+(i << 2):eat_header['address_of_names']-eat_addr+(i << 2)+4])[0]
        ceat_func_str_offset = ceat_func_str_addr-pe_opt_header['export_address_table_address']
        func_name = getString(eat_dump[ceat_func_str_offset:ceat_func_str_offset+0x200])
        ordinal_func = struct.unpack('H', eat_dump[eat_header['address_of_name_ordinals']-eat_addr+(i << 1):eat_header['address_of_name_ordinals']-eat_addr+(i << 1)+2])[0]
        ceat_func = struct.unpack('I', eat_dump[eat_header['address_of_functions']-eat_addr+(ordinal_func << 2):eat_header['address_of_functions']-eat_addr+(ordinal_func << 2)+4])[0]
        eat[func_name] = ceat_func
    result_pe['EAT'] = eat
    return result_pe


def unload_driver():
    try:
        import _winreg
    except Exception:
        import winreg as _winreg
    global dev_handle
    get_se_rights("SeLoadDriverPrivilege")
    get_se_rights("SeDebugPrivilege")
    service_name = "exapmem"
    reg_path_drv = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s" % service_name
    kd_path = "SYSTEM\\CurrentControlSet\\Services\\"+service_name

    unicode_str = []
    for i in range(len(reg_path_drv)):
        unicode_str.append(reg_path_drv[i]+"\x00")
    unicode_str.append("\x00\x00")
    unicode_str = ''.join(unicode_str)
    unicode_str_c = ctypes.create_string_buffer(bytes(bytearray(unicode_str, 'utf8')))
    if struct.calcsize('P') == 8:
        load_ptr = ctypes.create_string_buffer(struct.pack('H', len(unicode_str)-2)+struct.pack('H', len(unicode_str))+b"\x00\x00\x00\x00"+struct.pack('Q', ctypes.addressof(unicode_str_c)))
    else:
        load_ptr = ctypes.create_string_buffer(struct.pack('H', len(unicode_str)-2)+struct.pack('H', len(unicode_str))+struct.pack('I', ctypes.addressof(unicode_str_c)))

    ntUnloadDriver = ctypes.windll.ntdll.NtUnloadDriver

    ntstatus = ntUnloadDriver(load_ptr)
    if ntstatus != 0:
        print("Error on Driver unload : 0x%x" % (0x100000000+ntstatus))

    _winreg.CreateKey(_winreg.HKEY_LOCAL_MACHINE, kd_path)
    registry_key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, kd_path, 0,
                                   _winreg.KEY_WRITE)
    try:
        _winreg.DeleteValue(registry_key, 'ImagePath')
        _winreg.DeleteValue(registry_key, 'Start')
        _winreg.DeleteValue(registry_key, 'Type')
    except WindowsError:
        print("Delete keys failed :-( 1")
    try:
        _winreg.CloseKey(registry_key)
        _winreg.DeleteKey(_winreg.HKEY_LOCAL_MACHINE, kd_path)
    except WindowsError:
        print("Delete keys failed :-( 3 ")
        return


def load_driver():
    try:
        import _winreg
    except Exception:
        import winreg as _winreg
    global debug
    global dev_handle
    global cr3
    global Drivers_list
    global pfnDatabase
    global psLoadedModuleList
    global psActiveProcessHead
    global end_of_physmem
    get_se_rights("SeLoadDriverPrivilege")
    get_se_rights("SeDebugPrivilege")
    service_name = "exapmem"
    device_name = b"pmem"
    reg_path_drv = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s" % service_name
    kd_path = "SYSTEM\\CurrentControlSet\\Services\\"+service_name
    cur_dir = ctypes.create_string_buffer(0x400)
    ctypes.windll.kernel32.GetCurrentDirectoryA(0x400, cur_dir)
    cur_dir = cur_dir.raw.split(b"\x00")[0]
    diver_name = b"\\??\\"+cur_dir
    diver_name += b"\\winpmem_x64.sys"
    cservice_name = ctypes.create_string_buffer(b"\\??\\"+device_name)
    dev_handle = ctypes.windll.kernel32.CreateFileA(cservice_name, 0xC0000000, 0, 0, 3, 0x80, 0)
    if dev_handle == -1:
        try:
            _winreg.CreateKey(_winreg.HKEY_LOCAL_MACHINE, kd_path)
            registry_key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, kd_path, 0,
                                           _winreg.KEY_WRITE)
            _winreg.SetValueEx(registry_key, 'ImagePath', 0, _winreg.REG_SZ, diver_name.decode())
            _winreg.SetValueEx(registry_key, 'Start', 0, _winreg.REG_DWORD, 3)
            _winreg.SetValueEx(registry_key, 'Type', 0, _winreg.REG_DWORD, 1)
            _winreg.SetValueEx(registry_key, 'ErrorControl', 0, _winreg.REG_DWORD, 1)
            _winreg.CloseKey(registry_key)
        except WindowsError:
            print("Create service in registry failed :-(")
            return
        ntLoadDriver = ctypes.windll.ntdll.NtLoadDriver

        unicode_str = []
        for i in range(len(reg_path_drv)):
            unicode_str.append(reg_path_drv[i]+"\x00")
        unicode_str.append("\x00\x00")
        unicode_str = ''.join(unicode_str)
        unicode_str_c = ctypes.create_string_buffer(bytes(bytearray(unicode_str, 'utf8')))
        if struct.calcsize('P') == 8:
            load_ptr = ctypes.create_string_buffer(struct.pack('H', len(unicode_str)-2)+struct.pack('H', len(unicode_str))+b"\x00\x00\x00\x00"+struct.pack('Q', ctypes.addressof(unicode_str_c)))
        else:
            load_ptr = ctypes.create_string_buffer(struct.pack('H', len(unicode_str)-2)+struct.pack('H', len(unicode_str))+struct.pack('I', ctypes.addressof(unicode_str_c)))

        ntstatus = ntLoadDriver(load_ptr)
        if ntstatus != 0:
            print("Error on Driver load : 0x%x" % (0x100000000+ntstatus))
            print("  Error: %x" % ctypes.windll.kernel32.GetLastError())

        cservice_name = ctypes.create_string_buffer(b"\\??\\"+device_name)
        dev_handle = ctypes.windll.kernel32.CreateFileA(cservice_name, 0xC0000000, 0, 0, 3, 0x80, 0)
        if dev_handle == -1:
            print("Failed to open device (1)")
            cservice_name = ctypes.create_string_buffer("\\\\.\\Global\\"+device_name)
            dev_handle = ctypes.windll.kernel32.CreateFileA(cservice_name, 0xC0000000, 0, 0, 3, 0x80, 0)
            if dev_handle == -1:
                print("Failed to open device (2)")
                return False

    len_write = ctypes.create_string_buffer(b"\x00"*8)
    rawdata = ctypes.create_string_buffer(b"\x00"*0x2000)
    result = ctypes.windll.kernel32.DeviceIoControl(dev_handle, 0x22c40f, 0, 0, rawdata, 0x2000, len_write, 0)
    if result == 0:
        print("DeviceIoControl 0x22c40f Error: %x" % ctypes.windll.kernel32.GetLastError())
    rawdata = bytes(rawdata.raw)

    mapping_ioctl_offset = 0xa30

    nb_Runs = struct.unpack("Q", rawdata[mapping_ioctl_offset:mapping_ioctl_offset+8])[0]

    for i in range(0, nb_Runs):
        base_page = struct.unpack("Q", (rawdata[mapping_ioctl_offset+8+(i << 4):mapping_ioctl_offset+8+(i << 4)+0x8]))[0]
        size_buffer = struct.unpack("Q", (rawdata[mapping_ioctl_offset+8+(i << 4)+8:mapping_ioctl_offset+8+(i << 4)+0x10]))[0]
        phys_to_file.append([base_page, size_buffer, base_page])
        if debug > 1:
            print("          0x%X -> 0x%X" % (base_page, base_page+size_buffer))
        end_of_physmem = base_page+size_buffer
    pfnDatabase = 0
    psActiveProcessHead = 0
    cr3 = struct.unpack("Q", rawdata[0:8])[0] & 0xfffffffffffff000
    Drivers_list = {}
    ntoskrnl_base = struct.unpack("Q", rawdata[0x10:0x18])[0]
    if ntoskrnl_base > 0:
        decode_pe(ntoskrnl_base)
        if ntoskrnl_base in Drivers_list and 'PE' in Drivers_list[ntoskrnl_base] and 'EAT' in Drivers_list[ntoskrnl_base]['PE']:
            if b'PsLoadedModuleList' in Drivers_list[ntoskrnl_base]['PE']['EAT']:
                psLoadedModuleList = Drivers_list[ntoskrnl_base]['PE']['EAT'][b'PsLoadedModuleList']
    else:
        print("[!] Winpmem header is malformed")
    Drivers_list = None
    return True


def gdb_send(command):
    gdb_socket.send(b'$%s#%02x' % (command, sum(bytearray(command)) & 0xff))
    rcv = gdb_socket.recv(5000)
    gdb_socket.send(b'+')
    if rcv is None or not rcv.startswith(b'+'):
        return None
    if len(rcv) > 1 and b'#' in rcv[1:]:
        reply, chksum = rcv[1:].rsplit(b'#', 1)
    elif rcv == b'+':
        return rcv
    return reply


def gdb_read_feature(command, fname):
    offset = 0
    all_datas = []
    cdatas = gdb_send(b'%s:read:%s:0,1fa' % (command, fname))
    while cdatas is not None and len(cdatas) > 0:
        if cdatas is None:
            return None
        if cdatas.startswith(b'$m'):  # continue
            all_datas.append(cdatas[2:])
            if len(cdatas) == 508:
                offset += 0x1fa
                cdatas = gdb_send(b'%s:read:%s:%x,1fa' % (command, fname, offset))
        elif cdatas.startswith(b'$l'):  # end
            all_datas.append(cdatas[2:])
            break
        else:
            return None
    return b''.join(all_datas)


def gdb_read_register(register):
    registers = {b'rax': 0, b'rbx': 1, b'rcx': 2, b'rdx': 3, b'rsi': 4, b'rdi': 5, b'rbp': 6, b'rsp': 7, b'r8': 8, b'r9': 9, b'r10': 10, b'r11': 11, b'r12': 12, b'r13': 13, b'r14': 14, b'r15': 15, b'rip': 16, b'eflags': 17}
    register = register.lower()
    if register in registers:
        rcv = gdb_send(b'p%x' % (registers[register]))
        if rcv is not None and rcv.startswith(b'$'):
            return int(rcv[1:][::-1], 16)
    return None


def gdb_read_memory(vaddress, size):
    max_chunk_size = 0x1f0
    offset = 0

    all_datas = []

    while offset < size:
        if (size - offset) < max_chunk_size:
            cdata = gdb_send(b'm%s,%x' % (b'%08x' % (vaddress+offset), (size - offset)))
            offset += (size - offset)
        else:
            cdata = gdb_send(b'm%s,%x' % (b'%08x' % (vaddress+offset), max_chunk_size))
            offset += max_chunk_size
        if cdata == b'$E00':
            return None
        if cdata is not None and len(cdata) > 1 and cdata.startswith(b'$'):
            all_datas.append(bytes(bytearray().fromhex(cdata[1:].decode('utf8'))))
    return b''.join(all_datas)


def gdb_list_pages_from_PTE(va_address_from, va_address_to, va_address):
    global debug
    pxe_indx = (va_address >> 39) & 0x1ff
    ppe_indx = (va_address >> 30) & 0x1ff
    pde_indx = (va_address >> 21) & 0x1ff

    current_page = get_va_memory(0xffff000000000000 | (cr3_self_offset << 39) | (pxe_indx << 30) | (ppe_indx << 21) | (pde_indx << 12), 0x1000)

    if current_page is not None and len(current_page) == 0x1000:
        for i in range(0x1000 >> 3):
            page_table_i = struct.unpack('Q', current_page[i << 3:(i << 3)+8])[0]
            ptr_page_table_i = (page_table_i & 0x0000FFFFFFFFF000)
            cva_address = ((va_address | (i << 12)) & 0xfffffffff000)

            if cva_address >= (va_address_from & 0xfffffffff000) and cva_address < (va_address_to & 0xfffffffff000):
                if (page_table_i & 0x801):
                    if debug > 1:
                        print("      PTE [0x%x] : 0x%016X (0x%016X)" % (i, page_table_i, (va_address | (i << 12))))
                    right = get_rights_from_page_table(page_table_i)
                    cdesc = {}
                    cdesc["right"] = right
                    cdesc["phys"] = ptr_page_table_i
                    yield [(va_address | (i << 12)), cdesc]
                elif ((page_table_i & 0x400) == 0x400):
                    va_of_pte = 0xffff000000000000 | (page_table_i >> 0x10)
                    real_entry = get_qword_from_va(va_of_pte)
                    if real_entry is not None:
                        if debug > 1:
                            print("      PTE Prototype : 0x%016X" % (real_entry))
                        right = get_rights_from_page_table(real_entry)
                        cdesc = {}
                        cdesc["right"] = right
                        cdesc["phys"] = ptr_page_table_i
                        cdesc["prot_pte"] = True
                        yield [(va_address | (i << 12)), cdesc]


def gdb_list_pages_from_PDE(va_address_from, va_address_to, va_address):
    global debug
    pxe_indx = (va_address >> 39) & 0x1ff
    ppe_indx = (va_address >> 30) & 0x1ff

    current_page = get_va_memory(0xffff000000000000 | (cr3_self_offset << 39) | (cr3_self_offset << 30) | (pxe_indx << 21) | (ppe_indx << 12), 0x1000)

    if current_page is not None and len(current_page) == 0x1000:
        for i in range(0x1000 >> 3):
            page_table_i = struct.unpack('Q', current_page[i << 3:(i << 3)+8])[0]
            ptr_page_table_i = (page_table_i & 0x0000FFFFFFFFF000)
            if ((((va_address | (i << 21)) & 0xffffffe00000) >= (va_address_from & 0xffffffe00000)) and ((va_address_to & 0xffffffe00000) >= (((va_address) | (i << 21)) & 0xffffffe00000))):
                if ((page_table_i & 1) == 1):
                    if ((page_table_i & 0x80) == 0x80):
                        if debug > 1:
                            print("    PDE [0x%x] : 0x%016X (0x%016X) - G" % (i, page_table_i, (va_address | (i << 21))))
                        right = get_rights_from_page_table(page_table_i)
                        for y in range(0x1000 >> 3):
                            current_g_address = (va_address | (i << 21) | (y << 12)) & 0xfffffffff000
                            if ((current_g_address >= (va_address_from & 0xfffffffff000)) and ((va_address_to & 0xfffffffff000) > (current_g_address))):
                                cdesc = {}
                                cdesc["right"] = right
                                cdesc["phys"] = ptr_page_table_i+(y << 12)
                                cdesc["big_page"] = True
                                yield [(va_address | (i << 21))+(y << 12), cdesc]
                    else:
                        if debug > 1:
                            print("    PDE [0x%x] : 0x%016X (0x%016X)" % (i, page_table_i, (va_address | (i << 21))))
                        for clist in gdb_list_pages_from_PTE(va_address_from, va_address_to, (va_address | (i << 21))):
                            if clist is not None:
                                yield clist


def gdb_list_pages_from_PPE(va_address_from, va_address_to, va_address):
    pxe_indx = (va_address >> 39) & 0x1ff

    current_page = get_va_memory(0xffff000000000000 | (cr3_self_offset << 39) | (cr3_self_offset << 30) | (cr3_self_offset << 21) | (pxe_indx << 12), 0x1000)

    for i in range(0x1000 >> 3):
        page_table_i = struct.unpack('Q', current_page[i << 3:(i << 3)+8])[0]
        if ((((va_address | (i << 30)) & 0xffffc0000000) >= (va_address_from & 0xffffc0000000)) and ((va_address_to & 0xffffc0000000) >= (((va_address) | (i << 30)) & 0xffffc0000000))):
            if ((page_table_i & 1) == 1):
                if debug > 1:
                    print("  PPE [0x%x] : 0x%016X (0x%016X)" % (i, page_table_i, (va_address | (i << 30))))
                for clist in gdb_list_pages_from_PDE(va_address_from, va_address_to, (va_address | (i << 30))):
                    if clist is not None:
                        yield clist


def gdb_list_pages_from_PXE(va_address_from, va_address_to):
    start_index = (va_address_from >> 39) & 0x1ff
    end_index = (va_address_to >> 39) & 0x1ff

    current_page = get_va_memory(0xffff000000000000 | (cr3_self_offset << 39) | (cr3_self_offset << 30) | (cr3_self_offset << 21) | (cr3_self_offset << 12), 0x1000)

    while start_index <= end_index:
        page_table_i = struct.unpack('Q', current_page[start_index << 3:(start_index << 3)+8])[0]
        if (page_table_i & 1) == 1:
            if debug > 1:
                print("  PXE [0x%x] : 0x%016X (0x%016X)" % (start_index, page_table_i, (0xffff000000000000 | (start_index << 39))))
            for cpage in gdb_list_pages_from_PPE(va_address_from, va_address_to, 0xffff000000000000 | (start_index << 39)):
                yield cpage
        start_index += 1


def gdb_get_pages_list_iter(va_address_from, va_address_to):
    global bitness
    for cres in gdb_list_pages_from_PXE(va_address_from, va_address_to):
        yield cres


def gdb_get_from_PXE(page_address):
    global cache_pages

    if page_address in cache_pages:
        datas = cache_pages[page_address]
    else:
        if len(cache_pages) > 0x10000:
            cache_pages = {}
        datas = gdb_read_memory(page_address, 0x1000)
        cache_pages[page_address] = datas
    return datas


def gdb_find_self_mapping_offset():
    global cr3_self_offset
    for i in range(0x100, 0x200):
        cva = 0xffff000000000000 | (i << 39) | (i << 30) | (i << 21) | (i << 12)
        raw_page = gdb_read_memory(cva, 0x1000)
        if raw_page is not None and len(raw_page) == 0x1000:
            indx_val = struct.unpack('Q', raw_page[i << 3:(i+1) << 3])[0]
            if (indx_val & 0xff) == 0x63:
                cr3_self_offset = i
                return


def gdb_find_ntoskrnl_base_from_general_registers():
    general_register_raw = gdb_send(b'g')

    if general_register_raw is not None and general_register_raw.startswith(b'$'):
        general_register_raw = general_register_raw[1:]
        for i in range(len(general_register_raw) >> 3):
            reg_value = int(general_register_raw[i << 3:(i << 3)+16][::-1], 16)
            nt_addr = find_ntoskrnl_from_address_back(reg_value)
            if nt_addr is not None:
                return nt_addr


def find_ntoskrnl_from_address_back(address):
    content = get_va_memory(address, 0x1000)
    while content is not None and len(content) == 0x1000:
        if content.startswith(b'MZ') and b'ALMOSTRO' in content and b'PAGEKD' in content and b'INITKDBG' in content:
            return address
        address -= 0x1000
        content = get_va_memory(address, 0x1000)


def find_ntoskrnl_base_from_crawling():
    for page_address, page_infos in get_pages_list_iter(0xfffff80000000000, 0xffffffffffffffff):
        content = get_va_memory(page_address, 0x1000)
        if content is not None and len(content) == 0x1000:
            if content.startswith(b'MZ') and b'ALMOSTRO' in content and b'PAGEKD' in content and b'INITKDBG' in content:
                return page_address


def gdb_find_ntoskrnl_base():
    addr = gdb_find_ntoskrnl_base_from_general_registers()
    if addr is not None:
        if debug > 0:
            print("[*] Found nt base in general registers")
        return addr
    addr = find_ntoskrnl_base_from_crawling()
    if debug > 0:
        print("Crawling memory to find Ntoskrnl...")
    if addr is not None:
        if debug > 0:
            print("[*] Found nt base by crawling memory")
        return addr


def gdb_init_ntoskrnl_module_list():
    global Drivers_list
    global cr3
    global psLoadedModuleList

    if Drivers_list is not None:
        return

    ntoskrnl_base = gdb_find_ntoskrnl_base()
    if ntoskrnl_base is None or ntoskrnl_base == 0:
        print("[!] Ntoskrnl init failed :(")
        return

    Drivers_list = {}
    cr3 = 0x1000

    if ntoskrnl_base > 0:
        decode_pe(ntoskrnl_base)
        if ntoskrnl_base in Drivers_list and 'PE' in Drivers_list[ntoskrnl_base] and 'EAT' in Drivers_list[ntoskrnl_base]['PE']:
            if b'PsLoadedModuleList' in Drivers_list[ntoskrnl_base]['PE']['EAT']:
                psLoadedModuleList = Drivers_list[ntoskrnl_base]['PE']['EAT'][b'PsLoadedModuleList']


def gdb_setup(ip, port):
    global cr3_self_offset
    global gdb_socket_infos
    gdb_socket_infos = {'ip': ip, 'port': port}
    global get_from_PXE
    get_from_PXE = gdb_get_from_PXE
    global get_pages_list_iter
    get_pages_list_iter = gdb_get_pages_list_iter

    gdb_connect()
    gdb_send(b'!')  # Advise the target that extended remote debugging is being used
    gdb_send(b'?')  # Report why the target halted.
    gdb_find_self_mapping_offset()
    if cr3_self_offset is None:
        print("[!] Can't find CR3 self mapping :(")
        return False
    if debug > 0:
        print("[*] Self mapping offset : 0x%x" % (cr3_self_offset))
    gdb_init_ntoskrnl_module_list()
    if psLoadedModuleList is None:
        print("[!] Ntoskrnl not found :(")
        return False
    global Drivers_list
    Drivers_list = None
    return True


def gdb_disconnect():
    gdb_socket.close()


def gdb_connect():
    global gdb_socket
    gdb_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    gdb_socket.connect((gdb_socket_infos['ip'], gdb_socket_infos['port']))


def readFromFile_aff4(offset, length):
    global cache_pages_file
    global phys_to_file
    global fd_zip
    global zipfile_cache

    if length == 0:
        return ''

    if len(phys_to_file) > 0:
        max_offset = phys_to_file[-1][2] + phys_to_file[-1][1]
        if max_offset < (offset + length):
            return None

    read_offset = offset & 0xfffffffffffff000
    read_size = (offset+length)-read_offset
    if (read_size % 0x1000) != 0:
        read_size = (read_size & 0xfffffffffffff000) + 0x1000

    if len(cache_pages_file) > 0x20000:
        cache_pages_file = {}

    readed_tb = []
    for i_page in range(read_size >> 12):
        coffset = read_offset+(i_page << 12)
        if coffset in cache_pages_file:
            readed_tb.append(cache_pages_file[coffset])
        else:
            chunck_offset = (read_offset & 0x1fff000)
            cache_name = 'PhysicalMemory/data/%08d' % (coffset/0x2000000)
            if cache_name in zipfile_cache:
                all_datas = zipfile_cache[cache_name]
            else:
                if len(zipfile_cache) > 0x20:
                    zipfile_cache = {}
                all_datas = fd_zip.open(cache_name).read()
                zipfile_cache[cache_name] = all_datas
            readed_post = all_datas[chunck_offset:chunck_offset+read_size-(i_page << 12)]
            for to_cache in range((read_size >> 12)-i_page):
                cache_pages_file[coffset+(to_cache << 12)] = readed_post[(to_cache << 12):(to_cache << 12)+0x1000]
            cache_pages_file[coffset] = readed_post
            readed = ''.join(readed_tb)+readed_post
            return readed[offset-read_offset:(offset-read_offset)+length]
    readed = ''.join(readed_tb)
    return readed[offset-read_offset:(offset-read_offset)+length]


def set_infos_from_aff4_dump(fileDump):
    global fd_zip
    global readFromFile
    global pfnDatabase
    global psLoadedModuleList
    global psActiveProcessHead
    global cr3
    global Drivers_list
    global phys_to_file
    global zipfile_cache

    zipfile_cache = {}

    fd_zip = zipfile.ZipFile(fileDump)
    runs_data = fd_zip.open('PhysicalMemory/map').read()
    infos_yaml = fd_zip.open('PhysicalMemory/information.yaml').read()
    readFromFile = readFromFile_aff4
    cr3 = int(infos_yaml.split('  CR3: ')[1].split('\n')[0].replace('\r', ''))
    ntoskrnl_base = int(infos_yaml.split('KernBase: ')[1].split('\n')[0].replace('\r', ''))
    pfnDatabase = 0
    psActiveProcessHead = 0

    run_offset = 0
    temp_file_offset = 0
    while run_offset < len(runs_data):

        base_page = struct.unpack("Q", runs_data[run_offset:run_offset+8])[0]
        size_buffer = struct.unpack("Q", runs_data[run_offset+8:run_offset+0x10])[0]
        offset_buffer = struct.unpack("Q", runs_data[run_offset+0x10:run_offset+0x18])[0]
        phys_to_file.append([base_page, size_buffer, offset_buffer])
        temp_file_offset += size_buffer
        run_offset += 0x1c

    while get_va_memory(ntoskrnl_base, 0x100) is None:
        prev_cr3 = cr3
        print("Invalid CR3, try to find another...")
        find_valid_cr3(cr3+0x1000)
        if cr3 == prev_cr3 or cr3 is None:
            print("no valid CR3 found :(")
            return
    Drivers_list = {}
    if ntoskrnl_base > 0:
        decode_pe(ntoskrnl_base)
        if ntoskrnl_base in Drivers_list and 'PE' in Drivers_list[ntoskrnl_base] and 'EAT' in Drivers_list[ntoskrnl_base]['PE']:
            if 'PsLoadedModuleList' in Drivers_list[ntoskrnl_base]['PE']['EAT']:
                psLoadedModuleList = Drivers_list[ntoskrnl_base]['PE']['EAT']['PsLoadedModuleList']
                print("psLoadedModuleList : %x" % psLoadedModuleList)
    else:
        print("[!] Winpmem header is malformed")


def set_infos_from_raw_dump(fileDump):
    global readFromFile
    global phys_to_file
    global Drivers_list
    global psLoadedModuleList

    phys_to_file = [[0, os.stat(fileDump).st_size, 0]]

    print("[*] Searching a valid CR3 in raw dump")
    cr3_val = find_valid_cr3()
    if cr3_val is None:
        print("[!] No page corresponding to a CR3 was found :(")
    else:
        ntoskrnl_base = find_ntoskrnl_base_from_crawling()
        if ntoskrnl_base is None:
            print("[!] Imagebase of NtOskrnl was not found :(")
            return None
        else:
            Drivers_list = {}
            if ntoskrnl_base > 0:
                decode_pe(ntoskrnl_base)
                if ntoskrnl_base in Drivers_list and 'PE' in Drivers_list[ntoskrnl_base] and 'EAT' in Drivers_list[ntoskrnl_base]['PE']:
                    if b'PsLoadedModuleList' in Drivers_list[ntoskrnl_base]['PE']['EAT']:
                        psLoadedModuleList = Drivers_list[ntoskrnl_base]['PE']['EAT'][b'PsLoadedModuleList']


def set_infos_from_crashdump_header(rawdata):
    global pfnDatabase
    global psLoadedModuleList
    global psActiveProcessHead
    global cr3
    global paeEnabled
    global phys_to_file
    global end_of_physmem
    global dump_type
    global cache_pages_file

    if rawdata[:4] == b"PAGE":
        print("  [*] CrashDump file detected")
        if rawdata[4:8] == b"DU64":
            print("  [*] 64b image")
            if cr3 is None:
                cr3 = raw_to_int(rawdata[0x10:0x18]) & 0xfffffffffffff000
            pfnDatabase = raw_to_int(rawdata[0x18:0x20])
            psLoadedModuleList = raw_to_int(rawdata[0x20:0x28])
            psActiveProcessHead = raw_to_int(rawdata[0x28:0x30])
            offset_DumpType = 0xf98
            dump_type = raw_to_int(rawdata[offset_DumpType:offset_DumpType+4])
            if debug > 0:
                print("      DirectoryTableBase : 0x%X" % (cr3))
                print("      PFN Database : 0x%X" % (pfnDatabase))
                print("      PsLoadedModuleList : 0x%X" % (psLoadedModuleList))
                print("      PsActiveProcessHead : 0x%X" % (psActiveProcessHead))
                if dump_type == 1:
                    print("      Full dump")
                elif dump_type == 2:
                    print("      Kernel dump")
                elif dump_type == 6:
                    print("      Kernel dump v2")
            offset_PHYS_MEM_DESC = 0x88
            nb_Runs = raw_to_int(rawdata[offset_PHYS_MEM_DESC:offset_PHYS_MEM_DESC+4])
            size_dumped = raw_to_int(rawdata[offset_PHYS_MEM_DESC+8:offset_PHYS_MEM_DESC+0x10]) << 12
            if debug > 0:
                print("      Pages stored : 0x%X" % (size_dumped >> 12))
                print("      Physical Memory descriptors : 0x%x" % (nb_Runs))
            temp_file_offset = 0x2000
            if nb_Runs != 0x45474150:  # 'PAGE'
                for i in range(0, nb_Runs):
                    base_page = raw_to_int(rawdata[offset_PHYS_MEM_DESC+0x10+(i << 4):offset_PHYS_MEM_DESC+0x10+(i << 4)+0x8]) << 12
                    size_buffer = raw_to_int(rawdata[offset_PHYS_MEM_DESC+0x10+(i << 4)+8:offset_PHYS_MEM_DESC+0x10+(i << 4)+0x10]) << 12
                    phys_to_file.append([base_page, size_buffer, temp_file_offset])
                    temp_file_offset += size_buffer
                    end_of_physmem = base_page+size_buffer
            else:
                nb_Runs = 0
                size_dumped = temp_file_offset-0x2000
            if (temp_file_offset-0x2000) != size_dumped:
                print("  [!] Pages stored and described are different")
            offset_SDMP = 0x2000
            if dump_type == 2 and rawdata[offset_SDMP:offset_SDMP+0x4] == b"SDMP" and rawdata[offset_SDMP+0x8:offset_SDMP+0xc] == b"SDMP":
                sdmp_HeaderSize = raw_to_int(rawdata[offset_SDMP+0xc:offset_SDMP+0x10])
                sdmp_BitmapSize = raw_to_int(rawdata[offset_SDMP+0x10:offset_SDMP+0x14])
                sdmp_header_datas = readFromFile(offset_SDMP, sdmp_BitmapSize-offset_SDMP)
                phys_to_file = [[0, 0x1000, 0]]
                temp_file_offset = sdmp_HeaderSize
                print("sdmp_HeaderSize : %x" % sdmp_HeaderSize)
                bmp_ptr = 0x28
                cache_pages_file = {}  # reset bad temporary translation
                while bmp_ptr < len(sdmp_header_datas):
                    sdmp_bitmap_state = sdmp_header_datas[bmp_ptr]
                    for bit_i in range(0, 8):
                        if ((1 << bit_i) & sdmp_bitmap_state) != 0:
                            base_page = ((bmp_ptr-0x28) << 15)+(bit_i << 12)
                            sdmp_map[base_page] = temp_file_offset
                            phys_to_file[0][1] = base_page+0x1000
                            temp_file_offset += 0x1000
                            end_of_physmem = base_page+0x1000
                    bmp_ptr += 1
            if dump_type == 6 and rawdata[offset_SDMP:offset_SDMP+0x4] == b"SDMP" and rawdata[offset_SDMP+0x8:offset_SDMP+0xc] == b"\x00\x00\x00\x00":
                sdmp_HeaderSize = raw_to_int(rawdata[offset_SDMP+0x20:offset_SDMP+0x28])
                sdmp_BitmapSize = raw_to_int(rawdata[offset_SDMP+0x28:offset_SDMP+0x30])
                sdmp_dump_size = raw_to_int(rawdata[offset_SDMP+0x30:offset_SDMP+0x38])
                sdmp_header_datas = bytearray(readFromFile(offset_SDMP, sdmp_dump_size))
                phys_to_file = [[0, 0x1000, 0]]
                temp_file_offset = sdmp_HeaderSize
                bmp_ptr = 0x38
                bmp_ptr_base = bmp_ptr
                cache_pages_file = {}  # reset bad temporary translation
                while bmp_ptr < len(sdmp_header_datas):
                    sdmp_bitmap_state = sdmp_header_datas[bmp_ptr]
                    for bit_i in range(0, 8):
                        if ((1 << bit_i) & sdmp_bitmap_state) != 0:
                            base_page = ((bmp_ptr-bmp_ptr_base) << 15)+(bit_i << 12)
                            sdmp_map[base_page] = temp_file_offset
                            phys_to_file[0][1] = base_page+0x1000
                            temp_file_offset += 0x1000
                            end_of_physmem = base_page+0x1000
                    bmp_ptr += 1
        elif rawdata[4:8] == b"DUMP":
            print("  [*] 32b image")
            if cr3 is None:
                cr3 = raw_to_int(rawdata[0x10:0x14]) & 0xfffffffffffff000
            pfnDatabase = raw_to_int(rawdata[0x14:0x18])
            psLoadedModuleList = raw_to_int(rawdata[0x18:0x1c])
            psActiveProcessHead = raw_to_int(rawdata[0x1c:0x20])
            paeEnabled = bytearray(rawdata)[0x5c]
            if debug > 0:
                print("      DirectoryTableBase : 0x%X" % (cr3))
                print("      PFN Database : 0x%X" % (pfnDatabase))
                print("      PsLoadedModuleList : 0x%X" % (psLoadedModuleList))
                print("      PsActiveProcessHead : 0x%X" % (psActiveProcessHead))
                print("      PaeEnabled : 0x%X" % (paeEnabled))
            offset_PHYS_MEM_DESC = 0x64
            nb_Runs = raw_to_int(rawdata[offset_PHYS_MEM_DESC:offset_PHYS_MEM_DESC+4])
            size_dumped = raw_to_int(rawdata[offset_PHYS_MEM_DESC+4:offset_PHYS_MEM_DESC+0x8]) << 12
            if debug > 0:
                print("      Pages stored : 0x%X" % (size_dumped >> 12))
                print("      Physical Memory descriptors : %d" % (nb_Runs))
            temp_file_offset = 0x1000
            for i in range(0, nb_Runs):
                base_page = raw_to_int(rawdata[offset_PHYS_MEM_DESC+0x8+(i << 3):offset_PHYS_MEM_DESC+0x8+(i << 3)+0x4]) << 12
                size_buffer = raw_to_int(rawdata[offset_PHYS_MEM_DESC+0x8+(i << 3)+4:offset_PHYS_MEM_DESC+0x8+(i << 3)+0x8]) << 12
                phys_to_file.append([base_page, size_buffer, temp_file_offset])
                print("          0x%X -> 0x%X : 0x%X" % (base_page, base_page+size_buffer, temp_file_offset))
                end_of_physmem = base_page+size_buffer
                temp_file_offset += size_buffer
            if (temp_file_offset-0x1000) != size_dumped:
                print("  [!] Pages stored and described are different")
        else:
            print("  [!] format %s unsuported :-(" % (rawdata[4:8]))
            sys.exit()


def parsePTE(PTE_entry, va_address, va_address_from=0, va_address_to=0xffffffffffffffff):
    global debug
    global total_buffer
    global get_va_from_offset
    global cr3
    page_tables = readFromPhys(PTE_entry, 0x1000)

    if get_va_from_offset is not None:
        phys_offset = get_phys_from_file_offset(get_va_from_offset)

    for i in range(0x1000 / 8):
        page_table_i = raw_to_int(page_tables[i << 3:(i << 3)+8])
        page_table_i |= ((page_table_i & 0x7ff0000000000000) >> 52)
        ptr_page_table_i = (page_table_i & 0x0000FFFFFFFFF000)
        if (((va_address | (i << 12)) >= (va_address_from & 0xfffffffff000)) and ((va_address_to & 0xfffffffff000) >= ((va_address) | (i << 12)))):
            if ((page_table_i & 1) == 1):
                if debug > 1:
                    print("      PTE [0x%x] : 0x%016X (0x%016X)" % (i, page_table_i, (va_address | (i << 12))))
                if get_va_from_offset is not None:
                    if phys_offset >= ptr_page_table_i and phys_offset < (ptr_page_table_i+0x1000):
                        print("  [*] VA found in CR3 0x%X : 0x%X" % (cr3, (va_address | (i << 12))+(phys_offset-ptr_page_table_i)))
                    continue
                if total_buffer is None:
                    total_buffer = readFromPhys(ptr_page_table_i, 0x1000)
                else:
                    total_buffer += readFromPhys(ptr_page_table_i, 0x1000)
            else:
                if total_buffer is not None:
                    if check_dump(total_buffer):
                        writeFile_autoname(total_buffer)
                    total_buffer = None

    return None


def parsePDE(PDE_entry, va_address=0, va_address_from=0, va_address_to=0xffffffffffffffff):
    global debug
    global total_buffer
    global PDE_analyzed
    global get_va_from_offset

    if PDE_entry in PDE_analyzed:
        if debug > 1:
            print("    [I] Already analyzed")
        return None
    else:
        PDE_analyzed.append(PDE_entry)

    if get_va_from_offset is not None:
        phys_offset = get_phys_from_file_offset(get_va_from_offset)

    page_tables = readFromPhys(PDE_entry, 0x1000)
    if page_tables is None:
        return None

    for i in range(0x1000 / 8):
        page_table_i = raw_to_int(page_tables[i << 3:(i << 3)+8])
        ptr_page_table_i = (page_table_i & 0x0000FFFFFFFFF000)
        if (((va_address | (i << 21)) >= (va_address_from & 0xffffffe00000)) and ((va_address_to & 0xffffffe00000) >= ((va_address) | (i << 21)))):
            if ((page_table_i & 1) == 1):
                if ((page_table_i & 0x80) == 0x80):
                    if debug > 1:
                        print("    PDE [0x%x] : 0x%016X (0x%016X) - G" % (i, page_table_i, (va_address | (i << 21))))
                    if get_va_from_offset is not None:
                        if phys_offset >= ptr_page_table_i and phys_offset < (ptr_page_table_i+0x200000):
                            print("  [*] VA found in CR3 0x%X : 0x%X" % (cr3, (va_address | (i << 21))+(phys_offset-ptr_page_table_i)))
                        continue
                    if total_buffer is None:
                        total_buffer = readFromPhys(ptr_page_table_i, 0x200000)
                    else:
                        total_buffer += readFromPhys(ptr_page_table_i, 0x200000)
                else:
                    if debug > 1:
                        print("    PDE [0x%x] : 0x%016X (0x%016X)" % (i, page_table_i, (va_address | (i << 21))))
                    parsePTE(ptr_page_table_i, (va_address | (i << 21)), va_address_from, va_address_to)
            else:
                if total_buffer is not None:
                    if check_dump(total_buffer):
                        writeFile_autoname(total_buffer)
                    total_buffer = None
    return None


def parsePPE(PPE_entry, va_address=0, va_address_from=0, va_address_to=0xffffffffffffffff):
    global debug
    global total_buffer
    global PPE_analyzed

    if PPE_entry in PPE_analyzed:
        if debug > 1:
            print("    [I] Already analyzed")
        return None
    else:
        PPE_analyzed.append(PPE_entry)

    page_tables = readFromPhys(PPE_entry, 0x1000)
    if page_tables is None:
        return None

    for i in range(0x1000 / 8):
        page_table_i = raw_to_int(page_tables[i << 3:(i << 3)+8])
        ptr_page_table_i = (page_table_i & 0x0000FFFFFFFFF000)
        if (((va_address | (i << 30)) >= (va_address_from & 0xffffc0000000)) and ((va_address_to & 0xffffc0000000) >= ((va_address) | (i << 30)))):
            if ((page_table_i & 1) == 1):
                if debug > 1:
                    print("  PPE [0x%x] : 0x%016X (0x%016X)" % (i, page_table_i, (va_address | (i << 30))))
                parsePDE(ptr_page_table_i, (va_address | (i << 30)), va_address_from, va_address_to)
            else:
                if total_buffer is not None:
                    if check_dump(total_buffer):
                        writeFile_autoname(total_buffer)
                    total_buffer = None
    return None


def crawl_PXE(PXE_entry, va_address_from=0, va_address_to=0xffffffffffffffff):
    global debug
    global total_buffer
    global PXE_analyzed

    if PXE_entry in PXE_analyzed:
        if debug > 1:
            print("  [I] Already analyzed")
        return None
    else:
        PXE_analyzed.append(PXE_entry)

    va_address = 0
    page_tables = readFromPhys(PXE_entry, 0x1000)

    for i in range(0x1000 / 8):
        page_table_i = raw_to_int(page_tables[i << 3:(i << 3)+8])
        ptr_page_table_i = (page_table_i & 0x0000FFFFFFFFF000)
        if (i == 0x100):
            va_address = 0xFFFF000000000000
        if (((va_address | (i << 39)) >= (va_address_from & 0xff8000000000)) and ((va_address_to & 0xff8000000000) >= ((va_address) | (i << 39)))):
            if ((page_table_i & 1) == 1):
                if debug > 1:
                    print("PXE [0x%x] : 0x%016X (0x%016X)" % (i, page_table_i, (va_address | (i << 39))))
                parsePPE(ptr_page_table_i, (va_address | (i << 39)), va_address_from, va_address_to)
            else:
                if total_buffer is not None:
                    if check_dump(total_buffer):
                        writeFile_autoname(total_buffer)
                    total_buffer = None
    return None


def get_from_PTE(PTE_entry, va_address):
    global cache_pages
    datas = None
    page_tables = readFromPhys(PTE_entry, 0x1000)

    index = (va_address & 0x1ff000) >> 12
    page_table_i = struct.unpack('Q', (page_tables[index << 3:(index << 3)+8]))[0]
    ptr_page_table_i = (page_table_i & 0x0000FFFFFFFFF000)
    if debug > 1:
        print("      PTE [0x%x] : 0x%016X (0x%016X)" % (index, page_table_i, (va_address & 0xfffffffffffff000)))
    if debug > 1 and ((page_table_i & 0x3001) == 0x2000):
        print("      Pagefile number: va: 0x%x, offset: 0x%x" % (va_address, (page_table_i >> 32)))
    if (page_table_i & 0x863):  # soft bits for Prototype or Transition
        if ptr_page_table_i in cache_pages:
            datas = cache_pages[ptr_page_table_i]
        else:
            if len(cache_pages) > 0x10000:
                cache_pages = {}
            datas = readFromPhys(ptr_page_table_i, 0x1000)
            if debug > 1:
                print("try access PTE %x" % (ptr_page_table_i))
                print('------------------------')
            cache_pages[ptr_page_table_i] = datas
    elif ((page_table_i & 0x400) == 0x400):
        va_of_pte = page_table_i >> 0x10
        real_entry = get_qword_from_va(va_of_pte)
        if real_entry is not None:
            if debug > 1:
                print("      PTE Prototype : 0x%016X" % (real_entry))
            datas = readFromPhys(real_entry & 0xfffffffff000, 0x1000)
    return datas


def get_from_PDE(PDE_entry, va_address):
    global cache_pages
    datas = None
    page_tables = readFromPhys(PDE_entry, 0x1000)

    index = (va_address & 0x3fe00000) >> 21
    page_table_i = raw_to_int(page_tables[index << 3:(index << 3)+8])
    ptr_page_table_i = (page_table_i & 0x0000FFFFFFFFF000)

    if ((page_table_i & 1) == 1):
        if ((page_table_i & 0x80) == 0x80):
            if debug > 1:
                print("    PDE [0x%x] : 0x%016X (0x%016X) - G" % (index, page_table_i, (va_address & 0xffffffffffe00000)))
            big_index = (va_address & 0x1ff000)
            if (ptr_page_table_i+big_index) in cache_pages:
                datas = cache_pages[ptr_page_table_i+big_index]
            else:
                datas = readFromPhys(ptr_page_table_i+big_index, 0x1000)
                cache_pages[ptr_page_table_i+big_index] = datas
            return datas
        else:
            if debug > 1:
                print("    PDE [0x%x] : 0x%016X (0x%016X)" % (index, page_table_i, (va_address & 0xffffffffffe00000)))
            datas = get_from_PTE(ptr_page_table_i, va_address)
            return datas
    return datas


def get_from_PPE(PPE_entry, va_address):
    datas = None
    page_tables = readFromPhys(PPE_entry, 0x1000)

    index = (va_address & 0x7fc0000000) >> 30
    page_table_i = raw_to_int(page_tables[index << 3:(index << 3)+8])
    ptr_page_table_i = (page_table_i & 0x0000FFFFFFFFF000)
    if debug > 1:
        print("  PPE [0x%x] : 0x%016X (0x%016X)" % (index, page_table_i, (va_address & 0xffffffffc0000000)))
    if ((page_table_i & 1) == 1):
        datas = get_from_PDE(ptr_page_table_i, va_address)
        return datas
    return datas


def get_from_PXE(va_address):
    global cr3
    datas = None
    page_tables = readFromPhys(cr3, 0x1000)
    index = (va_address & 0xff8000000000) >> 39
    page_table_i = raw_to_int(page_tables[index << 3:(index << 3)+8])
    ptr_page_table_i = (page_table_i & 0x0000FFFFFFFFF000)
    if debug > 1:
        print("PXE [0x%x] : 0x%016X (0x%016X)" % (index, page_table_i, (va_address & 0xffffff8000000000)))
    if ((page_table_i & 1) == 1):
        datas = get_from_PPE(ptr_page_table_i, va_address)
        return datas
    return datas


def get_rights_from_page_table(PT_entry):
    rights = {}
    rights['value'] = ""
    if (PT_entry & 0x1) == 0x1:
        rights['value'] += "r"
        rights['present'] = True
    else:
        rights['value'] += "-"
        rights['present'] = False
    if (PT_entry & 0x2) == 0x2:
        rights['value'] += "w"
        rights['write'] = True
    else:
        rights['value'] += "-"
        rights['write'] = False
    if (PT_entry >> 63) == 1:
        rights['value'] += "-"
        rights['exec'] = False
    else:
        rights['value'] += "x"
        rights['exec'] = True
    if (PT_entry >> 10) == 1:
        rights['value'] += "c"
        rights['CopyOnWrite'] = True
    else:
        rights['value'] += "-"
        rights['CopyOnWrite'] = False
    return rights


def list_pages_from_PTE(PTE_entry, va_address, va_address_from=0, va_address_to=0xffffffffffffffff):
    global debug
    page_tables = readFromPhys(PTE_entry, 0x1000)
    phys_list = {}

    if page_tables is not None and len(page_tables) == 0x1000:
        for i in range(0x1000 >> 3):
            page_table_i = struct.unpack('Q', page_tables[i << 3:(i << 3)+8])[0]
            ptr_page_table_i = (page_table_i & 0x0000FFFFFFFFF000)
            cva_address = ((va_address | (i << 12)) & 0xfffffffff000)

            if cva_address >= (va_address_from & 0xfffffffff000) and cva_address < (va_address_to & 0xfffffffff000):
                if ptr_page_table_i in phys_list:
                    continue
                phys_list[ptr_page_table_i] = None
                if (page_table_i & 0x1):
                    if debug > 1:
                        print("      PTE [0x%x] : 0x%016X (0x%016X)" % (i, page_table_i, (va_address | (i << 12))))
                    right = get_rights_from_page_table(page_table_i)
                    cdesc = {}
                    cdesc["right"] = right
                    cdesc["phys"] = ptr_page_table_i
                    yield [(va_address | (i << 12)), cdesc]
                elif page_table_i & 0x400:
                    va_of_pte = page_table_i >> 0x10
                    real_entry = get_qword_from_va(va_of_pte)
                    if real_entry is not None:
                        if debug > 1:
                            print("      PTE Prototype : 0x%016X" % (real_entry))
                        right = get_rights_from_page_table(real_entry)
                        cdesc = {}
                        cdesc["right"] = right
                        cdesc["phys"] = ptr_page_table_i
                        cdesc["prot_pte"] = True
                        yield [(va_address | (i << 12)), cdesc]


def list_pages_from_PDE(PDE_entry, va_address=0, va_address_from=0, va_address_to=0xffffffffffffffff):
    global debug

    page_tables = readFromPhys(PDE_entry, 0x1000)
    phys_list = {}
    if page_tables is not None and len(page_tables) == 0x1000:
        for i in range(0x1000 >> 3):
            page_table_i = struct.unpack('Q', page_tables[i << 3:(i << 3)+8])[0]
            ptr_page_table_i = (page_table_i & 0x0000FFFFFFFFF000)
            if ((((va_address | (i << 21)) & 0xffffffe00000) >= (va_address_from & 0xffffffe00000)) and ((va_address_to & 0xffffffe00000) >= (((va_address) | (i << 21)) & 0xffffffe00000))):
                if ptr_page_table_i in phys_list:
                    continue
                phys_list[ptr_page_table_i] = None
                if ((page_table_i & 1) == 1):
                    if ((page_table_i & 0x80) == 0x80):
                        if debug > 1:
                            print("    PDE [0x%x] : 0x%016X (0x%016X) - G" % (i, page_table_i, (va_address | (i << 21))))
                        right = get_rights_from_page_table(page_table_i)
                        for y in range(0x1000 >> 3):
                            current_g_address = (va_address | (i << 21) | (y << 12)) & 0xfffffffff000
                            if ((current_g_address >= (va_address_from & 0xfffffffff000)) and ((va_address_to & 0xfffffffff000) > (current_g_address))):
                                cdesc = {}
                                cdesc["right"] = right
                                cdesc["phys"] = ptr_page_table_i+(y << 12)
                                cdesc["big_page"] = True
                                yield [(va_address | (i << 21))+(y << 12), cdesc]
                    else:
                        if debug > 1:
                            print("    PDE [0x%x] : 0x%016X (0x%016X)" % (i, page_table_i, (va_address | (i << 21))))
                        for clist in list_pages_from_PTE(ptr_page_table_i, (va_address | (i << 21)), va_address_from, va_address_to):
                            if clist is not None:
                                yield clist


def list_pages_from_PPE(PPE_entry, va_address=0, va_address_from=0, va_address_to=0xffffffffffffffff):
    global debug

    page_tables = readFromPhys(PPE_entry, 0x1000)
    phys_list = {}
    if page_tables is not None and len(page_tables) == 0x1000:
        for i in range(0x1000 >> 3):
            page_table_i = struct.unpack('Q', page_tables[i << 3:(i << 3)+8])[0]
            ptr_page_table_i = (page_table_i & 0x0000FFFFFFFFF000)
            if ((((va_address | (i << 30)) & 0xffffc0000000) >= (va_address_from & 0xffffc0000000)) and ((va_address_to & 0xffffc0000000) >= (((va_address) | (i << 30)) & 0xffffc0000000))):
                if ptr_page_table_i in phys_list:
                    continue
                phys_list[ptr_page_table_i] = None
                if ((page_table_i & 1) == 1):
                    if debug > 1:
                        print("  PPE [0x%x] : 0x%016X (0x%016X)" % (i, page_table_i, (va_address | (i << 30))))
                    for clist in list_pages_from_PDE(ptr_page_table_i, (va_address | (i << 30)), va_address_from, va_address_to):
                        if clist is not None:
                            yield clist


def list_pages_from_PXE(PXE_entry, va_address_from=0, va_address_to=0xffffffffffffffff):
    global debug
    va_address = 0
    page_tables = readFromPhys(PXE_entry, 0x1000)
    phys_list = {}
    if page_tables is not None and len(page_tables) == 0x1000:
        for i in range(0x1000 >> 3):
            page_table_i = struct.unpack('Q', page_tables[i << 3:(i << 3)+8])[0]
            ptr_page_table_i = (page_table_i & 0x0000FFFFFFFFF000)
            if (i == 0x100):
                va_address = 0xFFFF000000000000
            if ((((va_address | (i << 39)) & 0xff8000000000) >= (va_address_from & 0xff8000000000)) and ((va_address_to & 0xff8000000000) >= (((va_address) | (i << 39)) & 0xff8000000000))):
                if ptr_page_table_i in phys_list:
                    continue
                phys_list[ptr_page_table_i] = None
                if ((page_table_i & 1) == 1):
                    if debug > 1:
                        print("PXE [0x%x] : 0x%016X (0x%016X)" % (i, page_table_i, (va_address | (i << 39))))
                    for clist in list_pages_from_PPE(ptr_page_table_i, (va_address | (i << 39)), va_address_from, va_address_to):
                        yield clist


def get_pages_list_iter(va_address_from, va_address_to):
    global bitness
    global cr3
    if bitness == 64:
        for cres in list_pages_from_PXE(cr3, va_address_from, va_address_to):
            yield cres
    else:
        for cres in list_pages_from_PPE(cr3, (va_address_from & 0xff8000000000), va_address_from, va_address_to):
            yield cres


def get_pages_list(va_address_from, va_address_to):
    result = {}
    for page_addr, cdesc in get_pages_list_iter(va_address_from, va_address_to):
        result[page_addr] = cdesc
    return result


def get_page_rights(va_address):
    result = get_pages_list(va_address, va_address+0x1000)
    if result is not None and len(result) > 0:
        return result[list(result.keys())[0]]['right']
    else:
        return None


def get_va_memory(va_address, length):
    global debug
    global bitness
    global cr3
    pages = []
    if va_address > 0xffffffffffffffff:
        return None
    if (va_address+length) > 0xffffffffffffffff:
        length = 0x10000000000000000 - va_address
    base_va_address = va_address & 0xfffffffffffff000
    pages.append(base_va_address)
    while (base_va_address+0x1000) < (va_address+length):
        base_va_address += 0x1000
        pages.append(base_va_address)
    all_pages = b""
    for cpage in pages:
        try:
            if bitness == 64:
                all_pages += get_from_PXE(cpage)
            else:
                all_pages += get_from_PPE(cr3, cpage)
        except Exception:
            if debug > 1:
                print("  [!] Exception when reading pages !")
            return None
    from_offset = va_address - pages[0]
    return bytearray(all_pages[from_offset:from_offset+length])


def get_sizet_from_va(addr):
    global bitness
    if bitness == 64:
        qword_str = get_va_memory(addr, 8)
        if qword_str is not None and len(qword_str) == 8:
            return struct.unpack('Q', qword_str)[0]
    else:
        qword_str = get_va_memory(addr, 4)
        if qword_str is not None and len(qword_str) == 4:
            return struct.unpack('I', qword_str)[0]
    return None


def get_qword_from_va(addr):
    qword_str = get_va_memory(addr, 8)
    if qword_str is not None and len(qword_str) == 8:
        return struct.unpack('Q', qword_str)[0]
    return None


def get_dword_from_va(addr):
    dword_str = get_va_memory(addr, 4)
    if dword_str is not None:
        return raw_to_int(dword_str)
    return None


def get_word_from_va(addr):
    word_str = get_va_memory(addr, 2)
    if word_str is not None:
        return raw_to_int(word_str)
    return None


def get_byte_from_va(addr):
    word_str = get_va_memory(addr, 1)
    if word_str is not None:
        return raw_to_int(word_str)
    return None


def get_unicode_from_va(addr, ignore_length=False):
    global bitness
    length = get_word_from_va(addr)
    length_max = get_word_from_va(addr+2)
    if bitness == 64:
        buffer = get_qword_from_va(addr+8)
    else:
        buffer = get_dword_from_va(addr+4)
    if length is not None and length_max is not None and (length != 0 or ignore_length) and length <= length_max:
        if ignore_length:
            string_uni = get_va_memory(buffer, length_max)
        else:
            string_uni = get_va_memory(buffer, length)
        if string_uni is not None:
            return string_uni
    return None


def get_unicode_from_va_no_zero(addr, ignore_length=False):
    result = get_unicode_from_va(addr, ignore_length)
    if result is None:
        return None
    return result.split(b'\x00\x00')[0].replace(b"\x00", b'')


def find_list_entry(address, size=0x1000):
    size = size >> 3 << 3
    dump = get_va_memory(address, size)
    if dump is None:
        return None
    for i in range(0, len(dump) >> 3):
        val = struct.unpack("Q", dump[i << 3:(i << 3)+8])[0]
        if (address+(i*8)) == get_qword_from_va(val+8):
            return (i*8)
    return None


def WindowsTime(low, high):
    low = int(low)
    high = int(high)

    if (low == 0) and (high == 0):
        return None
    t = t = float(high)*2**32 + low
    unixtime = (t*1e-7 - 11644473600)
    try:
        dt = datetime.datetime.utcfromtimestamp(unixtime)
        return str(dt)
    except Exception:
        return None


def isPXE(phys_addr):
    global bitness
    phys_addr = phys_addr & 0xfffffffffffffffffffC
    if phys_addr == 0 or phys_addr > 0x40000000000 or (phys_addr & 0xfff) != 0:
        return False
    rawdata = readFromPhys(phys_addr, 0x1000)
    if rawdata is None or len(rawdata) < 0x1000:
        return False
    if bitness == 64:
        potential_PXE_0 = raw_to_int(rawdata[0:8])
        potential_PXE_fff = raw_to_int(rawdata[0xff8:0x1000])
        if (potential_PXE_0 & 0xfdf) == 0x847 and (potential_PXE_fff & 0xfff) == 0x63:
            return True
    else:
        potential_PDE_0 = raw_to_int(rawdata[0:8])
        if (potential_PDE_0 & 0xfff) == 0x1 and (potential_PDE_0 & 0xfffffffffffffffff000) != 0:
            return True
    return False


def isVadRoot(vadRootEntry):
    rawdata = get_va_memory(vadRootEntry, 0x30)
    if rawdata is None or rawdata == b"":
        return False
    childL = struct.unpack("Q", rawdata[0x8:0x10])[0]
    childR = struct.unpack("Q", rawdata[0x10:0x18])[0]
    if childL == childR:
        return False
    if get_qword_from_va(childL) != vadRootEntry or get_qword_from_va(childR) != vadRootEntry:
        return False
    return True


def isVadRootSystem(vadRootEntry):
    rawdata = get_va_memory(vadRootEntry, 0x30)
    if rawdata is None or rawdata == b"":
        return False
    childL = struct.unpack("Q", rawdata[0x8:0x10])[0]
    childR = struct.unpack("Q", rawdata[0x10:0x18])[0]
    if childL != 0:
        return False

    if get_qword_from_va(childR) != vadRootEntry or vadRootEntry != struct.unpack("Q", rawdata[0:0x8])[0]:
        return False

    return True


def detect_eprocess_struct(process_name=b"System"):
    global EPROCESS_Struct
    global EPROCESS_List_addr
    global cr3
    if psActiveProcessHead in [None, 0, 1]:
        return None
    result = {}
    str_to_find = process_name
    str_to_find += b"\x00"*(10-len(str_to_find))
    address = get_sizet_from_va(psActiveProcessHead)
    if address is None:
        return None
    memory_datas = get_va_memory(address, 0x400)
    if str_to_find in memory_datas:
        system_str_offset = memory_datas.index(str_to_find)
        result["SYTEM_Entry"] = address
        EPROCESS_List_addr[4] = address
        EPROCESS_Struct["ProcessListEntry"] = 0
        EPROCESS_Struct["Name"] = system_str_offset

        c_off = 0
        while c_off < 0x200:
            if get_sizet_from_va(address-0x80+c_off) == 4:
                EPROCESS_Struct["Pid"] = c_off-0x80
                break
            c_off += 8

        if 'Pid' in EPROCESS_Struct:
            c_off = 0
            while c_off < 0x200:
                if 0 < (get_sizet_from_va(address-0x80+c_off) & 0xff00000000000000) < 0x0300000000000000:
                    EPROCESS_Struct["CreateTime"] = c_off-0x80
                    break
                c_off += 8

        next_address = get_sizet_from_va(address)
        c_off = 0
        while c_off < 0x280:
            if get_sizet_from_va(next_address + c_off) == 4:
                EPROCESS_Struct["PPid"] = c_off
                break
            c_off += 8

        c_off = 0
        while c_off < 0xc00:
            if is_gdb:
                cpointer = get_sizet_from_va(address-0x600+c_off)
                if (cpointer >> 48) == 0xffff:
                    base_pointer = find_pool_chunck(cpointer)
                    if base_pointer is not None:
                        pool_chunk = get_pool_tag(base_pointer)
                        if pool_chunk['tag'] == b'Thre':
                            prev_cr3 = get_sizet_from_va((address-0x600+c_off)-8)
                            if prev_cr3 is not None and prev_cr3 > 0x10000 and prev_cr3 < 0x10000000000 and (prev_cr3 & 0xffc) == 0:
                                EPROCESS_Struct["CR3"] = c_off-8-0x600
                                EPROCESS_Struct["ThreadListHead"] = c_off-0x600
                                break
            elif isPXE(get_sizet_from_va(address-0x600+c_off) & 0xfffffffffffffffc):
                EPROCESS_Struct["CR3"] = c_off-0x600
                EPROCESS_Struct["ThreadListHead"] = c_off+8-0x600
                break
            c_off += 8
        next_addr = address
        tb_addr = []
        while not ('CR3' in EPROCESS_Struct) and not (next_addr in tb_addr):
            c_off = 0
            tb_addr.append(next_addr)
            next_addr = get_sizet_from_va(next_addr)
            while c_off < 0xc00:
                if is_gdb:
                    cpointer = get_sizet_from_va(address-0x600+c_off)
                    if (cpointer >> 48) == 0xffff:
                        base_pointer = find_pool_chunck(cpointer)
                        if base_pointer is not None:
                            pool_chunk = get_pool_tag(base_pointer)
                            if pool_chunk['tag'] == b'Thre':
                                prev_cr3 = get_sizet_from_va((address-0x600+c_off)-8)
                                if prev_cr3 is not None and prev_cr3 > 0x10000 and prev_cr3 < 0x10000000000 and (prev_cr3 & 0xffc) == 0:
                                    EPROCESS_Struct["CR3"] = c_off-8-0x600
                                    EPROCESS_Struct["ThreadListHead"] = c_off-0x600
                                    break
                elif isPXE(get_sizet_from_va(next_addr-0x600+c_off) & 0xfffffffffffffffc):
                    EPROCESS_Struct["CR3"] = c_off-0x600
                    EPROCESS_Struct["ThreadListHead"] = c_off+8-0x600
                    break
                c_off += 8

        if "CR3" in EPROCESS_Struct:
            bak_cr3 = cr3
            c_off = -0x200
            nn_eprocess = get_sizet_from_va(get_sizet_from_va(get_sizet_from_va(address)))
            new_cr3 = get_qword_from_va(nn_eprocess+EPROCESS_Struct["CR3"])
            if is_gdb:
                EPROCESS_Struct["PEB"] = c_off
            elif isPXE(new_cr3):
                cr3 = new_cr3
                while c_off < 0x600:
                    if is_PEB(get_sizet_from_va(nn_eprocess+c_off)):
                        EPROCESS_Struct["PEB"] = c_off
                        break
                    c_off += 8
            cr3 = bak_cr3
        return EPROCESS_Struct
    return None


def find_valid_cr3(form_phys_addr=0):
    global debug
    global cr3
    for base_page, size, file_offset in phys_to_file:
        if (base_page+size) < form_phys_addr:
            continue
        dist = 0
        if base_page < form_phys_addr:
            dist = (form_phys_addr-base_page)
        for cpage in range((size-dist) >> 12):
            cpage_address = base_page+dist+(cpage << 12)
            rawdata = readFromPhys(cpage_address, 0x1000)
            if rawdata is None or len(rawdata) < 0x1000:
                continue
            potential_PXE_0 = struct.unpack('Q', rawdata[0:8])[0]
            potential_PXE_fff = struct.unpack('Q', rawdata[0xff8:0x1000])[0]
            if (potential_PXE_0 & 0xfdf) == 0x847 and (potential_PXE_fff & 0xfff) == 0x63:
                for i in range(0x100):
                    if (struct.unpack('Q', rawdata[0x800+(i << 3):0x800+8+(i << 3)])[0] & 0x0000fffffffff000) == cpage_address:
                        cr3 = cpage_address
                        if debug > 0:
                            print("  [*] CR3 found : 0x%X !" % cr3)
                        return cr3
    if debug > 0:
        print("  [!] CR3 not found :(")
    return None


def find_eprocess_from_cr3():
    return None


def find_all_process_cr3():
    global debug

    if is_live:
        return None

    cr3_list = []
    readSize = 0x4000000
    totalRead = 0
    rawdata = readFromFile(0, readSize)
    while rawdata != "" and rawdata is not None:
        offset = 0
        while offset < len(rawdata):
            potential_PXE_0 = raw_to_int(rawdata[offset:offset+8])
            potential_PXE_fff = raw_to_int(rawdata[offset+0xff8:offset+0x1000])
            if (potential_PXE_0 & 0xfff) == 0x867 and rawdata[offset+0x80:offset+0x200].replace(b"\x00", b'') == b'' and (potential_PXE_fff & 0xfff) == 0x63:  # and (potential_PXE_0fff & 0xfff) == 0x867 and (potential_PXE_fff & 0xfff) == 0x63 and rawdata[offset+8:offset+0x78].replace("\x00",'') == '' and rawdata[offset+0x80:offset+0x200].replace("\x00",'') == '':
                cr3_list.append(get_phys_from_file_offset(totalRead+offset))
            offset += 0x1000
        totalRead += readSize
        rawdata = readFromFile(totalRead, readSize)
    return cr3_list


def get_va_from_phys(address):
    global kernel_mapping

    if kernel_mapping is None:
        kernel_mapping = get_pages_list(0xffff800000000000, 0xffffffffffffffff)
    for page in kernel_mapping:
        if kernel_mapping[page]['phys'] == (address & 0xfffffffff000):
            return (0xffff000000000000 | (page + (address & 0xfff)))
    return None


def find_kpcrb(start_kernel_va=0xffff800000000000, stop_kernel_va=0xffffffffffffffff):
    global kpcr_address
    global kernel_mapping
    if kpcr_address is not None:
        return kpcr_address
    if kernel_mapping is None:
        kernel_mapping = get_pages_list(start_kernel_va, stop_kernel_va)
    for page in kernel_mapping:
        if kernel_mapping[page]['right']['exec'] and kernel_mapping[page]['right']['write']:
            page = (page | 0xffff000000000000)
            datas = get_va_memory(page, 0x40)
            if datas is not None and len(datas) == 0x40:
                kpcr = struct.unpack('Q', datas[0x18:0x20])[0]
                if kpcr == page:
                    kpcr_address = kpcr
                    return kpcr


def find_crawl_vacb():
    global debug
    global cr3
    global struct_Vacb
    global vacbAddress
    global vacbSize

    if vacbAddress is None:
        dump = get_driver_section(b"nt", b".data")
        if dump is None:
            return None
        size = len(dump)-(len(dump) % 8)
        sdump = struct.unpack('Q'*(size >> 3), dump)
        for i in range(0, len(sdump)-1):
            sub_addr = sdump[i]
            sub_addr_next = sdump[i+1]

            if (sub_addr & 0xffff800000000000) != 0xffff800000000000 or (sub_addr & 0xfff) != 0:
                continue
            sub_dump = get_va_memory(sub_addr, 0x100)
            if sub_dump is None:
                continue
            try:
                sub_addr_next = struct.unpack("Q"*0x20, sub_dump).index(0)
                if sub_addr_next <= 0:
                    continue
            except Exception:
                continue
            sub_dump = get_va_memory(sub_addr, (sub_addr_next*8) + 8)
            if sub_dump is None or len(sub_dump) != ((sub_addr_next*8) + 8):
                continue
            ssub_dump = struct.unpack("Q"*(sub_addr_next+1), sub_dump)
            if ssub_dump[-1] != 0:
                continue
            is_vacb = True
            for csub_index in range(len(ssub_dump)-1):
                csub = ssub_dump[csub_index]
                if ((csub & 0xffff800000000000) == 0xffff800000000000):
                    vacb_header_dump = get_va_memory(csub, 0x40)
                    if vacb_header_dump is not None and len(vacb_header_dump) == 0x40 and struct.unpack("I", vacb_header_dump[:4])[0] == csub_index:
                        continue
                is_vacb = False
            if is_vacb:
                print("Vacb : %x ; size : %x" % (sub_addr, sub_addr_next))
                vacbAddress = sub_addr
                vacbSize = sub_addr_next
        if vacbAddress is None:
            return None
    crawl_vacb()
    return


def crawl_vacb():
    global vacbAddress
    global vacbSize
    global struct_VACB_ListEntry_Offset

    for cArrayAddr in struct.unpack("Q"*vacbSize, get_va_memory(vacbAddress, vacbSize*8)):
        if struct_VACB_ListEntry_Offset is None:
            struct_VACB_ListEntry_Offset = find_list_entry(cArrayAddr)
            if struct_VACB_ListEntry_Offset is None:
                continue
        crawl_list(cArrayAddr+struct_VACB_ListEntry_Offset, cb_check_vacb_array_element)


def cb_check_vacb_array_element(address):
    global share_cache_offset
    base_address_vacb = get_qword_from_va(address+0x18)

    if base_address_vacb is not None:
        if share_cache_offset is None:
            for cshare_cache_offset in range(3, 8):
                dest_ptr = get_qword_from_va(address+(cshare_cache_offset*8))
                if dest_ptr is not None and get_va_memory(dest_ptr-0xc, 4) == b"CcSc":
                    share_cache_offset = (cshare_cache_offset*8)
                    break
            if share_cache_offset is None:
                return
        dest_datas = get_va_memory(base_address_vacb, 0x40)
        share_cache_ptr = get_qword_from_va(address+share_cache_offset)
        if share_cache_ptr != 0 and dest_datas is not None and len(dest_datas) > 0x20:
            share_cache_infos = get_shared_cache_map(share_cache_ptr)
            if share_cache_infos is not None and 'FileObjectFastRef_name' in share_cache_infos and share_cache_infos['FileObjectFastRef_name'] is not None:
                if not (share_cache_infos['FileObjectFastRef_name'].replace(b"\x00", b'') in [b'\\$Directory']):
                    print("0x%x %s (%d)" % (base_address_vacb, share_cache_infos['FileObjectFastRef_name'].replace(b"\x00", b'').decode(), share_cache_infos['FileSize']))


def decode_shared_cache_map(address):
    global struct_SHARED_CACHE_MAP

    pool_header = get_pool_tag(address)
    if pool_header is None or 'tag' not in pool_header or pool_header['tag'] != b'CcSc':
        return None
    struct_SHARED_CACHE_MAP = {'OpenCount': 4, 'FileSize': 8, 'Bcd': 0x10, 'SectionSize': 0x20, 'Vacbs': 0x58}
    offset = 0x28
    while offset < 0x100:
        current_address = get_qword_from_va(address+offset)
        if (current_address & 0xffff800000000000) == 0xffff800000000000 and get_word_from_va(current_address) == 5:
            struct_SHARED_CACHE_MAP['FileObjectFastRef'] = offset
            uni_offset = find_unicode_string(current_address+0x8, 0x100)
            if uni_offset != 0 and uni_offset is not None:
                struct_SHARED_CACHE_MAP['FileObjectFastRef_name'] = uni_offset+8
            return struct_SHARED_CACHE_MAP
        offset += 8


def get_shared_cache_map(address):
    global struct_SHARED_CACHE_MAP

    if struct_SHARED_CACHE_MAP is None:
        decode_shared_cache_map(address)
    if struct_SHARED_CACHE_MAP is None:
        return None
    if not ('FileObjectFastRef_name' in struct_SHARED_CACHE_MAP):
        decode_shared_cache_map(address)
    result = {}

    result['OpenCount'] = get_dword_from_va(address+struct_SHARED_CACHE_MAP['OpenCount'])
    result['FileSize'] = get_qword_from_va(address+struct_SHARED_CACHE_MAP['FileSize'])
    result['SectionSize'] = get_qword_from_va(address+struct_SHARED_CACHE_MAP['SectionSize'])
    result['Vacbs'] = get_qword_from_va(address+struct_SHARED_CACHE_MAP['Vacbs'])
    if 'FileObjectFastRef' in struct_SHARED_CACHE_MAP:
        result['FileObjectFastRef_addr'] = get_qword_from_va(address+struct_SHARED_CACHE_MAP['FileObjectFastRef'])
        if result['FileObjectFastRef_addr'] is not None and result['FileObjectFastRef_addr'] != 0 and get_va_memory(result['FileObjectFastRef_addr'], 0x20) is not None and 'FileObjectFastRef_name' in struct_SHARED_CACHE_MAP:
            result['FileObjectFastRef_name'] = get_unicode_from_va(result['FileObjectFastRef_addr']+struct_SHARED_CACHE_MAP['FileObjectFastRef_name'])
    return result


def find_eprocess_without_system():
    global debug
    global cr3

    if is_live:
        return None

    backup_cr3 = cr3

    if debug > 0:
        print("  [*] Crawling all CR3 from raw memory dump")
    cr3_list = find_all_process_cr3()

    if cr3_list == []:
        print("WTF ?!?! Are you sur it's a memory dump ?")
        return None

    physList = []
    for cr3 in cr3_list:
        cr3 = cr3_list[0]
        pages = get_pages_list(0xffff800000000000, 0xffffffffffffffff)
        if len(pages) > 10000:
            physList = [pages[a]["phys"] for a in pages]
            break

    if debug > 0:
        print("  [*] Try to find Eprocess by CR3")
    regex_to_match = re.compile(b'(?:'+b'|'.join([int_to_raw(a).replace(b"\\", b"\\\\").replace(b".", b"\\.").replace(b"(", b"\\(").replace(b")", b"\\)").replace(b"+", b"\\+").replace(b"{", b"\\{").replace(b"}", b"\\}").replace(b"|", b"\\|").replace(b"[", b"\\[").replace(b"]", b"\\]") for a in cr3_list])+')')
    readSize = 0x4000000
    totalRead = 0
    rawdata = readFromFile(0, readSize)
    while rawdata != "" and rawdata is not None:
        offset = 0
        while offset < len(rawdata):
            match_regex = regex_to_match.search(rawdata, offset)
            if match_regex is not None:
                cr3_offset = match_regex.start()
                if (cr3_offset & 7) == 0:
                    matched_value = match_regex.group()
                    phys_offset = get_phys_from_file_offset(totalRead+cr3_offset)
                    if phys_offset is None:
                        offset += cr3_offset+1
                        continue
                    print("File : 0x%X" % (totalRead+cr3_offset))
                    print("PHYS : 0x%X" % phys_offset)
                    cr3 = raw_to_int(matched_value)

                    process_infos = get_process_informations()
                    print_process_infos_userland(process_infos)
                    if not ("ImagePathName" in process_infos):
                        offset += cr3_offset+1
                        continue
                    process_name = process_infos["ImagePathName"].split("\\")[-1][:14]
                    if (phys_offset & 0x0000fffffffff000) in physList:
                        print("Have a VA !")
                        for page in pages.keys():
                            if pages[page]["phys"] == (phys_offset & 0x0000fffffffff000):
                                print("PHYS : 0x%X is at 0x%X" % (phys_offset, page))
                                mempage = page-0x1000
                                memory_datas = ""
                                if get_va_memory(mempage, 0x1000) is not None:
                                    memory_datas += get_va_memory(mempage, 0x1000)
                                else:
                                    mempage += 0x1000
                                memory_datas += get_va_memory(page, 0x1000)
                                if get_va_memory(page+0x1000, 0x1000) is not None:
                                    memory_datas += get_va_memory(page+0x1000, 0x1000)
                                eprocess_struct = detect_eprocess_struct(memory_datas, mempage, process_name)
                                if eprocess_struct is not None:
                                    return eprocess_struct
            else:
                break
            offset += cr3_offset+1
        totalRead += readSize
        rawdata = readFromFile(totalRead, readSize)
    cr3 = backup_cr3


def find_eprocess_system():
    global debug
    global kernel_mapping
    global cr3
    global psActiveProcessHead

    dump = get_driver_section(b"nt", b".data")
    if dump is None:
        return None
    size = len(dump)-(len(dump) % 8)
    sdump = struct.unpack('Q'*(size >> 3), dump)
    for i in range(0, len(sdump)):
        sub_addr = sdump[i]
        if (sub_addr & 0xffff800000000000) != 0xffff800000000000:
            continue
        sub_dump = get_va_memory(sub_addr, 0x200)
        if sub_dump is None or len(sub_dump) != 0x200:
            continue
        sub_flink, sub_blink = struct.unpack("QQ", sub_dump[:0x10])
        if ((sub_flink & 0xffff800000000000) == 0xffff800000000000) and ((sub_blink & 0xffff800000000000) == 0xffff800000000000):
            if get_sizet_from_va(sub_flink) is not None and sub_flink == get_sizet_from_va(get_sizet_from_va(sub_flink)+8):
                sub_sub_dump = get_va_memory(get_sizet_from_va(sub_flink), 0x400)
                if sub_sub_dump is None:
                    continue
                system_offset = sub_sub_dump.find(b"System\x00\x00\x00\x00")
                if (system_offset & 0x3) == 0:
                    psActiveProcessHead = sub_flink
                    detect_eprocess_struct()
                    return sub_addr
    return None


def get_eprocess_infos_from_address(eprocess_flink_va):
    global EPROCESS_Struct
    process = {}
    for key in EPROCESS_Struct:
        if key == "Name":
            datas = get_va_memory(eprocess_flink_va + EPROCESS_Struct[key], 0x10)
            if datas is None:
                return {}
            process[key] = get_va_memory(eprocess_flink_va + EPROCESS_Struct[key], 0x10).split(b"\x00")[0]
        elif key == "ProcessListEntry":
            process["Flink"] = get_qword_from_va(eprocess_flink_va + EPROCESS_Struct[key])
            process["Blink"] = get_qword_from_va(eprocess_flink_va + EPROCESS_Struct[key] + 8)
        else:
            process[key] = get_qword_from_va(eprocess_flink_va + EPROCESS_Struct[key])
    return process


def get_eprocess_process_list():
    global EPROCESS_Struct
    global EPROCESS_List
    global EPROCESS_List_addr

    if not (4 in EPROCESS_List_addr):
        return None

    flink = EPROCESS_List_addr[4]
    eprocess_parsed = []
    while not (flink in eprocess_parsed) and flink is not None:
        curr_process = get_eprocess_infos_from_address(flink)
        if "CR3" in curr_process:
            EPROCESS_List[curr_process["Pid"]] = curr_process
            EPROCESS_List_addr[curr_process['Pid']] = flink
            try:
                time_str = WindowsTime(curr_process['CreateTime'] & 0xffffffff, curr_process['CreateTime'] >> 32)
            except Exception:
                time_str = "???"
            if 'PEB' in EPROCESS_Struct:
                print("%6d %6d %16s 0x%016x 0x%016x %x %s" % (curr_process['Pid'], curr_process['PPid'], curr_process['Name'].decode(errors='ignore'), curr_process['PEB'], curr_process['CR3'], flink, time_str))
            else:
                print("%6d %6d %16s 0x%016x %x %s" % (curr_process['Pid'], curr_process['PPid'], curr_process['Name'].decode(errors='ignore'), curr_process['CR3'], flink, time_str))
            eprocess_parsed.append(flink)
            flink = curr_process["Flink"]
        else:
            break
    for fpid in EPROCESS_List_addr:
        blink = EPROCESS_List_addr[fpid]
        eprocess_parsed_blink = []
        while not (blink in eprocess_parsed_blink):
            curr_process = get_eprocess_infos_from_address(blink)
            if "CR3" in curr_process and not (blink in eprocess_parsed):
                EPROCESS_List[curr_process["Pid"]] = curr_process
                print("%6d %6d %16s 0x%016x 0x%016x" % (curr_process['Pid'], curr_process['PPid'], curr_process['Name'], curr_process['PEB'], curr_process['CR3']))
                eprocess_parsed_blink.append(blink)
                blink = curr_process["Blink"]
            else:
                break

    return


def is_PEB(address):
    if address is None:
        return False
    if address >= 0x800000000000:
        return False
    process_PEB_Ldr = get_qword_from_va(address+0x18)
    if process_PEB_Ldr is None:
        return False
    process_PEB_Ldr_InMemoryOrderModuleList = get_qword_from_va(process_PEB_Ldr+0x20)
    if process_PEB_Ldr_InMemoryOrderModuleList is None:
        return False
    current_module_DllName = get_unicode_from_va(process_PEB_Ldr_InMemoryOrderModuleList+0x38)
    if current_module_DllName is None:
        return False
    current_module_DllName = current_module_DllName.replace(b"\x00", b'')
    if len(current_module_DllName) >= 4:
        return True
    return False


def is_TEB(address):
    if get_qword_from_va(address+0x30) == address:
        stack_size = get_qword_from_va(address+0x8) - get_qword_from_va(address+0x10)
        if stack_size > 0 and stack_size < 0x100000 and (stack_size & 0xfff) == 0:
            return True
    return False


def get_process_informations(pid=None):
    global cr3
    global Process_List
    process_infos = {}

    ceprocess = EPROCESS_List[pid]
    process_PEB = ceprocess["PEB"]
    bak_cr3 = cr3
    cr3 = ceprocess["CR3"]
    process_PEB_ImageBase = get_qword_from_va(process_PEB+0x10)
    process_PEB_ProcessParameters = get_qword_from_va(process_PEB+0x20)
    if process_PEB_ProcessParameters is None:
        print("Invalid PEB :(")
        cr3 = bak_cr3
        return {}
    print("process_PEB_ProcessParameters : "+hex(process_PEB_ProcessParameters))
    if process_PEB_ImageBase is None or process_PEB_ProcessParameters is None:
        return process_infos

    process_PEB_Ldr = get_qword_from_va(process_PEB+0x18)
    process_PEB_Ldr_InLoadOrderModuleList = get_qword_from_va(process_PEB_Ldr+0x10)
    if process_PEB_Ldr_InLoadOrderModuleList is not None:
        process_infos["InLoadOrderModuleList"] = process_PEB_Ldr_InLoadOrderModuleList

    process_PEB_Ldr_InMemoryOrderModuleList = get_qword_from_va(process_PEB_Ldr+0x20)
    if process_PEB_Ldr_InMemoryOrderModuleList is not None:
        process_infos["InMemoryOrderModuleList"] = process_PEB_Ldr_InMemoryOrderModuleList

    process_PEB_ProcessParameters_DllPath = get_unicode_from_va(process_PEB_ProcessParameters+0x50)
    if process_PEB_ProcessParameters_DllPath is not None:
        process_PEB_ProcessParameters_DllPath = process_PEB_ProcessParameters_DllPath.replace(b"\x00", b'')
        process_infos["Path"] = process_PEB_ProcessParameters_DllPath

    process_PEB_ProcessParameters_ImagePathName = get_unicode_from_va(process_PEB_ProcessParameters+0x60)
    if process_PEB_ProcessParameters_ImagePathName is not None:
        process_PEB_ProcessParameters_ImagePathName = process_PEB_ProcessParameters_ImagePathName.replace(b"\x00", b'')
        process_infos["ImagePathName"] = process_PEB_ProcessParameters_ImagePathName

    process_PEB_ProcessParameters_CommandLine = get_unicode_from_va(process_PEB_ProcessParameters+0x70)
    if process_PEB_ProcessParameters_CommandLine is not None:
        process_PEB_ProcessParameters_CommandLine = process_PEB_ProcessParameters_CommandLine.replace(b"\x00", b'')
        process_infos["CommandLine"] = process_PEB_ProcessParameters_CommandLine

    process_infos["CR3"] = cr3

    current_module = process_PEB_Ldr_InMemoryOrderModuleList
    list_modules = []
    list_modules_info = []
    while not (current_module in list_modules) and current_module is not None and current_module != 0:
        list_modules.append(current_module)
        current_module_infos = {}

        current_module_DllName = get_unicode_from_va(current_module+0x38)
        if current_module_DllName is not None:
            current_module_DllName = current_module_DllName.replace(b"\x00", b'')
            current_module_infos["DllName"] = current_module_DllName

        current_module_ImageBase = get_qword_from_va(current_module+0x20)
        if current_module_ImageBase is not None:
            current_module_infos["ImageBase"] = current_module_ImageBase

        current_module_Size = get_qword_from_va(current_module+0x40)
        if current_module_Size is not None:
            current_module_infos["Size"] = current_module_Size

        current_module_Timestamp = None
        if get_qword_from_va(current_module+0xf0) is not None:
            current_module_Timestamp = WindowsTime(get_dword_from_va(current_module+0xf0), get_dword_from_va(current_module+0xf4))
        if current_module_Timestamp is not None:
            current_module_infos["Timestamp"] = current_module_Timestamp
        else:
            current_module_Timestamp = "                          "

        if current_module_infos != {}:
            list_modules_info.append(current_module_infos)

        current_module = get_qword_from_va(current_module)

    process_infos['Modules'] = list_modules_info
    Process_List[cr3] = process_infos
    cr3 = bak_cr3
    return process_infos


def print_process_infos_userland(pi_datas):
    if 'PID' in pi_datas:
        print("    PID : %d" % pi_datas['PID'])
    if 'ImagePathName' in pi_datas:
        print("    ImagePathName : %s" % pi_datas['ImagePathName'])
    if 'CommandLine' in pi_datas:
        print("    CommandLine : %s" % pi_datas['CommandLine'])
    if 'Modules' in pi_datas:
        for module_datas in pi_datas['Modules']:
            if 'DllName' in module_datas:
                if 'Timestamp' in module_datas:
                    print("      %016X  %016X  %s  %s" % (module_datas['ImageBase'], module_datas['Size'], module_datas['Timestamp'], module_datas['DllName']))
                elif module_datas['DllName'] != '':
                    print("      %016X  %016X                              %s" % (module_datas['ImageBase'], module_datas['Size'], module_datas['DllName']))


def detect_driver_entry_struct(address_tag, trusted_struct=False):
    global Driver_list_Struct
    global Drivers_list_addr
    global cr3
    global bitness

    if bitness == 64:
        result = {'Flink': 0, 'Blink': 8}
    else:
        result = {'Flink': 0, 'Blink': 4}

    flink_offset = None

    if bitness == 64:
        address_tag = (0xffff000000000000 | address_tag)

    chunk = get_pool_tag(address_tag)
    if chunk is None or not ('tag' in chunk) or chunk['tag'] != b'MmLd':
        return None

    memory_dump = get_va_memory(address_tag, chunk['size'])

    if memory_dump is None:
        return None
    offset = 0
    pe_size_of_image = None
    while offset < len(memory_dump):
        if bitness == 64:
            flink_ptr = struct.unpack("Q", memory_dump[offset:offset+8])[0]
        else:
            flink_ptr = struct.unpack("I", memory_dump[offset:offset+4])[0]
        ptr_mem = get_va_memory(flink_ptr, 0x1000)
        if ptr_mem is not None:
            if (address_tag+offset) == get_sizet_from_va(flink_ptr+result['Blink']):
                flink_offset = offset
            if flink_offset is not None:
                if ptr_mem[:4] == b"MZ\x90\00":
                    result['ImageBase'] = offset - flink_offset
                    e_lfanew = struct.unpack('I', ptr_mem[0x3c:0x40])[0]
                    pe_size_of_image = struct.unpack('I', ptr_mem[e_lfanew+0x50:e_lfanew+0x54])[0]
        if flink_offset is not None and not ('Name' in result) and (trusted_struct or (flink_ptr & 0xffffffff) == 0x420042 or (flink_ptr & 0xffffffff) == 0x420044 or (flink_ptr & 0xffffffff) == 0x440042):
            uni_str = get_unicode_from_va(address_tag+offset)
            if uni_str is not None and uni_str.replace(b"\x00", b'').endswith(b'ntoskrnl.exe'):
                result['Name'] = offset - flink_offset
        if pe_size_of_image is not None and flink_ptr == pe_size_of_image:
            result['Size'] = offset
        if pe_size_of_image is not None and (flink_ptr >> 32) == pe_size_of_image:
            result['Size'] = offset+4
        if bitness == 64:
            offset += 8
        else:
            offset += 4
    if 'ImageBase' in result and 'Name' in result and flink_ptr is not None:
        Driver_list_Struct = result
        Drivers_list_addr = address_tag
        return result
    return None


def find_driver_list(start_from_offset=0, start_kernel_va=0xffff800000000000, stop_kernel_va=0xffffffffffffffff):
    global debug
    global kernel_mapping
    global cr3
    global cr3_system
    readSize = 0x4000000
    if cr3 is None:
        if cr3_system is None:
            if debug > 0:
                print("  [*] No CR3 set trying to find the a new CR3")
            find_valid_cr3()
            if cr3_system is None:
                if debug > 0:
                    print("  [!] Shit, CR3 not found :-( Go to crawl CR3 in the wild !")
                return None
        cr3 = cr3_system

    if psLoadedModuleList is not None:
        ntoskrnl_flink_addr = get_sizet_from_va(psLoadedModuleList)
        if ntoskrnl_flink_addr is None:
            print("  [!] PsLoadedModuleList not valid : %x" % psLoadedModuleList)
            return None
        driver_entry_struct = detect_driver_entry_struct(ntoskrnl_flink_addr, trusted_struct=True)
        if driver_entry_struct is not None:
            return driver_entry_struct

    if is_live:
        return None

    if kernel_mapping is None:
        kernel_mapping = get_pages_list(start_kernel_va, stop_kernel_va)
        if debug > 0:
            print("  [*] Pages list is carved : %d pages" % len(kernel_mapping))
    pages = kernel_mapping

    rawdata = readFromFile(start_from_offset, readSize)
    totalRead = start_from_offset

    physList = [pages[a]["phys"] for a in pages]
    while rawdata != "" and rawdata is not None:
        offset = 0
        while offset < len(rawdata):
            tag_offset = rawdata.find(b"\x42\x00\x42\x00\x00\x00\x00\x00", offset)
            if tag_offset == -1:
                tag_offset = rawdata.find(b"\x42\x00\x44\x00\x00\x00\x00\x00", offset)
            if tag_offset >= 0 and rawdata[tag_offset+14:tag_offset+16] == b"\xff\xff":
                if (tag_offset & 7) == 0:
                    phys_offset = get_phys_from_file_offset(totalRead+tag_offset)
                    if (phys_offset & 0x0000fffffffff000) in physList:
                        for page in pages.keys():
                            if pages[page]["phys"] == (phys_offset & 0x0000fffffffff000):
                                va_address_offset = page+phys_offset-pages[page]["phys"]
                                uni_str = get_unicode_from_va_no_zero(va_address_offset)
                                if uni_str is not None and uni_str.endswith(b'ntoskrnl.exe'):
                                    driver_entry_struct = detect_driver_entry_struct(va_address_offset-0xa0)
                                    if driver_entry_struct is not None:
                                        return driver_entry_struct
            else:
                break
            offset += tag_offset+1
        totalRead += readSize
        rawdata = readFromFile(totalRead, readSize)


def get_driver_infos_from_flink_address(driver_flink_va):
    global Driver_list_Struct
    driver = {}
    for key in Driver_list_Struct:
        if key == "Name":
            uni_str = get_unicode_from_va_no_zero(driver_flink_va + Driver_list_Struct[key], True)
            if uni_str is not None:
                driver[key] = uni_str
            else:
                return None
        elif key == 'Size':
            driver[key] = get_dword_from_va(driver_flink_va + Driver_list_Struct[key])
        else:
            driver[key] = get_sizet_from_va(driver_flink_va + Driver_list_Struct[key])
    return driver


def get_drivers_list(force=False):
    global Driver_list_Struct
    global Drivers_list_addr
    global Drivers_list
    global modules_eat
    global bitness

    if not force and Drivers_list is not None and len(Drivers_list) > 0:
        return Drivers_list

    cdrivers_list = {}
    if Drivers_list is None:
        Drivers_list = {}

    if Drivers_list_addr is None or Driver_list_Struct is None:
        if find_driver_list() is None:
            return None

    flink = Drivers_list_addr
    drivers_parsed = []
    while not (flink in drivers_parsed) and flink is not None:
        curr_driver = get_driver_infos_from_flink_address(flink)
        if curr_driver is None:
            break
        if "Name" in curr_driver and 'ImageBase' in curr_driver and not (curr_driver['ImageBase'] in Drivers_list):
            cdrivers_list[curr_driver['ImageBase']] = curr_driver
            Drivers_list[curr_driver['ImageBase']] = curr_driver
            drivers_parsed.append(flink)
            eat_name = b'.'.join([bytes(a) for a in curr_driver['Name'].split(b"\\")[-1].split(b'.')[:-1]])
            if eat_name == b'':
                eat_name = curr_driver['Name'].split(b"\\")[-1]
            if eat_name == b'ntoskrnl':
                eat_name = b'nt'
            eat_name = bytes(eat_name)
            if eat_name not in modules_eat:
                modules_eat[eat_name.lower()] = {}
        flink = curr_driver["Flink"]

    drivers_parsed = []
    to_update_drivers = {}
    for cimagebase in Drivers_list:
        blink = Drivers_list[cimagebase]["Blink"]
        while not (blink in drivers_parsed) and blink is not None:
            curr_driver = get_driver_infos_from_flink_address(blink)
            drivers_parsed.append(blink)
            if curr_driver is None:
                break
            if "Name" in curr_driver and 'ImageBase' in curr_driver and is_kernel_space(curr_driver["ImageBase"]) and not (curr_driver['ImageBase'] in Drivers_list):
                cdrivers_list[curr_driver['ImageBase']] = curr_driver
                if not (curr_driver['ImageBase'] in Drivers_list):
                    to_update_drivers[curr_driver['ImageBase']] = curr_driver
                eat_name = b'.'.join(curr_driver['Name'].split(b"\\")[-1].split(b'.')[:-1])
                if eat_name == b'':
                    eat_name = curr_driver['Name'].split(b"\\")[-1]
                if eat_name == b'ntoskrnl':
                    eat_name = b'nt'
                if eat_name not in modules_eat:
                    modules_eat[eat_name.lower()] = {}
            blink = curr_driver["Blink"]
    Drivers_list.update(to_update_drivers)
    return cdrivers_list


def dump_module(address, module_name=None, max_size=300000):
    datas = b""
    mem_dump = get_va_memory(address, 0x1000)
    offset = 0
    while mem_dump is not None and len(datas) < max_size:
        datas += mem_dump
        offset += 0x1000
        mem_dump = get_va_memory(address+offset, 0x1000)
    if module_name is None:
        open("%X-%X.sys" % (address, address+offset), "wb").write(datas)
    else:
        open(module_name, "wb").write(datas)


def is_PE_Entry(memory_dump):
    if memory_dump[:2] == b"MZ" or b"This program " in memory_dump:
        return True
    return False


def get_driver_name(filename):
    filename = filename.lower()
    if type(filename) is str:
        filename = bytes(bytearray(filename, 'utf8'))
    if filename.startswith(b"\\systemroot\\"):
        filename = filename.replace(b"\\systemroot\\", b"c:\\windows\\")
    if filename.startswith(b"\\??\\"):
        filename = filename.replace(b"\\??\\", b'')
    return filename


def isFile(filename):
    filename = get_driver_name(filename)
    if type(filename) is bytearray:
        filename = bytes(filename).decode()
    return os.path.isfile(filename)


def pe_decode_dos_header(datas):
    result = {}
    if len(datas) < 0x40:
        return result
    if datas[:2] != b'MZ':
        return result
    result['e_lfanew'] = struct.unpack('I', datas[0x3c:0x40])[0]
    return result


def pe_decode_pe_header(datas):
    global bitness
    result = {}

    if bitness == 64:
        opt_header_size = 0xf0
        opt_tables_start = 0x88
    else:
        opt_header_size = 0xe0
        opt_tables_start = 0x78
    if len(datas) < opt_header_size:
        return result
    result['machine'] = struct.unpack('H', datas[0x4:0x6])[0]
    result['number_of_sections'] = struct.unpack('H', datas[0x6:0x8])[0]
    result['timestamp'] = struct.unpack('I', datas[0x8:0xc])[0]
    result['size_of_optional_header'] = struct.unpack('H', datas[0x14:0x16])[0]
    result['characteristics'] = struct.unpack('H', datas[0x16:0x18])[0]
    result['magic'] = struct.unpack('H', datas[0x18:0x1a])[0]
    result['size_of_code'] = struct.unpack('I', datas[0x1c:0x20])[0]
    result['entry_point'] = struct.unpack('I', datas[0x28:0x2c])[0]
    if bitness == 64:
        result['image_base'] = struct.unpack('Q', datas[0x30:0x38])[0]
    else:
        result['image_base'] = struct.unpack('I', datas[0x34:0x38])[0]
    result['size_of_image'] = struct.unpack('I', datas[0x50:0x54])[0]
    result['size_of_headers'] = struct.unpack('I', datas[0x54:0x58])[0]
    result['export_address_table_address'] = struct.unpack('I', datas[opt_tables_start:opt_tables_start+4])[0]
    result['export_address_table_size'] = struct.unpack('I', datas[opt_tables_start+4:opt_tables_start+8])[0]
    result['import_address_table_address'] = struct.unpack('I', datas[opt_tables_start+8:opt_tables_start+0xc])[0]
    result['import_address_table_size'] = struct.unpack('I', datas[opt_tables_start+0xc:opt_tables_start+0x10])[0]
    result['relocation_table_address'] = struct.unpack('I', datas[opt_tables_start+0x28:opt_tables_start+0x2c])[0]
    result['relocation_table_size'] = struct.unpack('I', datas[opt_tables_start+0x2c:opt_tables_start+0x30])[0]
    return result


def pe_decode_sections(datas):
    global bitness
    result = []
    number_of_sections = struct.unpack('H', datas[0x6:0x8])[0]
    if bitness == 64:
        size_of_optional_header = 0x108
    else:
        size_of_optional_header = 0xf8

    for i in range(0, number_of_sections):
        tresult = {}
        tresult['name'] = datas[size_of_optional_header+(0x28*i):size_of_optional_header+8+(0x28*i)].split(b"\x00")[0]
        tresult['virtual_size'] = struct.unpack('I', datas[size_of_optional_header+0x8+(0x28*i):size_of_optional_header+0xc+(0x28*i)])[0]
        tresult['virtual_address'] = struct.unpack('I', datas[size_of_optional_header+0xc+(0x28*i):size_of_optional_header+0x10+(0x28*i)])[0]
        tresult['raw_size'] = struct.unpack('I', datas[size_of_optional_header+0x10+(0x28*i):size_of_optional_header+0x14+(0x28*i)])[0]
        tresult['raw_address'] = struct.unpack('I', datas[size_of_optional_header+0x14+(0x28*i):size_of_optional_header+0x18+(0x28*i)])[0]
        tresult['reloc_address'] = struct.unpack('I', datas[size_of_optional_header+0x18+(0x28*i):size_of_optional_header+0x1c+(0x28*i)])[0]
        tresult['line_numbers'] = struct.unpack('I', datas[size_of_optional_header+0x1c+(0x28*i):size_of_optional_header+0x20+(0x28*i)])[0]
        tresult['reloc_numbers'] = struct.unpack('H', datas[size_of_optional_header+0x20+(0x28*i):size_of_optional_header+0x22+(0x28*i)])[0]
        tresult['line_numbers_number'] = struct.unpack('H', datas[size_of_optional_header+0x22+(0x28*i):size_of_optional_header+0x24+(0x28*i)])[0]
        tresult['caracteristics'] = struct.unpack('I', datas[size_of_optional_header+0x24+(0x28*i):size_of_optional_header+0x28+(0x28*i)])[0]
        result.append(tresult)
    return result


def pe_decode_relocs(datas):
    tb_relocs = []
    i = 0
    while i < len(datas):
        currVA = struct.unpack("I", datas[i:i+4])[0]
        i += 4
        currVAsize = struct.unpack("I", datas[i:i+4])[0]
        i += 4
        currVAsize = (currVAsize - 8)
        while currVAsize > 0:
            currReloc = struct.unpack("H", datas[i:i+2])[0]
            if ((currReloc & 0xf000) == 0xa000):  # 64b
                currReloc = (currReloc & 0xfff) + currVA
            elif ((currReloc & 0xf000) == 0x3000):  # 32b
                currReloc = (currReloc & 0xfff) + currVA
                tb_relocs.append(currReloc)
            currVAsize -= 2
            i += 2
    return tb_relocs


def pe_decode_eat_header(datas):
    result = {}
    if len(datas) < 0x30:
        return result
    result['characteristics'] = struct.unpack('I', datas[0x0:0x4])[0]
    result['timestamp'] = struct.unpack('I', datas[0x4:0x8])[0]
    result['name'] = struct.unpack('I', datas[0xc:0x10])[0]
    result['base'] = struct.unpack('I', datas[0x10:0x14])[0]
    result['number_of_functions'] = struct.unpack('I', datas[0x14:0x18])[0]
    result['number_of_names'] = struct.unpack('I', datas[0x18:0x1c])[0]
    result['address_of_functions'] = struct.unpack('I', datas[0x1c:0x20])[0]
    result['address_of_names'] = struct.unpack('I', datas[0x20:0x24])[0]
    result['address_of_name_ordinals'] = struct.unpack('I', datas[0x24:0x28])[0]
    return result


def decode_pe(image_base):
    global modules_eat
    global Drivers_list

    eat = {}
    if image_base not in Drivers_list:
        Drivers_list[image_base] = {}
    first_page = get_va_memory(image_base, 0x1000)
    if first_page is None:
        return eat
    if 'PE' in Drivers_list[image_base] and 'EAT' in Drivers_list[image_base]['PE']:
        return Drivers_list[image_base]['PE']
    dos_header = pe_decode_dos_header(first_page)
    if 'e_lfanew' in dos_header:
        Drivers_list[image_base]['PE'] = {}
        pe_header = pe_decode_pe_header(first_page[dos_header['e_lfanew']:])
        Drivers_list[image_base]['PE']['Optional_Header'] = pe_header
        Drivers_list[image_base]['PE']['Sections'] = pe_decode_sections(first_page[dos_header['e_lfanew']:])
        if 'export_address_table_address' in pe_header and pe_header['export_address_table_address'] != 0:
            eat_addr = pe_header['export_address_table_address']
            eat_dump = get_va_memory(image_base+eat_addr, pe_header['export_address_table_size'])
            if eat_dump is None or len(eat_dump) < 0x30:
                return eat
            eat_header = pe_decode_eat_header(eat_dump)
            for i in range(0, eat_header['number_of_names']):
                ceat_func_str_addr = struct.unpack('I', eat_dump[eat_header['address_of_names']-eat_addr+(i << 2):eat_header['address_of_names']-eat_addr+(i << 2)+4])[0]
                str_dump = get_va_memory(image_base+ceat_func_str_addr, 0x200)
                if str_dump is None:
                    break
                ceat_func_str = getString(str_dump)
                ordinal_func = struct.unpack('H', eat_dump[eat_header['address_of_name_ordinals']-eat_addr+(i << 1):eat_header['address_of_name_ordinals']-eat_addr+(i << 1)+2])[0]
                ceat_func = struct.unpack('I', eat_dump[eat_header['address_of_functions']-eat_addr+(ordinal_func << 2):eat_header['address_of_functions']-eat_addr+(ordinal_func << 2)+4])[0]
                eat[bytes(ceat_func_str)] = image_base+ceat_func
            if image_base in Drivers_list:
                if 'Name' not in Drivers_list[image_base]:
                    Drivers_list[image_base]['Name'] = b"???"
                    Drivers_list[image_base]['PE']['EAT'] = eat
                else:
                    drv_name = b'.'.join([bytes(a) for a in Drivers_list[image_base]['Name'].split(b"\\")[-1].split(b'.')[:-1]])
                    if drv_name == b'':
                        drv_name = Drivers_list[image_base]['Name'].split(b"\\")[-1]
                    if drv_name == b'ntoskrnl':
                        drv_name = b'nt'
                    if not (drv_name in modules_eat) or modules_eat[drv_name] == {}:
                        modules_eat[drv_name.lower()] = eat
                        Drivers_list[image_base]['PE']['EAT'] = eat


def getString(str_to_identify):
    if b"\x00" in str_to_identify:
        end_offset = str_to_identify.index(b"\x00")
    else:
        end_offset = len(str_to_identify)
    if end_offset >= 0:
        return str_to_identify[:end_offset]
    else:
        return ""


def is_integer(str_to_check):
    try:
        int(str_to_check, 16)
        return True
    except Exception:
        return False


def get_section_address(module_name, section_name):
    drv_addr = resolve_symbol(module_name)
    if drv_addr is None:
        return None
    decode_pe(drv_addr)
    if type(section_name) is str:
        section_name = bytes(bytearray(section_name, 'utf8'))
    if drv_addr in Drivers_list and 'PE' in Drivers_list[drv_addr]:
        for csection in Drivers_list[drv_addr]['PE']['Sections']:
            if csection['name'] == section_name:
                section_addr = drv_addr+csection['virtual_address']
                return section_addr
    return None


def resolve_symbol(str_to_resolve):
    global bitness
    global modules_eat
    global Drivers_list

    if type(str_to_resolve) is not str:
        str_to_resolve = str_to_resolve.decode()

    str_to_resolve = str_to_resolve.replace('`', '')

    result = None
    if str_to_resolve.startswith("0x"):
        try:
            return int(str_to_resolve, 16)
        except Exception:
            pass
    if str_to_resolve.startswith("poi("):
        res_val = resolve_symbol(str_to_resolve[4:str_to_resolve.rfind(')')])
        if bitness == 64:
            result = get_qword_from_va(res_val)
        else:
            result = get_dword_from_va(res_val)
        return resolve_symbol(("%X" % result)+str_to_resolve[str_to_resolve.rfind(')')+1:])
    if str_to_resolve.count('!') == 1:
        drv_name, sym_name = str_to_resolve.split('!')
        drv_name = bytes(bytearray(drv_name, 'utf8'))
        sym_name = bytes(bytearray(sym_name, 'utf8'))
        if drv_name not in modules_eat:
            get_drivers_list()
            if drv_name not in modules_eat:
                return None
        if sym_name not in modules_eat[drv_name]:
            for cimagebase in Drivers_list:
                cname = (b'.'.join([bytes(a) for a in Drivers_list[cimagebase]['Name'].split(b"\\")[-1].split(b'.')[:-1]])).lower()
                if cname == b'ntoskrnl':
                    cname = b'nt'
                if cname == drv_name:
                    decode_pe(cimagebase)
        if sym_name in modules_eat[drv_name]:
            return modules_eat[drv_name][sym_name]
        return None
    if not ("(" in str_to_resolve) and not ("+" in str_to_resolve) and not ("-" in str_to_resolve):
        if str_to_resolve not in modules_eat:
            get_drivers_list()
            if len(Drivers_list) == 0:
                return None
        for cimagebase in Drivers_list:
            cname = (b'.'.join([bytes(a) for a in Drivers_list[cimagebase]['Name'].split(b"\\")[-1].split(b'.')[:-1]])).lower()
            if cname == b'ntoskrnl':
                cname = b'nt'
            if cname.decode() == str_to_resolve:
                return cimagebase
        if not is_integer(str_to_resolve):
            return None
    if not ("(" in str_to_resolve):
        if "+" in str_to_resolve or '-' in str_to_resolve:
            is_plus = str_to_resolve.find("+")
            is_moins = str_to_resolve.find("-")
            cval = 0
            offset = 0
            operation = '+'
            while (is_plus != -1 or is_moins != -1):
                if is_plus >= 0 and is_moins == -1:
                    cval = resolve_symbol(str_to_resolve[offset:offset+is_plus])
                    offset += is_plus+1
                    is_plus = str_to_resolve[offset:].find("+")
                    is_moins = str_to_resolve[offset:].find("-")
                    operation = '+'
                elif is_moins >= 0 and is_plus == -1:
                    cval = resolve_symbol(str_to_resolve[offset:offset+is_moins])
                    offset += is_moins+1
                    is_plus = str_to_resolve[offset:].find("+")
                    is_moins = str_to_resolve[offset:].find("-")
                    operation = '-'
                elif is_moins > is_plus:
                    cval = resolve_symbol(str_to_resolve[offset:offset+is_plus])
                    offset += is_plus+1
                    is_plus = str_to_resolve[offset:].find("+")
                    is_moins = str_to_resolve[offset:].find("-")
                    operation = '+'
                else:
                    cval = resolve_symbol(str_to_resolve[offset:offset+is_moins])
                    offset += is_moins+1
                    is_plus = str_to_resolve[offset:].find("+")
                    is_moins = str_to_resolve[offset:].find("-")
                    operation = '-'
                if result is None:
                    result = cval
                else:
                    if operation == '+':
                        result += cval
                    else:
                        result -= cval
            if offset < len(str_to_resolve):
                if operation == '+':
                    result += resolve_symbol(str_to_resolve[offset:])
                else:
                    result -= resolve_symbol(str_to_resolve[offset:])
        elif len(str_to_resolve) == 0:
            return 0
        else:
            return int(str_to_resolve, 16)
    return result


def get_driver_infos_from_address(address):
    global Drivers_list
    if Drivers_list is None:
        get_drivers_list()
    for image_base in Drivers_list:
        drv_size = Drivers_list[image_base]['Size']
        if address >= image_base and address < (image_base+drv_size):
            return Drivers_list[image_base]
    return None


def get_driver_name_from_address(address):
    global Drivers_list
    if Drivers_list is None:
        get_drivers_list()
    for image_base in Drivers_list:
        drv_size = Drivers_list[image_base]['Size']
        if address >= image_base and address < (image_base+drv_size):
            return Drivers_list[image_base]['Name']
    return None


def get_device_node_struct(address):
    global device_node_struct
    result = {'Sibling': 0, 'Child': 0x8, 'Parent': 0x10, 'LastChild': 0x18, 'PhysicalDeviceObject': 0x20, 'InstancePath': 0x28, 'ServiceName': 0x38}
    entry_node_address = get_qword_from_va(address+0x8)
    if entry_node_address is None or entry_node_address < 0xffff800000000000:
        return result
    list_entry = find_list_entry(address+0x48, 0x300)
    if list_entry is not None:
        print("list_entry : %x" % (0x48+list_entry))
    device_node_struct = result
    return result


def get_object_from_name(name):
    global obpRootDirectoryObject
    global rootDirectoryObject_list
    if obpRootDirectoryObject is None:
        find_ObpRootDirectoryObject()
    if obpRootDirectoryObject is None:
        return None
    if type(name) is str:
        name = bytes(bytearray(name, 'utf8'))
    result = {}
    for cpath in rootDirectoryObject_list:
        if cpath.lower().startswith(name):
            result[cpath] = rootDirectoryObject_list[cpath]
    return result


def find_ObpRootDirectoryObject():
    global debug
    global obpRootDirectoryObject
    global bitness
    from_addr = resolve_symbol('nt!HalDispatchTable')
    to_addr = resolve_symbol('nt!LpcPortObjectType')

    if from_addr is not None and from_addr != 0 and to_addr is not None and to_addr != 0:
        size = to_addr-from_addr
    else:
        return None
    dump = get_va_memory(from_addr, size)
    if dump is None:
        return None
    if bitness == 64:
        sdump = struct.unpack('Q'*(size >> 3), dump[:size-(size % 8)])
        word_size = 8
    else:
        sdump = struct.unpack('I'*(size >> 2), dump[:size-(size % 4)])
        word_size = 4
    for i in range(0, len(sdump)):
        if not is_kernel_space(sdump[i]):
            continue
        ptr_datas = get_va_memory(sdump[i]-0x50, 0x60 + (int(word_size * 37)))  # 0x128 = size of 37 directories indexs
        if ptr_datas is None or len(ptr_datas) < (0x60+(int(word_size * 37))):
            continue
        if len(ptr_datas) != (0x60+(int(word_size * 37))):
            continue
        if bitness == 64:
            sptr_datas = struct.unpack('Q'*(len(ptr_datas) >> 3), ptr_datas)
        else:
            sptr_datas = struct.unpack('I'*(len(ptr_datas) >> 2), ptr_datas)

        for y in range(0, int(80/word_size)):
            if (sptr_datas[y] == 0x40002 or sptr_datas[y] == 0x20002) and get_dword_from_va(sptr_datas[y+1]) == 0x5c:
                obpRootDirectoryObject = sdump[i]
                print("  [*] FOUND ObpRootDirectoryObject : 0x%x" % (obpRootDirectoryObject))
                get_all_objects_by_name()
                get_obj_list("\\")
                return obpRootDirectoryObject


def decode_file_object(address):
    global file_object_struct
    if file_object_struct is not None:
        return file_object_struct
    result = {'Type': 0, 'Size': 0x2, 'DeviceObject': 0x8, 'Vpb': 0x10, 'FsContext': 0x18, 'FsContext2': 0x20, 'SectionObjectPointer': 0x28}

    fileType = get_word_from_va(address)
    fileSize = get_word_from_va(address+2)
    fsContext = get_qword_from_va(address+0x18)
    if fileType != 5 or fsContext is None:
        return None

    uni_offset = find_unicode_string(address+0x20, fileSize-0x20)
    if uni_offset is None:
        return None

    result['FileName'] = uni_offset+0x20
    file_object_struct = result
    return result


def get_file_object(address):
    global file_object_struct
    if file_object_struct is None:
        decode_file_object(address)
        if file_object_struct is None:
            return None
    result = {}
    result['Type'] = get_word_from_va(address+file_object_struct['Type'])
    if result['Type'] != 5:
        return None
    result['Size'] = get_word_from_va(address+file_object_struct['Size'])
    result['DeviceObject'] = get_qword_from_va(address+file_object_struct['DeviceObject'])
    result['Vpb'] = get_qword_from_va(address+file_object_struct['Vpb'])
    result['FsContext'] = get_qword_from_va(address+file_object_struct['FsContext'])
    result['FsContext2'] = get_qword_from_va(address+file_object_struct['FsContext2'])
    result['SectionObjectPointer'] = get_qword_from_va(address+file_object_struct['SectionObjectPointer'])
    result['FileName'] = get_unicode_from_va(address+file_object_struct['FileName'], True)
    if result['FileName'] is None:
        return None
    result['FileName'] = result['FileName'].split(b"\x00\x00")[0].replace(b"\x00", b"")
    return result


def get_object_infos(address):
    global obHeaderCookie
    global bitness
    result = {}
    if address is None or address == 0:
        return result
    if bitness == 64:
        header_size = 0x30
        obj_header = get_va_memory(address-0x30, 0x40)
        typeIndex_offset = 0x18
        infoMask_offset = 0x1a
        flags_offset = 0x1b
        name_offset = 0x18
    else:
        header_size = 0x18
        typeIndex_offset = 0xc
        infoMask_offset = 0xe
        flags_offset = 0x10
        name_offset = 0xc
    obj_header = get_va_memory(address-header_size, header_size+0x10)
    if obj_header is None or len(obj_header) < (header_size+0x10):
        return result
    result['TypeIndex'] = obj_header[typeIndex_offset]
    if obHeaderCookie != -1 and obHeaderCookie is not None:
        result['TypeIndex'] ^= obHeaderCookie ^ (((address-0x30) >> 8) & 0xff)
    result['InfoMask'] = obj_header[infoMask_offset]
    result['Flags'] = obj_header[flags_offset]
    result['Object'] = address
    push_header_len = 0
    if result['InfoMask'] & 1:
        if bitness == 64:
            push_header_len = 0x20
        else:
            push_header_len = 0x10
    if result['InfoMask'] & 2:
        name = get_unicode_from_va_no_zero(address-header_size-push_header_len-name_offset)
        if name is None:
            return result
        result["Name"] = name
    return result


def find_obHeaderCookie():
    global obpRootDirectoryObject
    global obHeaderCookie

    obHeaderCookie = -1
    temp_xor = None
    directory_etries = struct.unpack('Q'*37, get_va_memory(obpRootDirectoryObject, 0x128))  # 0x128 = size of 37 directories indexs

    for dir_entry in directory_etries:
        if dir_entry == 0:
            continue
        next_obj = dir_entry
        next_list = []
        while next_obj != 0 and not (next_obj in next_list):
            next_list.append(next_obj)
            mem_dmp = get_va_memory(next_obj, 0x10)
            if mem_dmp is None or len(mem_dmp) != 0x10:
                break
            next_obj, obj_addr = struct.unpack('QQ', get_va_memory(next_obj, 0x10))
            obj_infos = get_object_infos(obj_addr)
            if 'Name' in obj_infos:
                rootDirectoryObject_list[b"\\"+bytes(obj_infos['Name'])] = obj_infos
                if (b"\\"+obj_infos['Name']) in [b"\\Driver", b"\\Device", b"\\ObjectTypes", b"\\NLS", b"\\Sessions", b"\\Global??", b"\\KnowDlls", b"\\Callback", b"\\BaseNamedObjects", b"\\Device", b"\\FileSystem"]:  # known directory objects
                    if temp_xor is None and obj_infos['TypeIndex'] == 3:
                        obHeaderCookie = -1
                        continue
                    elif temp_xor is None:
                        temp_xor = ((((obj_addr-0x30) >> 8) & 0xff) ^ obj_infos['TypeIndex'] ^ 3)
                    elif temp_xor != ((((obj_addr-0x30) >> 8) & 0xff) ^ obj_infos['TypeIndex'] ^ 3):
                        print("  [!] Failed to decode ObHeaderCookie")
                        return -1
    if temp_xor is not None:
        obHeaderCookie = temp_xor
        print("  [*] Found ObHeaderCookie : 0x%x" % obHeaderCookie)
    return obHeaderCookie


def get_all_objects_by_name(path=b"", directory_base=None):
    global obpRootDirectoryObject
    global rootDirectoryObject_list
    global obHeaderCookie
    global bitness

    if obpRootDirectoryObject is None:
        find_ObpRootDirectoryObject()

    if (directory_base is None and obpRootDirectoryObject is not None):
        directory_base = obpRootDirectoryObject
    elif directory_base is None:
        return None
    if bitness == 64:
        dir_datas = get_va_memory(directory_base, (8*37))
        if dir_datas is None or len(dir_datas) < (8*37):
            return None
    else:
        dir_datas = get_va_memory(directory_base, (4*37))
        if dir_datas is None or len(dir_datas) < (4*37):
            return None
    spath = path.split(b"\\")
    for cname in spath:
        if cname != '':
            break
    if bitness == 64:
        directory_etries = struct.unpack('Q'*37, dir_datas)  # 0x128 = size of 37 directories indexs
        word_size = 8
    else:
        directory_etries = struct.unpack('I'*37, dir_datas)  # 0x128 = size of 37 directories indexs
        word_size = 4

    if obHeaderCookie is None:
        find_obHeaderCookie()

    for dir_entry in directory_etries:
        next_list = []
        if dir_entry == 0:
            continue
        next_obj = dir_entry
        while next_obj != 0 and not (next_obj in next_list):
            next_list.append(next_obj)
            mem_dmp = get_va_memory(next_obj, word_size*2)
            if mem_dmp is None or len(mem_dmp) != (word_size*2):
                break
            if bitness == 64:
                nnext_obj, obj_addr = struct.unpack('QQ', get_va_memory(next_obj, 0x10))
            else:
                nnext_obj, obj_addr = struct.unpack('II', get_va_memory(next_obj, 8))
            obj_infos = get_object_infos(obj_addr)
            if 'Name' in obj_infos:
                rootDirectoryObject_list[bytes(path)+b"\\"+bytes(obj_infos['Name'])] = obj_infos
                if obj_infos['TypeIndex'] == 0x3:  # directory
                    get_all_objects_by_name(path+b"\\"+obj_infos['Name'], obj_addr)
            next_obj = nnext_obj


def find_IopRootDeviceNode():
    global debug
    global iopRootNodeDevice
    from_addr = resolve_symbol('nt!KdDebuggerEnabled')
    to_addr = resolve_symbol('nt!IoReadOperationCount')
    if from_addr is not None and from_addr != 0 and to_addr is not None and to_addr != 0:
        from_addr = from_addr & 0xfffffffffffffff0
        to_addr = to_addr & 0xfffffffffffffff0
        size = to_addr-from_addr
    else:
        return None
    dump = get_va_memory(from_addr, size)
    if dump is None:
        return None
    sdump = struct.unpack('Q'*(size >> 3), dump[:size-(size % 8)])
    for i in range(0, len(sdump)):
        if sdump[i] < 0xffff800000000000:
            continue
        ptr_datas = get_va_memory(sdump[i], 0x18)
        if ptr_datas is None or len(ptr_datas) < 0x18:
            continue
        if len(ptr_datas) != 0x18:
            continue
        sptr_datas = struct.unpack('QQQ', ptr_datas)
        if sptr_datas[0] == 0 and sptr_datas[2] == 0 and sptr_datas[1] > 0xffff800000000000:
            if get_qword_from_va(sptr_datas[1]+0x10) == sdump[i]:
                if debug > 0:
                    print('  [*] FOUND IopRootDeviceNode : %x' % sdump[i])
                iopRootNodeDevice = sdump[i]
                return sdump[i]


def get_driver_object_struct(address):
    global driver_object_struct
    global bitness

    if bitness == 64:
        word_size = 8
        result = {'Size': 2, 'DeviceObject': 0x8}
    else:
        word_size = 4
        result = {'Size': 2, 'DeviceObject': 0x4}

    size = get_word_from_va(address+2)
    if size is None:
        return None

    result['IRP_MJ_entry'] = size-(28*word_size)  # 28 qword of IRP_MJ_*
    result['DriverUnload'] = result['IRP_MJ_entry']-word_size
    result['DriverStartIo'] = result['IRP_MJ_entry']-(word_size*2)
    result['DriverInit'] = result['IRP_MJ_entry']-(word_size*3)

    offset = word_size*2
    while offset < size:
        cword = get_sizet_from_va(address+offset)
        header = get_va_memory(cword, 4)
        if header is not None and len(header) == 4 and header[0:2] == b"MZ":
            result['Driver'] = offset
        uni = get_unicode_from_va_no_zero(address+offset)
        if uni is not None and len(uni) > 2 and len(uni) < 0x40 and (uni.startswith(b"\\Driver\\") or uni.startswith(b"\\FileSystem\\")):
            result['DriverName'] = offset
        offset += word_size
    driver_object_struct = result
    return result


def decode_driver_object(address):
    global driver_object_struct
    global bitness
    result = {}
    size = get_word_from_va(address+2)
    if size is None or size == 0:
        return None
    datas = get_va_memory(address, size)
    if datas is None:
        return None
    uni = get_unicode_from_va_no_zero(address+0x38)
    if uni is not None:
        result['DriverName'] = uni
    if bitness == 64:
        result['Type'] = struct.unpack('H', datas[:2])[0]
        result['DeviceObject'] = struct.unpack('Q', datas[8:0x10])[0]
        result['Driver'] = struct.unpack('Q', datas[0x18:0x20])[0]
        result['DriverSize'] = struct.unpack('Q', datas[0x20:0x28])[0]
        result['DriverSection'] = struct.unpack('Q', datas[0x28:0x30])[0]
        result['DriverExtension'] = struct.unpack('Q', datas[0x30:0x38])[0]
        result['DriverInit'] = struct.unpack('Q', datas[0x58:0x60])[0]
        result['DriverStartIo'] = struct.unpack('Q', datas[0x60:0x68])[0]
        result['DriverUnload'] = struct.unpack('Q', datas[0x68:0x70])[0]
        result['IRP_MJ'] = struct.unpack('Q'*28, datas[0x70:0x70+(28*8)])
    else:
        result['IRP_MJ'] = struct.unpack('I'*28, datas[driver_object_struct['IRP_MJ_entry']:driver_object_struct['IRP_MJ_entry']+(28*4)])
        result['Driver'] = struct.unpack('I', datas[driver_object_struct['Driver']:driver_object_struct['Driver']+4])[0]
        result['DeviceObject'] = struct.unpack('I', datas[driver_object_struct['DeviceObject']:driver_object_struct['DeviceObject']+4])[0]
        result['DriverUnload'] = struct.unpack('I', datas[driver_object_struct['DriverUnload']:driver_object_struct['DriverUnload']+4])[0]
        result['DriverStartIo'] = struct.unpack('I', datas[driver_object_struct['DriverStartIo']:driver_object_struct['DriverStartIo']+4])[0]
        result['DriverInit'] = struct.unpack('I', datas[driver_object_struct['DriverInit']:driver_object_struct['DriverInit']+4])[0]
    return result


def decode_vpb(address):
    global bitness
    result = {}
    datas = get_va_memory(address, 0x40)
    if datas is None:
        return None
    if bitness == 64:
        result['Type'] = struct.unpack('H', datas[:2])[0]
        result['Size'] = struct.unpack('H', datas[2:4])[0]
        result['Flags'] = struct.unpack('H', datas[4:6])[0]
        result['VolumeLabelLength'] = struct.unpack('H', datas[6:8])[0]
        result['DeviceObject'] = struct.unpack('Q', datas[0x8:0x10])[0]
        result['RealDevice'] = struct.unpack('Q', datas[0x10:0x18])[0]
        result['SerialNumber'] = struct.unpack('I', datas[0x18:0x1c])[0]
        result['ReferenceCount'] = struct.unpack('I', datas[0x1c:0x20])[0]
        if result['VolumeLabelLength'] == 0:
            result['VolumeLabel'] = ''
        elif result['VolumeLabelLength'] < 0x40:
            try:
                result['VolumeLabel'] = datas[0x20:0x20+result['VolumeLabelLength']].decode('utf-16')
            except Exception:
                result['VolumeLabel'] = ''
        else:
            result['VolumeLabel'] = ''
    return result


def decode_device_object(address):
    global bitness
    result = {}
    datas = get_va_memory(address, 0x140)
    if datas is None:
        return None
    if bitness == 64:
        result['ReferenceCount'] = struct.unpack('I', datas[4:8])[0]
        result['DriverObject'] = struct.unpack('Q', datas[8:0x10])[0]
        result['NextDevice'] = struct.unpack('Q', datas[0x10:0x18])[0]
        result['AttachedDevice'] = struct.unpack('Q', datas[0x18:0x20])[0]
        result['CurrentIrp'] = struct.unpack('Q', datas[0x20:0x28])[0]
        result['Vpb'] = struct.unpack('Q', datas[0x38:0x40])[0]
        result['DeviceType'] = struct.unpack('I', datas[0x48:0x4c])[0]
    else:
        result['ReferenceCount'] = struct.unpack('I', datas[4:8])[0]
        result['DriverObject'] = struct.unpack('I', datas[8:0xc])[0]
        result['NextDevice'] = struct.unpack('I', datas[0xc:0x10])[0]
        result['AttachedDevice'] = struct.unpack('I', datas[0x10:0x14])[0]
    return result


def decode_device_node(address):
    global device_node_struct
    result = {}
    datas = get_va_memory(address, 0x100)
    if datas is None:
        return None
    result['Sibling'] = struct.unpack('Q', datas[device_node_struct['Sibling']:device_node_struct['Sibling']+8])[0]
    result['Child'] = struct.unpack('Q', datas[device_node_struct['Child']:device_node_struct['Child']+8])[0]
    result['Parent'] = struct.unpack('Q', datas[device_node_struct['Parent']:device_node_struct['Parent']+8])[0]
    result['LastChild'] = struct.unpack('Q', datas[device_node_struct['LastChild']:device_node_struct['LastChild']+8])[0]
    result['PhysicalDeviceObject'] = struct.unpack('Q', datas[device_node_struct['PhysicalDeviceObject']:device_node_struct['PhysicalDeviceObject']+8])[0]
    uni_str = get_unicode_from_va(address+device_node_struct['InstancePath'])
    if uni_str is not None:
        result['InstancePath'] = uni_str.replace(b"\x00", b'')
    uni_str = get_unicode_from_va(address+device_node_struct['ServiceName'])
    if uni_str is not None:
        result['ServiceName'] = uni_str.replace(b"\x00", b'')
    return result


def get_device_name_from_address(addr):
    global rootDirectoryObject_list
    for cobj in rootDirectoryObject_list:
        if rootDirectoryObject_list[cobj]['Object'] == addr:
            return cobj
    return None


def check_all_drivers_IRP_table(driver_to_check=None):
    global obj_header_types

    if driver_to_check is None:
        obj_list = get_object_from_name("\\driver\\")
        if obj_list is None or len(obj_list) < 1:
            return None
        for path in sorted(list(obj_list.keys())):
            drv_obj = decode_driver_object(obj_list[path]['Object'])
            if drv_obj is not None:
                check_driver_IRP_table(drv_obj)
        obj_list = get_object_from_name("\\filesystem\\")
    else:
        obj_list = get_object_from_name(driver_to_check.lower())
    if obj_list is None or len(obj_list) < 1:
        return None
    for path in sorted(list(obj_list.keys())):
        if obj_list[path]['TypeIndex'] in obj_header_types and obj_header_types[obj_list[path]['TypeIndex']] == 'Driver':
            drv_obj = decode_driver_object(obj_list[path]['Object'])
            if drv_obj is not None:
                check_driver_IRP_table(drv_obj)


def is_in_ms_list(driver_name):
    if type(driver_name) is str:
        driver_name = bytes(bytearray(driver_name, 'utf8'))
    for cmsdriver in ms_infos.ms_driver_list:
        if driver_name[1] != bytearray(b':')[0]:
            end_ms_name = cmsdriver.split(b"\\")[-1]
            if end_ms_name == driver_name:
                return True
        else:
            if cmsdriver == driver_name:
                return True
    return False


def check_driver_IRP_table(drv_obj):
    global irp_mj_list
    global debug
    if 'DriverName' in drv_obj:
        print("  Driver : %s" % (drv_obj['DriverName'].decode(errors="ignore")))
    print("    Address: %x" % (drv_obj['Driver']))
    drv_path = get_driver_name_from_address(drv_obj['Driver'])
    if drv_path is not None:
        drv_name = drv_path
        drv_path = get_driver_name(drv_path)
        drv_path = drv_path.lower()
    else:
        drv_name = b""
        drv_path = b""
    if drv_name is not None:
        drv_name = drv_name.split(b"\\")[-1]
    else:
        drv_name = "*Unkown*"
    print("    Driver : %s" % (drv_name.decode()))
    target_name = get_driver_name_from_address(drv_obj['DriverUnload'])
    if target_name is not None:
        target_name_long = get_driver_name(target_name).lower()
        target_name = target_name.split(b"\\")[-1]
    else:
        target_name = "*Unkown*"
        target_name_long = "*Unkown*"

    if drv_obj['DriverUnload'] != 0:
        if not is_in_ms_list(target_name_long) and (target_name_long != drv_path):
            print("    DriverUnload : %x  %s ***SUSPICIOUS*** Not in MS list" % (drv_obj['DriverUnload'], target_name_long.decode()))
        elif debug > 0:
            print("    DriverUnload : %x  %s" % (drv_obj['DriverUnload'], target_name_long.decode()))

    target_name = get_driver_name_from_address(drv_obj['DriverStartIo'])
    if target_name is not None:
        target_name_long = get_driver_name(target_name).lower()
        target_name = target_name.split(b"\\")[-1]
    else:
        target_name = "*Unkown*"
        target_name_long = "*Unkown*"

    if drv_obj['DriverStartIo'] != 0:
        if not is_in_ms_list(target_name_long) and (target_name_long != drv_path):
            print("    DriverStartIo : %x  %s ***SUSPICIOUS*** Not in MS list" % (drv_obj['DriverStartIo'], target_name_long.decode()))
        elif debug > 0:
            print("    DriverStartIo : %x  %s" % (drv_obj['DriverStartIo'], target_name_long.decode()))

    target_name = get_driver_name_from_address(drv_obj['DriverInit'])
    if target_name is not None:
        target_name_long = get_driver_name(target_name).lower()
        target_name = target_name.split(b"\\")[-1]
    else:
        target_name = "*Unkown*"
        target_name_long = "*Unkown*"

    if drv_obj['DriverInit'] != 0:
        if not is_in_ms_list(target_name_long) and (target_name_long != drv_path):
            print("    DriverInit : %x  %s ***SUSPICIOUS*** Not in MS list" % (drv_obj['DriverInit'], target_name_long.decode()))
        elif debug > 0:
            print("    DriverInit : %x  %s" % (drv_obj['DriverInit'], target_name_long.decode()))

    own_irp = False
    for i in range(0, len(drv_obj['IRP_MJ'])):
        cIrp = drv_obj['IRP_MJ'][i]
        target_name = get_driver_name_from_address(cIrp)
        if target_name is not None:
            target_name_long = get_driver_name(target_name).lower()
            target_name = target_name.split(b"\\")[-1]
        else:
            target_name = "*Unkown*"
            target_name_long = "*Unkown*"

        if not is_in_ms_list(target_name_long) and (target_name_long == drv_path) and not own_irp:
            print("             ***SUSPICIOUS*** IRP_MJ Not in MS list : %s" % (target_name_long.decode()))
            own_irp = True
        elif not is_in_ms_list(target_name_long) and (target_name_long != drv_path):
            print("        %s %x  %s ***SUSPICIOUS*** Not in MS list" % (irp_mj_list[i]+(" "*(32-len(irp_mj_list[i]))), cIrp, target_name_long.decode()))
        if debug > 0:
            print("        %s %x  %s" % (irp_mj_list[i]+(" "*(32-len(irp_mj_list[i]))), cIrp, target_name.decode()))


def crawl_device_object(address):
    dev_obj = decode_device_object(address)
    if dev_obj['Vpb'] > 0xffff80000000000:
        vpb = decode_vpb(dev_obj['Vpb'])
        print("  VPB : %x ('%s')" % (dev_obj['Vpb'], vpb['VolumeLabel']))
        vpb_devices = ['DeviceObject', 'RealDevice']
        for ccheck_vpb_dev in vpb_devices:
            if vpb[ccheck_vpb_dev] > 0xffff80000000000:
                last_dev_address = vpb[ccheck_vpb_dev]
                vpb_devobj = decode_device_object(vpb[ccheck_vpb_dev])
                print("    VPB %s Device Object : %x" % (ccheck_vpb_dev, vpb[ccheck_vpb_dev]))
                if vpb[ccheck_vpb_dev] == address:
                    print("    (Same Device)")
                    continue
                while vpb_devobj['AttachedDevice'] != 0:
                    print("  VPB Device : %x / Driver Object : %x" % (last_dev_address, vpb_devobj['DriverObject']))
                    drv_obj = decode_driver_object(vpb_devobj['DriverObject'])
                    if drv_obj is None:
                        print("  [!] DriverObject Invalid !")
                    else:
                        check_driver_IRP_table(drv_obj)
                    last_dev_address = vpb_devobj['AttachedDevice']
                    vpb_devobj = decode_device_object(vpb_devobj['AttachedDevice'])
                    if vpb_devobj is None:
                        return
                print("  VPB Device : %x / Driver Object : %x" % (last_dev_address, vpb_devobj['DriverObject']))
                drv_obj = decode_driver_object(vpb_devobj['DriverObject'])
                if drv_obj is None:
                    print("  [!] DriverObject Invalid !")
                else:
                    check_driver_IRP_table(drv_obj)
        print('')
    while dev_obj['AttachedDevice'] != 0:
        print("  Driver Object : %x" % (dev_obj['DriverObject']))
        drv_obj = decode_driver_object(dev_obj['DriverObject'])
        if drv_obj is None:
            print("  [!] DriverObject Invalid !")
        else:
            check_driver_IRP_table(drv_obj)
        dev_obj = decode_device_object(dev_obj['AttachedDevice'])
        if dev_obj is None:
            return
    print("  Driver Object : %x" % (dev_obj['DriverObject']))
    drv_obj = decode_driver_object(dev_obj['DriverObject'])
    check_driver_IRP_table(drv_obj)


def crawl_device_nodes(address):
    global device_node_struct
    if device_node_struct is None:
        return None
    sibling = address
    while sibling is not None and sibling != 0:
        cdevice = decode_device_node(sibling)
        child = cdevice['Child']
        if 'InstancePath' in cdevice:
            print('InstancePath : '+cdevice['InstancePath'].decode())
        if 'ServiceName' in cdevice:
            print('ServiceName : '+cdevice['ServiceName'].decode())
        print("  PhysicalDeviceObject : %x" % (cdevice['PhysicalDeviceObject']))
        crawl_device_object(cdevice['PhysicalDeviceObject'])
        if child is not None and child != 0:
            crawl_device_nodes(child)
        sibling = cdevice['Sibling']
        child = cdevice['Child']


def crawl_from_IopRootDeviceNode(address):
    nodes_entry = get_qword_from_va(address+8)
    if nodes_entry is not None and nodes_entry > 0xffff800000000000:
        crawl_device_nodes(nodes_entry)


def crawl_cb_devices_entry(address):
    dump = get_va_memory(address, 0x18)
    if dump is None or len(dump) != 0x18:
        return None
    sdump = struct.unpack('QQQ', dump)
    device_obj_addr = sdump[2]
    device_obj = decode_device_object(device_obj_addr)
    if device_obj is not None:
        if device_obj['ReferenceCount'] > 10000:
            return None
        if not (device_obj['AttachedDevice'] == 0 or ((device_obj['AttachedDevice'] & 0xffff800000000000) == 0xffff800000000000 and get_va_memory(device_obj['DriverObject'], 1) is not None)):
            return None
        if not (device_obj['NextDevice'] == 0 or ((device_obj['NextDevice'] & 0xffff800000000000) == 0xffff800000000000 and get_va_memory(device_obj['NextDevice'], 1) is not None)):
            return None
        if (device_obj['DriverObject'] & 0xffff800000000000) == 0xffff800000000000:
            drv_obj_size = get_word_from_va(device_obj['DriverObject']+2)
            if drv_obj_size is not None and (drv_obj_size < 0x200 or drv_obj_size > 0x130):
                return device_obj
    return None


def crawl_list(address, callback_function, ignore_first=False):
    addresses = []
    results = []
    flink = address
    while not (flink in addresses) and flink is not None:
        if not is_kernel_space(flink):
            return results
        if not (ignore_first and flink == address):
            results.append(callback_function(flink))
        addresses.append(flink)
        flink = get_sizet_from_va(flink)
    return results


def cb_callback_list_devices(address):
    global bitness
    datas = get_va_memory(address, 0x20)
    if bitness == 64:
        sdata = struct.unpack('Q'*(len(datas) >> 3), datas)
    else:
        sdata = struct.unpack('I'*(len(datas) >> 2), datas)
    dev_addr = sdata[2]
    obj_infos = get_object_infos(dev_addr)
    if 'Name' in obj_infos:
        print("  Name : %s" % (obj_infos['Name']).decode())
    crawl_device_object(dev_addr)


def cb_callback_list(address):
    global bitness
    datas = get_va_memory(address, 0x20)
    if bitness == 64:
        sdata = struct.unpack('Q'*(len(datas) >> 3), datas)
    else:
        sdata = struct.unpack('I'*(len(datas) >> 2), datas)
    code_ptr = sdata[3]
    driver_infos = get_driver_infos_from_address(code_ptr)
    if driver_infos is None or not is_in_ms_list(get_driver_name(driver_infos['Name']).lower()):
        if driver_infos is not None:
            print("        [!] Suspicious Callback execution : %x (%s)" % (code_ptr, driver_infos['Name'].decode()))
        else:
            code = get_va_memory(code_ptr, 0x10)
            if code is None:
                code = "???"
            else:
                code = ' '.join(["%02x" % a for a in bytearray(code)])
            print("        [!] Suspicious Callback execution : %x ***Unknown*** %s" % (code_ptr, code))


def crawl_all_devices_directory():
    callbacks = get_obj_list("\\Callback")
    for callback_str in sorted(list(callbacks.keys())):
        print("  [*] Checking %s : 0x%x" % (callback_str.decode(), callbacks[callback_str]['Object']))
        if get_va_memory(callbacks[callback_str]['Object'], 4) == b"Call":
            crawl_list(callbacks[callback_str]['Object']+0x10, cb_callback_list, True)


def crawl_callback_directory():
    global bitness
    callbacks = get_obj_list("\\Callback")
    for callback_str in sorted(list(callbacks.keys())):
        print("  [*] Checking %s : 0x%x" % (callback_str.decode(), callbacks[callback_str]['Object']))
        if get_va_memory(callbacks[callback_str]['Object'], 4) == b"Call":
            if bitness == 64:
                crawl_list(callbacks[callback_str]['Object']+0x10, cb_callback_list, True)
            else:
                crawl_list(callbacks[callback_str]['Object']+0x8, cb_callback_list, True)


def get_device_from_address(addrObj):
    global rootDirectoryObject_list
    for a in rootDirectoryObject_list:
        if rootDirectoryObject_list[a]['Object'] == addrObj:
            return rootDirectoryObject_list[a]
    return None


def x64_get_lea(addr):
    datas = get_va_memory(addr, 8)
    if datas is None:
        return None
    if datas[0] in [0x48, 0x4c, 0x4d] and datas[1] == 0x8d and datas[2] in [0x05, 0x0d, 0x15, 0x1d, 0x25, 0x2d, 0x35, 0x3d]:
        ptr = struct.unpack('i', datas[3:7])[0]
        ptr = addr+7+ptr
        return ptr
    return None


def x86_get_mov(addr):
    datas = get_va_memory(addr, 8)
    if datas is None:
        return None
    if (0xb8 <= datas[0] <= 0xbf) and datas[5] >= 0x80:
        ptr = struct.unpack('I', datas[1:5])[0]
        return ptr

    if (datas[0] == 0xc7 and datas[1] == 0x45) and datas[7] >= 0x80:
        ptr = struct.unpack('I', datas[3:7])[0]
        return ptr
    return None


def find_retn(datas):
    for i in range(0, len(datas)-3):
        if datas[i] == 0xc3 and datas[i+1] == 0xcc:
            return i+1
        if datas[i] == 0xc2 and datas[i+2] == 0x00 and (datas[1] & 3) == 0x00:
            return i+3
    return len(datas)


def identify_list_entry_from_code(symbol, cbStructDetection=None, no_recursive=False):
    global bitness
    import lde
    disas = lde.LDE(bitness)
    from_addr = resolve_symbol(symbol)
    if from_addr is None:
        return

    if bitness == 64:
        nt_get_global = x64_get_lea
    else:
        nt_get_global = x86_get_mov

    sub_func = []
    instr_list = disas.get_function_instructions(from_addr, get_va_memory)
    for instr_addr in instr_list.keys():
        ptr = nt_get_global(instr_addr)
        if len(instr_list[instr_addr]) > 2 and instr_list[instr_addr][1] == 'call':
            sub_func.append(instr_list[instr_addr][2])
        if ptr is not None:
            flink = get_sizet_from_va(ptr)
            if flink is None:
                continue
            if cbStructDetection is not None:
                is_struct = cbStructDetection(ptr)
                if is_struct:
                    return ptr
                else:
                    continue
            if bitness == 64:
                blink = get_qword_from_va(flink+8)
            else:
                blink = get_dword_from_va(flink+4)
            if flink is None:
                continue
            if flink is not None and blink == ptr:
                return ptr

    if len(instr_list) < 0x20 and not no_recursive:
        for cfunc in sub_func:
            result = identify_list_entry_from_code("0x%x" % cfunc, cbStructDetection, no_recursive=True)
            if result is not None:
                return result
    return


def identify_CiOptions(cbStructDetection=None, no_recursive=False):
    global bitness
    import lde

    disas = lde.LDE(bitness)
    from_addr = resolve_symbol("ci!CiInitialize")
    if from_addr is None:
        return

    if bitness == 64:
        pattern_mov_CiOptions = b"\x89\x0d"  # MOV dword ptr [g_CiOptions ],ECX

    sub_func = []
    instr_list = disas.get_function_instructions(from_addr, get_va_memory)
    for instr_addr in instr_list.keys():
        if len(instr_list[instr_addr]) > 2 and instr_list[instr_addr][1] == 'call':
            sub_func.append(instr_list[instr_addr][2])
        if instr_list[instr_addr][0] == 6 and get_va_memory(instr_addr, instr_list[instr_addr][0])[:2] == pattern_mov_CiOptions:
            rel_addr = get_dword_from_va(instr_addr+2)
            if (rel_addr >> 31) == 1:
                rel_addr = -(2**32 - rel_addr)
            address_CiOptions = instr_addr + 6 + rel_addr
            return address_CiOptions

    if len(instr_list) < 0x20 and not no_recursive:
        for cfunc in sub_func:
            heades_func = get_va_memory(cfunc, 0x40)
            pattern_offset = heades_func.find(pattern_mov_CiOptions)
            if pattern_offset > 0:
                address_CiOptions = cfunc + pattern_offset + 6 + struct.unpack("i", heades_func[pattern_offset+2:pattern_offset+6])[0]
                return address_CiOptions
    return


def detect_ndisCbIoList(address):
    global ndisCbIo_struct
    if address == 0:
        return False
    if (address & 0xffff800000000000) != 0xffff800000000000 or (address & 7) != 0:
            return False
    pool_chunk = get_pool_tag(address)
    if pool_chunk is None or (pool_chunk['tag'] != b"NDpb" and pool_chunk['tag'] != b"NDfv"):
        return False
    if not ('driver' in ndisCbIo_struct['NDfv_ptr']) and pool_chunk['tag'] == b"NDfv":  # Pool tag allocation
        if not ('address' in ndisCbIo_struct['NDfv_ptr']):
            ndisCbIo_struct['NDfv_ptr']['address'] = []
        ndisCbIo_struct['NDfv_ptr']['address'].append(address)
        ndisCbIo_struct['NDfv_ptr']['size'] = 0x2
        ndisCbIo_struct['NDfv_ptr']['next'] = 0x8  # to check if offset change, possible pour detect in auto
        chunk_size = get_word_from_va(address+ndisCbIo_struct['NDfv_ptr']['size'])
        sub_offset = 0
        while sub_offset < chunk_size:
            csname = get_unicode_from_va(address+sub_offset)
            if csname is not None and len(csname) < 0x80 and csname[:8].count(b'\x00') == 4:
                csname = csname.replace(b"\x00", b'')
                if not ('GUID' in ndisCbIo_struct['NDfv_ptr']) and csname.startswith(b'{'):
                    ndisCbIo_struct['NDfv_ptr']['GUID'] = sub_offset
                elif not ('driver' in ndisCbIo_struct['NDfv_ptr']) and csname.lower().endswith(b'.sys'):
                    ndisCbIo_struct['NDfv_ptr']['driver'] = sub_offset
                elif not ('description' in ndisCbIo_struct['NDfv_ptr']):
                    ndisCbIo_struct['NDfv_ptr']['description'] = sub_offset
                elif not ('driver_name' in ndisCbIo_struct['NDfv_ptr']):
                    ndisCbIo_struct['NDfv_ptr']['driver_name'] = sub_offset
            sub_offset += 8
        return True
    elif pool_chunk['tag'] == b"NDfv":
        if not ('address' in ndisCbIo_struct['NDfv_ptr']):
            ndisCbIo_struct['NDfv_ptr']['address'] = []
        if not (address in ndisCbIo_struct['NDfv_ptr']['address']):
            ndisCbIo_struct['NDfv_ptr']['address'].append(address)
        return True
    if not ('name') in ndisCbIo_struct['NDpb_ptr'] and pool_chunk['tag'] == b"NDpb":  # Pool tag allocation
        if not ('address' in ndisCbIo_struct['NDpb_ptr']):
            ndisCbIo_struct['NDpb_ptr']['address'] = []
        if not (address in ndisCbIo_struct['NDpb_ptr']['address']):
            ndisCbIo_struct['NDpb_ptr']['address'].append(address)
        ndisCbIo_struct['NDpb_ptr']['size'] = 0x2
        ndisCbIo_struct['NDpb_ptr']['next'] = 0x10  # to check if offset change, possible pour detect in auto
        chunk_size = get_word_from_va(address+ndisCbIo_struct['NDpb_ptr']['size'])
        sub_offset = 0
        while sub_offset < chunk_size:
            csname = get_unicode_from_va(address+sub_offset)
            if not ('name' in ndisCbIo_struct['NDpb_ptr']) and csname is not None and len(csname) < 0x80:
                csname = csname.replace(b"\x00", b'')
                ndisCbIo_struct['NDpb_ptr']['name'] = sub_offset
            sub_offset += 8
        return True
    elif pool_chunk['tag'] == b"NDpb":
        if not ('address' in ndisCbIo_struct['NDpb_ptr']):
            ndisCbIo_struct['NDpb_ptr']['address'] = []
        if not (address in ndisCbIo_struct['NDpb_ptr']['address']):
            ndisCbIo_struct['NDpb_ptr']['address'].append(address)
        return True

    return False


def detect_ndisMiniportList(address):
    global ndisCbIo_struct
    size = get_word_from_va(address+2)
    type = get_word_from_va(address)
    if not (type == 0x111 and 0x1500 <= size <= 0x1800 and get_dword_from_va(address+4) == 0):
        return False
    header_tag = get_qword_from_va(address)
    dump = get_va_memory(address, size)
    if dump is None or len(dump) < size:
        return False
    result = {}
    sdump = struct.unpack('Q'*(size >> 3), dump)
    for i in range(len(sdump)):
        caddr = sdump[i]
        if caddr == address:
            continue
        cuni = get_unicode_from_va_no_zero(address+(i << 3))
        if cuni is not None and len(cuni) > 8 and is_ascii(cuni):
            if not ('SymLink' in result) and cuni[0:4] == b'\\??\\':
                result['SymLink'] = i << 3
            elif not ('Device' in result) and cuni[0:7].lower() == b'\\device':
                result['Device'] = i << 3
            elif not ('GUID' in result) and cuni[0] == b'{':
                result['GUID'] = i << 3
        sub_qword = get_qword_from_va(caddr)
        if sub_qword == header_tag:
            if not ('Next' in result):
                result['Next'] = i*8
    if 'Next' in result and 'SymLink' in result and 'Device' in result and 'GUID' in result:
        ndisCbIo_struct['ndisMiniportList_addr'].append(address)
        ndisCbIo_struct['ndisMiniportList_struct'] = result
        return True
    return False


def is_data_buffer(datas):
    global bitness
    if datas is None or len(datas) < 0x10:
        return False
    if bitness == 64:
        w0, w1 = struct.unpack('HH', datas[:4])
        d1 = struct.unpack('I', datas[4:8])[0]
        q0 = struct.unpack('Q', datas[:8])[0]
        q1 = struct.unpack('Q', datas[8:0x10])[0]
        if w0 >= w1 and d1 == 0 and w0 < 0x100 and is_kernel_space(q1):
            return True
        if q0 == 0 or q1 == 0:
            return True
        if (is_kernel_space(q0) or ((q0 & 0xffff800000000000) == 0)) and (is_kernel_space(q1) or ((q1 & 0xffff800000000000) == 0)):
            return True
        if (datas[4:].replace(b"\x00", b'') == b'' or (d1 == 0 and is_kernel_space(q1))) and not (datas[0] in [0xeb, 0xe8, 0xe9, 0x90]):
            return True
        if w0 == 0 or (q0 >> 44) == 0xfffff:
            return True
        if datas.count(b'\xff\xff') == 2 and datas.count(b'\xff\xff\xff') == 0:
            return True
        counter = 0
        for i in range(len(datas)):
            if datas[i] < 0x80:
                counter += 1
        if counter == (len(datas)):
            return True
    return False


def check_ndis_callbacks():
    global ndisCbIo_struct

    if 'driver' in ndisCbIo_struct['NDfv_ptr']:
        print(" [*] Checking NDIS Firewall layers")
        for address in ndisCbIo_struct['NDfv_ptr']['address']:
            print("  [*] List from %x" % (address))
            for address in ndisCbIo_struct['NDfv_ptr']['address']:
                while address != 0 and address is not None:
                    if not is_kernel_space(address, 8):
                        break
                    print("    Driver      : %s" % (get_unicode_from_va_no_zero(address+ndisCbIo_struct['NDfv_ptr']['driver']).decode(errors='replace')))
                    print("    GUID        : %s" % (get_unicode_from_va_no_zero(address+ndisCbIo_struct['NDfv_ptr']['GUID']).decode(errors='replace')))
                    print("    Description : %s" % (get_unicode_from_va_no_zero(address+ndisCbIo_struct['NDfv_ptr']['description']).decode(errors='replace')))
                    i = ndisCbIo_struct['NDfv_ptr']['driver_name']+0x10
                    max_len = get_word_from_va(address+ndisCbIo_struct['NDfv_ptr']['size'])
                    while i < max_len:
                        cbaddr = get_qword_from_va(address+i)
                        if not is_kernel_space(cbaddr):
                            i += 8
                            continue
                        if cbaddr is None:
                            break
                        rights = get_page_rights(cbaddr)
                        if rights is None:
                            i += 8
                            continue
                        if rights['exec']:
                            drv_path = get_driver_name_from_address(cbaddr)
                            if drv_path is None:
                                code = get_va_memory(cbaddr, 0x10)
                                if not is_data_buffer(code):
                                    if code is None:
                                        code = "???"
                                    else:
                                        code = ' '.join(["%02x" % a for a in bytearray(code)])
                                    print("  Callback %x -> SUSPICIOUS ***Unknown*** %s" % (cbaddr, code))
                            else:
                                drv_path = get_driver_name(drv_path)
                                if not is_in_ms_list(drv_path):
                                    print("  Callback %x -> %s (not in white list) SUSPICIOUS" % (cbaddr, drv_path.decode()))
                        i += 8
                    address = get_qword_from_va(address+ndisCbIo_struct['NDfv_ptr']['next'])
    if 'name' in ndisCbIo_struct['NDpb_ptr']:
        print(" [*] Checking NDIS Protocol layers")
        for address in ndisCbIo_struct['NDpb_ptr']['address']:
            print("  [*] List from %x" % (address))
            while address != 0 and address is not None:
                if not is_kernel_space(address, 8):
                    break
                print("    Name : %s" % (get_unicode_from_va_no_zero(address+ndisCbIo_struct['NDpb_ptr']['name']).decode()))
                i = ndisCbIo_struct['NDpb_ptr']['name']+0x10
                max_len = get_word_from_va(address+ndisCbIo_struct['NDpb_ptr']['size'])
                while i < max_len:
                    cbaddr = get_qword_from_va(address+i)
                    if cbaddr is None:
                        break
                    if not is_kernel_space(cbaddr):
                        i += 8
                        continue
                    if cbaddr is None:
                        break
                    rights = get_page_rights(cbaddr)
                    if rights is None:
                        i += 8
                        continue
                    if rights['exec']:
                        drv_path = get_driver_name_from_address(cbaddr)
                        if drv_path is None:
                            code = get_va_memory(cbaddr, 0x10)
                            if not is_data_buffer(code):
                                if code is None:
                                    code = "???"
                                else:
                                    code = ' '.join(["%02x" % a for a in bytearray(code)])
                                print("  Callback %x -> SUSPICIOUS ***Unknown*** %s" % (cbaddr, code))
                        else:
                            drv_path = get_driver_name(drv_path)
                            if not is_in_ms_list(drv_path):
                                print("  Callback %x -> %s (not in white list) SUSPICIOUS" % (cbaddr, drv_path.decode()))
                    i += 8
                address = get_qword_from_va(address+ndisCbIo_struct['NDpb_ptr']['next'])
    if len(ndisCbIo_struct['ndisMiniportList_addr']) > 0 and 'ndisMiniportList_addr' in ndisCbIo_struct:
        print(" [*] Checking NDIS Miniports layers")
        for cndis_addr in ndisCbIo_struct['ndisMiniportList_addr']:
            size = get_word_from_va(cndis_addr+2)
            print("  [*] List from %x" % cndis_addr)
            while cndis_addr is not None and cndis_addr != 0:
                symlink = get_unicode_from_va_no_zero(cndis_addr+ndisCbIo_struct['ndisMiniportList_struct']['SymLink'])
                device = get_unicode_from_va_no_zero(cndis_addr+ndisCbIo_struct['ndisMiniportList_struct']['Device'])
                print("   SymLink : %s" % symlink)
                print("    Device : %s" % device)
                dump = get_va_memory(cndis_addr, size)
                if dump is not None and len(dump) == size:
                    sdump = struct.unpack('Q'*(size >> 3), dump)
                    for i in range(len(sdump)):
                        caddr = sdump[i]
                        if not (is_kernel_space(caddr)):
                            continue
                        rights = get_page_rights(caddr)
                        if rights is not None and rights['exec']:
                            drv_path = get_driver_name_from_address(caddr)
                            if drv_path is None:
                                code = get_va_memory(caddr, 0x10)
                                if not is_data_buffer(code):
                                    if code is None:
                                        code = "???"
                                    else:
                                        code = ' '.join(["%02x" % a for a in bytearray(code)])
                                    print("     Callback %x -> SUSPICIOUS ***Unknown*** %s" % (caddr, code))
                            else:
                                drv_path = get_driver_name(drv_path)
                                if not is_in_ms_list(drv_path):
                                    print("     Callback %x -> %s (not in white list) SUSPICIOUS" % (caddr, drv_path.decode()))

                cndis_addr = get_qword_from_va(cndis_addr+ndisCbIo_struct['ndisMiniportList_struct']['Next'])


def check_ndis():
    dump = get_driver_section(b"ndis", b".data")
    if dump is None:
        print("  [!] .data of ndis is not accessible")
        return
    sdump = struct.unpack('Q'*(len(dump) >> 3), dump)
    for i in range(0, len(sdump)):
        sub_addr = sdump[i]
        if not is_kernel_space(sub_addr, 8):
            continue
        if detect_ndisCbIoList(sub_addr):
            continue
        if detect_ndisMiniportList(sub_addr):
            continue
        sub_dump = get_va_memory(sub_addr, 0x80)
        if sub_dump is None or len(sub_dump) != 0x80:
            continue
    check_ndis_callbacks()


def get_driver_section(driver_name, section_name):
    global Drivers_list
    if type(section_name) is str:
        section_name = bytes(bytearray(section_name, 'utf8'))
    if type(driver_name) is str:
        driver_name = bytes(bytearray(driver_name, 'utf8'))
    drv_addr = resolve_symbol(driver_name)
    if drv_addr is None:
        return None
    if 'PE' not in Drivers_list[drv_addr]:
        decode_pe(drv_addr)
    if 'PE' in Drivers_list[drv_addr]:
        for csection in Drivers_list[drv_addr]['PE']['Sections']:
            if csection['name'] == section_name:
                size = csection['virtual_size']-(csection['virtual_size'] % 8)
                dump = get_va_memory(drv_addr+csection['virtual_address'], size)
                return dump
    return None


def is_ascii(datas):
    for a in datas:
        if not (0x20 <= a <= 0x7e):
            return False
    return True


def find_poolbigpagetable():
    global pPoolBigPageTable

    if pPoolBigPageTable == []:
        return None
    if pPoolBigPageTable is None:
        pPoolBigPageTable = []
        dump = get_driver_section(b"nt", b".data")
        if dump is None:
            return None
        size = len(dump)-(len(dump) % 8)
        sdump = struct.unpack('Q'*(size >> 3), dump)
        for i in range(0, len(sdump)-1):
            sub_addr = sdump[i]
            if (sub_addr & 0xffff800000000000) != 0xffff800000000000 or (sub_addr & 0xfff) != 0:
                continue
            sub_dump = get_va_memory(sub_addr, 0x1000)
            if sub_dump is None or len(sub_dump) != 0x1000:
                continue
            is_CM16 = sub_dump.find(b"CM16")
            is_CM17 = sub_dump.find(b"CM17")
            is_CM31 = sub_dump.find(b"CM31")
            is_CM25 = sub_dump.find(b"CM25")
            is_MmSt = sub_dump.find(b"MmSt")
            is_MmAc = sub_dump.find(b"MmAc")
            is_ArbA = sub_dump.find(b"ArbA")
            is_found = 0

            if is_ArbA >= 0 and (is_ArbA % 0x18) == 8:
                is_found += 1
            if is_MmAc >= 0 and (is_MmAc % 0x18) == 8:
                is_found += 1
            if is_CM16 >= 0 and (is_CM16 % 0x18) == 8:
                is_found += 1
            if is_CM17 >= 0 and (is_CM17 % 0x18) == 8:
                is_found += 1
            if is_CM31 >= 0 and (is_CM31 % 0x18) == 8:
                is_found += 1
            if is_CM25 >= 0 and (is_CM25 % 0x18) == 8:
                is_found += 1
            if is_MmSt >= 0 and (is_MmSt % 0x18) == 8:
                is_found += 1

            if is_found >= 1:
                pPoolBigPageTable.append(sub_addr)
    if pPoolBigPageTable == []:
        return None
    return pPoolBigPageTable


def get_poolbigpagetable_from_tag(tag_to_find):
    global pPoolBigPageTable
    addresses = []

    find_poolbigpagetable()
    if pPoolBigPageTable == []:
        return None
    if pPoolBigPageTable == []:
        return None
    for cPoolBigPageTable in pPoolBigPageTable:
        cpage = 0
        dump = get_va_memory(cPoolBigPageTable, 0xff0)
        while dump is not None:
            i = 0
            while i < len(dump):
                addr_pool = struct.unpack('Q', dump[i:i+8])[0] & 0xfffffffffffffffffffffffe
                tag = dump[i+8:i+0xc]
                pooltype = struct.unpack('I', dump[i+0xc:i+0x10])[0]
                if (addr_pool & 0xfff) != 0 or (addr_pool != 0 and (addr_pool & 0xffff800000000000) != 0xffff800000000000):
                    i += 0x18
                    continue
                if tag == tag_to_find:
                    pool_size = struct.unpack('Q', dump[i+0x10:i+0x18])[0]
                    addresses.append({'address': addr_pool, 'tag': tag, 'size': pool_size, 'type': pooltype})
                i += 0x18
            cpage += 0xff0
            dump = get_va_memory(cPoolBigPageTable+cpage, 0xff0)
    return addresses


def get_from_poolbigpagetable(address):
    global pPoolBigPageTable

    if pPoolBigPageTable == [] or (address & 0xfff) != 0 or (address & 0xffff800000000000) != 0xffff800000000000:
        return None
    if pPoolBigPageTable is None:
        find_poolbigpagetable()
    if pPoolBigPageTable is None:
        return None
    for cPoolBigPageTable in pPoolBigPageTable:
        cpage = 0
        dump = get_va_memory(cPoolBigPageTable, 0xff0)
        while dump is not None:
            i = 0
            while i < len(dump):
                addr_pool = struct.unpack('Q', dump[i:i+8])[0] & 0xfffffffffffffffffffffffe
                tag = dump[i+8:i+0xc]
                if address == addr_pool:
                    pool_size = struct.unpack('Q', dump[i+0x10:i+0x18])[0]
                    return {'tag': tag, 'size': pool_size}
                if (addr_pool & 0xfff) != 0 or (addr_pool != 0 and (addr_pool & 0xffff800000000000) != 0xffff800000000000):
                    return None
                i += 0x18
            cpage += 0xff0
            dump = get_va_memory(cPoolBigPageTable+cpage, 0xff0)
    return None


def get_pool_tag(address, force=False):
    global bitness

    if bitness == 64:
        word_size = 8
        pool_tag_size = 0x10
    else:
        word_size = 4
        pool_tag_size = 8

    if not is_kernel_space(address, word_size):
        return None
    pool_header = get_va_memory(address-pool_tag_size, pool_tag_size)
    if pool_header is not None and len(pool_header) >= 8:
        tag = pool_header[4:8]
        size = (pool_header[2]*pool_tag_size)-pool_tag_size
        if size >= 0:
            prev_size = pool_header[0]*pool_tag_size

            if force or is_ascii(tag[:3]):
                tag_str = ''.join(['%c' % a if a < 0x80 else '?' for a in tag])
                if tag_str in ms_infos.pooltags:
                    return {'tag': tag, 'size': size, 'prev_size': prev_size, 'tag_infos': ms_infos.pooltags[tag_str]}
                else:
                    return {'tag': tag, 'size': size, 'prev_size': prev_size}
    if (address & 0xfff) == 0:
        return get_from_poolbigpagetable(address)
    return None


def check_netio():
    global Drivers_list

    WfpC_list = get_poolbigpagetable_from_tag(b"WfpC")
    if WfpC_list is None or len(WfpC_list) != 1:
        print("  [!] Failed, no tag WfpC in poolBigPage")
        return
    elif len(WfpC_list) != 1:
        print("  [!] Failed, not 1 tag WfpC in poolBigPage : %d" % (len(WfpC_list)))
        return
    pool_chunck = WfpC_list[0]
    caddr = pool_chunck['address']
    print("  [*] FwpkCLNT/NetIo Callouts (callbacks) : %x (%x)" % (caddr, pool_chunck['size']))
    netio_callout_dump = get_va_memory(caddr, pool_chunck['size'])
    if netio_callout_dump is None:
        return
    snetio_callout_dump = struct.unpack('Q'*(len(netio_callout_dump) >> 3), netio_callout_dump)
    cb_list = []
    for callout_addr in snetio_callout_dump:
        if not is_kernel_space(callout_addr):
            continue
        drv_path = get_driver_name_from_address(callout_addr)
        if drv_path is None:
            code = get_va_memory(callout_addr, 0x10)
            if code is None:
                continue
            if not is_data_buffer(code):
                if callout_addr in cb_list:
                    continue
                else:
                    cb_list.append(callout_addr)
                code = ' '.join(["%02x" % (a) for a in code])
                print("  Callback %x -> SUSPICIOUS ***Unknown*** %s" % (callout_addr, code))
        else:
            drv_path = get_driver_name(drv_path)
            if not is_in_ms_list(drv_path):
                if callout_addr in cb_list:
                    continue
                else:
                    cb_list.append(callout_addr)
                print("  Callback %x -> %s (not in white list) SUSPICIOUS" % (callout_addr, drv_path.decode()))
            elif debug > 0:
                print("  Callback %x -> %s" % (callout_addr, drv_path))


def crawl_driver_tags(driver_name, start_tag=b""):
    global Drivers_list
    dump = get_driver_section(driver_name, b".data")
    if dump is None:
        print("  [!] .data of fltmgr is not accessible")
        return
    sdump = struct.unpack('Q'*(len(dump) >> 3), dump)
    for sub_addr in sdump:
        if (sub_addr & 0xffff800000000000) != 0xffff800000000000 or (sub_addr & 7) != 0:
            continue
        cchunk = get_pool_tag(sub_addr)
        ptr_addr = get_qword_from_va(sub_addr)
        if ptr_addr is None:
            continue
        if start_tag == b"":
            if is_list_entry(ptr_addr):
                print("LIST_ENTRY : %x" % (sub_addr))
                print(hexprint(get_va_memory(sub_addr, 0x40), sub_addr, word_size=8))
        if cchunk is not None and cchunk['tag'].startswith(start_tag):  # and tag != "WfpC":
            print(cchunk['tag'])
            print(hexprint(get_va_memory(sub_addr, cchunk['size']), sub_addr, word_size=8))


def check_ObFl_entry(address):
    global struct_ObFl

    if struct_ObFl is not None and 'self_header' in struct_ObFl:
        obFl_base = get_qword_from_va(address+struct_ObFl['self_header'])
        print('    [*] Filter base at 0x%x Altitude %s' % (obFl_base, get_unicode_from_va_no_zero(obFl_base+struct_ObFl['header_uAltitude']).decode()))

    chunk = get_pool_tag(obFl_base)
    if chunk is None:
        size = 0x100
    else:
        size = chunk['size']
    offset = 0
    while offset < size:
        obj_addr = get_qword_from_va(address+offset)
        if obj_addr is None:
            return
        if is_kernel_space(obj_addr):
            rights = get_page_rights(obj_addr)
            if rights is not None and rights['exec']:
                dvr_name = get_driver_name_from_address(obj_addr)
                if dvr_name is not None:
                    dvr_name = get_driver_name(dvr_name)
                    if not is_in_ms_list(dvr_name):
                        print("    Callback %x -> %s (not in white list) SUSPICIOUS" % (obj_addr, dvr_name.decode()))
                    elif debug > 0:
                        print("    Callback %x : %s" % (obj_addr, dvr_name.decode()))
                else:
                    code = get_va_memory(obj_addr, 0x10)
                    if not is_data_buffer(code):
                        if code is None:
                            code = b"???"
                        else:
                            code = ' '.join(["%02x" % a for a in bytearray(code)])
                        print("    Callback %x  SUSPICIOUS ***Unknown*** %s" % (obj_addr, code))
        offset += 8


def check_BaseType_entry(address):
    global struct_PsProcessType
    global struct_ObFl

    chunk = get_pool_tag(address+struct_PsProcessType['header'])
    print('  [*] Checking callbacks for %s at 0x%x' % (get_va_memory(address+struct_PsProcessType['object_Type'], 4).decode(), address+struct_PsProcessType['header']))
    if chunk is None:
        return None
    else:
        size = chunk['size']
    offset = 0
    while offset < size:
        obj_addr = get_qword_from_va(address+offset)
        if obj_addr is None:
            return
        if is_kernel_space(obj_addr):
            rights = get_page_rights(obj_addr)
            if rights is not None and rights['exec']:
                dvr_name = get_driver_name_from_address(obj_addr)
                if dvr_name is not None:
                    dvr_name = get_driver_name(dvr_name)
                    if not is_in_ms_list(dvr_name):
                        print("    Callback %x -> %s (not in white list) SUSPICIOUS" % (obj_addr, dvr_name.decode()))
                    elif debug > 0:
                        print("    Callback %x : %s" % (obj_addr, dvr_name.decode()))
                else:
                    code = get_va_memory(obj_addr, 0x10)
                    if not is_data_buffer(code):
                        if code is None:
                            code = b"???"
                        else:
                            code = ' '.join(["%02x" % a for a in bytearray(code)])
                        print("    Callback %x  SUSPICIOUS ***Unknown*** %s" % (obj_addr, code))
        offset += 8

    if 'object_filters' in struct_PsProcessType:
        filters = get_qword_from_va(address+struct_PsProcessType['object_filters'])
        if is_kernel_space(filters) and filters != (address+struct_PsProcessType['object_filters']):
            crawl_list(address+struct_PsProcessType['object_filters'], check_ObFl_entry, True)


def crawl_BaseType_entry(address):
    global struct_PsProcessType

    header_addr = address+(struct_PsProcessType['header']-struct_PsProcessType['list_base_types'])

    chunk = get_pool_tag(header_addr)
    if chunk is None:
        return None
    check_BaseType_entry(header_addr-struct_PsProcessType['header'])


def check_KernelTypes():
    global struct_PsProcessType
    global struct_ObFl

    PsProcessType_addr = resolve_symbol("nt!PsProcessType")
    if PsProcessType_addr is None or PsProcessType_addr == 0:
        print("[!] PsProcessType not found in ntoskrnl :(")
        return

    if struct_PsProcessType is None:
        decode_PsProcessType(PsProcessType_addr)

    if struct_PsProcessType is not None and 'list_base_types' in struct_PsProcessType and 'object_Type' in struct_PsProcessType:
        print("[*] Checking kernel types")
        first_entry = get_qword_from_va(PsProcessType_addr)
        crawl_list(first_entry+struct_PsProcessType['list_base_types'], crawl_BaseType_entry, False)
    else:
        print("[!] decoding of PsProcessType failed :(")


def decode_PsProcessType(base_addr):
    global struct_PsProcessType
    global struct_ObFl

    struct_PsProcessType = {'list_duno': 0}  # from LIST_ENTRY

    first_PsProcessType = get_qword_from_va(base_addr)
    if first_PsProcessType is None or first_PsProcessType == 0:
        print("[!] PsProcessType is not allocated")
        return

    addr = find_pool_chunck(first_PsProcessType)
    if addr is None:
        print("[!] PsProcessType is not a pool allocation")
        return
    pool_chunk = get_pool_tag(addr)
    align_offset = addr-first_PsProcessType
    struct_PsProcessType['header'] = align_offset
    first_PsProcessType_dump = get_va_memory(addr, pool_chunk['size'])
    if first_PsProcessType_dump is None:
        print("[!] First PsProcessType is not allocated")
        return

    sdump = struct.unpack('Q'*(len(first_PsProcessType_dump) >> 3), first_PsProcessType_dump)
    sub_addr_index = 0
    while sub_addr_index < len(sdump):
        sub_addr = sdump[sub_addr_index]
        if sub_addr != (addr+(sub_addr_index << 3)) and sub_addr != (addr+(sub_addr_index << 3)-8) and is_list_entry(sub_addr):
            addr_next = find_pool_chunck(sub_addr)
            pool_chunk = get_pool_tag(addr_next)
            if pool_chunk is not None:
                if pool_chunk['tag'].startswith(b'Obj') and 'list_base_types' not in struct_PsProcessType:
                    struct_PsProcessType['list_base_types'] = (sub_addr_index << 3)+align_offset
                elif pool_chunk['tag'] == b'ObFl' and 'object_filters' not in struct_PsProcessType:
                    struct_PsProcessType['object_filters'] = (sub_addr_index << 3)+align_offset
        if 'object_Type' not in struct_PsProcessType:
            if first_PsProcessType_dump[sub_addr_index << 3:(sub_addr_index << 3)+4] == b'Proc':
                struct_PsProcessType['object_Type'] = (sub_addr_index << 3)+align_offset
            elif first_PsProcessType_dump[(sub_addr_index << 3)+4:(sub_addr_index << 3)+8] == b'Proc':
                struct_PsProcessType['object_Type'] = (sub_addr_index << 3)+4+align_offset
        sub_addr_index += 1

    if 'object_filters' in struct_PsProcessType and struct_ObFl is None:
        struct_ObFl = {'header_uAltitude': 0x10}
        obFlt_entry_addr = get_qword_from_va(first_PsProcessType+struct_PsProcessType['object_filters'])

        obFlt_dump = get_va_memory(obFlt_entry_addr, 0x50)
        sdump = struct.unpack('Q'*(len(obFlt_dump) >> 3), obFlt_dump)
        sub_addr_index = 0
        while sub_addr_index < len(sdump):
            sub_addr = sdump[sub_addr_index]
            pool_chunk = get_pool_tag(sub_addr)
            if pool_chunk is not None and 'self_header' not in struct_ObFl and pool_chunk['tag'] == b'ObFl':
                struct_ObFl['self_header'] = sub_addr_index << 3
            sub_addr_index += 1


def check_fltmgr():
    dump = get_driver_section("fltmgr", b".data")
    if dump is None:
        print("  [!] .data of fltmgr is not accessible")
        return
    sdump = struct.unpack('Q'*(len(dump) >> 3), dump)
    for sub_addr in sdump:
        if (sub_addr & 0xffff800000000000) != 0xffff800000000000 or (sub_addr & 7) != 0:
            continue

        if not (is_list_entry(sub_addr)):
            continue
        if crawl_fltmgr_frame(sub_addr):
            return


def crawl_fltmgr_frame(address):
    global struct_FltmgrFrame
    if struct_FltmgrFrame is None:
        decode_struct_FltmgrFrame(address)
    if struct_FltmgrFrame is None:
        return False
    frame_AltitudeIntervalLow = get_unicode_from_va_no_zero(struct_FltmgrFrame['first_frame']+struct_FltmgrFrame['frame_AltitudeIntervalLow'])
    frame_AltitudeIntervalHigh = get_unicode_from_va_no_zero(struct_FltmgrFrame['first_frame']+struct_FltmgrFrame['frame_AltitudeIntervalHigh'])
    if frame_AltitudeIntervalLow is None:
        print("  [!] Failed to get Frame name")
    if debug > 0:
        print("FrameId : %d at 0x%x (Altitude %s)" % (get_dword_from_va(address+struct_FltmgrFrame['FrameId']), address, frame_AltitudeIntervalHigh.decode()))
    else:
        print("FrameId : %d (Altitude %s)" % (get_dword_from_va(address+struct_FltmgrFrame['FrameId']), frame_AltitudeIntervalHigh.decode()))
    crawl_list(struct_FltmgrFrame['first_frame']+struct_FltmgrFrame['list_drivers'], check_fltmgr_entry, True)
    return True


def check_fltmgr_entry(address):
    global struct_FltmgrFltFilter
    dvr_name = get_unicode_from_va_no_zero(address+struct_FltmgrFltFilter['driver_name'])
    flt_altitude = get_unicode_from_va_no_zero(address+struct_FltmgrFltFilter['filter_DefaultAltitude'])
    if debug > 0:
        print("  FLT_FILTER address : 0x%x" % (address))
    if dvr_name is not None:
        print("  Driver name : %s (Altitude %s)" % (dvr_name.decode(), flt_altitude.decode()))
    else:
        print('  No Driver name for filter at 0x%x (Altitude %s)' % (address, flt_altitude.decode()))
    offset = struct_FltmgrFltFilter['filter_DefaultAltitude']+0x10
    chunk = get_pool_tag(address+struct_FltmgrFltFilter['header'])
    if chunk is None:
        size = 0x100
    else:
        size = chunk['size']
    while offset < size:
        obj_addr = get_qword_from_va(address+offset)
        if obj_addr is None:
            return
        if is_kernel_space(obj_addr):
            rights = get_page_rights(obj_addr)
            if rights is not None and rights['exec']:
                dvr_name = get_driver_name_from_address(obj_addr)
                if dvr_name is not None:
                    dvr_name = get_driver_name(dvr_name)
                    if not is_in_ms_list(dvr_name):
                        print("    Callback %x -> %s (not in white list) SUSPICIOUS" % (obj_addr, dvr_name.decode()))
                    elif debug > 0:
                        print("    Callback %x : %s" % (obj_addr, dvr_name.decode()))
                else:
                    code = get_va_memory(obj_addr, 0x10)
                    if not is_data_buffer(code):
                        if code is None:
                            code = b"???"
                        else:
                            code = ' '.join(["%02x" % a for a in bytearray(code)])
                        print("    Callback %x  SUSPICIOUS ***Unknown*** %s" % (obj_addr, code))
        offset += 8


def is_list_entry(address):
    if (address >> 48) != 0xffff or (address & 7) != 0:
        return False
    qword_1 = get_qword_from_va(address)
    qword_2 = get_qword_from_va(address+8)
    if qword_1 is None or qword_2 is None:
        return False
    if (qword_1 >> 48) != 0xffff or (qword_1 & 7) != 0 or (qword_2 >> 48) != 0xffff or (qword_2 & 7) != 0:
        return False
    if qword_2 is not None and (get_qword_from_va(qword_1+8) == (address)) and (get_qword_from_va(qword_2) == (address)):
        return True
    return False


def find_pool_header_up(address, size=0x80, tag=None):
    offset = 0
    chunk = get_pool_tag(address)
    while (chunk is None or (tag is not None and chunk['tag'] != tag)) and (offset < size):
        chunk = get_pool_tag(address-offset)
        if (chunk is not None and tag is None) or (tag is not None and chunk['tag'] == tag):
            break
        offset += 8
    if chunk is not None:
        chunk['address'] = address - offset
    return chunk


def find_pool_chunck(addr):
    offset = 0
    first_pool_chunk = None
    while get_va_memory(addr-offset, 8) and offset < 0x2000:
        pool_chunk = get_pool_tag(addr-offset)
        if pool_chunk is not None:
            if first_pool_chunk is None and pool_chunk['size'] > offset:
                first_pool_chunk = (addr-offset)
            next_pool = get_pool_tag((addr-offset)+pool_chunk['size']+0x10)
            if next_pool is not None and next_pool['prev_size'] == (pool_chunk['size']+0x10) and addr < ((addr-offset)+pool_chunk['size']+0x10):
                return (addr-offset)
            if pool_chunk['size'] > 0 and pool_chunk['size'] < 0x2000 and 'prev_size' in pool_chunk and pool_chunk['prev_size'] == 0 and addr < ((addr-offset)+pool_chunk['size']+0x10):
                return (addr-offset)
        offset += 8
    return first_pool_chunk


def find_unicode_string(address, size):
    datas = get_va_memory(address, size)

    offset = 0
    while offset < len(datas):
        qword_1 = struct.unpack('Q', datas[offset:offset+8])[0]
        if (offset+8) < len(datas):
            qword_2 = struct.unpack('Q', datas[offset+8:offset+0x10])[0]
        else:
            return None
        if (qword_1 >> 32) == 0 and (qword_1 > 0):
            uni_size = qword_1 & 0xffff
            uni_maxsize = (qword_1 >> 16) & 0xffff
            if qword_2 is not None and (qword_2 >> 48) == 0xffff and uni_size <= uni_maxsize:
                uni_str = get_unicode_from_va(address+offset)
                if uni_str is not None and len(uni_str) < 0x200 and len(uni_str) <= uni_maxsize:
                    return offset
        offset += 8


def is_int_str(datas):
    for a in datas:
        if a < 0x30 or a > 0x39:
            return False
    return True


def decode_struct_FltmgrFrame(address):
    global struct_FltmgrFrame
    global struct_FltmgrFltFilter
    result = {}
    chunk = get_pool_tag(address)

    frame_AltitudeIntervalHigh = b""

    datas = get_va_memory(address, 0x200)

    offset = 0
    while offset < len(datas):
        if offset > 0x40 and not ('frame_AltitudeIntervalLow' in result):
            break
        qword_1 = struct.unpack('Q', datas[offset:offset+8])[0]
        if (offset+8) < len(datas):
            qword_2 = struct.unpack('Q', datas[offset+8:offset+0x10])[0]
        else:
            qword_2 = None

        if not ('frame_AltitudeIntervalLow' in result) and (qword_1 >> 32) == 0 and (qword_1 > 0):
            if qword_2 is not None and (qword_2 >> 48) == 0xffff and (qword_1 > 0):
                uni_str = get_unicode_from_va_no_zero(address+offset)
                if uni_str is not None and len(uni_str) < 0x80:
                    if uni_str == b"0":  # Found the frame name !
                        result['frame_AltitudeIntervalLow'] = offset
                    frame_AltitudeIntervalHigh = get_unicode_from_va_no_zero(address+offset+0x10)
                    if frame_AltitudeIntervalHigh is not None and len(frame_AltitudeIntervalHigh) < 0x18:
                        result['frame_AltitudeIntervalHigh'] = offset+0x10
        if is_list_entry(qword_1):
            uni_str_offset = find_unicode_string(qword_1, 0x40)
            if uni_str_offset is not None:
                uni_str = get_unicode_from_va_no_zero(qword_1+uni_str_offset)
                if uni_str is not None and len(uni_str) < 0x100:
                    uni_str_2 = get_unicode_from_va_no_zero(qword_1+uni_str_offset+0x10)
                    if frame_AltitudeIntervalHigh is not None and uni_str_2 is not None and len(uni_str_2) > 4 and len(frame_AltitudeIntervalHigh) > 4 and is_int_str(uni_str_2) and is_int_str(frame_AltitudeIntervalHigh):
                        result['first_frame'] = address
                        result['FrameId'] = 0x10
                        result['list_drivers'] = offset
                        chunk = find_pool_header_up(qword_1, 0x60)
                        if chunk is not None and chunk['tag'] == b'FMfl':
                            struct_FltmgrFltFilter = {}
                            struct_FltmgrFltFilter['header'] = chunk['address']-qword_1
                            struct_FltmgrFltFilter['list_entry'] = 0
                            decode_struct_FltmgrFltFilter(qword_1, chunk['size']+struct_FltmgrFltFilter['header'])
                            if 'filter_DefaultAltitude' in struct_FltmgrFltFilter:
                                struct_FltmgrFrame = result
                                return
                        return
        offset += 8


def decode_struct_FltmgrFltFilter(address, size):
    global struct_FltmgrFltFilter
    uni_str_offset = find_unicode_string(address, size)
    if uni_str_offset is None:
        return
    uni_str_offset_ref = find_unicode_string(address+uni_str_offset+0x10, size-uni_str_offset-0x10)
    if uni_str_offset_ref is None:
        return
    uni_str_offset_ref = uni_str_offset+0x10
    offset = uni_str_offset_ref
    while offset < size:
        obj_addr = get_qword_from_va(address+offset)
        if obj_addr is None:
            return
        struct_FltmgrFltFilter['driver_name'] = uni_str_offset
        struct_FltmgrFltFilter['filter_DefaultAltitude'] = uni_str_offset_ref
        offset += 8


def is_kernel_space(address, align=1):
    global bitness

    if bitness == 64:
        min_addr = 0xffff800000000000
    else:
        min_addr = 0x80000000
    if (address & min_addr) == min_addr and (address & (align-1)) == 0:
        return True
    else:
        return False


def is_CallbackRoutine(address):
    global bitness
    if not is_kernel_space(address):
        return False
    if bitness == 64:
        mask = 0xf
    else:
        mask = 7
    ptr_addr = get_sizet_from_va(address)
    if is_kernel_space(ptr_addr) and (ptr_addr & mask) == mask:
        if bitness == 64:
            rundownProtect = get_qword_from_va(ptr_addr ^ mask)
            callbackFunction = get_qword_from_va((ptr_addr ^ mask)+8)
        else:
            rundownProtect = get_dword_from_va(ptr_addr ^ mask)
            callbackFunction = get_dword_from_va((ptr_addr ^ mask)+4)
    else:
        return False
    if not (rundownProtect in [0x10, 0x20]):
        return False
    rights = get_page_rights(callbackFunction)
    if rights is not None and rights['exec']:
        return True
    return False


def cb_callback_list_CM(address):
    global cm_Callback_struct

    altitude = get_unicode_from_va_no_zero(address+cm_Callback_struct['altitude'])
    cb_func = get_qword_from_va(address+cm_Callback_struct['callback'])

    drv_base = get_driver_name_from_address(address)
    if drv_base is not None and drv_base == b"c:\\windows\\system32\\ntoskrnl.exe":
        return

    print("  [*] Altitude %s" % (altitude.decode()))
    dvr_name = get_driver_name_from_address(cb_func)
    if dvr_name is not None:
        dvr_name = get_driver_name(dvr_name)
        if not is_in_ms_list(dvr_name):
            print("    Callback %x -> %s (not in white list) SUSPICIOUS" % (cb_func, dvr_name.decode()))
        elif debug > 0:
            print("    Callback %x : %s" % (cb_func, dvr_name.decode()))
    else:
        code = get_va_memory(cb_func, 0x10)
        code = ' '.join(["%02x" % a for a in bytearray(code)])
        print("    Callback %x -> SUSPICIOUS ***Unknown*** %s" % (cb_func, code))


def is_cm_Callback(address):
    cm_ptr = get_qword_from_va(address)
    if cm_ptr is not None and is_kernel_space(cm_ptr, 8) and is_list_entry(cm_ptr):
        pool_tag = get_pool_tag(cm_ptr)
        if pool_tag is not None and pool_tag['tag'] == b'CMcb':
            if debug > 0:
                print("  [*] CallbackListHead at 0x%x" % (address))
            return address


def decode_cm_Callback(address):
    global addr_CallbackListHead
    global cm_Callback_struct

    cm_Callback_struct = {}
    ptr_cm = get_qword_from_va(address)
    pool_tag = get_pool_tag(ptr_cm)
    for chunk_indx in range(pool_tag['size'] >> 3):
        caddress = ptr_cm+(chunk_indx << 3)
        cvalue = get_qword_from_va(caddress)
        if not ((cvalue >> 48) in [0, 0xffff]):
            cm_Callback_struct['cookie_offset'] = chunk_indx << 3
            cm_Callback_struct['cookie'] = cvalue
        elif get_unicode_from_va(caddress) is not None:
            raw_altitude = get_unicode_from_va(caddress)
            if raw_altitude.count(b'\x00') == (len(raw_altitude) >> 1):
                u_altitude = get_unicode_from_va_no_zero(caddress)
                if 0 < len(u_altitude) < 0x20:
                    cm_Callback_struct['altitude'] = chunk_indx << 3
        elif chunk_indx > 2 and is_list_entry(cvalue) and 'filters_list' not in cm_Callback_struct:
            cm_Callback_struct['filters_list'] = chunk_indx << 3
        elif is_kernel_space(cvalue):
            rights = get_page_rights(cvalue)
            if rights['exec']:
                cm_Callback_struct['callback'] = chunk_indx << 3
        if 'filters_list' in cm_Callback_struct:
            break


def check_registry_callbacks():
    global addr_CallbackListHead
    if addr_CallbackListHead is None:
        addr_CallbackListHead = identify_list_entry_from_code('nt!CmUnRegisterCallback', is_cm_Callback)
        if addr_CallbackListHead is None:
            addr_CallbackListHead = identify_list_entry_from_code('nt!CmSetCallbackObjectContext', is_cm_Callback)

    if addr_CallbackListHead is None and get_va_memory(resolve_symbol('nt!CmUnRegisterCallback'), 5) == b'' and get_va_memory(resolve_symbol('nt!CmSetCallbackObjectContext'), 5) == b'':
        addr_CallbackListHead = crawl_nt_for_CallbackListHead()

    if addr_CallbackListHead is not None:
        if cm_Callback_struct is None or len(cm_Callback_struct) == 0:
            decode_cm_Callback(addr_CallbackListHead)
        if 'altitude' in cm_Callback_struct and 'callback' in cm_Callback_struct:
            print(" [*] CallbackListHead")
            crawl_list(addr_CallbackListHead, cb_callback_list_CM, True)
    if addr_CallbackListHead is None:
        print("  [!] CallbackListHead not found (probably empty)")
    elif 'altitude' not in cm_Callback_struct or 'callback' not in cm_Callback_struct:
        print("  [!] CallbackListHead is not correctly decoded :(")


def crawl_nt_for_CallbackListHead():
    data_section = get_driver_section(b'nt', b'.data')
    data_section_addr = get_section_address(b'nt', b'.data')

    sdata_section = struct.unpack('Q'*(len(data_section) >> 3), data_section)

    nt_base = resolve_symbol('nt')

    for i in range(len(sdata_section)):
        qword = sdata_section[i]
        if is_kernel_space(qword, 8) and not (nt_base <= qword < (nt_base+0x10000000)) and is_list_entry(qword):
            pool_tag = get_pool_tag(qword)
            if pool_tag is not None and pool_tag['tag'] == b'CMcb':
                for chunk_indx in range(pool_tag['size'] >> 3):
                    caddress = qword+(chunk_indx << 3)
                    cvalue = get_qword_from_va(caddress)
                    if not ((cvalue >> 48) in [0, 0xffff]):
                        for incrase_cookie in range(50):
                            if (cvalue+incrase_cookie) in sdata_section[i-10:i+10]:  # is cookie in near datas
                                if debug > 0:
                                    print(" [*] CallbackListHead is at 0x%x" % (data_section_addr+(i << 3)))
                                return data_section_addr+(i << 3)


def find_all_old_Callbacks():
    global debug
    global obpRootDirectoryObject
    global Drivers_list
    global bitness
    global addr_IopNotifyLastChanceShutdownQueueHead
    global addr_IopNotifyShutdownQueueHead
    global addr_PspLoadImageNotifyRoutine
    global addr_PspCreateProcessNotifyRoutine
    global addr_PspCreateThreadNotifyRoutine

    addr_IopNotifyLastChanceShutdownQueueHead = identify_list_entry_from_code('nt!IoRegisterLastChanceShutdownNotification')
    addr_IopNotifyShutdownQueueHead = identify_list_entry_from_code('nt!IoRegisterShutdownNotification')
    addr_PspLoadImageNotifyRoutine = identify_list_entry_from_code('nt!PsRemoveLoadImageNotifyRoutine', is_CallbackRoutine)
    addr_PspCreateProcessNotifyRoutine = identify_list_entry_from_code('nt!PsSetCreateProcessNotifyRoutine', is_CallbackRoutine)
    addr_PspCreateThreadNotifyRoutine = identify_list_entry_from_code('nt!PsSetCreateThreadNotifyRoutine', is_CallbackRoutine)


def check_all_old_Callbacks():
    global debug
    global obpRootDirectoryObject
    global Drivers_list
    global bitness
    global addr_IopNotifyLastChanceShutdownQueueHead
    global addr_IopNotifyShutdownQueueHead
    global addr_PspLoadImageNotifyRoutine
    global addr_PspCreateProcessNotifyRoutine
    global addr_PspCreateThreadNotifyRoutine

    if addr_IopNotifyLastChanceShutdownQueueHead is not None:
        print(" [*] IopNotifyLastChanceShutdownQueueHead")
        crawl_list(addr_IopNotifyLastChanceShutdownQueueHead, cb_callback_list_devices, True)
    else:
        print(" [!] IopNotifyLastChanceShutdownQueueHead not found")

    if addr_IopNotifyShutdownQueueHead is not None:
        print(" [*] IopNotifyShutdownQueueHead")
        crawl_list(addr_IopNotifyShutdownQueueHead, cb_callback_list_devices, True)
    else:
        print(" [!] IopNotifyShutdownQueueHead not found")

    if addr_PspLoadImageNotifyRoutine is not None:
        print(" [*] PspLoadImageNotifyRoutine")
        offset = 0
        cbPtr = get_sizet_from_va(addr_PspLoadImageNotifyRoutine)
        while (cbPtr is not None and cbPtr != 0):
            if bitness == 64:
                callback = get_qword_from_va((cbPtr & 0xfffffffffffffff0)+8)
            else:
                callback = get_dword_from_va((cbPtr & 0xfffffff8)+4)
            rights = get_page_rights(callback)
            if rights is not None and rights['exec']:
                drv_path = get_driver_name_from_address(callback)
                if drv_path is None:
                    code = get_va_memory(callback, 0x10)
                    if code is None:
                        code = "???"
                    else:
                        code = ' '.join(["%02x" % a for a in bytearray(code)])
                    print("  Callback %x -> SUSPICIOUS ***Unknown*** %s" % (callback, code))
                else:
                    drv_path = get_driver_name(drv_path)
                    if not is_in_ms_list(drv_path):
                        print("  Callback %x -> %s (not in white list) SUSPICIOUS" % (callback, drv_path.decode()))
            offset += 8
            cbPtr = get_sizet_from_va(addr_PspLoadImageNotifyRoutine+offset)
    else:
        print(" [!] PspLoadImageNotifyRoutine not found")

    if addr_PspCreateProcessNotifyRoutine is not None:
        print(" [*] PspCreateProcessNotifyRoutine")
        offset = 0
        cbPtr = get_sizet_from_va(addr_PspCreateProcessNotifyRoutine)
        while (cbPtr is not None and cbPtr != 0):
            if bitness == 64:
                callback = get_qword_from_va((cbPtr & 0xfffffffffffffff0)+8)
            else:
                callback = get_dword_from_va((cbPtr & 0xfffffff8)+4)
            rights = get_page_rights(callback)
            if rights is not None and rights['exec']:
                drv_path = get_driver_name_from_address(callback)
                if drv_path is None:
                    code = get_va_memory(callback, 0x10)
                    if code is None:
                        code = "???"
                    else:
                        code = ' '.join(["%02x" % a for a in bytearray(code)])
                    print("  Callback %x -> SUSPICIOUS ***Unknown*** %s" % (callback, code))
                else:
                    drv_path = get_driver_name(drv_path)
                    if not is_in_ms_list(drv_path):
                        print("  Callback %x -> %s (not in white list) SUSPICIOUS" % (callback, drv_path.decode()))
            offset += 8
            cbPtr = get_sizet_from_va(addr_PspCreateProcessNotifyRoutine+offset)
    else:
        print(" [!] PspCreateProcessNotifyRoutine not found")

    if addr_PspCreateThreadNotifyRoutine is not None:
        print(" [*] PspCreateThreadNotifyRoutine")
        offset = 0
        cbPtr = get_sizet_from_va(addr_PspCreateThreadNotifyRoutine)
        while (cbPtr is not None and cbPtr != 0):
            if bitness == 64:
                callback = get_qword_from_va((cbPtr & 0xfffffffffffffff0)+8)
            else:
                callback = get_dword_from_va((cbPtr & 0xfffffff8)+4)
            rights = get_page_rights(callback)
            if rights is not None and rights['exec']:
                drv_path = get_driver_name_from_address(callback)
                if drv_path is None:
                    code = get_va_memory(callback, 0x10)
                    if code is None:
                        code = "???"
                    else:
                        code = ' '.join(["%02x" % a for a in bytearray(code)])
                    print("  Callback %x -> SUSPICIOUS ***Unknown*** %s" % (callback, code))
                else:
                    drv_path = get_driver_name(drv_path)
                    if not is_in_ms_list(drv_path):
                        print("  Callback %x -> %s (not in white list) SUSPICIOUS" % (callback, drv_path.decode()))
            offset += 8
            cbPtr = get_sizet_from_va(addr_PspCreateThreadNotifyRoutine+offset)
    else:
        print(" [!] PspCreateThreadNotifyRoutine not found")


def check_sensitives_devices():
    global rootDirectoryObject_list
    global obj_header_types
    devs_to_check = [b"\\Ntfs", b"\\Fat", b"\\Device\\KeyboardClass0", b"\\Device\\Tcp", b"\\Device\\Udp", b"\\Device\\Tcp6", b"\\Device\\Udp6", b"\\Device\\Afd", b"\\Device\\BitLocker", b"\\Device\\Ip", b"\\Device\\Ip6", b"\\Device\\Ndis", b"\\Device\\RawDisk", b"\\Device\\RawIp", b"\\Device\\VolMgrControl", b"\\GLOBAL??\\PhysicalDrive0", b"\\GLOBAL??\\PhysicalDrive1", b"\\Device\\Harddisk1\\DR1", b"\\GLOBAL??\\C:", b"\\Device\\Null", b"\\Device\\Beep", b"\\Device\\Nsi", b"\\Device\\Tcp"]
    for cdev_name in devs_to_check:
        if not (cdev_name in rootDirectoryObject_list):
            continue
        print(" [*] Checking %s" % cdev_name.decode())
        if rootDirectoryObject_list[cdev_name]['TypeIndex'] in obj_header_types and obj_header_types[rootDirectoryObject_list[cdev_name]['TypeIndex']] == 'SymbolicLink':
            sym = get_symboliclink(rootDirectoryObject_list[cdev_name]['Object'])
            if sym is not None:
                sym = sym.replace(b"\x00", b'')
            sym = bytes(sym)
            print("  -> %s" % (sym.decode()))
            if not (sym in rootDirectoryObject_list):
                continue
            cdev_name = sym
        cdev = rootDirectoryObject_list[cdev_name]
        if cdev is not None:
            crawl_device_object(cdev['Object'])


def check_PE_in_kernel(check_file=True):
    global bitness

    driver_list = get_drivers_list()

    if bitness == 64:
        min_addr = 0xffff800000000000
        max_addr = 0xffffffffffffffff
    else:
        min_addr = 0x80000000
        max_addr = 0xffffffff

    phys_addresses = {}
    prev_pages = []
    for page_address, page_infos in get_pages_list_iter(min_addr, max_addr):
        if len(phys_addresses) > 5000:
            phys_addresses = {}
        if page_infos['phys'] in phys_addresses:
            continue
        phys_addresses[page_infos['phys']] = None
        if len(prev_pages) > 5000:
            prev_pages = prev_pages[-4:]
        prev_pages.append([page_address, page_infos])
        if not page_infos['right']['exec']:
            continue
        if len(prev_pages) > 2:
            if prev_pages[-3][0] == (page_address-0x2000):
                continue
            if prev_pages[-2][0] != (page_address-0x1000):
                continue
            if prev_pages[-2][1]['right']['exec']:
                continue
        page = page_address-0x1000
        if bitness == 64:
            page = (page | 0xffff000000000000)
        if page > min_addr and page < max_addr:
            mem_dmp = get_va_memory(page, 0x1000)
            if mem_dmp is not None and is_PE_Entry(mem_dmp):
                if page in driver_list:
                    if check_file:
                        if isFile(driver_list[page]['Name']):
                            print("  [OK] %x : %s" % (page, driver_list[page]['Name'].decode()))
                        else:
                            print("  [OK] %x : %s (not on FS)" % (page, driver_list[page]['Name'].decode()))
                    else:
                        print("  [OK] %x : %s" % (page, driver_list[page]['Name'].decode()))
                else:
                    if b".text\x00\x00\x00" in mem_dmp:
                        if mem_dmp[:2] != b"MZ":
                            print("  [NO] %x (Header overwritten)" % (page))
                        else:
                            print("  [NO] %x" % (page))
                        dump_module(page)
                    elif b".rsrc\x00\x00\x00" in mem_dmp:
                        print("  [NO] %x (no .text, but .rsrc)" % (page))
                    else:
                        print("  [NO] %x (no .text and .rsrc)" % (page))
        elif page in driver_list:
            print("  [??] %x %s" % (page, driver_list[page]['Name']))
            mem_dmp = get_va_memory(page, 0x1000)


def get_obj_from_address(address):
    global rootDirectoryObject_list
    global obj_header_types

    if rootDirectoryObject_list == {}:
        get_all_objects_by_name()

    for name in rootDirectoryObject_list:
        if address == rootDirectoryObject_list[name]['Object']:
            result = rootDirectoryObject_list[name]
            result['Path'] = name
            return result
    return None


def get_obj_list(name, sub_tree=False):
    global rootDirectoryObject_list
    global obj_header_types

    results = {}

    if type(name) is str:
        name = bytes(bytearray(name, 'utf8'))

    if name[-1] == b"\\":
        name = name[:-1]

    if rootDirectoryObject_list == {}:
        get_all_objects_by_name()

    if obj_header_types == {}:
        for obj_name in rootDirectoryObject_list:
            if obj_name == b"\\clfs":
                obj_header_types[rootDirectoryObject_list[obj_name]['TypeIndex']] = "Device"
            if obj_name == b"\\REGISTRY":
                obj_header_types[rootDirectoryObject_list[obj_name]['TypeIndex']] = "Key"
            if obj_name == b"\\RPC Control\\eventlog":
                obj_header_types[rootDirectoryObject_list[obj_name]['TypeIndex']] = "ALPC Port"
            if obj_name == b"\\SAM_SERVICE_STARTED":
                obj_header_types[rootDirectoryObject_list[obj_name]['TypeIndex']] = "Event"
            if obj_name == b"\\Driver\\ACPI":
                obj_header_types[rootDirectoryObject_list[obj_name]['TypeIndex']] = "Driver"
            if obj_name == b"\\Callback\\PowerState":
                obj_header_types[rootDirectoryObject_list[obj_name]['TypeIndex']] = "Callback"
            if obj_name == b"\\SystemRoot":
                obj_header_types[rootDirectoryObject_list[obj_name]['TypeIndex']] = "SymbolicLink"
            if obj_name == b"\\LsaPerformance":
                obj_header_types[rootDirectoryObject_list[obj_name]['TypeIndex']] = "Section"

    for dev_obj in rootDirectoryObject_list:
        if sub_tree and dev_obj.startswith(name):
            results[dev_obj] = rootDirectoryObject_list[dev_obj]
        if not sub_tree and (dev_obj.startswith(name) and ((name.count(b"\\")+1) == dev_obj.count(b"\\"))):
            results[dev_obj] = rootDirectoryObject_list[dev_obj]

    return results


def get_symboliclink(address):
    return get_unicode_from_va(address+8)


def is_hooked(datas, address=None):
    jmp_1 = ["\xeb", "\xe9"]
    jmp_2 = ["\xff\xe0", "\xff\xe1", "\xff\xe2", "\xff\xe3", "\xff\xe4", "\xff\xe5", "\xff\xe6", "\xff\xe7", "\xff\xd0", "\xff\xd1", "\xff\xd2", "\xff\xd3", "\xff\xd4", "\xff\xd5", "\xff\xd6", "\xff\xd7"]

    if datas is None or len(datas) < 5:
        return False

    if datas[0] in jmp_1:
        if address is not None:
            relative_addr = get_dword_from_va(address+1)
            if relative_addr & 0x80000000:
                relative_addr |= 0xffffffff00000000
            ptr_addr = 0xffffffffffffffff & ((address+5)+relative_addr)
            drv1 = get_driver_name_from_address(ptr_addr)
            drv2 = get_driver_name_from_address(address)
            if drv1 == drv2:
                return False
            else:
                return True
        else:
            return True
    for cjmp_2 in jmp_2:
        if cjmp_2 in datas:
            return True
    return False


def get_exec_section_from_pe(image_base):
    global Drivers_list

    if not (image_base in Drivers_list):
        return None

    decode_pe(image_base)


def is_block_of_address(raw, mem):
    size = len(raw)
    ok_bytes = 0

    for i in range(size):
        if raw[i] == mem[i]:
            ok_bytes += 1
        elif raw[i:i+3] == b"\x00\x00\x00" and mem[i:i+3] == b"\xf8\xff\xff":
            ok_bytes += 3
    if (size*0.40) < (ok_bytes):
        return True
    return False


def diff_file_mem(raw_dump, mem_dump, image_base=0):
    diffs = {}

    i = 0
    while i < len(raw_dump):
        if raw_dump[i:i+0x100] != mem_dump[i:i+0x100]:
            if raw_dump[i] != mem_dump[i]:
                start_diff = i
                while raw_dump[i:i+8] != mem_dump[i:i+8] and i < len(raw_dump):
                    i += 1

                end_diff = i
                size_diff = end_diff - start_diff

                if size_diff < 5:
                    continue

                if size_diff <= 8 and (raw_dump[end_diff:end_diff+2] == b"\xff\xff" or (raw_dump[end_diff-2:end_diff] == b"\x00\x00" and mem_dump[end_diff-2:end_diff] == b"\xff\xff")):
                    continue

                if is_block_of_address(raw_dump[start_diff:end_diff], mem_dump[start_diff:end_diff]):
                    continue

                if (start_diff-8) >= 0:
                    start_diff_min = start_diff-8
                else:
                    start_diff_min = 0
                if (end_diff+8) >= 0:
                    end_diff_max = end_diff+8
                else:
                    end_diff_max = len(raw_dump)

                diffs[start_diff_min+image_base] = [size_diff, raw_dump[start_diff_min:end_diff_max],  mem_dump[start_diff_min:end_diff_max]]
                continue
            i += 1
            continue
        i += 0x100
    return diffs


def check_driver_integrity(image_base=None, driver_path=None):
    global Drivers_list
    global offline_mode
    global image_base_to_file
    global bitness

    if Drivers_list is None:
        get_drivers_list()

    if image_base is None and driver_path is None:
        return None

    if image_base is None:
        image_base = resolve_symbol(driver_path)
        if image_base is None or image_base < 0x80000000:
            return None
        if image_base is not None:
            driver_path = get_driver_name(Drivers_list[image_base]['Name'].lower())
        else:
            driver_path = driver_path.lower()
            for cimagebase in Drivers_list:
                cname = get_driver_name(Drivers_list[cimagebase]['Name'].lower())
                if cname == driver_path:
                    image_base = cimagebase
                    break

    if not (image_base in Drivers_list):
        return {}

    if not ('PE' in Drivers_list[image_base]):
        decode_pe(image_base)

    if not ('PE' in Drivers_list[image_base]):
        return {}
    pe = Drivers_list[image_base]['PE']

    if offline_mode == 0:
        driver_path = get_driver_name(Drivers_list[image_base]['Name'].lower())
        try:
            driver_fd = open(driver_path.decode(), "rb")
        except Exception:
            return None
        if not (driver_fd):
            return None
        driver_file = driver_fd.read()
        driver_fd.close()
    else:
        download_from_ms(image_base=image_base)
        if image_base in image_base_to_file and image_base_to_file[image_base] is not None:
            driver_fd = open(image_base_to_file[image_base], "rb")
            if not (driver_fd):
                return None
            driver_file = driver_fd.read()
            driver_fd.close()
        else:
            return None
    diffs = {}
    relocs = []
    for csection in pe['Sections']:
        if (csection['name'] in [b'.text', b'PAGE'] and (csection['caracteristics'] & 0x20)):
            text_entry = csection['virtual_address']
            text_end = csection['virtual_address']+csection['raw_size']
            mem_dump = get_va_memory(image_base+csection['virtual_address'], csection['raw_size'])
            if mem_dump is None:
                continue
            mem_dump = bytearray(mem_dump)
            raw_dump = bytearray(driver_file[csection['raw_address']:csection['raw_address']+csection['raw_size']])

            dos_header = pe_decode_dos_header(driver_file)
            pe_opt_header = pe_decode_pe_header(driver_file[dos_header['e_lfanew']:dos_header['e_lfanew']+0x200])
            if pe_opt_header['timestamp'] != Drivers_list[image_base]['PE']['Optional_Header']['timestamp']:
                print("  [!] File stored and file in memory are differents")
                return None
            pe_sections = pe_decode_sections(driver_file[dos_header['e_lfanew']:dos_header['e_lfanew']+0x800])
            for fcsection in pe_sections:
                if pe_opt_header['relocation_table_address'] >= fcsection['virtual_address'] and pe_opt_header['relocation_table_address'] < fcsection['virtual_address']+fcsection['virtual_size']:
                    reloc_addr = pe_opt_header['relocation_table_address'] - fcsection['virtual_address'] + fcsection['raw_address']
                    relocs = pe_decode_relocs(driver_file[reloc_addr:reloc_addr+pe_opt_header['relocation_table_size']])
            for creloc in relocs:
                if text_entry <= creloc < text_end:
                    if bitness == 64:
                        raw_base_reloc = creloc-csection['virtual_address']
                        fva = struct.unpack('Q', raw_dump[raw_base_reloc:raw_base_reloc+8])[0]
                        fva = fva - pe_opt_header['image_base'] + image_base
                        raw_dump[raw_base_reloc:raw_base_reloc+8] = struct.pack('Q', fva)
                    else:
                        raw_base_reloc = creloc-csection['virtual_address']
                        fva = struct.unpack('I', raw_dump[raw_base_reloc:raw_base_reloc+4])[0]
                        fva = fva - pe_opt_header['image_base'] + image_base
                        raw_dump[raw_base_reloc:raw_base_reloc+4] = struct.pack('I', fva)
            if len(raw_dump) == len(mem_dump):
                diffs.update(diff_file_mem(raw_dump, mem_dump, image_base+csection['virtual_address']))
    return diffs


def check_critical_drivers(driver_name=None):
    if driver_name is None:
        dirvers = ["nt", "win32k", "acpi", "hal", "afd", "ataport", "atapi", "disk", "fltmgr", "ntfs", "fwpkclnt", "netio", "ndis", "partmgr", "scsiport", "storport", "tcpip", "tdi", "tdx", "volmgr", "volsnap", "volsnap", "ci", "srv", "null", "beep", "iastor", "iastorv", "idechndr", "nvata", "nvatabus", "nvgts", "nvstor", "nvstor32", "sisraid"]
    else:
        dirvers = [driver_name]

    for cdriver in dirvers:
        print("Checking %s" % cdriver)
        diffs = check_driver_integrity(driver_path=cdriver)
        if diffs is None:
            if debug > 0:
                print("  [!] Impossible to check %s" % (cdriver))
            continue
        for offset in sorted(list(diffs.keys())):
            ori_datas = diffs[offset][1]
            mod_datas = diffs[offset][2]
            print("  [!] Original code at 0x%x : %s" % (offset, ' '.join("%02x" % a for a in bytearray(ori_datas))))
            print("  [!] Modified code at 0x%x : %s" % (offset, ' '.join("%02x" % a for a in bytearray(mod_datas))))
            print("")


def check_hooks_inline():
    functions_to_check = ["nt!NtAdjustPrivilegesToken", "nt!NtClose", "nt!NtConnectPort", "nt!NtCreateEvent", "nt!NtCreateFile", "nt!NtCreateSection", "nt!NtDeleteFile", "nt!NtDeviceIoControlFile", "nt!NtDuplicateObject", "nt!NtDuplicateToken", "nt!NtFsControlFile", "nt!NtGetEnvironmentVariableEx", "nt!NtMapViewOfSection", "nt!NtNotifyChangeDirectoryFile", "nt!NtOpenFile", "nt!NtOpenProcess", "nt!NtOpenProcessToken", "nt!NtOpenProcessTokenEx", "nt!NtOpenThread", "nt!NtOpenThreadToken", "nt!NtOpenThreadTokenEx", "nt!NtQueryDirectoryFile", "nt!NtQueryEaFile", "nt!NtQueryEnvironmentVariableInfoEx", "nt!NtQueryInformationFile", "nt!NtQueryInformationProcess", "nt!NtQueryInformationThread", "nt!NtQueryInformationToken", "nt!NtQuerySecurityAttributesToken", "nt!NtQuerySecurityObject", "nt!NtQuerySystemInformation", "nt!NtQuerySystemInformationEx", "nt!NtQueryVolumeInformationFile", "nt!NtReadFile", "nt!NtSetEaFile", "nt!NtSetEvent", "nt!NtSetInformationFile", "nt!NtSetInformationProcess", "nt!NtSetInformationThread", "nt!NtSetInformationToken", "nt!NtSetInformationVirtualMemory", "nt!NtSetSecurityObject", "nt!NtSetVolumeInformationFile", "nt!NtShutdownSystem", "nt!NtUnlockFile", "nt!NtVdmControl", "nt!NtWaitForSingleObject", "nt!NtWriteFile"]

    for function_to_check in functions_to_check:
        caddr = resolve_symbol(function_to_check)
        if caddr is None:
            print("not found : %s" % (function_to_check))
            continue
        datas = get_va_memory(caddr, 0x20)
        if debug > 0:
            print("  [*] Checking %s" % (function_to_check))
        if is_hooked(datas, caddr):
            print("  [!] %s is hooked !" % (function_to_check))


def find_timertable_in_kprcb(kprcb_address):
    offset = 0x1c0
    while offset < 0x10000:
        ckprcb_address = kprcb_address+offset
        cdatas = get_va_memory(ckprcb_address, 0x40)
        if cdatas is None or len(cdatas) < 0x40:
            return None
        if cdatas.replace(b"\x00", b'') == b'':
            index = 0
            is_ktimer = True
            while index < 10 and is_ktimer:
                if not (get_qword_from_va(ckprcb_address+0x40+(index*0x20)) == 0 and is_kernel_space(get_qword_from_va(ckprcb_address+0x48+(index*0x20))) and is_kernel_space(get_qword_from_va(ckprcb_address+0x50+(index*0x20)))):
                    is_ktimer = False
                index += 1
            if is_ktimer and index == 10:
                return ckprcb_address-0x1c0-kprcb_address
        offset += 8
    return None


def __ROL8__(num, index):
    index = index % 64
    return align_64((num << index) | (num >> (64-index)))


def __ROR8__(num, index):
    index = index % 64
    return align_64((num >> index) | ((num & ((2**index)-1)) << (64-index)))


def align_64(num):
    return (num & 0xffffffffffffffff)


def find_kiWaitNever_kiWaitAlways():
    global kiWaitNever
    global kiWaitAlways
    global debug
    global bitness

    if kiWaitNever is not None and kiWaitAlways is not None:
        return True

    keSetTimerEx = resolve_symbol("nt!KeSetTimerEx")
    if keSetTimerEx is None:
        print("  [!] Can't resolve nt!KeSetTimerEx")
        return False
    import lde
    disas = lde.LDE(bitness)
    instr_list = disas.get_function_instructions(keSetTimerEx, get_va_memory, 80)
    if len(instr_list) < 50:
        sub_func = None
        for caddr in instr_list:
            if len(instr_list[caddr]) > 2 and instr_list[caddr][1] == 'call':
                sub_func = instr_list[caddr][2]
                break
        if sub_func is None:
            print("  [!] Can't reverse nt!KeSetTimerEx")
            return False
        instr_list = disas.get_function_instructions(sub_func, get_va_memory, 80)
    sorted_instr_list = list(instr_list.keys())
    sorted_instr_list.sort()
    for caddr in sorted_instr_list:
        if instr_list[caddr][0] == 7:
            if kiWaitNever is None:
                kiWaitNever = caddr+struct.unpack('i', get_va_memory(caddr+3, 4))[0]+7
                kiWaitNever = get_qword_from_va(kiWaitNever)
                if debug > 0:
                    print("KiWaitNever : %x" % kiWaitNever)
            elif kiWaitAlways is None:
                kiWaitAlways = caddr+struct.unpack('i', get_va_memory(caddr+3, 4))[0]+7
                kiWaitAlways = get_qword_from_va(kiWaitAlways)
                if debug > 0:
                    print("KiWaitAlways : %x" % kiWaitAlways)
                return True


def decode_DPC_address(address, from_addr):
    global kiWaitNever
    global kiWaitAlways
    if kiWaitNever == -1:
        return None
    if kiWaitNever is None or kiWaitAlways is None:
        find_kiWaitNever_kiWaitAlways()
    if kiWaitNever is None or kiWaitAlways is None:
        kiWaitNever = -1
        return None
    t = __ROL8__(kiWaitNever ^ address, kiWaitNever)
    t = t ^ (from_addr)
    t = struct.unpack(">Q", struct.pack("Q", t))[0]
    return (t ^ kiWaitAlways)


def cb_ktimer_dpc(address):
    global debug
    top_list = get_qword_from_va(address-0x18)
    if top_list is None or not (is_list_entry(top_list) and is_kernel_space(top_list)) or get_dword_from_va(address-0x1c) != 0:
        return
    dpc_addr = get_qword_from_va(address+0x10)
    if debug > 0:
        print("DPC list : %x" % (address))
    if dpc_addr != 0xffffffff00000000:
        dpc_dest = decode_DPC_address(dpc_addr, address-0x20)
        if dpc_dest != 0:
            dpc_list = [dpc_dest]
            result = []
            while dpc_dest is not None and dpc_dest != 0:
                dpc_fags = get_qword_from_va(dpc_dest)  # 0x113 == DPC (KeInitializeDpc -referenced in EAT-)
                raw_datas = get_va_memory(dpc_dest, 0x80)
                if raw_datas is None:
                    return
                if debug > 0:
                    print(" DPC (decoded) :")
                    hexprint(get_va_memory(dpc_dest, 0x80), dpc_dest, 8)
                list_ptr = get_qword_from_va(dpc_dest+0x8)  # sur
                func_ptr = get_qword_from_va(dpc_dest+0x18)  # sur
                context_ptr = get_qword_from_va(dpc_dest+0x20)  # sur, with check in KeInitializeDpc
                systemArgument1 = get_qword_from_va(dpc_dest+0x28)
                systemArgument2 = get_qword_from_va(dpc_dest+0x30)

                if func_ptr is None:
                    return
                rights = get_page_rights(func_ptr)
                if rights is not None and rights['exec']:
                    if (dpc_fags & 0xffff00ff) == 0x13 and context_ptr is not None and context_ptr != 0 and get_va_memory(context_ptr, 0x60) is not None:
                        if debug > 0:
                            print(" DPC context %x :" % (context_ptr))
                            hexprint(get_va_memory(context_ptr, 0x60), context_ptr, 8)
                    if debug > 0:
                        drv_path = get_driver_name_from_address(func_ptr)
                        if drv_path is None:
                            code = get_va_memory(func_ptr, 0x10)
                            if code is None:
                                code = "???"
                            else:
                                code = ' '.join(["%02x" % a for a in bytearray(code)])
                            print("  DPC function %x -> SUSPICIOUS ***Unknown*** %s" % (func_ptr, code))
                        else:
                            drv_path = get_driver_name(drv_path)
                            if not is_in_ms_list(drv_path):
                                print("  DPC function %x -> %s (not in white list) SUSPICIOUS" % (func_ptr, drv_path.decode()))
                            else:
                                print("  DPC function %x -> %s" % (func_ptr, drv_path.decode()))
                    result.append([func_ptr, dpc_dest, context_ptr, systemArgument1, systemArgument2])
                dpc_dest = list_ptr
                if dpc_dest != 0 and is_kernel_space(dpc_dest):
                    dpc_dest -= 8
                if dpc_dest in dpc_list:
                    break
                dpc_list.append(dpc_dest)
            return result


def check_ktimers():
    uniq_funcs = get_ktimers()
    for cfunc in uniq_funcs:
        if cfunc is None:
            continue
        drv_path = get_driver_name_from_address(cfunc)
        if drv_path is None:
            code = get_va_memory(cfunc, 0x10)
            if code is None:
                code = b"???"
            else:
                code = ' '.join(["%02x" % a for a in bytearray(code)])
            print("  DPC function %x -> SUSPICIOUS ***Unknown*** %s" % (cfunc, code))
        else:
            drv_path = get_driver_name(drv_path)
            if not is_in_ms_list(drv_path):
                print("  DPC function %x -> %s (not in white list) SUSPICIOUS" % (cfunc, drv_path))
            elif debug > 0:
                print("  DPC function %x -> %s" % (cfunc, drv_path))


def get_ktimers():

    global debug
    global kprcb_list
    global kiWaitNever
    global kiWaitAlways

    if kprcb_list is None:
        find_KPRCB()
    uniq_funcs = {}
    for sub_addr in kprcb_list:
        ktimer_offset = find_timertable_in_kprcb(sub_addr)
        if ktimer_offset is None:
            continue
        if debug > 0:
            print("  offset nt!_KPRCB.TimerTable = %x (%x)" % (ktimer_offset, sub_addr+ktimer_offset))
        find_kiWaitNever_kiWaitAlways()
        if kiWaitNever is not None and kiWaitAlways is not None:
            for i in range(256):
                timer_func = []
                if get_qword_from_va(sub_addr+ktimer_offset+0x200+(i*0x20)+8) == 0:
                    break
                timer_func += crawl_list(get_qword_from_va(sub_addr+ktimer_offset+0x200+(i*0x20)+8), cb_ktimer_dpc, ignore_first=False)
                timer_func += crawl_list(get_qword_from_va(sub_addr+ktimer_offset+0x200+(i*0x20)+0x10), cb_ktimer_dpc, ignore_first=False)
                for ctimer_groups in timer_func:
                    if ctimer_groups is None:
                        continue
                    for ctimer_group in ctimer_groups:
                        ctimer_func = ctimer_group[0]
                        ctimer_context = ctimer_group[1:]
                        if not (ctimer_func in uniq_funcs):
                            uniq_funcs[ctimer_func] = []
                        if not (ctimer_context in uniq_funcs[ctimer_func]):
                            uniq_funcs[ctimer_func].append(ctimer_context)
    return uniq_funcs


def find_KPRCB():
    global kprcb_list
    global debug

    kprcb_list = {}
    dump = get_driver_section(b"nt", b"ALMOSTRO")
    if dump is None:
        print("  [!] ALMOSTRO of ntoskrnl is not accessible")
        return
    sdump = struct.unpack('Q'*(len(dump) >> 3), dump)
    for i in range(0, len(sdump)):
        sub_addr = sdump[i]
        if not is_kernel_space(sub_addr, 8):
            continue
        dword_ptr = get_dword_from_va(sub_addr)
        if dword_ptr == 0x1f80:
            if debug > 0:
                print("Found _KPRCB: %x" % sub_addr)
            if not (sub_addr in kprcb_list):
                kprcb_list[sub_addr] = None


def reconstruct_idt_entry(idt_entry_data):
    offsetLow = raw_to_int(idt_entry_data[0:2])
    offsetMiddle = raw_to_int(idt_entry_data[6:8])
    offsetHigh = raw_to_int(idt_entry_data[8:0xc])
    return (offsetHigh << 32) | (offsetMiddle << 16) | offsetLow


def check_idt():
    if kprcb_list is None or len(kprcb_list) == 0:
        find_KPRCB()
    if kprcb_list is None or len(kprcb_list) == 0:
        return None

    idt_parsed_entries = {}

    for cKpcrb in sorted(list(kprcb_list.keys())):
        cKpcr = cKpcrb - 0x180
        cidt = get_qword_from_va(cKpcr+0x38)
        print("  [*] Checking IDT 0x%x in KPCR 0x%x" % (cidt, cKpcr))
        all_entries = get_va_memory(cidt, 256 << 4)
        for idt_index in range(256):
            real_entry = reconstruct_idt_entry(all_entries[idt_index << 4:(idt_index << 4)+0x10])
            if real_entry in idt_parsed_entries:
                target_name = idt_parsed_entries[real_entry]
            else:
                target_name = get_driver_name_from_address(real_entry)
                idt_parsed_entries[real_entry] = target_name
            if target_name is not None:
                target_name_long = get_driver_name(target_name).lower()
                target_name = target_name.split(b"\\")[-1]
            else:
                target_name = b"*Unkown*"
                target_name_long = b"*Unkown*"
            if debug > 0:
                print("    [%02x] %x %s" % (idt_index, real_entry, target_name_long.decode()))
            if real_entry != 0 and not is_in_ms_list(target_name_long):
                shit_pattern = b"\x50\x55\x48\x8D\x2D\x67\xFF\xFF\xFF\xFF\x65\x50\xCC"  # because Win7...
                if shit_pattern != get_va_memory(real_entry, 0xd):
                    print("    [!] IDT entry %d call function 0x%x point to driver %s ****** SUSPICIOUS ******" % (idt_index, real_entry, target_name_long.decode()))

    return


def is_pg_in_dpc(address):
    is_pg_active = 0
    dpc_list = [address]
    while address is not None:
        dpc_list_entry = get_qword_from_va(address+0x8)
        dpc_routine = get_qword_from_va(address+0x18)
        dpc_context = get_qword_from_va(address+0x20)
        dpc_sysarg1 = get_qword_from_va(address+0x28)
        dpc_sysarg2 = get_qword_from_va(address+0x30)
        is_pg_func = is_PG_function(dpc_routine)
        if is_pg_func > 0:
            print("  PG DPC function (%x) : %x" % (address, dpc_routine))
            print("    function : %x ; context : %x ; SystemArgument1 : %x ; SystemArgument2 : %x" % (dpc_routine, dpc_context, dpc_sysarg1, dpc_sysarg2))
            if is_pg_func > 1 or not ((dpc_context >> 0x30) in [0xffff, 0]):
                return 2
            else:
                is_pg_active = 1
        if dpc_list_entry != 0 and is_kernel_space(dpc_list_entry):
            address = dpc_list_entry
            if address != 0:
                address -= 8
                if address in dpc_list:
                    break
            else:
                break
        else:
            break
        dpc_list.append(address)
    return is_pg_active


def is_CiValidateImageHeader(CiValidateImageHeader_addr):
    datas = get_va_memory(CiValidateImageHeader_addr, 0x2000)

    eof = datas.find(b'\xcc\xcc\xcc')
    if eof > 0:
        datas = datas[:eof]
    else:
        eof = datas.find(b'\x90\x90\x90')
        if eof > 0:
            datas = datas[:eof]

    if len(datas) < 900:
        return False

    sub_rsp_offset = datas.find(b'\x48\x8d\x6c')
    if sub_rsp_offset < 0:
        sub_rsp_offset = datas.find(b'\x48\x81\xec')

    if 4 < sub_rsp_offset < 0x20:
        if datas.count(b"\x03\x06\x00\xC0") >= 2:
            return True
    return False


def is_CiValidateImageData(CiValidateImageHeader_addr):
    datas = get_va_memory(CiValidateImageHeader_addr, 0x2000)

    if datas is None:
        return False

    eof = datas.find(b'\xcc\xcc\xcc')
    if eof > 0:
        datas = datas[:eof]
    else:
        eof = datas.find(b'\x90\x90\x90')
        if eof > 0:
            datas = datas[:eof]

    if 100 < len(datas) < 900:
        return True

    return False


def check_SeCiCallbacks_in_nt():
    ci_base = resolve_symbol('ci')

    functions = {}

    if ci_base is None:
        print("[!] CI not found :(")
        return None

    dump = get_driver_section(b"nt", b".data")
    if dump is None:
        print("  [!] .data of ntoskrnl is not accessible")
        return

    page_section_address = get_section_address('nt', '.data')
    for i in range(len(dump) >> 3):
        cqword = raw_to_int(dump[i << 3:(i << 3)+8])
        if ci_base < cqword < (ci_base+0x200000):
            found_driver = get_driver_name_from_address(cqword)
            rights = get_page_rights(cqword)
            if found_driver is not None and rights is not None and rights['exec'] and found_driver.decode().lower().endswith(r'\systemroot\system32\ci.dll'):
                if is_CiValidateImageHeader(cqword):
                    if debug > 0:
                        print("[*] CiValidateImageHeader found in Ntoskrnl at 0x%x -> 0x%x" % (page_section_address+(i << 3), cqword))
                    functions['CiValidateImageHeader'] = cqword
                    ncqword = raw_to_int(dump[(i+1) << 3:((i+1) << 3)+8])
                    nfound_driver = get_driver_name_from_address(ncqword)
                    if found_driver is not None and rights is not None and rights['exec'] and nfound_driver is not None and nfound_driver.decode().lower().endswith(r'\systemroot\system32\ci.dll'):
                        if is_CiValidateImageData(ncqword):
                            if debug > 0:
                                print("[*] CiValidateImageData found in Ntoskrnl at 0x%x -> 0x%x" % (page_section_address+((i+1) << 3), ncqword))
                            functions['CiValidateImageData'] = ncqword
                            break
    return functions


def check_CI_checks_cb():
    global seValidateImageHeader_callback
    global seValidateImageData_callback
    global seValidateImageHeader_callback_addr
    global seValidateImageData_callback_addr

    print("Checking integrity-check callbacks (like PatchGuard)")
    ci_functions = check_SeCiCallbacks_in_nt()
    if 'CiValidateImageHeader' not in ci_functions:
        print('[!] CiValidateImageHeader not found in Nt! DSE fix? ***** SUSPICIOUS *****')
    elif 'CiValidateImageData' not in ci_functions:
        print('[!] CiValidateImageData not found in Nt! DSE fix? ***** SUSPICIOUS *****')

    repattern_SeValidateImageData = [re.compile(b"\x48\x8B\x05....\x4C\x8B\xD1\x48\x85\xC0\x74"), re.compile(b"\x4C\x8B\x0D....\x4C\x3B\xC8")]  # Win10,Win7

    seValidateImageHeader_callback_addr = None
    seValidateImageData_callback_addr = None

    seValidateImageHeader_callback_ptr = None
    seValidateImageData_callback_ptr = None

    dump_page = get_driver_section(b"nt", b"PAGE")
    if dump_page is None:
        print("  [!] PAGE of ntoskrnl is not accessible")
        return

    page_section_address = get_section_address(b'nt', b'PAGE')
    for cpattern in repattern_SeValidateImageData:
        for cmatch in cpattern.finditer(dump_page):
            offset_SeValidateImageData = cmatch.span()[0]
            rel_addr = raw_to_int(dump_page[offset_SeValidateImageData+3:offset_SeValidateImageData+3+4])
            if (rel_addr & 0x80000000) != 0:
                rel_addr = -(0x100000000-rel_addr)
            seValidateImageHeader_callback_addr = (page_section_address+offset_SeValidateImageData+7+rel_addr)-8
            seValidateImageHeader_callback_ptr = get_qword_from_va(seValidateImageHeader_callback_addr)
            seValidateImageData_callback_addr = page_section_address+offset_SeValidateImageData+7+rel_addr
            seValidateImageData_callback_ptr = get_qword_from_va(seValidateImageData_callback_addr)
            if debug > 0:
                print('  SeValidateImageData callback : 0x%x' % (seValidateImageData_callback_ptr))
            break
        if seValidateImageData_callback_ptr is not None:
            break

    if seValidateImageData_callback_ptr is None:
        print("[!] SeValidateImageData callback not found :(")
    else:
        found_driver = get_driver_name_from_address(seValidateImageData_callback_ptr)
        if found_driver is None:
            print("[!] No driver found for the callback SeValidateImageData: 0x%x ***** SUSPICIOUS *****" % (seValidateImageData_callback_ptr))
        elif found_driver.decode().lower().endswith(r'\systemroot\system32\ci.dll'):
            cb_SeValidateImageData = get_va_memory(seValidateImageData_callback_ptr, 2)
            if cb_SeValidateImageData != b"\x48\x89":
                print("[!] Callback SeValidateImageData is patched at 0x%x ***** SUSPICIOUS *****" % (seValidateImageData_callback_ptr))
            else:
                print("[*] SeValidateImageData OK")
                seValidateImageData_callback = seValidateImageData_callback_ptr
            if 'CiValidateImageHeader' in ci_functions and ci_functions['CiValidateImageHeader'] == seValidateImageHeader_callback_ptr:
                print("[*] SeValidateImageHeader OK")
                seValidateImageHeader_callback = seValidateImageHeader_callback_ptr
            else:
                print("[!] Callback SSeValidateImageHeader is patched at 0x%x ***** SUSPICIOUS *****" % (seValidateImageHeader_callback_ptr))
        else:
            print("[!] Driver %s (at 0x%x) is not CI.dll for the callback SeValidateImageData ***** SUSPICIOUS *****" % (found_driver, seValidateImageData_callback_ptr))

    return


def find_PG_in_KPRCB():
    global kprcb_list
    kprcb_size_to_check = 0x2000
    if kprcb_list is None:
        find_KPRCB()
    all_check_ok = {}
    is_pg_active = 0
    for c_KPRCB in sorted(list(kprcb_list.keys())):
        print(" checking KPRCB %x" % c_KPRCB)
        dump = get_va_memory(c_KPRCB, kprcb_size_to_check)
        if dump is not None and len(dump) == kprcb_size_to_check:
            sdump = struct.unpack("Q"*(kprcb_size_to_check >> 3), dump)
            for index_field in range(len(sdump)):
                c_value = sdump[index_field]
                if (c_value & 0xffff800000000000) == 0xffff800000000000:
                    if c_value in all_check_ok:
                        continue
                    if get_qword_from_va(c_value) is not None and (get_qword_from_va(c_value) & 0xfffffffffffff0ff) != 0x13:
                        continue
                    dpc_routine = get_qword_from_va(c_value+0x18)
                    if dpc_routine is None or (dpc_routine & 0xffff800000000000) != 0xffff800000000000:
                        continue
                    rights = get_page_rights(dpc_routine)
                    if rights is not None and rights['exec']:
                        drv_path = get_driver_name_from_address(dpc_routine)
                        if drv_path is not None and drv_path.lower().endswith(b"\\ntoskrnl.exe"):
                            cpg = is_pg_in_dpc(c_value)
                            if cpg > 0:
                                print("   _KPRCB+%x (%x)" % (index_field*8, c_KPRCB + (index_field*8)))
                                is_pg_active = cpg
                        else:
                            all_check_ok[dpc_routine] = None
    return is_pg_active


def is_PG_function(cfunc):
    import lde
    global gKiInterruptThunk
    disas = lde.LDE(bitness)
    all_instr = {}
    all_instr_base = {}
    all_instr_base[cfunc] = False
    indirections = 0
    if cfunc is None:
        return 0
    datas = get_va_memory(cfunc, 0x200)
    if datas is None:
        return 0
    if b"\x2E\x48\x31\x11\x48\x31\x51\x08" in datas:
        return 2
    if gKiInterruptThunk is None:
        gKiInterruptThunk = find_KiInterruptThunk_in_ntoskrnl()
    if gKiInterruptThunk is not None:
        if cfunc >= gKiInterruptThunk and cfunc <= (gKiInterruptThunk + 0x200):
            return 2
    while False in all_instr_base.values():
        for cbase in [a for a in all_instr_base if not all_instr_base[a]]:
            indirections += 1
            if indirections > 3:
                return 0
            if not all_instr_base[cbase]:
                all_instr_base[cbase] = True
                try:
                    instr_list = disas.get_function_instructions(cbase, get_va_memory, 80)
                except Exception:
                    print("  [!] broked function %x" % (cbase))
                    continue
                for cinstr in instr_list:
                    if cinstr in all_instr:
                        continue
                    if instr_list[cinstr][0] == 3:
                        byte0, byte1, byte2 = struct.unpack("BBB", get_va_memory(cinstr, 3))
                        if byte0 in [0x48, 0x49, 0x4c, 0x4d] and byte1 in [0xd0, 0xd1, 0xd2, 0xd3] and (byte2 & 0xf0) == 0xc0:
                            return 1
                    if instr_list[cinstr][0] == 4:
                        byte0, byte1, byte2 = struct.unpack("BBB", get_va_memory(cinstr, 3))
                        if byte0 in [0x48, 0x49, 0x4c, 0x4d] and byte1 in [0xc0, 0xc1, 0xc2, 0xc3] and (byte2 & 0xf0) == 0xc0:
                            return 1
                    if len(instr_list[cinstr]) > 2 and instr_list[cinstr][1].startswith('jcc') and not (instr_list[cinstr][2] in all_instr_base):
                        all_instr_base[instr_list[cinstr][2]] = False
                all_instr.update(instr_list)

    return 0


def find_PsActiveProcessHead():
    global psActiveProcessHead
    global EPROCESS_Struct
    if not (psActiveProcessHead in [None, 0, 1, -1]):
        if EPROCESS_Struct is None or len(EPROCESS_Struct) == 0:
            detect_eprocess_struct()
        return psActiveProcessHead
    dump = get_driver_section(b"nt", b".data")
    if dump is None:
        print("  [!] .data of ntoskrnl is not accessible")
        return
    sdump = struct.unpack('Q'*(len(dump) >> 3), dump)
    for i in range(0, len(sdump)):
        sub_addr = sdump[i]
        if not is_kernel_space(sub_addr, 8):
            continue
        sub_dump = get_va_memory(sub_addr, 0x400)
        if sub_dump is not None:
            system_offset = sub_dump.find(b"System\x00\x00\x00\x00")
            if (system_offset & 0x3) == 0 and is_list_entry(sub_addr) and get_qword_from_va(sub_addr) != sub_addr and b"System\x00\x00\x00" in get_va_memory(sub_addr, 0x400):
                psActiveProcessHead = get_qword_from_va(sub_addr+8)  # BLINK
                if psActiveProcessHead is not None:
                    detect_eprocess_struct()
                    if EPROCESS_Struct is None or len(EPROCESS_Struct) == 0 or EPROCESS_Struct['Pid'] != -8:
                        psActiveProcessHead = None
                    else:
                        print("  [*] Found PsActiveProcessHead : %x" % (psActiveProcessHead))
                        return psActiveProcessHead
    return None


def detect_stack_poping_for_ret(address):
    instr_list = disas.get_function_instructions(address, get_va_memory)
    stack_add = 0
    done_instr = {}
    todo_instr = [[address, 0]]
    while len(todo_instr) > 0:
        cinstr_addr, stack_add = todo_instr.pop()
        while cinstr_addr in instr_list:
            if cinstr_addr in done_instr:
                break
            else:
                done_instr[cinstr_addr] = None
            cinstr = instr_list[cinstr_addr]
            print(" -> %x %s" % (cinstr_addr, cinstr))
            if len(cinstr) > 1:
                if cinstr[1] == 'add_rsp':
                    stack_add += cinstr[2]
                elif cinstr[1].startswith('pop'):
                    stack_add += 8
                elif cinstr[1] == 'ret':
                    print(" Ret : %x" % cinstr_addr)
                    return [stack_add, cinstr[2]]
                elif cinstr[1].startswith('jmp'):
                    if cinstr[2] in instr_list:
                        cinstr_addr = cinstr[2]
                        continue
                    else:
                        break
                elif cinstr[1].startswith('jcc'):
                    todo_instr.append([cinstr[2], stack_add])
            cinstr_addr += cinstr[0]
    return [None, None]


def cb_kthread_infos(address):
    global KTHREAD_List_Struct
    is_pg_active = 0
    if KTHREAD_List_Struct is None:
        coff = 0x40
        while coff < 0x400:
            t_InitialStack = get_qword_from_va(address-coff+0x28)
            t_StackLimit = get_qword_from_va(address-coff+0x30)
            t_KernelStack = get_qword_from_va(address-coff+0x38)
            if (t_StackLimit & 0xfff) == 0 and \
              is_kernel_space(t_InitialStack) and is_kernel_space(t_StackLimit) and is_kernel_space(t_KernelStack) and \
              (t_InitialStack & 0xfffffffffff00000) == (t_StackLimit & 0xfffffffffff00000) == (t_KernelStack & 0xfffffffffff00000) and \
              t_InitialStack != t_StackLimit != t_KernelStack:
                KTHREAD_List_Struct = {}
                KTHREAD_List_Struct['top'] = -coff
                KTHREAD_List_Struct['InitialStack'] = -coff+0x28
                KTHREAD_List_Struct['StackLimit'] = -coff+0x30
                KTHREAD_List_Struct['KernelStack'] = -coff+0x38
                if t_InitialStack < t_KernelStack:
                    next_off = 0x40
                    while next_off < 0x200:
                        tvalue = get_qword_from_va(address-coff+next_off)
                        if (tvalue & 0xfffffffffff00000) == (t_StackLimit & 0xfffffffffff00000):
                            KTHREAD_List_Struct['KernelStack'] = -coff+next_off
                            break
                        next_off += 8
                break
            coff += 8
    if KTHREAD_List_Struct is None:
        print("Can't recover KTHREAD struct :(")
        return None
    base_KTHREAD = address+KTHREAD_List_Struct['top']
    print("  KTHREAD : %x" % (base_KTHREAD))

    if not ('KAPC' in KTHREAD_List_Struct):
        coff = 0x40
        while coff < 0x400:
            t_type_size = get_qword_from_va(base_KTHREAD+coff)
            t_thread = get_qword_from_va(base_KTHREAD+coff+8)
            if (t_type_size & 0xff00000000ff0000) == 0x580000 and t_thread == base_KTHREAD:
                KTHREAD_List_Struct['KAPC'] = KTHREAD_List_Struct['top']+coff
                KTHREAD_List_Struct['KAPC.Thread'] = KTHREAD_List_Struct['top']+coff+8
                KTHREAD_List_Struct['KAPC.ApcListEntry'] = KTHREAD_List_Struct['top']+coff+0x10
                KTHREAD_List_Struct['KAPC.KernelRoutine'] = KTHREAD_List_Struct['top']+coff+0x20
                KTHREAD_List_Struct['KAPC.RundownRoutine'] = KTHREAD_List_Struct['top']+coff+0x28
                KTHREAD_List_Struct['KAPC.NormalRoutine'] = KTHREAD_List_Struct['top']+coff+0x30
                KTHREAD_List_Struct['KAPC.NormalContext'] = KTHREAD_List_Struct['top']+coff+0x38
                KTHREAD_List_Struct['KAPC.ApcStateIndex'] = KTHREAD_List_Struct['top']+coff+0x50
                break
            coff += 8

    kapc_list_entry = get_qword_from_va(address+KTHREAD_List_Struct['KAPC.ApcListEntry'])
    if kapc_list_entry is None:
        return 0
    if kapc_list_entry != 0:
        print("KAPC LIST TO ADD !!!")
        print(hex(kapc_list_entry))
        hexprint(get_va_memory(kapc_list_entry, 0x100), kapc_list_entry, 8)
    kapc_NormalRoutine = get_qword_from_va(address+KTHREAD_List_Struct['KAPC.NormalRoutine'])
    if (kapc_NormalRoutine & 0xffff000000000000) == 0xffff000000000000:
        is_pg_func = is_PG_function(kapc_NormalRoutine)
        if is_pg_func > 0:
            print("    KAPC NormalRoutine PatchGuard at %x (%s)" % (kapc_NormalRoutine, get_driver_name_from_address(kapc_NormalRoutine)))
            is_pg_active = 2
    kapc_RundownRoutine = get_qword_from_va(address+KTHREAD_List_Struct['KAPC.RundownRoutine'])
    if (kapc_RundownRoutine & 0xffff000000000000) == 0xffff000000000000:
        is_pg_func = is_PG_function(kapc_RundownRoutine)
        if is_pg_func > 0:
            print("    KAPC RundownRoutine PatchGuard at %x (%s)" % (kapc_RundownRoutine, get_driver_name_from_address(kapc_RundownRoutine)))
            is_pg_active = 2
    kapc_KernelRoutine = get_qword_from_va(address+KTHREAD_List_Struct['KAPC.KernelRoutine'])
    if (kapc_KernelRoutine & 0xffff000000000000) == 0xffff000000000000:
        is_pg_func = is_PG_function(kapc_KernelRoutine)
        if is_pg_func > 0:
            print("    KAPC KernelRoutine PatchGuard at %x (%s)" % (kapc_KernelRoutine, get_driver_name_from_address(kapc_KernelRoutine)))
            is_pg_active = 2

    kthread_stack = get_qword_from_va(address+KTHREAD_List_Struct['KernelStack'])
    current_rsp = kthread_stack+0x178  # apparently the size of some datas
    kthread_InitialStack = get_qword_from_va(base_KTHREAD+0x28)  # apparently the size of some datas
    values_checked = {}
    if kthread_InitialStack > current_rsp:
        stack_dump = get_va_memory(current_rsp, kthread_InitialStack-current_rsp)
        if stack_dump is None:
            return None
        for cvalue in struct.unpack("Q"*(len(stack_dump) >> 3), stack_dump):
            if (cvalue & 0xffff000000000000) == 0xffff000000000000 and get_qword_from_va(cvalue) is not None:
                if cvalue in values_checked:
                    continue
                else:
                    values_checked[cvalue] = None
                rights = get_page_rights(cvalue)
                if rights is not None and rights['exec']:
                    is_pg_func = is_PG_function(cvalue)
                    if is_pg_func > 0 and get_byte_from_va(cvalue-5) == 0xe8:
                        drv_name = get_driver_name_from_address(cvalue)
                        if drv_name is None:
                            drv_name = b"???"
                        print("    PatchGuard in call-stack at %x (%s) ; current stack is %x" % (cvalue, drv_name.decode(), current_rsp))
                        is_pg_active = 2
    ethread_dump = get_va_memory(address+KTHREAD_List_Struct['top'], 0x800)
    if ethread_dump is not None:
        saddress = struct.unpack("Q"*(len(ethread_dump) >> 3), ethread_dump)
        for ethread_dump_index in range(len(saddress)):
            cethread_ptr = saddress[ethread_dump_index]
            if (cethread_ptr & 0xffff00000000) == 0xffff00000000 and (cethread_ptr & 0xffffffff0000) != 0xffffffff0000:
                rights = get_page_rights(cethread_ptr)
                if rights is not None and rights['exec']:
                    is_pg_func = is_PG_function(cethread_ptr)
                    if is_pg_func > 0:
                        print("    PatchGuard ETHREAD entry at %x (%s)" % (cethread_ptr, get_driver_name_from_address(cethread_ptr)))
                        is_pg_active = 2
    return is_pg_active


def find_PG_in_System_threads():
    global EPROCESS_Struct
    find_PsActiveProcessHead()
    current_eprocess = psActiveProcessHead
    count = 0
    while count < 3 and get_va_memory(current_eprocess+EPROCESS_Struct['Name'], 0x10).split(b'\x00')[0] != b"System":
        current_eprocess = get_qword_from_va(current_eprocess)
    kthread_entry = current_eprocess+EPROCESS_Struct['ThreadListHead']
    threads_results = crawl_list(kthread_entry, cb_kthread_infos, True)
    if 2 in threads_results:
        return 2
    if 1 in threads_results:
        return 1
    return 0


def ROR64(key, nb):
    return ((key >> nb) | (key << (64-nb))) & 0xffffffffffffffff


pgCtx_host_config_2 = {
    1: 'RANDOM / KiStackProtectNotifyEvent',  # (*pKeWaitForSingleObject)(Object,Executive,'\0','\0',local_c58);
    2: 'RtlIsMultiSessionSku',
    4: 'ExReferenceCallBackBlock(MmSessionGetWin32Callouts)',
    0x8: 'RANDOM_8(?)',
    0x10: 'KiIsKernelCfgActive',
    0x40: 'KiAreCodePatchesAllowed',
    0x80: 'RANDOM_80',
    0x100: 'RANDOM_100',
    0x200: 'RANDOM_200 / Write MSR',
    0x400: 'RANDOM_400',
    0x800: 'RANDOM_800 & (pgctx_0x834 + 4) != 7 / Process && IDT',
    0x1000: 'Randomize CheckID',
    0x2000: 'KiSwInterruptPresent',
    0x8000: 'pg_new_stub_init',
    0x20000: 'RANDOM_20000',
    0x40000: 'HvlIsHypervisorPresent',
    0x100000: 'KeIsRetpolineEnabled',
}
pgCtx_host_config_1 = {
    0x80000000: 'KiSwInterruptPresent',
}
pgCtx = {
    'host_config_2': [0x994, pgCtx_host_config_2],
    'pg_lock': [0x800, None]
}


def pg_decoder_PageHashMismatch(entry_ptr):
    imageBase = get_qword_from_va(entry_ptr+0x20)
    size_of_image = get_dword_from_va(entry_ptr+0x28)
    drv_infos = get_driver_infos_from_address(imageBase)
    print("    Check %s ; Size : %x" % (drv_infos['Name'].decode(), size_of_image))


pgTypeEntry = {
    0x0: ['A generic data region', None],
    0x1: ['A function modification or the Itanium-based function location', None],
    0x2: ['A processor interrupt dispatch table (IDT)', None],
    0x3: ['A processor global descriptor table (GDT)', None],
    0x4: ['A type-1 process list corruption', None],
    0x5: ['A type-2 process list corruption', None],
    0x6: ['A debug routine modification', None],
    0x7: ['A critical MSR modification', None],
    0x8: ['Object type', None],
    0x9: ['A processor IVT', None],
    0xA: ['Modification of a system service function', None],
    0xB: ['A generic session data region', None],
    0xC: ['Modification of a session function or .pdata', None],
    0xD: ['Modification of an import table', None],
    0xE: ['Modification of a session import table', None],
    0xF: ['Ps Win32 callout modification', None],
    0x10: ['Debug switch routine modification', None],
    0x11: ['IRP allocator modification', None],
    0x12: ['Driver call dispatcher modification', None],
    0x13: ['IRP completion dispatcher modification', None],
    0x14: ['IRP deallocator modification', None],
    0x15: ['A processor control register', None],
    0x16: ['Critical floating point control register modification', None],
    0x17: ['Local APIC modification', None],
    0x18: ['Kernel notification callout modification', None],
    0x19: ['Loaded module list modification', None],
    0x1A: ['Type 3 process list corruption', None],
    0x1B: ['Type 4 process list corruption', None],
    0x1C: ['Driver object corruption', None],
    0x1D: ['Executive callback object modification', None],
    0x1E: ['Modification of module padding', None],
    0x1F: ['Modification of a protected process', None],
    0x20: ['A generic data region', None],
    0x21: ['A page hash mismatch', pg_decoder_PageHashMismatch],
    0x22: ['A session page hash mismatch', None],
    0x23: ['Load config directory modification', None],
    0x24: ['Inverted function table modification', None],
    0x25: ['Session configuration modification', None],
    0x26: ['An extended processor control register', None],
    0x27: ['Type 1 pool corruption', None],
    0x28: ['Type 2 pool corruption', None],
    0x29: ['Type 3 pool corruption', None],
    0x101: ['General pool corruption', None],
    0x102: ['Modification of win32k.sys', None]
}


def decode_pg_context(pg_context_address):
    global pgctx_base
    pg_context_datas = get_va_memory(pg_context_address, 0x1000)
    pExAcquireResourceSharedLite = resolve_symbol("nt!ExAcquireResourceSharedLite")
    if pExAcquireResourceSharedLite is not None:
        offset_start = pg_context_datas.find(b"\x2e\x48\x31\x11\x48\x31\x51\x08\x48\x31\x51\x10\x48\x31\x51\x18")
        if offset_start > 0:
            print("    - PG CmpAppendDllSection code start at +0x%x (start of PgCtx)" % (offset_start))
        else:
            print("    ! No CmpAppendDllSection found :( abort")
            return
        pgctx_base = pg_context_address+offset_start
        offset = pg_context_datas.find(struct.pack('Q', pg_context_address))
        if offset >= 0:
            print("    - PG itself pointer at +0x%x" % (offset-offset_start))
        raw_addr = struct.pack('Q', pExAcquireResourceSharedLite)[:6]
        offset = pg_context_datas.find(raw_addr)
        if offset > 0:
            print("    - PG function table start at +0x%x" % (offset))


def find_PG_Context():
    is_pg_initialized = 0
    global pPoolBigPageTable
    find_poolbigpagetable()
    if len(pPoolBigPageTable) == 0:
        return 0
    drv_addr = resolve_symbol("nt")
    decode_pe(drv_addr)
    initkdbg_size = 0
    if 'PE' in Drivers_list[drv_addr]:
        for csection in Drivers_list[drv_addr]['PE']['Sections']:
            if csection['name'] == b'INITKDBG':
                initkdbg_size = csection['virtual_size']
    if initkdbg_size == 0:
        return 0
    cpage = 0
    for cPoolBigPageTable in pPoolBigPageTable:
        dump = get_va_memory(cPoolBigPageTable, 0xff0)
        while dump is not None:
            i = 0
            while i < len(dump):
                addr_pool = struct.unpack('Q', dump[i:i+8])[0] & 0xfffffffffffffffffffffffe
                tag = dump[i+8:i+0xc]
                pooltype = struct.unpack('I', dump[i+0xc:i+0x10])[0]
                pool_size = struct.unpack('Q', dump[i+0x10:i+0x18])[0]
                if pool_size > 0x19600 and pool_size < 0x10000000:
                    chunk_dump = get_va_memory(addr_pool, 0x1000)
                    if chunk_dump is not None and b"\x2e\x48\x31\x11\x48\x31\x51\x08\x48\x31\x51\x10\x48\x31\x51\x18" in chunk_dump:
                        pg_pool_tags = [b'ObDi', b'CcBc', b'CcZe', b'Cdma', b'DPwr', b'Flvp', b'NtFW', b'AlSc', b'AfdB', b'FOCX']
                        if tag in pg_pool_tags:
                            print("  [*] PG Context found! SUR!")
                        else:
                            print("  [*] PG Context found!")
                        print("    Address: %x ; tag: %s ; Size: %x ; Type: %x" % (addr_pool, tag.decode(), pool_size, pooltype))
                        decode_pg_context(addr_pool)
                        is_pg_initialized = 1
                i += 0x18
            cpage += 0xff0
            dump = get_va_memory(cPoolBigPageTable+cpage, 0xff0)
    return is_pg_initialized


def find_PG_structs_in_ntoskrnl():
    drv_addr = resolve_symbol('nt')
    section_addr = None
    decode_pe(drv_addr)
    cestions_addr = {}
    if 'PE' in Drivers_list[drv_addr]:
        for csection in Drivers_list[drv_addr]['PE']['Sections']:
            section_addr = drv_addr+csection['virtual_address']
            cestions_addr[bytes(csection['name'])] = section_addr
    pExAcquireResourceExclusiveLite = resolve_symbol("nt!ExAcquireResourceExclusiveLite")
    pExAllocatePoolWithTag = resolve_symbol("nt!ExAllocatePoolWithTag")
    for cextion_name in [b'.data', b'ALMOSTRO']:
        section_addr = cestions_addr[cextion_name]
        dump = get_driver_section(b'nt', cextion_name)
        if dump is None:
            print("  [!] .data of ntoskrnl is not accessible")
            return
        pattern = b"\x2e\x48\x31\x11\x48\x31\x51\x08\x48\x31\x51\x10\x48\x31\x51\x18"
        if pExAllocatePoolWithTag is not None and pExAcquireResourceExclusiveLite is not None:
            sdump = struct.unpack('Q'*(len(dump) >> 3), dump)
            for i in range(0, len(sdump)):
                cqword = sdump[i]
                sub_dump = get_va_memory(cqword, 0x200)
                if sub_dump is not None:
                    sub_offset = sub_dump.find(pattern)
                    if sub_offset >= 0:
                        pg_header_addr = cqword+sub_offset
                        print(" - PatchGuard in NtOsKrnl at %x" % (section_addr+(i*8)))
                        print(" - PatchGuard header at %x" % (pg_header_addr))
                        decode_pg_context(pg_header_addr & (~0xfff))


def find_KiInterruptThunk_in_ntoskrnl():
    drv_addr = resolve_symbol('nt')
    decode_pe(drv_addr)
    if 'PE' in Drivers_list[drv_addr]:
        for csection in Drivers_list[drv_addr]['PE']['Sections']:
            if csection['name'] == b'.text':
                section_addr = drv_addr+csection['virtual_address']
                dump = get_driver_section(b"nt", b".text")
                offset = dump.find(b"\x00\x00\x33\xc0\x90\x90\x90\xe9")
                if offset > 0:
                    return section_addr+offset+2
    return None


def find_SdbpCheckDll_in_ntoskrnl():
    drv_addr = resolve_symbol('nt')
    decode_pe(drv_addr)
    pattern = b"\x8b\xd8\x8b\xf8\x8b\xe8\x4c\x8b\xd0\x4c\x8b\xd8\x4c\x8b\xe0\x4c\x8b\xe8\x4c\x8b\xf0\x4c\x8b\xf8\xff\xe6"
    if 'PE' in Drivers_list[drv_addr]:
        for csection in Drivers_list[drv_addr]['PE']['Sections']:
            if csection['name'] == b'INITKDBG':
                section_addr = drv_addr+csection['virtual_address']
                dump = get_driver_section(b"nt", b"INITKDBG")
                if dump is None:
                    return None
                offset = dump.find(pattern)
                if offset > 0:
                    return section_addr+offset-0x22
    return None


def find_pg_callback_in_mssecflt():
    drv_addr = resolve_symbol('mssecflt')
    if drv_addr is None:
        return None
    decode_pe(drv_addr)
    if 'PE' in Drivers_list[drv_addr]:
        for csection in Drivers_list[drv_addr]['PE']['Sections']:
            if csection['name'] in [b'.data', b'SecReini']:
                section_addr = drv_addr+csection['virtual_address']
                dump = get_driver_section(b"mssecflt", csection['name'])
                sdump = struct.unpack("Q"*(len(dump) >> 3), dump)
                for qword_id in range(len(sdump)):
                    caddr = sdump[qword_id]
                    if (caddr >> 48) == 0xffff:
                        name = get_driver_name_from_address(caddr)
                        if name is not None and name.endswith(b"\\ntoskrnl.exe"):
                            return [caddr, section_addr+(qword_id*8)]
    return None


def find_PG_DPC_in_ntoskrnl():
    is_pg_active = 0
    drv_addr = resolve_symbol('nt')
    decode_pe(drv_addr)
    section_addr = get_section_address(b'nt', b'.data')
    dump = get_driver_section(b"nt", b".data")
    if dump is None:
        print("  [!] .data of ntoskrnl is not accessible")
        return
    sdump = struct.unpack('Q'*(len(dump) >> 3), dump)
    for i in range(0, len(sdump)-20):
        cdpc_type = sdump[i]
        cdpc_DeferredRoutine = sdump[i+3]
        if not ((cdpc_type & 0xffffffffff0000ff) == 0x13):
            continue
        if not is_kernel_space(cdpc_DeferredRoutine):
            continue
        rights = get_page_rights(cdpc_DeferredRoutine)
        if rights is None or not rights['exec']:
            continue
        is_pg_active = is_pg_in_dpc(section_addr+(i << 3))
        if is_pg_active > 1:
            print("  [*] PG armed DPC found at 0x%x" % (section_addr+(i << 3)))
            return is_pg_active
    return is_pg_active


def find_PG_in_KTHREAD():
    global kprcb_list
    if kprcb_list is None:
        find_KPRCB()
    global kprocess_struct
    global kthread_struct
    for c_KPRCB in kprcb_list:
        print(" checking KPRCB %x" % c_KPRCB)
        currentThread = get_qword_from_va(c_KPRCB+0x8)
        nextThread = get_qword_from_va(c_KPRCB+0x10)
        idleThread = get_qword_from_va(c_KPRCB+0x18)
        if (get_qword_from_va(currentThread) & 0xffffffffff0000ff) != 6:
            print("  [!] %x not a valid KTHREAD" % (currentThread))
            continue
        print("  currentThread : %x" % (currentThread))
        print("  nextThread : %x" % (nextThread))
        print("  idleThread : %x" % (idleThread))
        if kprocess_struct is None:
            print("try to find and detect _KTHREAD struct")
            kthread_struct = {}
            dump = get_va_memory(currentThread, 0x400)
            if dump is None or len(dump) < 0x400:
                print("FAIL to read KTHREAD datas")
                continue
            sdump = struct.unpack("Q"*(0x400 >> 3), dump)
            for cindex in range(len(sdump)):
                cvalue = sdump[cindex]
                if is_list_entry(cvalue+0x18):
                    print("  ?? _KPROCESS at +%x (%x)" % (cindex*8, cvalue))
                    print("   %x (-8)" % (sdump[cindex-1]))
                    print("   %x" % (get_qword_from_va(cvalue+0x28)))
                if (cvalue & 0xffff000000000000) == 0xffff000000000000 and \
                    is_list_entry(cvalue+0x18) and \
                    isPXE(get_qword_from_va(cvalue+0x28)+0x10):  # FORCE the +0x10 to fail always
                    print("_KPROCESS at +%x" % (cindex*8))
                    continue
                if not ('ktimer_Dpc' in kthread_struct) and not ((cvalue >> 0x30) in [0, 0xffff]):  # is not canonical (DPCs are encoded)
                    decoded_value = decode_DPC_address(cvalue, currentThread+(cindex*8)-0x30)
                    if (decoded_value >> 0x30) in [0, 0xffff]:
                        kthread_struct['ktimer_list'] = (cindex*8)-0x10
                        kthread_struct['ktimer_Dpc'] = (cindex*8)
                        print("Kthread.Ktimer.Dpc +%x" % (cindex*8))
                if (cvalue & 0xffff000000000000) == 0xffff000000000000 and \
                    get_qword_from_va(cvalue) != (currentThread+(cindex*8)) and \
                    is_list_entry(cvalue) and \
                    get_qword_from_va(cvalue-(cindex*8)) == sdump[0]:
                    print("  KTHREAD LIST_ENTRY at +%x" % (cindex*8))


def find_PatchGuard():
    global pg_context_ExpOkToTimeZoneRefresh
    is_pg_active = 0
    mssec_start = None
    mssec_end = None
    for cimage in Drivers_list:
        if 'Name' in Drivers_list[cimage]:
            if Drivers_list[cimage]['Name'].lower().endswith(b'\\mssecflt.sys'):
                mssec_start = cimage
                mssec_end = cimage+Drivers_list[cimage]['Size']
    KiInterruptThunk = find_KiInterruptThunk_in_ntoskrnl()
    pSdbpCheckDll = find_SdbpCheckDll_in_ntoskrnl()
    if KiInterruptThunk is not None:
        print("KiInterruptThunk : %x" % (KiInterruptThunk))
    if pSdbpCheckDll is not None:
        print("SdbpCheckDll : %x" % (pSdbpCheckDll))
        mssecflt_infos = find_pg_callback_in_mssecflt()
        if mssecflt_infos is not None:
            mssec_cb, mssec_cb_addr = mssecflt_infos
            print("PG Mssecflt callback : %x at %x" % (mssec_cb, mssec_cb_addr))
    uniq_funcs = get_ktimers()
    for cfunc in uniq_funcs:
        if mssec_start is not None and cfunc > mssec_start and cfunc < mssec_end:
            print("MSSECFLT : %x" % (cfunc))

        is_pg_func = is_PG_function(cfunc)
        if is_pg_func == 0 and KiInterruptThunk is not None:
            if cfunc >= KiInterruptThunk and cfunc <= (KiInterruptThunk+0x200):
                is_pg_func = 0  # to bypass the check
                is_pg_active = 2
                print("DIRECT PatchGuard CALL !!!!!!!!")
        if is_pg_func > 0:
            drv_path = get_driver_name_from_address(cfunc)
            print("  Timer DPC of PG detected at %x %s" % (cfunc, drv_path.decode()))
            for context_dpc in uniq_funcs[cfunc]:
                dpc_addr = context_dpc[0]
                ccontext = context_dpc[1]
                sysarg1 = context_dpc[2]
                sysarg2 = context_dpc[3]
                if is_pg_func > 1 or not ((ccontext >> 0x30) in [0xffff, 0]):
                    is_pg_active = 2
                else:
                    is_pg_active = 1
                print("    DPC : %x ; Context : %x ; SystemArgument1 : %x ; SystemArgument2 : %x" % (dpc_addr, ccontext, sysarg1, sysarg2))
    return is_pg_active


def find_PatchGuard_routines():
    if Drivers_list is None or len(Drivers_list) == 0:
        get_drivers_list()
    nt_datas = None
    for cdrv_base in Drivers_list:
        if 'Name' in Drivers_list[cdrv_base] and Drivers_list[cdrv_base]['Name'].lower() == b'\\systemroot\\system32\\ntoskrnl.exe':
            nt_base = cdrv_base
            nt_size = Drivers_list[cdrv_base]['Size']
            list_pages_datas = []
            for cpage in range(0, (nt_size >> 12)+1):
                cpage_datas = get_va_memory(nt_base+(cpage << 12), 0x1000)
                if cpage_datas is None:
                    cpage_datas = b"\x00"*0x1000
                list_pages_datas.append(bytes(cpage_datas))
            nt_datas = b''.join(list_pages_datas)

    if nt_datas is None:
        print("  [!] Ntoskrnl not found :(")
        return

    obfu_stub = re.compile(b"\\x0d\\x91\\xb5\\x85")

    for cre_result in obfu_stub.finditer(nt_datas):
        find_offset = cre_result.start()
        func_start_1 = nt_datas.rfind(b"\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc", 0, find_offset)+8
        func_start_2 = nt_datas.rfind(b"\x90\x90\x90\x90\x90\x90\x90\x90", 0, find_offset)+8
        if func_start_1 > func_start_2:
            func_start = func_start_1
        else:
            func_start = func_start_2
        if func_start > 8:
            print(" [*] Potential PG function inside ntoskrnl: nt+%x nt+%x " % (func_start, find_offset))


def find_pfn():
    global pfnDatabase
    global cr3
    global struct_Pfn

    if pfnDatabase is not None and struct_Pfn is not None:
        return struct_Pfn

    result = {}
    for cindx in range(256):
        pfn_addr = 0xffff800000000000 | (cindx << 39)
        dump = get_va_memory(pfn_addr, 0x1000)
        if dump is None:
            continue
        sdump = struct.unpack('Q'*0x200, dump)
        print("Alloc at : %x" % (pfn_addr))
        if sdump.count(0x0020000FFFFFFFFD) > 3 or sdump.count(0x0000000000460002) > 3 or sdump.count(0x000FFFFFFFFFFFFD) > 3:
            print("PFN at : %x" % (pfn_addr))
            pfnDatabase = pfn_addr
            dump = b""
            for cpfn_page in range(8):
                cdump = get_va_memory(pfn_addr+(cpfn_page << 12), 0x1000)
                if cdump is not None:
                    dump += cdump
                else:
                    dump += b"\x00" * 0x1000
            if dump is not None:
                for index_pfn in range(int(len(dump)/0x30)):
                    c_pfn = struct.unpack("QQQQQQ", dump[index_pfn*0x30:(index_pfn+1)*0x30])
                    for coff in range(6):
                        if not ('pte_addr' in result) and ((c_pfn[coff]) & 0xffff000000000007) == 0xffff000000000000 and (get_qword_from_va(c_pfn[coff]) & 1) == 1:
                            result['pte_addr'] = coff*8
                        if (c_pfn[coff] & 0x400) == 0x400:
                            p_ori_pte = get_qword_from_va(0xffff000000000000 | (c_pfn[coff] >> 16))
                            if p_ori_pte is not None:
                                if get_pool_tag(p_ori_pte) is not None and get_pool_tag(p_ori_pte)['tag'] in [b'MmCa', b'MmCi']:
                                    result['ori_pte'] = coff*8
                                    struct_Pfn = result
                                    return result
    if pfnDatabase is not None:
        struct_Pfn = result
        return result
    for cindx in range(256):
        pfn_addr = 0xffff800000000000 | (cindx << 39)
        dump = get_va_memory(pfn_addr, 0x1000)
        if dump is None:
            continue
        sdump = struct.unpack('Q'*512, dump)
        if dump is None:
            continue
        for page_indx in range(len(sdump)):
            cval = sdump[page_indx]
            if page_indx < 6 and cval != 0:
                break
            if page_indx < 6:
                continue
            if (cval & 0xffff000000000000) == 0xffff000000000000:
                cpte = get_qword_from_va(cval)
                if cpte is None:
                    continue
                cpte_indx = ((cpte & 0xfffffff000) >> 12)
                if (page_indx/6) == (cpte_indx):
                    pfnDatabase = pfn_addr
                    pte_offset = (page_indx*8)-(cpte_indx*0x30)
                    return {'pte_addr': pte_offset}
    return None


def finditer_pattern_in_PhyMem(pattern, block_size=0x20000):
    offset_base = 0
    big_page = readFromPhys(offset_base, block_size)
    while big_page is not None:
        coffset = 0
        while coffset >= 0:
            coffset = big_page.find(pattern, coffset)
            if coffset >= 0:
                yield (offset_base+coffset)
                coffset += 1
        offset_base += block_size
        big_page = readFromPhys(offset_base, block_size)


def get_pfn_infos(pfn_index):
    global pfnDatabase
    global struct_Pfn

    if struct_Pfn == -1:
        return None
    if struct_Pfn is None or pfnDatabase in [None, 0]:
        struct_Pfn = find_pfn()
        if struct_Pfn is None or struct_Pfn == {}:
            print("No PFN found :(")
            return None
    offset_index = pfn_index*0x30
    pte = get_qword_from_va(pfnDatabase+offset_index+struct_Pfn['pte_addr'])
    if pte is None:
        return None
    is_kernel_flag = ((pte >> 55) & 1)
    if is_kernel_flag == 1:
        va_address = (((pte << 9) & 0xffffffffffffffff) | 0xffff000000000000)
    else:
        va_address = (((pte << 9) & 0xffffffffffffffff) & 0x0000ffffffffffff)
    if 'ori_pte' in struct_Pfn:
        cori_pte = get_qword_from_va(pfnDatabase+offset_index+struct_Pfn['ori_pte'])
        if cori_pte is None:
            return {'pte_addr': pte, 'is_kernel': ((pte >> 55) & 1), 'va': va_address, 'ori_pte': None}
        dest_ori_pte = get_qword_from_va(0xffff000000000000 | (cori_pte >> 16))
        if dest_ori_pte is not None:
            ori_pte = dest_ori_pte
        else:
            ori_pte = None
    else:
        ori_pte = None
    return {'pte_addr': pte, 'is_kernel': ((pte >> 55) & 1), 'va': va_address, 'ori_pte': ori_pte}


def decode_control_area(address):
    global struct_MmCa

    struct_MmCa = {}
    if get_pool_tag(address) is None or not (get_pool_tag(address)['tag'] in [b'MmCa', b'MmCi']):
        return None
    tag_size = get_pool_tag(address)['size']
    tag_size = tag_size - (tag_size % 8)
    for index in range(tag_size >> 3):
        pfileobj = get_qword_from_va(address+(index*8))
        if pfileobj is not None and pfileobj != 0 and is_kernel_space(pfileobj):
            cfile_obj = get_file_object(pfileobj & 0xfffffffffffffff0)
            if cfile_obj is not None:
                struct_MmCa['file_object'] = index*8
    return struct_MmCa


def get_control_area(address):
    global struct_MmCa
    if struct_MmCa is None:
        decode_control_area(address)
    if struct_MmCa is None:
        return None
    if get_pool_tag(address) is None and get_pool_tag(address)['tag'] in [b'MmCa', b'MmCi']:
        return None
    result = {}
    result['segment'] = get_qword_from_va(address)
    if 'file_object' in struct_MmCa:
        pfileobj = get_qword_from_va(address+struct_MmCa['file_object'])
        if pfileobj is not None and pfileobj != 0:
            result['file_object'] = get_file_object(pfileobj & 0xfffffffffffffff0)
    return result


def get_section_object_pointers(address):
    return {'DataSectionObject': get_qword_from_va(address), 'SharedCacheMap': get_qword_from_va(address+8), 'ImageSectionObject': get_qword_from_va(address+0x10)}


def get_files_from_pfn():
    find_pfn()
    blacklist = [b"\\Windows\\System32\\config\\SOFTWARE", b"\\$Directory", b"\\$Secure:$SII:$INDEX_ALLOCATION", b"\\$Mft", b"\\$LogFile", b"\\$BitMap", b"\\$ConvertToNonresident"]
    c_pfn_id = 0
    while True:
        cpfn = get_pfn_infos(c_pfn_id)
        if cpfn is None:
            c_pfn_id += 1
            continue
        if c_pfn_id >= (end_of_physmem >> 12):
            break
        ori_pte = cpfn['ori_pte']
        if ori_pte is not None and ori_pte != 0 and is_kernel_space(ori_pte):
            cpooltag = get_pool_tag(ori_pte)
            if cpooltag is not None and 'tag' in cpooltag and cpooltag['tag'] in [b'MmCa', b'MmCi']:
                carea = get_control_area(ori_pte)
                if carea is not None and 'file_object' in carea and carea['file_object'] is not None and 'FileName' in carea['file_object']:
                    if not (carea['file_object']['FileName'] in blacklist):
                        try:
                            print("%x %x %s" % (c_pfn_id, ori_pte, carea['file_object']['FileName'].decode()))
                        except Exception:
                            pass
        c_pfn_id += 1


def check_ssdt():
    keServiceDescriptorTable = resolve_symbol("nt!KeServiceDescriptorTable")
    serviceTableBase = get_dword_from_va(keServiceDescriptorTable)
    numberOfServices = get_dword_from_va(keServiceDescriptorTable+8)

    if numberOfServices > 0x400:
        return None

    datas = get_va_memory(serviceTableBase, numberOfServices*4)
    if len(datas) < (numberOfServices*4):
        return None

    for caddr in struct.unpack('I'*(numberOfServices), datas):
        drv = get_driver_name_from_address(caddr)
        if drv is not None:
            if drv == b"ntoskrnl.exe":
                print("  %X : %s" % (caddr, drv))
            else:
                print("  %X : %s HOOK" % (caddr, drv))
        else:
            print("  %X : ***Unknown***" % (caddr))


readSize = 0x4000000
totalRead = 0
percent = -1

get_va_from_offset = None
fileDmp = ""
extract_kernel = False
cr3 = None
curr_opt = 1
tool_mode = "shell"
shell_command = None


while (curr_opt < len(sys.argv)):
    if (sys.argv[curr_opt] == '-v'):
        debug = 1
    elif (sys.argv[curr_opt] == '-vv'):
        debug = 2
    elif (sys.argv[curr_opt] == '-gdb'):
        if len(sys.argv) > (curr_opt+2) and not sys.argv[curr_opt+1].startswith('-'):
            gdb_setup(sys.argv[curr_opt+1], int(sys.argv[curr_opt+2], 0))
        else:
            gdb_setup("127.0.0.1", 8864)
        is_gdb = True
    elif (sys.argv[curr_opt] == '-l'):
        load_driver()
        fileDmp = r"NoFile"
        is_live = True
    elif (sys.argv[curr_opt][:6] == '-shell') or (sys.argv[curr_opt][:7] == '--shell'):
        sshell = sys.argv[curr_opt].split('=', 1)
        if len(sshell) > 1:
            shell_command = sshell[1]
    else:
        fileDmp = sys.argv[curr_opt]
    curr_opt += 1

if dev_handle is None and not is_gdb:
    file_fd = open(fileDmp, "rb")
    rawdata = file_fd.read(0x4000)
    if rawdata[:8] in [b"PAGEDUMP", b"PAGEDU64"]:
        rawdata = readFromFile(0, 0x4000)
        set_infos_from_crashdump_header(rawdata)
    elif rawdata[:2] == b"PK":
        file_fd.close()
        set_infos_from_aff4_dump(fileDmp)
    else:
        set_infos_from_raw_dump(fileDmp)


def set_self_mapping_offset(force=False):
    global cr3
    global cr3_self_offset
    if cr3_self_offset is None or force:
        pxe_dump = readFromPhys(cr3, 0x1000)
        for i in range(0x400):
            cppe = raw_to_int(pxe_dump[(i << 3):(i << 3)+8])
            if cppe & 0x0000fffffffff000 == cr3:
                cr3_self_offset = i
                return True
    else:
        return True
    return False


def get_pte_addr_form_address(address):
    pte_offset = (address & 0x1ff000) >> 12
    pde_offset = (address & 0x3fe00000) >> 21
    ppe_offset = (address & 0x7fc0000000) >> 30
    pxe_offset = (address & 0xff8000000000) >> 39
    return (0xffff << 48) | (cr3_self_offset << 39) | (pxe_offset << 30) | (ppe_offset << 21) | (pde_offset << 12) | pte_offset << 3


def is_current_CR3_valid():
    global cr3
    global cr3_self_offset
    global force_cr3
    if is_gdb:
        return True
    if not force_cr3 and (cr3 is None or not isPXE(cr3)):
        if debug > 0:
            print("  [!] CR3 is invalid, try fo foud a new CR3")
        find_valid_cr3()
        if cr3 is None:
            print("  [!] No CR3 found :-(")
            return False
    set_self_mapping_offset()
    return True


def flush_caches():
    global cache_pages
    global cache_pages_file
    global Driver_list
    cache_pages = {}
    cache_pages_file = {}
    Driver_list = None


is_current_CR3_valid()

help_str = "  all : perform all checks\n"
help_str = "  ci : check if some drivers codes are modified (for file dump use \"offline 1\" command to download them from MS)\n"
help_str += "  fpg : Find if PatchGuard and check if it's running\n"
help_str += "  cirp : check IRP table of all drivers\n"
help_str += "  cio : check IRP table of PnP devices\n"
help_str += "  cci : check g_CiOptions state and CI DSE callbacks\n"
help_str += "  ccb : check Callback directory\n"
help_str += "  cndis : check NDIS callbacks\n"
help_str += "  cnetio : check FwpkCLNT/NetIo callbacks\n"
help_str += "  cktypes : check kernel types callbacks\n"
help_str += "  cfltmgr : check FltMgr callbacks\n"
help_str += "  ctimer : check DPC timers\n"
help_str += "  cidt : check IDT entries\n"
help_str += "  pe : check kernel memory to find hidden drivers\n"
help_str += "  drv_stack : display stacks devices to go to the driver\n"
help_str += "  filecache : Find Vacbs and crawl PFN to identify files mapped\n"
help_str += "  winobj [\\Device] : list objects\n"
help_str += "  list start end : display memory\n"
help_str += "  lm : list modules\n"
help_str += "  dump addr length: display memory\n"
help_str += "  !addr addr: get infos on the address\n"
help_str += "  dqs addr [length]: display memory with informations\n"
help_str += "  d[bdq] addr [length]: display memory\n"
help_str += "  !d[bdq] addr [length]: display physical memory\n"
help_str += "  fpool ADDR : Find pool chunck of address\n"
help_str += "  pool ADDR : Get informations on a pool chunck\n"
help_str += "  obj ADDR : Get informations on an object\n"
help_str += "  v[v0] : verbose [very/stop]\n"
help_str += "  offline [0/1] : set 1 if you are analyzing cold dump\n"
help_str += "  cr3 addr : set CR3 register\n"
help_str += "  ncr3 : find next CR3 valid value\n"
help_str += "  o2p 0x123 : file offset to phys address\n"
help_str += "  p2v 0x123 : phys address to virtual address\n"
help_str += "  o2v 0x123 : file offset to virtual address\n"
help_str += "  ? : help\n"
if 'raw_input' in dir(__builtins__):
    get_command = __builtins__.raw_input
else:
    get_command = input
try:
    get_drivers_list()
except Exception as e:
    import traceback; traceback.print_exc()
    print(e)
    pass
while True:
    try:
        if shell_command is None:
            if is_gdb:
                gdb_disconnect()
            commands = get_command("#>> ")
        else:
            commands = shell_command
            shell_command = None
    except Exception as e:
        import traceback; traceback.print_exc()
        print(e)
        sys.exit()
    if is_live:
        flush_caches()
    if is_gdb:
        gdb_connect()
    try:
        commands = ";"+commands+";"
        commands = commands.replace(';all;', ';print Check : cidt;cidt;print Check : cirp;cirp;print Check : cdev;cdev;print Check : ccb;ccb;print Check : cktypes;cktypes;print Check : cio;cio;print Check : cndis;cndis;print Check : cnetio;cnetio;print Check : cfltmgr;cfltmgr;print Check : ctimer;ctimer;print Check : fpg;fpg;print Check : ci;ci;print Check : cci;cci;print Check : pe;pe;')
        commands = commands.split(";")
        while '' in commands:
            commands.remove('')

        for command in commands:
            command = command.strip()
            if len(command) == 0:
                continue
            args = command.split(" ")
            if args[0] == "print":
                if len(args) > 1:
                    print("%s" % (' '.join(args[1:])))
            elif args[0] == "?":
                if len(args) > 1:
                    addr = resolve_symbol(args[1])
                    print("0x%x" % (addr))
                else:
                    print(help_str)
            elif args[0] == "ispg":
                if len(args) > 1:
                    addr = resolve_symbol(args[1])
                    if is_PG_function(addr) > 0:
                        print("Yes it's PG!")
                    else:
                        print("No PG here :(")
            elif args[0] == "re":
                if len(args) > 3:
                    addr = resolve_symbol(args[1])
                    length = int(args[2], 16)
                    ceregex = re.compile(args[3])
                    list_pages_datas = []
                    for cpage in range(0, (length >> 12)+1):
                        cpage_datas = get_va_memory(addr+(cpage << 12), 0x1000)
                        if cpage_datas is None:
                            cpage_datas = b"\x00"*0x1000
                        for cre_result in ceregex.finditer(cpage_datas):
                            print("  FOUND at %x (%s+%x) : %s" % (addr + (cpage << 12) + cre_result.start(), args[1], (cpage << 12) + cre_result.start(), ' '.join([("%02x" % cbyte) for cbyte in cre_result.group()])))
                        list_pages_datas.append(cpage_datas)
                else:
                    print("You must set an address, a size and a REGEX")
            elif args[0] == "dump":
                if len(args) > 2:
                    addr = resolve_symbol(args[1])
                    length = int(args[2], 16)
                    list_pages_datas = []
                    for cpage in range(0, (length >> 12)+1):
                        cpage_datas = get_va_memory(addr+(cpage << 12), 0x1000)
                        if cpage_datas is None:
                            print("page %x not mapped, replaced by \\x00" % (addr+(cpage << 12)))
                            cpage_datas = "\x00"*0x1000
                        list_pages_datas.append(cpage_datas)
                    datas = b''.join(list_pages_datas)[:length]
                    if datas is None:
                        print("Memory address is not allocated")
                    else:
                        writeFile("%016X_%016X_%X.mem" % (cr3, addr, length), datas)
                else:
                    print("You must set an address")
            elif args[0] == "dqs":
                if len(args) > 2:
                    size = int(args[2], 16)
                else:
                    size = 0x40
                if len(args) > 1:
                    base_addr = resolve_symbol(args[1])
                    offset = 0
                    while offset < size:
                        addr = get_qword_from_va(base_addr+offset)
                        drv = get_driver_name_from_address(addr)
                        comment = []
                        if drv is not None:
                            for image_base in Drivers_list:
                                if Drivers_list[image_base]["Name"] == drv:
                                    comment = ["%s+%x" % ('.'.join(drv.decode().split("\\")[-1].split('.')[:-1]), addr-image_base)]
                                    if 'PE' not in Drivers_list[image_base]:
                                        decode_pe(image_base)
                                    if 'PE' in Drivers_list[image_base] and 'Sections' in Drivers_list[image_base]['PE']:
                                        for csection in Drivers_list[image_base]['PE']['Sections']:
                                            if (image_base+csection['virtual_address']) <= addr < (image_base+csection['virtual_address']+csection['virtual_size']):
                                                comment = ["%s+%s+%x" % ('.'.join(drv.decode().split("\\")[-1].split('.')[:-1]), csection['name'].decode(), addr-(image_base+csection['virtual_address']))]
                                    if 'PE' in Drivers_list[image_base] and 'EAT' in Drivers_list[image_base]['PE']:
                                        near_eat = {'function': None, 'diff': 99999999999}
                                        for ceat_function in Drivers_list[image_base]['PE']['EAT']:
                                            ceat_func_addr = Drivers_list[image_base]['PE']['EAT'][ceat_function]
                                            if (addr-ceat_func_addr) >= 0 and near_eat['diff'] > (addr-ceat_func_addr):
                                                near_eat['diff'] = (addr-ceat_func_addr)
                                                near_eat['function'] = ceat_function
                                        if near_eat['function'] is not None:
                                            comment = ["%s+%s+%x" % ('.'.join(drv.decode().split("\\")[-1].split('.')[:-1]), near_eat['function'].decode(), near_eat['diff'])]
                        elif addr != (base_addr+offset) and addr != (base_addr+offset-8):  # prevent self LIST_ENTRY
                            chunck_addr = find_pool_chunck(addr)
                            if chunck_addr is not None and get_pool_tag(chunck_addr) is not None:
                                pool_chunk = get_pool_tag(chunck_addr)
                                if addr == chunck_addr:
                                    comment.append("Pool top Tag '%s'" % (''.join(['%c' % a if a < 0x80 else '?' for a in pool_chunk['tag']])))
                                else:
                                    comment.append("Pool start at -0x%x Tag '%s'" % (addr-chunck_addr, ''.join(['%c' % a if a < 0x80 else '?' for a in pool_chunk['tag']])))
                        if is_list_entry(addr):
                            if addr != (base_addr+offset) and addr != (base_addr+offset-8):
                                comment.append("LIST_ENTRY")
                            else:
                                comment.append("Self LIST_ENTRY")
                        if len(comment) > 0:
                            print("%x : %016x // %s" % (base_addr+offset, addr, ' ; '.join(comment)))
                        else:
                            print("%x : %016x" % (base_addr+offset, addr))
                        offset += 8
            elif args[0] == "!address" or args[0] == "!addr":
                if len(args) > 1:
                    addr = resolve_symbol(args[1])
                    drv = get_driver_name_from_address(addr)
                    if drv is not None:
                        for image_base in Drivers_list:
                            if Drivers_list[image_base]["Name"] == drv:
                                print("%x in %s" % (addr, drv.decode()))
                                print("%s+%x" % ('.'.join(drv.decode().split("\\")[-1].split('.')[:-1]), addr-image_base))
                                if 'PE' not in Drivers_list[image_base]:
                                    decode_pe(image_base)
                                if 'PE' in Drivers_list[image_base] and 'Sections' in Drivers_list[image_base]['PE']:
                                    for csection in Drivers_list[image_base]['PE']['Sections']:
                                        if (image_base+csection['virtual_address']) <= addr < (image_base+csection['virtual_address']+csection['virtual_size']):
                                            print("%s %s+%x" % ('.'.join(drv.decode().split("\\")[-1].split('.')[:-1]), csection['name'].decode(), addr-(image_base+csection['virtual_address'])))
                                if 'PE' in Drivers_list[image_base] and 'EAT' in Drivers_list[image_base]['PE']:
                                    near_eat = {'function': None, 'diff': 99999999999}
                                    for ceat_function in Drivers_list[image_base]['PE']['EAT']:
                                        ceat_func_addr = Drivers_list[image_base]['PE']['EAT'][ceat_function]
                                        if (addr-ceat_func_addr) >= 0 and near_eat['diff'] > (addr-ceat_func_addr):
                                            near_eat['diff'] = (addr-ceat_func_addr)
                                            near_eat['function'] = ceat_function
                                    if near_eat['function'] is not None:
                                        print("%s %s+%x" % ('.'.join(drv.decode().split("\\")[-1].split('.')[:-1]), near_eat['function'].decode(), near_eat['diff']))
                    else:
                        chunck_addr = find_pool_chunck(addr)
                        if chunck_addr is not None and get_pool_tag(chunck_addr) is not None:
                            pool_chunk = get_pool_tag(chunck_addr)
                            print("Pool        : %x" % (chunck_addr))
                            if 'tag_infos' in pool_chunk:
                                print("  Tag infos : %s" % (pool_chunk['tag_infos']))
                            print("  Tag       : %s" % (''.join(['%c' % a if a < 0x80 else '?' for a in pool_chunk['tag']])))
                            print("  Size      : %x" % (pool_chunk['size']))
                            if 'prev_size' in pool_chunk:
                                print("  Prev Size : %x" % (pool_chunk['prev_size']))
                        else:
                            print("%x" % (addr))
            elif args[0] == "pool":
                if len(args) > 1:
                    addr = resolve_symbol(args[1])
                    pool_chunk = get_pool_tag(addr)
                    if pool_chunk is not None:
                        if 'tag_infos' in pool_chunk:
                            print("  Tag infos : %s" % (pool_chunk['tag_infos']))
                        print("  Tag       : %s" % (pool_chunk['tag'].decode(errors='replace')))
                        print("  Size      : %x" % (pool_chunk['size']))
                        print("  Prev Size : %x" % (pool_chunk['prev_size']))
                    else:
                        print("Not a pool chunk address")
            elif args[0] == "fpool":
                if len(args) > 1:
                    addr = find_pool_chunck(resolve_symbol(args[1]))
                    if addr is None:
                        print("No pool chunck header found")
                    else:
                        pool_chunk = get_pool_tag(addr)
                        if pool_chunk is not None:
                            print("Pool        : %x" % (addr))
                            if 'tag_infos' in pool_chunk:
                                print("  Tag infos : %s" % (pool_chunk['tag_infos']))
                            print("  Tag       : %s" % (''.join(['%c' % a if a < 0x80 else '?' for a in pool_chunk['tag']])))
                            print("  Size      : %x" % (pool_chunk['size']))
                            print("  Prev Size : %x" % (pool_chunk['prev_size']))
                        else:
                            print("Not a pool chunk address")
            elif args[0] == "db":
                if len(args) > 1:
                    addr = resolve_symbol(args[1])
                    if addr is not None:
                        if len(args) == 3:
                            length = int(args[2], 16)
                        else:
                            length = 0x40
                        datas = get_va_memory(addr, length)
                        if datas is None:
                            print("Memory address is not allocated")
                        else:
                            hexprint(datas, addr)
                    else:
                        print("Can't resolve that :-(")
                else:
                    print("You must set an address")
            elif args[0] == "dd":
                if len(args) > 1:
                    addr = resolve_symbol(args[1])
                    if addr is not None:
                        if len(args) == 3:
                            length = int(args[2], 16)
                        else:
                            length = 0x40
                        datas = get_va_memory(addr, length)
                        if datas is None:
                            print(" %016X not mapped" % addr)
                        else:
                            hexprint(datas, addr, word_size=4)
                    else:
                        print("Can't resolve that :-(")
                else:
                    print("You must set an address")
            elif args[0] == "dq":
                if len(args) > 1:
                    addr = resolve_symbol(args[1])
                    if addr is not None:
                        if len(args) == 3:
                            length = int(args[2], 16)
                        else:
                            length = 0x40
                        datas = get_va_memory(addr, length)
                        if datas is None:
                            print(" %016X not mapped" % addr)
                        else:
                            hexprint(datas, addr, word_size=8)
                    else:
                        print("Can't resolve that :-(")
                else:
                    print("You must set an address")
            elif args[0][:2] == "!d":
                sizes = {'q': 8, 'd': 4, 'b': 1}
                if len(args[0]) != 3 or args[0][2] not in sizes:
                    print("Commands are !db !dd !dq")
                elif len(args) > 1:

                    addr = int(args[1], 16)
                    if len(args) == 3:
                        length = int(args[2], 16)
                    else:
                        length = 0x40
                    datas = readFromPhys(addr, length)
                    if datas is None:
                        print("Memory address is not allocated")
                    else:
                        hexprint(datas, addr, word_size=sizes[args[0][2]])
                else:
                    print("You must set an address")
            elif args[0] == "cirp":
                if len(args) > 1:
                    check_all_drivers_IRP_table(args[1])
                else:
                    check_all_drivers_IRP_table()
            elif args[0] == "cio":
                root_node = find_IopRootDeviceNode()
                get_device_node_struct(root_node)
                crawl_from_IopRootDeviceNode(root_node)
            elif args[0] == "ci":
                if len(args) > 1:
                    check_critical_drivers(args[1])
                else:
                    check_critical_drivers()
            elif args[0] == "cfltmgr":
                check_fltmgr()
            elif args[0] == "cktypes":
                check_KernelTypes()
            elif args[0] == "cnetio":
                check_netio()
            elif args[0] == "cndis":
                check_ndis()
            elif args[0] == "ctimer":
                check_ktimers()
            elif args[0] == "fpg":
                pg_checks = []
                print("Searching PatchGuard context...")
                pg_checks.append(find_PG_Context())
                print("Searching PatchGuard DPC in ntoskrnl...")
                pg_checks.append(find_PG_DPC_in_ntoskrnl())
                if not (1 in pg_checks):
                    print("Searching PatchGuard refecences in Ntoskrnl...")
                    find_PG_structs_in_ntoskrnl()
                print("Searching PatchGuard in KPRCB...")
                pg_checks.append(find_PG_in_KPRCB())
                print("Searching PatchGuard in timers...")
                pg_checks.append(find_PatchGuard())
                print("Searching PatchGuard in KTHREAD (APC + Stack)...")
                pg_checks.append(find_PG_in_System_threads())
                find_PatchGuard_routines()
                if 2 in pg_checks:
                    print(" [*] PatchGuard is running")
                elif pg_checks[0] == 1:
                    print(" [?] PatchGuard is initialized but no execution was found")
                else:
                    print(" [!] PatchGuard is NOT running")
            elif args[0] == "creg":
                check_registry_callbacks()
            elif args[0] == "ccb":
                crawl_callback_directory()
                find_all_old_Callbacks()
                check_all_old_Callbacks()
            elif args[0] == "cci":
                print("Checking CI.dll")
                g_CiOptions = identify_CiOptions()
                if g_CiOptions is not None:
                    print("&g_CiOptions = %x" % (g_CiOptions))
                    ci_state = get_byte_from_va(g_CiOptions)
                    if ci_state is not None:
                        if ci_state != 6:
                            print("[!] g_CiOptions = %x (patched) probably DSE Fix" % (ci_state))
                        else:
                            print("g_CiOptions state is OK")
                    else:
                        print("g_CiOptions is not mapped :(")
                else:
                    print("g_CiOptions not found :(")
                check_CI_checks_cb()
            elif args[0] == "flush":
                flush_caches()
            elif args[0] == "kp":

                user_mapping = get_pages_list(0, 0x00007fffffffffff)
                print("mapping done")
                for page in user_mapping:
                    mem_dmp = get_qword_from_va(page)

            elif args[0] == "u" or args[0] == "uf":
                addr = args[1]
                sym_resolve = resolve_symbol(addr)
                if args[0] == "u":
                    max_instr = 5
                else:
                    max_instr = 0x1000
                if len(args) > 2:
                    max_instr = int(args[2])
                if sym_resolve is not None:
                    import lde
                    start_address = sym_resolve
                    disas = lde.LDE(bitness)
                    instr_list = disas.get_function_instructions(sym_resolve, get_va_memory, max_instr)
                    addr_list = list(instr_list.keys())
                    addr_list.sort()
                    for instr_addr in addr_list:
                        opcodes = ''.join(['%02x' % a for a in get_va_memory(instr_addr, instr_list[instr_addr][0])])
                        opcodes += " "*(32-(len(opcodes) % 32))
                        if start_address == instr_addr:
                            first_byte = '>'
                        else:
                            first_byte = ' '
                        if len(instr_list[instr_addr]) > 2:
                            print("%s %x | %s | %s -> %x" % (first_byte, instr_addr, opcodes, instr_list[instr_addr][1], instr_list[instr_addr][2]))
                        elif len(instr_list[instr_addr]) > 1:
                            print("%s %x | %s | %s" % (first_byte, instr_addr, opcodes, instr_list[instr_addr][1]))
                        else:
                            print("%s %x | %s |" % (first_byte, instr_addr, opcodes))
                else:
                    print("%s not found" % (addr))
            elif args[0] == "x":
                addr = args[1]
                sym_resolve = resolve_symbol(addr)
                if sym_resolve is not None:
                    print("%x" % (resolve_symbol(addr)))
                else:
                    print("Can't resolve it")
            elif args[0] == "drv_stack":
                if len(args) > 1:
                    devs = get_obj_list("\\")
                    if args[1] in rootDirectoryObject_list:
                        dev_obj = rootDirectoryObject_list[args[1]]
                        drv_obj = decode_driver_object(dev_obj['Object'])
                        dev_addr = drv_obj['DeviceObject']
                        dev_obj = decode_device_object(dev_addr)
                        while dev_addr != 0:
                            dev_name = get_device_name_from_address(dev_addr)
                            print("")
                            if dev_name is not None:
                                print("- Stack of device name : %s" % (dev_name))
                            else:
                                obj_infos = get_object_infos(dev_addr)
                                if 'Name' in obj_infos:
                                    print("- Stack of device at : %x ('%s')" % (dev_addr, obj_infos['Name']))
                                else:
                                    print("- Stack of device at : %x" % (dev_addr))
                            crawl_device_object(dev_addr)
                            dev_addr = dev_obj['NextDevice']
                            dev_obj = decode_device_object(dev_addr)
                    else:
                        print("Driver not found")
                else:
                    print("usage : drv_stack \\Driver\\ACPI")
            elif args[0] == "q":
                if dev_handle is not None:
                    unload_driver()
                sys.exit()
            elif args[0] == "v0":
                debug = 0
            elif args[0] == "vv":
                debug = 2
            elif args[0] == "v":
                debug = 1
            elif args[0] == "pi":
                if len(args) > 1:
                    pid_to_use = int(args[1], 0)
                    print_process_infos_userland(get_process_informations(pid_to_use))
            elif args[0] == "ssdt":
                if bitness == 32:
                    check_ssdt()
                else:
                    print("Just available for 32b")
            elif args[0] == "filecache":
                find_crawl_vacb()
                get_files_from_pfn()
            elif args[0] == "lm":
                driver_list = get_drivers_list()
                if driver_list is None:
                    print("[!] Failed to get modules")
                    driver_list = {}
                imagebase_list = list(driver_list.keys())
                imagebase_list.sort()
                for imagebase in imagebase_list:
                    if len(args) > 1:
                        if bytes(bytearray(args[1].lower(), 'utf8')) in driver_list[imagebase]['Name'].lower():
                            print(" %16x %8x  %s" % (driver_list[imagebase]['ImageBase'], driver_list[imagebase]['Size'], driver_list[imagebase]['Name'].decode()))
                    else:
                        print(" %16x %8x  %s" % (driver_list[imagebase]['ImageBase'], driver_list[imagebase]['Size'], driver_list[imagebase]['Name'].decode()))
            elif args[0] == "pe":
                check_PE_in_kernel()
            elif args[0] == "pslist":
                if psActiveProcessHead is None or psActiveProcessHead == 0:
                    find_eprocess_system()
                    if psActiveProcessHead is not None and psActiveProcessHead != 0:
                        print("  [*] Find psActiveProcessHead : %x" % (psActiveProcessHead))
                    else:
                        print("  [!] psActiveProcessHead not found :(")
                elif EPROCESS_Struct == {}:
                    print("  [*] Try to find EPROCESS of SYSTEM and decode it")
                    find_eprocess_system()
                if EPROCESS_Struct != {} and psActiveProcessHead is not None:
                    print("  [*] EPROCESS found and is decoded")
                    get_eprocess_process_list()
                else:
                    print("  [!] Can't find the SYSTEM EPROCESS :-(")

            elif args[0] == "set":
                if len(args) > 1:
                    pid_to_use = int(args[1], 0)
                    if pid_to_use in EPROCESS_List:
                        cr3 = EPROCESS_List[pid_to_use]['CR3'] & 0xfffffffffffff000
                    else:
                        print("PID not found")
            elif args[0] == "pfn":
                if len(args) > 1:
                    pfn_index = int(args[1], 16)
                    current_pfn = get_pfn_infos(pfn_index)
                    if current_pfn is not None:
                        print("%x pfn is at pte %x (%s) VA : %x" % (pfn_index, current_pfn['pte_addr'], "kernel" if current_pfn['is_kernel'] == 1 else "user", current_pfn['va']))
                        hexprint(get_va_memory(pfnDatabase+(pfn_index*0x30), 0x30), pfnDatabase+(pfn_index*0x30), 8)
                else:
                    find_pfn()
                    print("PFN Database addresse : %x" % (pfnDatabase))
            elif args[0] == "fileobj":
                if len(args) > 1:
                    obj_addr = int(args[1], 16)
                    obj_infos = get_file_object(obj_addr)
                    if obj_infos is None:
                        print("Not a FILE_OBJECT")
                    else:
                        print("FileName     : %s" % obj_infos["FileName"])
                        print("DeviceObject : 0x%x" % obj_infos["DeviceObject"])
                        print("FsContext    : 0x%x (Scb)" % obj_infos["FsContext"])
                        print("FsContext2   : 0x%x (Ccb)" % obj_infos["FsContext2"])
                        print("Vpb          : 0x%x" % obj_infos["Vpb"])
                else:
                    print("Specify the FILE_OBJECT address")
            elif args[0] == "cdev":
                devs = get_obj_list("\\")
                if len(args) > 1:
                    if args[1].startswith("0x"):
                        addrObj = int(args[1], 0)
                        dev_obj = get_device_from_address(addrObj)
                        if dev_obj is not None:
                            print(" Device Object address : %x" % dev_obj['Object'])
                            crawl_device_object(dev_obj['Object'])
                        else:
                            print("No device found.")
                    elif "\\" in args[1]:
                        device_to_check = bytes(bytearray(args[1], 'utf8'))
                        if device_to_check in rootDirectoryObject_list:
                            dev_obj = rootDirectoryObject_list[device_to_check]
                            if dev_obj['TypeIndex'] in obj_header_types and obj_header_types[dev_obj['TypeIndex']] == 'SymbolicLink':
                                typestr = obj_header_types[dev_obj['TypeIndex']]
                                if typestr == 'SymbolicLink':
                                    sym = get_symboliclink(dev_obj['Object'])
                                    if sym is not None:
                                        sym = sym.replace(b"\x00", b'')
                                    else:
                                        sym = ""
                                    print(" SymbolicLink -> %s" % (sym))
                                    if sym in rootDirectoryObject_list:
                                        dev_obj = rootDirectoryObject_list[sym]
                                    else:
                                        print("  [!] Pointed device not found")
                                        dev_obj = None
                            if dev_obj is not None:
                                print(" Device Object address : %x" % dev_obj['Object'])
                                crawl_device_object(dev_obj['Object'])
                        else:
                            print("No device found.")
                    else:
                        crawl_device_object(int(args[1], 16))
                else:
                    check_sensitives_devices()
            elif args[0] == "cidt":
                check_idt()
            elif args[0] == "cdrv":
                devs = get_obj_list("\\")
                if len(args) > 1:
                    if args[1].startswith("0x"):
                        addrObj = int(args[1], 0)
                        drv_obj = decode_driver_object(addrObj)
                        if drv_obj is not None:
                            print(" Device Object address : %x" % dev_obj['Object'])
                            crawl_device_object(dev_obj['Object'])
                        else:
                            print("No device found.")
                    elif args[1] in rootDirectoryObject_list:
                        p_obj = rootDirectoryObject_list[args[1]]
                        drv_obj = decode_driver_object(p_obj['Object'])
                    else:
                        drv_obj = None
                    if drv_obj is None:
                        print("Driver object not found :(")
                    else:
                        print("Checking IRP table")
                        check_driver_IRP_table(drv_obj)
                        print("Checking Device Stack")
                        dev_addr = drv_obj['DeviceObject']
                        dev_obj = decode_device_object(dev_addr)
                        while dev_addr != 0:
                            dev_name = get_device_name_from_address(dev_addr)
                            print("")
                            if dev_name is not None:
                                print("- Stack of device name : %s" % (dev_name))
                            else:
                                obj_infos = get_object_infos(dev_addr)
                                if 'Name' in obj_infos:
                                    print("- Stack of device at : %x ('%s')" % (dev_addr, obj_infos['Name']))
                                else:
                                    print("- Stack of device at : %x" % (dev_addr))
                            crawl_device_object(dev_addr)
                            dev_addr = dev_obj['NextDevice']
                            dev_obj = decode_device_object(dev_addr)
            elif args[0] == "obj":
                if len(args) > 1:
                    addr = resolve_symbol(args[1])
                    obj = get_object_infos(addr)
                    print("Info mask : %x" % (obj['InfoMask']))
                    print("Index type : %x" % (obj['TypeIndex']))
                    print("Flags : %x" % (obj['Flags']))
                    if 'Name' in obj:
                        print("Name : %s" % (obj['Name']))
                else:
                    print("You must specify an address")
            elif args[0] == "winobj":
                if len(args) > 1:
                    dev_root = args[1]
                else:
                    dev_root = "\\"
                if dev_root[0] != '\\':
                    devs = get_obj_list("\\")
                    devs = rootDirectoryObject_list
                else:
                    devs = get_obj_list(dev_root)
                if len(devs) == 0 and dev_root in rootDirectoryObject_list:
                    devs[dev_root] = rootDirectoryObject_list[dev_root]
                for dev_obj in devs:
                    if dev_root[0] != '\\' and not (bytes(bytearray(dev_root, 'utf8')) in dev_obj):
                        continue
                    if devs[dev_obj]['TypeIndex'] == 3:
                        print("   <DIR>         %s" % (dev_obj))
                    elif devs[dev_obj]['TypeIndex'] in obj_header_types:
                        typestr = obj_header_types[devs[dev_obj]['TypeIndex']]
                        print(" %s%s %s  (%x)" % (typestr, ' '*(15-len(typestr)), dev_obj.decode(), devs[dev_obj]['Object']))
                        if typestr == 'SymbolicLink':
                            sym = get_symboliclink(devs[dev_obj]['Object'])
                            if sym is not None:
                                sym = sym.replace(b"\x00", b'')
                            else:
                                sym = ""
                            print("                   +-> %s" % (sym))
                    else:
                        print("                 %s  (%x)" % (dev_obj, devs[dev_obj]['Object']))
            elif args[0] == "o2p":
                addr = int(args[1], 16)
                print("Physical address : 0x%X" % (get_phys_from_file_offset(addr)))
            elif args[0] == "p2v":
                addr = int(args[1], 16)
                vaddr = get_va_from_phys(addr)
                if vaddr is not None:
                    print("Virtaul address : 0x%X" % (get_va_from_phys(addr)))
                else:
                    print("Page not mapped")
            elif args[0] == "o2v":
                oaddr = int(args[1], 16)
                paddr = get_phys_from_file_offset(oaddr)
                vaddr = get_va_from_phys(paddr)
                if vaddr is not None:
                    print("Virtual address : 0x%X" % (vaddr))
                else:
                    print("Page not mapped")
            elif args[0] == "offline":
                if len(args) > 1:
                    offline_mode = int(args[1], 16)
                else:
                    print("offline_mode : 0x%x" % offline_mode)
            elif args[0] == "ncr3":
                find_valid_cr3(cr3+0x1000)
            elif args[0] == "cr3":
                if len(args) > 1:
                    cr3 = int(args[1], 16) & 0xfffffffffffff000
                else:
                    print("CR3 : 0x%x" % cr3)
            elif args[0] == "list":
                if len(args) > 1:
                    addr = resolve_symbol(args[1])
                    if len(args) == 3:
                        end_page = resolve_symbol(args[2])
                    else:
                        end_page = addr+0x1000
                    pages = get_pages_list(addr, end_page)
                    pages_list = list(pages.keys())
                    pages_list.sort()
                    for addr_page in pages_list:
                        if (addr_page & 0x0000800000000000) != 0:
                            print("    %016X %s" % (0xFFFF000000000000 | addr_page, pages[addr_page]['right']['value']))
                        else:
                            print("    %016X %s" % (addr_page, pages[addr_page]['right']['value']))
                    if pages_list == []:
                        print("Memory address is not allocated")
                else:
                    print("You must set an address")
            else:
                print("Command not found :-(")
    except Exception as e:
        import traceback; traceback.print_exc()
        print(e)
        pass
