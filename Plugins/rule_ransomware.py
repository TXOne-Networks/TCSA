'''
Determine Input Binaries Is Ransomware.

Plugin Concpet from SetupTools:
https://github.com/OctoPrint/Plugin-Examples/blob/master/helloworld/setup.py
'''
from random import getrandbits


chakraCore = None
guessList_findDataStruct, guessList_fileData_cFileName, accessMemStrList = {}, {}, {}

def isPointer(emu, num):
    try:
        return (emu.getVivTaint(num) != None) or (emu.getMemoryMap(num) != None)
    except:
        return False
        
def record_handle(_dict, fva, _key, _val):
    if _key:
        if fva in list(_dict.keys()):
            if _key in list(_dict[fva].keys()):
                if _val not in _dict[fva][_key]:
                    _dict[fva][_key].append(_val)
            else:
                _dict[fva][_key] = [_val]
        else:
            _dict[fva] = {}
            _dict[fva][_key] = [_val]

# write unique taint value for preventing the same taint value by default '\xfe\xfe\xfe\xfe'
# [TODO] we might miss handle value because vivisect's out-of-order cfg walking  
def taint_handle(emu, va, typename="ransom"):
    if emu.getMemoryMap(va) != None:
        emu.writeMemoryPtr(va, getrandbits(emu.imem_psize*8))
        return emu.readMemoryPtr(va)
    
    # taint = emu.getVivTaint(va)
    # if taint != None:
    #     MM_RWX = 0x7
    #     emu.addMemoryMap(va, perms=MM_RWX, fname='', bytez=b'\0'*0x2000, align=None)
    #     emu.writeMemoryPtr(va, getrandbits(emu.imem_psize*8))
    
    return None
    
# Cryptographic Provider Type
PROV_RSA_AES = 0x00000018
PROV_RSA_FULL = 0x01

# Algid
# ref: https://github.com/tpn/winsdk-7/blob/master/v7.1A/Include/WinCrypt.h
## Algorithm types
ALG_TYPE_ANY        = (0)
ALG_TYPE_RSA        = (2 << 9)
ALG_TYPE_BLOCK      = (3 << 9)
ALG_TYPE_STREAM     = (4 << 9)

## Algorithm classes
ALG_CLASS_ANY           = (0)
ALG_CLASS_MSG_ENCRYPT   = (2 << 13)
ALG_CLASS_DATA_ENCRYPT  = (3 << 13)


## Block cipher sub ids
ALG_SID_DES                    = 1
ALG_SID_3DES                   = 3
ALG_SID_DESX                   = 4
ALG_SID_IDEA                   = 5
ALG_SID_CAST                   = 6
ALG_SID_SAFERSK64              = 7
ALG_SID_SAFERSK128             = 8
ALG_SID_3DES_112               = 9
ALG_SID_CYLINK_MEK             = 12
ALG_SID_RC5                    = 13
ALG_SID_AES_128                = 14
ALG_SID_AES_192                = 15
ALG_SID_AES_256                = 16
ALG_SID_AES                    = 17

CALG_AES     = 0x6611
CALG_AES_128 = 0x660E
CALG_AES_192 = 0x660F
CALG_AES_256 = 0x6610

# dwShareMode / ShareAccess
FILE_SHARE_LOCK   = 0x00000000
FILE_SHARE_DELETE = 0x00000004
FILE_SHARE_READ   = 0x00000001
FILE_SHARE_WRITE  = 0x00000002

# DesiredAccess
GENERIC_WRITE = 0x40000000
GENERIC_READ  = 0x80000000
GENERIC_ALL   = 0x10000000

# dwCreationDisposition
TRUNCATE_EXISTING   = 0x00000005
OPEN_ALWAYS         = 0x00000004
OPEN_EXISTING       = 0x00000003
CREATE_ALWAYS       = 0x00000002
CREATE_NEW          = 0x00000001


# dwFlagsAndAttributes
FILE_FLAG_WRITE_THROUGH        = 0x80000000
FILE_FLAG_OVERLAPPED           = 0x40000000
FILE_FLAG_NO_BUFFERING         = 0x20000000
FILE_FLAG_RANDOM_ACCESS        = 0x10000000
FILE_FLAG_SEQUENTIAL_SCAN      = 0x08000000
FILE_FLAG_DELETE_ON_CLOSE      = 0x04000000
FILE_FLAG_BACKUP_SEMANTICS     = 0x02000000
FILE_FLAG_POSIX_SEMANTICS      = 0x01000000
FILE_FLAG_SESSION_AWARE        = 0x00800000
FILE_FLAG_OPEN_REPARSE_POINT   = 0x00200000
FILE_FLAG_OPEN_NO_RECALL       = 0x00100000
FILE_FLAG_FIRST_PIPE_INSTANCE  = 0x00080000
FILE_FLAG_ALL = FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED | FILE_FLAG_NO_BUFFERING | FILE_FLAG_RANDOM_ACCESS | FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_DELETE_ON_CLOSE | FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_POSIX_SEMANTICS | FILE_FLAG_SESSION_AWARE | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OPEN_NO_RECALL | FILE_FLAG_FIRST_PIPE_INSTANCE

FILE_ATTRIBUTE_READONLY             = 0x00000001 
FILE_ATTRIBUTE_HIDDEN               = 0x00000002 
FILE_ATTRIBUTE_SYSTEM               = 0x00000004 
FILE_ATTRIBUTE_DIRECTORY            = 0x00000010 
FILE_ATTRIBUTE_ARCHIVE              = 0x00000020 
FILE_ATTRIBUTE_DEVICE               = 0x00000040 
FILE_ATTRIBUTE_NORMAL               = 0x00000080 
FILE_ATTRIBUTE_TEMPORARY            = 0x00000100 
FILE_ATTRIBUTE_SPARSE_FILE          = 0x00000200 
FILE_ATTRIBUTE_REPARSE_POINT        = 0x00000400 
FILE_ATTRIBUTE_COMPRESSED           = 0x00000800 
FILE_ATTRIBUTE_OFFLINE              = 0x00001000 
FILE_ATTRIBUTE_NOT_CONTENT_INDEXED  = 0x00002000 
FILE_ATTRIBUTE_ENCRYPTED            = 0x00004000 
FILE_ATTRIBUTE_INTEGRITY_STREAM     = 0x00008000 
FILE_ATTRIBUTE_VIRTUAL              = 0x00010000 
FILE_ATTRIBUTE_NO_SCRUB_DATA        = 0x00020000 
FILE_ATTRIBUTE_EA                   = 0x00040000 
FILE_ATTRIBUTE_PINNED               = 0x00080000 
FILE_ATTRIBUTE_UNPINNED             = 0x00100000 
FILE_ATTRIBUTE_RECALL_ON_OPEN       = 0x00040000 
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS= 0x00400000
FILE_ATTRIBUTE_ALL = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_DEVICE | FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_SPARSE_FILE | FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | FILE_ATTRIBUTE_ENCRYPTED | FILE_ATTRIBUTE_INTEGRITY_STREAM | FILE_ATTRIBUTE_VIRTUAL | FILE_ATTRIBUTE_NO_SCRUB_DATA | FILE_ATTRIBUTE_PINNED | FILE_ATTRIBUTE_UNPINNED | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS

fva_collection = {
    'file_encrypt':[],
    'file_op':[],
    'file_enum':[]
}

file_handle_candidate = {}
file_handle_list = {}

crypt_prov_candidate = {}
crypt_prov_list = {}

crypt_key_candidate = {}
crypt_key_list = {}

enum_fva_list = {}
file_fva_list = {}
enc_fva_list = {}


def callback(emu, starteip, op, iscall, callname, argv, argv_snapshot, ret):

    if emu.funcva not in guessList_findDataStruct:
        guessList_findDataStruct[emu.funcva], guessList_fileData_cFileName[emu.funcva] = [], []

    if len(op.opers) > 1 and len(guessList_fileData_cFileName[emu.funcva]) > 0:
        if emu.getOperAddr(op, 1)  in guessList_fileData_cFileName[emu.funcva] or \
        emu.getOperValue(op, 1) in guessList_fileData_cFileName[emu.funcva]:
            print(f'[+] fva: {hex(emu.funcva)}, Taint FileData.cFileName: {hex(starteip)}')
            enum_fva_list[emu.funcva] = 1
    '''
    if iscall:
        print(f"{hex(starteip)} - {op}{tuple([e[1] for e in argv_snapshot])}")
    else:
        print(f"{hex(starteip)} - {op}")
    '''
    
    # try to scan accessed pointer, that contains ".txt", ".pdf", ".docx" or not. 
    # only enable this scan after found FindFirstFile() 
    if len(guessList_findDataStruct[emu.funcva]) > 0:
        for opIndx in range(len(op.opers)):
            val = emu.getOperValue(op, opIndx)  
            if isPointer(emu, val):
                membuf = emu.readMemory(val, 10).lower()
                if not emu.funcva in accessMemStrList: accessMemStrList[emu.funcva] = ""
                if (b't\x00x\x00t' in membuf) or (b'txt' in membuf):
                    accessMemStrList[emu.funcva] += "T"
                if (b'd\x00o\x00c' in membuf) or (b'doc' in membuf):
                    accessMemStrList[emu.funcva] += "D"
                if (b'j\x00p\x00g' in membuf) or (b'jpg' in membuf):
                    accessMemStrList[emu.funcva] += "J"
    if iscall:
        arg1, arg2, arg3 = argv_snapshot[0][1], argv_snapshot[1][1], argv_snapshot[2][1]
        # FindFirstFileW, FindNextFileW, FindFirstFileExW, NtQueryDirectoryFile, zwQueryDirectoryFile
        # case FindNextFile
        #FindNextFileA( hFindFile, lpFindFileData );
        if ("FindNextFileA" in callname) or ("FindNextFileW" in callname) or \
        ((len(argv) >= 2) and ((arg1, arg2) in guessList_findDataStruct[emu.funcva]) and isPointer(emu, arg2)):
            guessList_fileData_cFileName[emu.funcva].append(arg2 + 0x2C) # 32b - offset of FindFileData.cFileName

        # case FindFirstFile    
        # HANDLE FindFirstFileA( pFileName, lpFindFileData );
        if ("FindFirstFileA" in callname) or ("FindFirstFileW" in callname) or \
        ((len(argv) >= 2) and (isPointer(emu, arg2) or (arg2 == 0))):
            guessList_findDataStruct[emu.funcva].append(( ret, arg2 ))


        # case FindFirstFileEx  
        # HANDLE FindFirstFileExA( pFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags );
        if ("FindFirstFileExA" in callname) or ("FindFirstFileExW" in callname) or \
        ((len(argv) >= 6) and (isPointer(emu, arg3) or (arg3 == 0))):
            guessList_findDataStruct[emu.funcva].append(( ret, arg3 ))

        # case NtQueryDirectoryFile

        # case CreateFile
        if ("CreateFileA" in callname) or ("CreateFileW" in callname) or \
        ((len(argv) >= 7) and \
        not isPointer(emu, argv[1]) and (argv[1] & 0xFFFFFFFF & (GENERIC_READ | GENERIC_WRITE | GENERIC_ALL)) and \
        not isPointer(emu, argv[2]) and (argv[2] == 0 or argv[2] & 0xFFFFFFFF & (FILE_SHARE_LOCK | FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)) and \
        not isPointer(emu, argv[4]) and (argv[4] & 0xFFFFFFFF in (CREATE_ALWAYS, OPEN_EXISTING, CREATE_NEW, OPEN_ALWAYS)) and \
        not isPointer(emu, argv[5])):
            
            record_handle(file_handle_list, emu.funcva, ret, starteip)
            record_handle(file_handle_candidate, emu.funcva, ret, starteip)
                        
        
        # case SetFilePointer(Ex)
        if ("SetFilePointer" in callname) or \
        ((len(argv) >= 4) and argv[3] == 0): # FILE_BEGIN
            record_handle(file_handle_candidate, emu.funcva, argv[0], starteip)

        # GetFileSize
        # GetFileSizeEx
        if ("GetFileSizeEx" == callname) or \
        ((len(argv) >= 2) and isPointer(emu, argv[1])): # FILE_BEGIN
            record_handle(file_handle_candidate, emu.funcva, argv[0], starteip)
        
        if ("GetFileSize" == callname) or \
        ((len(argv) >= 1)): # FILE_BEGIN
            record_handle(file_handle_candidate, emu.funcva, argv[0], starteip)



        # case ReadFile(Ex)
        # case WriteFile(Ex)
        if ("ReadFile" in callname) or ("WriteFile" in callname) or \
        ((len(argv) >= 5) and isPointer(emu, argv[1])):
            record_handle(file_handle_candidate, emu.funcva, argv[0], starteip)

 



        # case NtCreateFile
        if ("NtCreateFile" in callname) or \
        ((len(argv) >= 11) and \
        not isPointer(emu, argv[1]) and (argv[1] & 0xFFFFFFFF & (GENERIC_READ | GENERIC_WRITE | GENERIC_ALL | 0x10000)) and \
        not isPointer(emu, argv[6]) and ((argv[6] == 0) or (argv[6] & 0xFFFFFFFF & (FILE_SHARE_LOCK | FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE))) and \
        not isPointer(emu, argv[7]) and (argv[7] & 0xFFFFFFFF in (CREATE_ALWAYS, OPEN_EXISTING, CREATE_NEW, OPEN_ALWAYS))):
            record_handle(file_handle_list, emu.funcva, argv[0], starteip)
            record_handle(file_handle_candidate, emu.funcva, argv[0], starteip)
             


        # case NtReadFile
        # case NtWriteFile
        if ("NtReadFile" in callname) or ("NtWriteFile" in callname) or \
        ((len(argv) >= 9) and isPointer(emu, argv[0]) and isPointer(emu, argv[5])):
            record_handle(file_handle_candidate, emu.funcva, argv[0], starteip)

        # [CASE STUDY]:
        #   NtQueryDirectory

        # [CASE STUDY]: 
        #   Nt* File ops
        #       NtCreateFile
        #       NtReadFile
        #       NtWriteFile

        # [CASE STUDY]: 
        #   msvcrt file ops:
        #       fopen
        #       fread
        #       fwrite

        # [CASE STUDY]: 7b1bce1838a6d93e2777e44991c4edffc86e755b7a3475b84f22775bd2a50a0a
        #   File Mapping
        #       a = CreateFile (,,,,,,)
        #       b = CreateFileMapping (a,,,,,)
        #       MapViewOfFile (b,,,,)
            
        # [CASE STUDY]: 0dc0da0739b227a9dae83be93d1b232c645dbffc7499709ae05c4ffa1bf44000
        #   MultiThread pass (global) overlapped struct by IoCompletionPort 
        #     Func A 
        #       NtCreateIoCompletion (a, , ,)
        #       NtCreateFile (b, , , , , , , )
        #       NtSetInformationFile (b, , a, , )
        #     Func B 
        #       NtCreateIoCompletion (a, , , )
        #       NtRemoveIoCompletion (a, , , , )
        #       NtReadFile (b, , , , , , , , )
        #       Encryption
        #       NtWriteFile (b, , , , , , , , )

        # [CASE STUDY]: 7b1bce1838a6d93e2777e44991c4edffc86e755b7a3475b84f22775bd2a50a0a
        #   Crypt APIs Scenario
        #       CryptAcquireContext (&a, , L"Microsoft Enhanced RSA and AES Cryptographic Provider", PROV_RSA_FULL,)
        #       CryptGenKey (a, Algid, , c) / CryptDeriveKey (a, Algid, , , c) / CryptImportKey (a, , , , , c)
        #       CryptEncrypt (c, , , , , , )


        # CryptAcquireContext
        if ("CryptAcquireContext" in callname) or \
        ((len(argv) >= 5) and isPointer(emu, argv[0]) and \
        (isPointer(emu, argv[1]) or argv[1] == 0) and (isPointer(emu, argv[2]) or argv[2] == 0) and \
        (argv[3] in (PROV_RSA_AES ,PROV_RSA_FULL)) and not isPointer(emu, argv[3]) and not isPointer(emu, argv[4])):
            crypt_prov_val = taint_handle(emu, argv[0])
            record_handle(crypt_prov_list, emu.funcva, crypt_prov_val, starteip)
            record_handle(crypt_prov_candidate, emu.funcva, crypt_prov_val, starteip)
            

        # CryptGenKey
        if ("CryptGenKey" in callname) or \
        ((len(argv) >= 4) and not isPointer(emu, argv[0]) and not isPointer(emu, argv[1]) and not isPointer(emu, argv[2]) and \
        isPointer(emu, argv[3])):
            record_handle(crypt_prov_candidate, emu.funcva, argv[0], starteip)
            
            crypt_key_val = taint_handle(emu, argv[3])
            record_handle(crypt_key_list, emu.funcva, crypt_key_val, starteip)
            record_handle(crypt_key_candidate, emu.funcva, crypt_key_val, starteip)

        # CryptDeriveKey
        if ("CryptDeriveKey" in callname) or \
        ((len(argv) >= 5) and not isPointer(emu, argv[0]) and not isPointer(emu, argv[1]) and not isPointer(emu, argv[2]) and \
        not isPointer(emu, argv[3]) and isPointer(emu, argv[4])):
            record_handle(crypt_prov_candidate, emu.funcva, argv[0], starteip)

            crypt_key_val = taint_handle(emu, argv[4])
            record_handle(crypt_key_list, emu.funcva, crypt_key_val, starteip)
            record_handle(crypt_key_candidate, emu.funcva, crypt_key_val, starteip)
            
        # CryptImportKey
        if ("CryptImportKey" in callname) or \
        ((len(argv) >= 6) and not isPointer(emu, argv[0]) and isPointer(emu, argv[1]) and not isPointer(emu, argv[2]) and \
        not isPointer(emu, argv[3]) and not isPointer(emu, argv[4]) and isPointer(emu, argv[5])):
            record_handle(crypt_prov_candidate, emu.funcva, argv[0], starteip)

            crypt_key_val = taint_handle(emu, argv[5])
            record_handle(crypt_key_list, emu.funcva, crypt_key_val, starteip)
            record_handle(crypt_key_candidate, emu.funcva, crypt_key_val, starteip)

        # CryptEncrypt
        if ("CryptEncrypt" in callname) or \
        ((len(argv) >= 7) and not isPointer(emu, argv[0]) and not isPointer(emu, argv[1]) and not isPointer(emu, argv[2]) and \
        not isPointer(emu, argv[3]) and isPointer(emu, argv[4]) and isPointer(emu, argv[5]) and not isPointer(emu, argv[6])):
            record_handle(crypt_key_candidate, emu.funcva, argv[0], starteip)
        # CryptDecrypt

        # if starteip in [0x4d68a5, 0x4d694c]:
        #     print(hex(starteip), argv, ret)
        #     crypt_key_val = emu.readMemoryPtr(ret)
        #     print(crypt_key_val)

        # if starteip == 0x4d6a05:
        #     print(hex(starteip), argv, ret)
        #     crypt_key_val = emu.readMemoryPtr(argv[0])
        #     print(crypt_key_val)

        # if starteip in [0x40de43, 0x40d72e]:
        #     print(hex(starteip), argv, ret)
        #     print(emu.readMemory(ret, 4))
        #     # crypt_key_val = taint_handle(emu, ret)
        #     va, typename, taint = emu.taints[ret & emu.taintmask] 
        #     op, taint_bytes, conv, other = taint
        #     taint = (op, getrandbits(emu.imem_psize*8), conv, other )
        #     emu.taints[ret & emu.taintmask] = (va, typename, taint)
        #     # print(crypt_key_val)
        #     print(emu.readMemory(ret, 4))
        #     print(emu.getVivTaint(ret))
        #     # print(emu.getRegisters())

        # if starteip == 0x40e7e1:
        #     print(hex(starteip), argv, ret)
        #     print(emu.readMemory(argv[0], 4))

            
        #     print(emu.getRegisters())
        #     # crypt_key_val = emu.getVivTaint(int(input("va:")))
        #     # print(crypt_key_val)

            

MAX_DEPTH = 5
NOT_FOUND = -1
TOO_DEEP = -2
FOUND = 0
fvas = []
def traverse_fva_tree(vw, parent_fva, child_fva, current_depth=0):
    global fvas
    if current_depth == 0:
        fvas = []
    fvas.append(hex(parent_fva))
    if current_depth > MAX_DEPTH:
        fvas.pop(-1)
        return TOO_DEEP
    if parent_fva == child_fva:
        return current_depth
    for callee_fva in vw.funcmeta[parent_fva]['CallsFrom']:
        if callee_fva == parent_fva:
            continue
        # if callee == child_fva:
        #     fvas.append(hex(child_fva))
        #     return current_depth
        depth = traverse_fva_tree(vw, callee_fva, child_fva, current_depth+1)
        if depth >= 0:
            return depth

    fvas.pop(-1)
    return NOT_FOUND

# semantics-capability-automata
def initialize( In_chakraCore ):
    global chakraCore
    chakraCore = In_chakraCore
    print('[OK] Rule Ransomware Attached.')
    pass

def cleanup( In_chakraCore, In_capaMatchRet ):

    from Subsystem.miniCapa.main import print_result
    capa_fva_list = print_result(In_capaMatchRet) # for parsing log
    enc_fva_list = capa_fva_list["encrypts"]
    file_fva_list = capa_fva_list["file_ops"]
    
    for fva in list(file_handle_list.keys()):
        for handle in list(file_handle_list[fva].keys()):
            CreateFile_addr = [hex(h1) for h1 in file_handle_list[fva][handle]]
            Taint_handle = [hex(h2) for h2 in file_handle_candidate[fva][handle]]
            if len(Taint_handle) > 1:
                print(f"[+] fva: {hex(fva)}, CreateFile addr: {CreateFile_addr}, Taint Handle: {Taint_handle}")
                file_fva_list[fva] = 1

    for fva in list(crypt_prov_list.keys()):
        for handle in list(crypt_prov_list[fva].keys()):
            CryptAcquireContext_addr = [hex(h1) for h1 in crypt_prov_list[fva][handle]]
            Taint_handle = [hex(h2) for h2 in crypt_prov_candidate[fva][handle]]
            if len(Taint_handle) > 1:
                print(f"[+] fva: {hex(fva)}, CryptAcquireContext addr: {CryptAcquireContext_addr}, Taint Handle: {Taint_handle}")


                if fva in list(crypt_key_list.keys()):
                    for handle in list(crypt_key_list[fva].keys()):
                        Crypt_Key_addr = [hex(h1) for h1 in crypt_key_list[fva][handle]]
                        Taint_handle = [hex(h2) for h2 in crypt_key_candidate[fva][handle]]
                        if len(Taint_handle) > 1:
                            print(f"[+] fva: {hex(fva)}, Crypt*Key addr: {Crypt_Key_addr}, Taint Handle: {Taint_handle}")
                            enc_fva_list[fva] = 1
            
    # print(crypt_key_candidate)
    # print(crypt_key_list)

    for funva in accessMemStrList:
        if 'J' in accessMemStrList[funva] and 'T' in accessMemStrList[funva] and 'D' in accessMemStrList[funva]:
            print(f"[+] sub_{funva:x} - try to enumerate local files.")




    print("========== function topology ==========")
    # [TODO] function v.s basic block in CAPA
    global fvas

    for src_fva in file_fva_list.keys():
        for dst_fva in enc_fva_list.keys():
            fvas = []
            depth = traverse_fva_tree(In_chakraCore.vw, src_fva, dst_fva)
            if depth >= 0:
                print(f"[file->encrypt] depth: {depth}, chain: {fvas}")


    for src_fva in enum_fva_list.keys():
        for dst_fva in enc_fva_list.keys():
            fvas = []
            depth = traverse_fva_tree(In_chakraCore.vw, src_fva, dst_fva)
            if depth >= 0:
                print(f"[enum->encrypt] depth: {depth}, chain: {fvas}")
