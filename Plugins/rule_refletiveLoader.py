'''
Determine Input Binaries have the ability to do Reflective-Loader on DLL files.

Plugin Concpet from SetupTools:
https://github.com/OctoPrint/Plugin-Examples/blob/master/helloworld/setup.py
'''
chakraCore = None

def callback(emu, starteip, op, iscall, callname, argv, argv_snapshot, ret):
    if not hasattr(callback, "gc") or callback.gc['currFunc'] != emu.funcva:
        callback.gc = { 'currFunc' : emu.funcva, 
            'ntHdrList' : list(), 'sizeOfImgList' : list(), 'impAddrDrList' : list(), 'entryAddrList' : list(), 
            'newImageAt' : 0xffffffff, 'entryRva' : 0xffffffff, 'detect' : False }
    argValues = [ emu.getOperValue(op, _) for _ in range(len(op.opers)) ]

    if op.mnem == 'cmp' and 0x4550 in argValues: # try to parse "PE" field?
        for _ in range(len(op.opers)):
            if guessNtHdrPtr := emu.getOperAddr(op, _):
                callback.gc['ntHdrList'].append(guessNtHdrPtr)  # append this guess ntHdr addr into watch list.
                callback.gc['sizeOfImgList'].append(emu.readMemoryPtr(guessNtHdrPtr + 0x50)) # append the value of ntHdr.sizeOfImg into watch list.
                callback.gc['impAddrDrList'].append(emu.readMemoryPtr(guessNtHdrPtr + 0x80)) # append the address of ntHdr.DataDir[IMPORT_DIR] into watch list.
                callback.gc['entryAddrList'].append(emu.readMemoryPtr(guessNtHdrPtr + 0x28)) # append the ntHdr.AddressOfEntry into watch list.
                print(f"[*] found NtHdr parsing on {starteip:x} - {op}")

    # pVirtualAlloc( NULL, ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );
    if iscall and len(argv) >= 4 and argv[1] in callback.gc['sizeOfImgList']:
        callback.gc['newImageAt'] = ret

    if set(argValues) & set(callback.gc['impAddrDrList']):
        callback.gc['parseIat'] = True

    if set(argValues) & set(callback.gc['entryAddrList']):
        callback.gc['parseEntry'] = True
        callback.gc['entryRva'] = ( set(argValues) & set(callback.gc['entryAddrList']) ).pop()

    if op.mnem == 'call' and callback.gc['entryRva'] + callback.gc['newImageAt'] in argValues:
        callback.gc['jmpNewImageEntry'] = True

    if not callback.gc['detect'] and callback.gc['newImageAt'] != 0xffffffff and 'parseIat' in callback.gc and 'jmpNewImageEntry' in callback.gc:
        print(f"[v] found Reflective PE Loader at {emu.funcva:x}")
        callback.gc['detect'] = True
    
# semantics-capability-automata
def initialize( In_chakraCore ):
    global chakraCore
    chakraCore = In_chakraCore
    print('[OK] Rule ReflectLoader Attached.')
    pass

def cleanup( In_chakraCore, In_capaMatchRet ):
    pass