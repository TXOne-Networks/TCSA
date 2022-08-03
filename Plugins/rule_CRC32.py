'''
Determine Input Binaries have the ability to calculate CRC32.

Plugin Concpet from SetupTools:
https://github.com/OctoPrint/Plugin-Examples/blob/master/helloworld/setup.py
'''
chakraCore = None

def callback(emu, starteip, op, iscall, callname, argv, argv_snapshot, ret):

    if not hasattr(callback, "gc") or callback.gc['currFunc'] != emu.funcva:
        callback.gc = { 'currFunc' : emu.funcva, 'magic' : False, 'loop8' : False, 'xor' : False, 'detect' : False }

    if iscall and 'RtlComputeCrc32' in callname:
        print('[v] found CRC32 at sub_%x() - by ntdll!RtlComputeCrc32' % callback.gc['currFunc'])
        callback.gc['detect'] = True

    argValues = [ emu.getOperValue(op, _) for _ in range(len(op.opers)) ]

    if 0xedb88320 in argValues:
        callback.gc['magic'] = True
    
    if 8 in argValues:
        callback.gc['loop8'] = True

    if 'xor' in op.mnem:    
        callback.gc['xor'] = True
    
    if callback.gc['magic'] and callback.gc['loop8'] and callback.gc['xor'] and not callback.gc['detect']:
        print('[v] found CRC32 at sub_%x() - by binary features' % callback.gc['currFunc'])
        callback.gc['detect'] = True
    pass

# semantics-capability-automata
def initialize( In_chakraCore ):
    global chakraCore
    chakraCore = In_chakraCore
    print('[OK] Rule CRC32 Attached.')
    pass

def cleanup( In_chakraCore, In_capaMatchRet ):
    pass