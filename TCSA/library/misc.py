import logging, re

# disable vivsect alert.
def set_vivisect_log_level(level):
    logging.getLogger("vivisect").setLevel(level)
    logging.getLogger("vivisect.base").setLevel(level)
    logging.getLogger("vivisect.impemu").setLevel(level)
    logging.getLogger("vtrace").setLevel(level)
    logging.getLogger("envi").setLevel(level)
    logging.getLogger("envi.codeflow").setLevel(level)


# TODO: finish the sprintf shit :(
def msvcrt_sprintf(emu, callconv, api, argv):
    fmt = emu.readMemString(argv[1]).decode()

    stackValList, stackArgvList = [], []
    for x in range(12): stackValList.append( emu.readMemoryPtr(emu.getStackCounter() + 12 + x*4) )
    
    stackValIter = iter(stackValList)
    for eachFmt in re.findall(r"\%[diouXxfFeEgGaAcSsbn$.]",fmt):
        if eachFmt[-1] == 's' or eachFmt[-1] == 'S':
            bytearrApiName = emu.readMemory(next(stackValIter), 64) # cache max 32 alphabets for wstring-like api name.
            stackArgvList.append(bytearrApiName.decode('utf-16' if eachFmt[-1] == 'S' else 'utf-8').split('\x00')[0])
        if eachFmt[-1] in 'di' or eachFmt[-1] in 'DI':
            stackArgvList.append(next(stackValIter))

    szAnser = (fmt.replace('%S', '%s') % tuple(stackArgvList)).encode() + b'\x00'  # python format string don't support "%S" instead "%s".
    emu.writeMemory(argv[0], szAnser)
    callconv.execCallReturn(emu, 0xdeadbeef, len(argv)) # return value of sprintf is useless.

MAX_DEPTH = 5
NOT_FOUND = -1
TOO_DEEP = -2
FOUND = 0
def traverse_fva_tree(vw, src_fva, dst_fva, current_depth=0):
    if current_depth > MAX_DEPTH:
        return TOO_DEEP
    for callee in vw.funcmeta[src_fva]['CallsFrom']:
        if callee == dst_fva:
            return FOUND
        if traverse_fva_tree(vw, callee, dst_fva, current_depth+1) == FOUND:
            return FOUND

    return NOT_FOUND