import viv_utils, vivisect, sys, os, logging, importlib
from library.misc import set_vivisect_log_level, msvcrt_sprintf
from  DefUseCore import collect_reachDefinition, getFuncRetVal_Symbol
from vivisect.impemu.emulator import WorkspaceEmulator, envi, vg_path, v_exc, e_exc
import importlib.util
from Subsystem import *

SAMPLE_CPP_HOLLOWING = 'samples/1c64966bdcbc55db0256a1aa3fc99062ba1837849b1cc5aa59ce0e31bf279e09_unupx' # [MINGW]  Process Hollowing
SAMPLE_CPP_DECODESTR = 'samples/decodePrint.exe'
SAMPLE_CPP_PIKA_HOLLOWING = 'samples/pikaProcHollowing.exe'                                             # [MSVCRT] Process Hollowing
SAMPLE_CPP_HELLO_RECURSIV = 'samples/hello_recur.exe'

class taintEmulator(WorkspaceEmulator):
    def __init__(self, vw, **kwargs):
        self.emu = vw.getEmulator()

        # record where's current register value from
        self.defuseList = {}
        '''
            defuseList[ where2write, dataVal ] = ( dataRef, refType: "DATA_REF"|"CALL_RET"|"INIT_VAL"|"FORK_REF", refCode )
            Examples:
                0x4010a0 - mov ecx, [0xdeadbeef] -> ('ecx', dataVal)     : (           0xdeadbeef,  "DATA_REF", 0x4010a0 )
                0x40134a - call WriteFileA       -> ('eax', dataVal)     : (         "WriteFileA",  "CALL_RET", 0x40134a )
                0x401702 - mov [0xea7cafe],rcx   -> (0xea7cafe, dataVal) : (                'rcx',  "INIT_VAL", 0x401702 )
                0x401350 - lea rdx, [rax+256]    -> ('rdx', dataVal)     : ( ( "rax", $rax, 256 ),  "FORK_REF", 0x401350 )
        '''


        self.funcArgv_defuseList = [] # [ (callee_fva, funcNickName, caller_fva, retAddr, {}) ]
        self.emu.hooks['msvcrt.sprintf'] = msvcrt_sprintf


    '''
    def parseCallArgs_fromCurrState(self, endeip):

        # leak invoked call's arguments.
        rtype, rname, convname, callname, funcargs = self.emu.getCallApi(endeip)
        callname = f"sub_{endeip:x}" if callname == None else callname
        callconv = self.emu.getCallingConvention(convname)

        if len(funcargs) < 1 and ('sub_' in callname or callname == 'UnknownApi'):
            argv = callconv.getCallArgs(self.emu, 12) # dump max 12 stack values.
        else:
            argv = callconv.getCallArgs(self.emu, len(funcargs))  # normal fetch argument info.

        argv_snapshot = []
        if iscall:
            sp = self.emu.getStackCounter()
            sp += callconv.pad + callconv.align # add align for skipping retAddr.

            argc = 12 # dump max 12 stack values.
            for arg_type, arg_val in callconv.arg_def:
                if argc < 1 : break 
                if arg_type == vivisect.envi.CC_REG:
                    regName = self.emu.getRealRegisterNameByIdx(arg_val)
                    argv_snapshot.append( (regName, self.emu.getRegister(arg_val)) )
                    argc -= 1
                elif arg_type == vivisect.envi.CC_STACK:
                    argv_snapshot.append( (sp, self.emu.readMemoryFormat(sp, '<P')[0]) )
                    argc -= 1
                    sp += callconv.align
                elif arg_type == vivisect.envi.CC_STACK_INF:
                    for _ in range(argc):
                        argv_snapshot.append( (sp, self.emu.readMemoryFormat(sp, '<P')[0]) )
                        sp += callconv.align
                        argc -= 1

                    if argc != 0:
                        raise Exception('wrong num of args from readMemoryFormat')
                else:
                    raise Exception('unknown argument type')

        # simulate the call.
        self.emu.checkCall(starteip, endeip, op)
        ret = callconv.getReturnValue(self.emu)
        '''
        
    # rewrite from vivisect.impemu.emulator.runFunction.
    def funcTinyRunner(self, funcva, callbackToRun, _currDepth = 0, _givenSnap = None):
        if _givenSnap: self.emu.setEmuSnap(_givenSnap)
        self.emu.funcva = funcva
        if _currDepth > 3: return
        # Let the current (should be base also) path know where we are starting
        vg_path.setNodeProp(self.emu.curpath, 'bva', funcva)
        hits = {}
        modifyState = False
        todo = [(funcva, self.emu.getEmuSnap(), self.emu.path)]
        vw = self.emu.vw  # Save a dereference many many times

        while len(todo):

            va, esnap, self.emu.curpath = todo.pop()
            self.emu.setEmuSnap(esnap)
            self.emu.setProgramCounter(va)

            while True:
                starteip = self.emu.getProgramCounter()
                if not vw.isValidPointer(starteip): break

                # maxhit = 1
                if starteip in hits: break
                hits[starteip] = 1

                # If we ran out of path (branches that went
                # somewhere that we couldn't follow)?
                if self.emu.curpath is None: break
                try:
                    op = self.emu.parseOpcode(starteip)
                    iscall = bool(op.iflags & envi.IF_CALL)
                    self.emu.op = op

                    self.emu.executeOpcode(op)
                    vg_path.getNodeProp(self.emu.curpath, 'valist').append(starteip)
                    endeip = self.emu.getProgramCounter()

                    # leak invoked call's arguments.
                    rtype, rname, convname, callname, funcargs = self.emu.getCallApi(endeip)
                    callname = f"sub_{endeip:x}" if callname == None else callname
                    callconv = self.emu.getCallingConvention(convname)

                    if len(funcargs) < 1 and ('sub_' in callname or callname == 'UnknownApi'):
                        argv = callconv.getCallArgs(self.emu, 12) # dump max 12 stack values.
                    else:
                        argv = callconv.getCallArgs(self.emu, len(funcargs))  # normal fetch argument info.
                    #
                    modifyState |= callbackToRun(self.emu, starteip, op, iscall, argv)
                    
                    # simulate the call.
                    if iscall:
                        currSnap = self.emu.getEmuSnap()
                        if not self.funcTinyRunner(endeip, callbackToRun, _currDepth + 1, currSnap):
                            self.emu.setEmuSnap(currSnap)
        
                    self.emu.checkCall(starteip, endeip, op)
                    ret = callconv.getReturnValue(self.emu)
                    
   
                    if self.emu.emustop: return

                    # If it wasn't a call, check for branches, if so, add them to the todo list and go around again...
                    if not iscall:
                        blist = self.emu.checkBranches(starteip, endeip, op)
                        if len(blist):
                            # pc in the snap will be wrong, but over-ridden at restore
                            esnap = self.emu.getEmuSnap()
                            for bva, bpath in blist:
                                todo.append((bva, esnap, bpath))
                            break

                    # If we enounter a procedure exit, it doesn't matter what EIP is, we're done here.
                    if op.iflags & envi.IF_RET:
                        vg_path.setNodeProp(self.emu.curpath, 'cleanret', True)
                        break
                    if self.emu.vw.isNoReturnVa(op.va) and op.va != funcva:
                        vg_path.setNodeProp(self.emu.curpath, 'cleanret', False)
                        break

                
                except envi.BadOpcode:
                    break
                except envi.UnsupportedInstruction as e:
                    if self.emu.strictops:
                        #print('runFunction failed: unsupported instruction - 0x%08x %s' %(e.op.va, e.op.mnem)) 
                        break
                    else:
                        #print('runFunction continuing after unsupported instruction - 0x%08x %s' % (e.op.va, e.op.mnem))
                        self.emu.setProgramCounter(e.op.va + e.op.size)
                except v_exc.BadOutInstruction:
                    break

                except e_exc.BreakpointHit:
                    pass # drop bp.
            
                except Exception as e:
                    print(e)
                    if self.emu.emumon is not None and not isinstance(e, e_exc.BreakpointHit):
                        self.emu.emumon.logAnomaly(self, starteip, str(e))

                    break  # If we exc during execution, this branch is dead.

        return modifyState
    # rewrite from vivisect.impemu.emulator.runFunction.
    def reachAnalyze(self, funcva, callbackQueue:list, stopva=None):
        self.emu.funcva = funcva
        self.defuseList[funcva] = {}
        # Let the current (should be base also) path know where we are starting
        vg_path.setNodeProp(self.emu.curpath, 'bva', funcva)
        hits = {}
        todo = [(funcva, self.emu.getEmuSnap(), self.emu.path)]
        vw = self.emu.vw  # Save a dereference many many times

        while len(todo):

            va, esnap, self.emu.curpath = todo.pop()
            self.emu.setEmuSnap(esnap)
            self.emu.setProgramCounter(va)

            usedArgStackSize = 0

            while True:
                starteip = self.emu.getProgramCounter()
                if not vw.isValidPointer(starteip): break
                if starteip == stopva: return

                # maxhit = 1
                if starteip in hits: break
                hits[starteip] = 1

                # If we ran out of path (branches that went
                # somewhere that we couldn't follow)?
                if self.emu.curpath is None: break
                try:
                    op = self.emu.parseOpcode(starteip)
                    iscall = bool(op.iflags & envi.IF_CALL)
                    self.emu.op = op

                    # DefUse Case#1 - record data reference. 
                    collect_reachDefinition(self, op, self.emu, starteip)

                    vg_path.getNodeProp(self.emu.curpath, 'valist').append(starteip)
                    endeip = self.emu.getProgramCounter()

                    # leak invoked call's arguments.
                    rtype, rname, convname, callname, funcargs = self.emu.getCallApi(endeip)
                    callname = f"sub_{endeip:x}" if callname == None else callname
                    callconv = self.emu.getCallingConvention(convname)

                    if len(funcargs) < 1 and ('sub_' in callname or callname == 'UnknownApi'):
                        argv = callconv.getCallArgs(self.emu, 12) # dump max 12 stack values.
                    else:
                        argv = callconv.getCallArgs(self.emu, len(funcargs))  # normal fetch argument info.

                    argv_snapshot = []
                    if iscall:
                        sp = self.emu.getStackCounter()
                        sp += callconv.pad + callconv.align # add align for skipping retAddr.

                        argc = 12 # dump max 12 stack values.
                        for arg_type, arg_val in callconv.arg_def:
                            if argc < 1 : break 
                            if arg_type == vivisect.envi.CC_REG:
                                regName = self.emu.getRealRegisterNameByIdx(arg_val)
                                argv_snapshot.append( (regName, self.emu.getRegister(arg_val)) )
                                argc -= 1
                            elif arg_type == vivisect.envi.CC_STACK:
                                argv_snapshot.append( (sp, self.emu.readMemoryFormat(sp, '<P')[0]) )
                                argc -= 1
                                sp += callconv.align
                            elif arg_type == vivisect.envi.CC_STACK_INF:
                                for _ in range(argc):
                                    argv_snapshot.append( (sp, self.emu.readMemoryFormat(sp, '<P')[0]) )
                                    sp += callconv.align
                                    argc -= 1
    
                                if argc != 0:
                                    raise Exception('wrong num of args from readMemoryFormat')
                            else:
                                raise Exception('unknown argument type')
    
                    # simulate the call.
                    self.emu.checkCall(starteip, endeip, op)
                    ret = callconv.getReturnValue(self.emu)
                    
                    if iscall:
                        if not self.emu.vw.isFunction(endeip):
                            if _ := self.emu.getVivTaint(endeip):
                                tva, ttype, tinfo = _
                                if ttype == 'apicall':
                                    #print(hex(starteip), ttype, usedArgStackSize)
                                    self.emu.setRegisterByName('esp', self.emu.getRegisterByName('esp') + usedArgStackSize)
                                
                        usedArgStackSize = 0
                    else:
                        if op.mnem == 'push':
                            usedArgStackSize += op.opers[0].tsize



                    # DefUse Case#2 - register eax case:
                    # (a.) call instruction will refresh eax. should re-define.
                    if iscall:
                        retValSymbol = getFuncRetVal_Symbol(self, callconv) # assert it should be EAX or RAX in i386.
                        self.defuseList[funcva][retValSymbol, ret] = (callname, "CALL_RET", starteip)
                    
                    # DefUse Case#3 - passing variables between cross functions 
                    # so, we're going to record the parameter-definition of callee.
                    #if 0x0004018D4 == starteip: # caller
                    if iscall:
                        callee_fva, funcNickName, caller_fva, retAddr = endeip, callname, self.emu.funcva, self.emu.getProgramCounter()
                        self.funcArgv_defuseList.append(  (callee_fva, funcNickName, caller_fva, retAddr, argv_snapshot) )
                    #    pass

                    # let's put a hook here. for user to monitor every instruction.
                    # TODO: it's workaround & not stable. to adjust stack frame at the time when API got invoked?
                    for callbackToExec in callbackQueue:
                        callbackToExec(self.emu, starteip, self.emu.op, iscall, callname, argv, argv_snapshot, ret)
                    if self.emu.emustop: return

                    # If it wasn't a call, check for branches, if so, add them to the todo list and go around again...
                    if not iscall:
                        blist = self.emu.checkBranches(starteip, endeip, op)
                        if len(blist):
                            # pc in the snap will be wrong, but over-ridden at restore
                            esnap = self.emu.getEmuSnap()
                            for bva, bpath in blist:
                                todo.append((bva, esnap, bpath))
                            break

                    # If we enounter a procedure exit, it doesn't matter what EIP is, we're done here.
                    if op.iflags & envi.IF_RET:
                        vg_path.setNodeProp(self.emu.curpath, 'cleanret', True)
                        break
                    if self.emu.vw.isNoReturnVa(op.va) and op.va != funcva:
                        vg_path.setNodeProp(self.emu.curpath, 'cleanret', False)
                        break

                
                except envi.BadOpcode:
                    break
                except envi.UnsupportedInstruction as e:
                    if self.emu.strictops:
                        #print('runFunction failed: unsupported instruction - 0x%08x %s' %(e.op.va, e.op.mnem)) 
                        break
                    else:
                        #print('runFunction continuing after unsupported instruction - 0x%08x %s' % (e.op.va, e.op.mnem))
                        self.emu.setProgramCounter(e.op.va + e.op.size)
                except v_exc.BadOutInstruction:
                    break

                except e_exc.BreakpointHit:
                    pass # drop bp.
                
    
                except Exception as e:
                    print(e)
                    if self.emu.emumon is not None and not isinstance(e, e_exc.BreakpointHit):
                        self.emu.emumon.logAnomaly(self, starteip, str(e))

                    break  # If we exc during execution, this branch is dead.
 


class chakraEngine():
    
    class currSimulate:
        pass
    class globalDefuse:
        pass

    def __init__(self, pathToFile):
        set_vivisect_log_level(logging.CRITICAL)
        self.halt = False
        self.funcArgv_defuseList, self.defuseList = [], {}
        self.pluginList = []
        self.vw = viv_utils.getWorkspace(pathToFile, analyze=False, should_save=False)
        self.vw.analyze()

        def simuGet_forkRef_OfData(where2write, curr_val):
            eleLookup = (where2write, curr_val)
            if eleLookup in chakraCore.te.defuseList[chakraCore.te.emu.funcva]:
                dataRef, refType, refCode  = chakraCore.te.defuseList[chakraCore.te.emu.funcva][ eleLookup ] # get reference of hProcess value from.
                return (dataRef, refType, refCode) if refType == 'FORK_REF' else None
            else:
                return None

        def simuGet_RefOfData(where2write, curr_val): # top of the stack should be retaddr. so argv#0 start at stackptr + 4
            eleLookup = (where2write, curr_val)
            if eleLookup in chakraCore.te.defuseList[chakraCore.te.emu.funcva]:
                dataRef, refType, refCode  = chakraCore.te.defuseList[chakraCore.te.emu.funcva][ eleLookup ] # get reference of hProcess value from.
                return (dataRef, refType, refCode)  if refType == 'DATA_REF' else None
            else:
                return None

        def simuGet_funcArgv_OfData(where2write, curr_val): # top of the stack should be retaddr. so argv#0 start at stackptr + 4
            eleLookup = (where2write, curr_val)
            if eleLookup in chakraCore.te.defuseList[chakraCore.te.emu.funcva]:
                dataRef, refType, refCode  = chakraCore.te.defuseList[chakraCore.te.emu.funcva][ eleLookup ] # get reference of hProcess value from.
                return (dataRef, refType, refCode) if refType == 'INIT_REF' else None
            else:
                return None
        
        def simuGet_getAny_refOfData(where2write, curr_val): # top of the stack should be retaddr. so argv#0 start at stackptr + 4
            if _ := simuGet_forkRef_OfData(where2write, curr_val):
                return _[0]
            if _ := simuGet_RefOfData(where2write, curr_val):
                return _[0]
            if _ := simuGet_funcArgv_OfData(where2write, curr_val):
                return _[0]
            return None

        def globalGet_forkRef_OfData( funcva, where2write, curr_val):
            eleLookup = (where2write, curr_val)
            if eleLookup in self.defuseList[funcva]:
                dataRef, refType, refCode  = self.defuseList[funcva][ eleLookup ] # get reference of hProcess value from.
                return (dataRef, refType, refCode)  if refType == 'FORK_REF' else None
            else:
                return None

        def globalGet_RefOfData( funcva, where2write, curr_val): # top of the stack should be retaddr. so argv#0 start at stackptr + 4
            eleLookup = (where2write, curr_val)
            if eleLookup in self.defuseList[funcva]:
                dataRef, refType, refCode  = self.defuseList[funcva][ eleLookup ] # get reference of hProcess value from.
                return (dataRef, refType, refCode)  if refType == 'DATA_REF' else None
            else:
                return None

        def globalGet_funcArgv_OfData( funcva, where2write, curr_val): # top of the stack should be retaddr. so argv#0 start at stackptr + 4
            eleLookup = (where2write, curr_val)
            if eleLookup in self.defuseList[funcva]:
                dataRef, refType, refCode  = self.defuseList[funcva][ eleLookup ] # get reference of hProcess value from.
                return (dataRef, refType, refCode)  if refType == 'INIT_REF' else None
            else:
                return None

        def globalGet_retVal_RefOfCall( funcva, where2write, curr_val): # top of the stack should be retaddr. so argv#0 start at stackptr + 4
            eleLookup = (where2write, curr_val)
            if eleLookup in self.defuseList[funcva]:
                dataRef, refType, refCode  = self.defuseList[funcva][ eleLookup ] # get reference of hProcess value from.
                return (dataRef, refType, refCode)  if refType == 'CALL_RET' else None
            else:
                return None


        self.currSimulate.get_forkRef_OfData = simuGet_forkRef_OfData
        self.currSimulate.get_RefOfData = simuGet_RefOfData
        self.currSimulate.get_funcArgv_OfData = simuGet_funcArgv_OfData
        self.currSimulate.getAny_refOfData = simuGet_getAny_refOfData

        
        self.globalDefuse.get_forkRef_OfData = globalGet_forkRef_OfData
        self.globalDefuse.get_RefOfData = globalGet_RefOfData
        self.globalDefuse.get_funcArgv_OfData = globalGet_funcArgv_OfData
        self.globalDefuse.get_retVal_RefOfCall = globalGet_retVal_RefOfCall
    
    def taintSingleFunction(self, fva):
        taintEngine = taintEmulator(self.vw)
        self.te = taintEngine
        taintEngine.reachAnalyze(fva, [plugin.callback for plugin in self.pluginList], stopva=None)
        self.funcArgv_defuseList.extend( self.te.funcArgv_defuseList )
        self.defuseList[fva] = self.te.defuseList[fva] 

    def tinySimulateSingleFunction(self, fva, callbackToRun):
        taintEngine = taintEmulator(self.vw)
        self.te = taintEngine
        taintEngine.funcTinyRunner(fva, callbackToRun)

    def taintAllFunctions(self):
        for fva in self.vw.getFunctions():
            if not self.halt: self.taintSingleFunction(fva)

    def chk_RefType_isFuncParams(self, where2write, curr_val):
        eleLookup = (where2write, curr_val)
        if eleLookup in self.te.defuseList[self.te.emu.funcva]:
            dataRef, refType, refCode  = self.te.defuseList[self.te.emu.funcva][ eleLookup ] # get reference of hProcess value from.
            return refType == 'INIT_REF'
        else:
            return None
    
    def lookup_Caller(self, callee_fva):
        return [(er, sn) for ee, fn, er, retva, sn in self.funcArgv_defuseList if ee == callee_fva]       



import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import multiprocessing


if __name__ == "__main__":
    print('''
████████╗ ██████╗███████╗ █████╗ 
╚══██╔══╝██╔════╝██╔════╝██╔══██╗
   ██║   ██║     ███████╗███████║
   ██║   ██║     ╚════██║██╔══██║
   ██║   ╚██████╗███████║██║  ██║
   ╚═╝    ╚═════╝╚══════╝╚═╝  ╚═╝
TXOne Code Semantics Analyzer (TCSA) v1.''')

    import time
    start_time = time.time()

    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} [path/to/file]")
        sys.exit(-1)
    
    # spawn a single process, to run miniCapa & analyze features by Capa rules.
    if not "-noCapa" in sys.argv:
        from Subsystem.miniCapa.main import capaScan
        from Subsystem.miniCapa.main import print_result
        with ProcessPoolExecutor(max_workers=20) as executor:
            task_miniCapa = executor.submit(capaScan, None, sys.argv[1], "Plugins/capaRules")
        
    # Akali AutoMata init.
    chakraCore = chakraEngine( sys.argv[1] )
    for szPlugin in os.listdir('Plugins/'):
        if szPlugin.endswith(".py"):
            spec = importlib.util.spec_from_file_location("Plugins", f"Plugins/{szPlugin}")
            package = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(package)
            chakraCore.pluginList.append(package)
    
    for plugin in chakraCore.pluginList: plugin.initialize( chakraCore )
    chakraCore.taintAllFunctions()
    capaMatchRet = task_miniCapa.result() if not "-noCapa" in sys.argv else {}
    for plugin in chakraCore.pluginList: plugin.cleanup( chakraCore, capaMatchRet )
    print(f"  --- total used {time.time() - start_time} sec ---")