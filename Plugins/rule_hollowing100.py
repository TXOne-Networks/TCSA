'''
Determine Input Binaries Have The Ability of Process Hollowing.

Plugin Concpet from SetupTools:
https://github.com/OctoPrint/Plugin-Examples/blob/master/helloworld/setup.py
'''
chakraCore = None
def checkNum_isMemPtr(emu, num):
    return any([num in range(x,y) for x,y, *z in emu._map_defs])

def checkNum_isData(emu, num):
    return emu.getVivTaint(num) != None or checkNum_isMemPtr(emu, num)
    
def callback(emu, starteip, op, iscall, callname, argv, argv_snapshot, ret):
    arglist = op.getOperands()
  
    if iscall and len(argv) >= 10 and argv[2] == argv[3] == argv[4] == 0:
        useNewProc = True
        ptrPInfo = argv_snapshot[9]
        callback.list_spawnProc.append( (emu.funcva, starteip) ) # ( funcva, createProcess_callAt )
        print(f'[*] spawn process? {starteip:x} @ sub_{emu.funcva:x} - {callname}{tuple(argv)}')        

callback.list_spawnProc = []

# semantics-capability-automata
def initialize( In_chakraCore ):
    global chakraCore
    print("[OK] Rule Attached - Hollowing for 100 Samples.")
    chakraCore = In_chakraCore
    pass


'''
BOOL CreateProcessA(
  [in, optional]      LPCSTR                #0 - lpApplicationName,
  [in, out, optional] LPSTR                 #1 - lpCommandLine,
  [in, optional]      LPSECURITY_ATTRIBUTES #2 - lpProcessAttributes,
  [in, optional]      LPSECURITY_ATTRIBUTES #3 - lpThreadAttributes,
  [in]                BOOL                  #4 - bInheritHandles,
  [in]                DWORD                 #5 - dwCreationFlags,
  [in, optional]      LPVOID                #6 - lpEnvironment,
  [in, optional]      LPCSTR                #7 - lpCurrentDirectory,
  [in]                LPSTARTUPINFOA        #8 - lpStartupInfo,
  [out]               LPPROCESS_INFORMATION #9 - lpProcessInformation
);
'''
def cleanup( In_chakraCore, In_capaMatchRet ):

    # check the each potential CreateProcess usage.
    for funcAddr, newProc_callAt in callback.list_spawnProc:
    
        # hollowing detection state-machine
        def stateMachine_hollowing(emu, eip, op, iscall, argv):
            modifyState = False
            arglist = set( [ emu.getOperValue(op, _) for _ in range(len(op.opers)) ] )

            if eip == newProc_callAt and len(argv) >= 9 and argv[5] == 0x04 and checkNum_isData(emu, argv[9]):
                guess_procInfoAt = argv[9] # lpProcessInformation
                emu.allocateMemory(256, suggestaddr=guess_procInfoAt) # ensure the struct is allocated in memory
                emu.writeMemoryPtr( guess_procInfoAt + 0, 0xDEADDEAD ) # set hProcess to 0xDEADDEAD
                emu.writeMemoryPtr( guess_procInfoAt + 4, 0xBEEFBEEF ) # set hThread to 0xBEEFBEEF 
                modifyState = True
    
            # [CASE] CONTEXT.ContextFlags = CONTEXT_FULL
            set_CONTEXTFLAGS = set([ 0x10007, 0x1003F ])
            stateMachine_hollowing.useCtxFlag_CTXFULL |= {} != set_CONTEXTFLAGS & arglist
            
            # [CASE] GetThreadContext( 0xBEEFBEEF, &CONTEXT ) 
            if iscall and len(argv) >= 2 \
               and argv[0] == 0xBEEFBEEF and checkNum_isData(emu, argv[1]): 

                ebxVal = emu.readMemoryPtr(argv[1] + 0xA4) # offsetof(CONTEXT, Ebx) = A4h
                stateMachine_hollowing.guess_pebImageBaseAt.add(ebxVal + 8)
            
            if arglist & stateMachine_hollowing.guess_pebImageBaseAt:
                print(f"[v] found accesss PEB.ImageBase at {eip:x} - {op}")

            # [TRUE]:  keep the modified execution-state if we're doing some kinda necessary patchs.
            # [FALSE]: state-machine will forgot all the memory patchs when running out of the current function scope. (back to the parent function) 
            return modifyState 

        stateMachine_hollowing.guess_pebImageBaseAt = set()
        stateMachine_hollowing.useCtxFlag_CTXFULL = False

        # verify the behavior of the each caller. 
        for callerFunc, argSnapshot in chakraCore.lookup_Caller(funcAddr):
            chakraCore.tinySimulateSingleFunction(callerFunc, stateMachine_hollowing)
        
        # verify the function which contains the potential CreateProcess
        # means that function might not have any parent function, it's a entry function?
        chakraCore.tinySimulateSingleFunction(funcAddr, stateMachine_hollowing)
    pass