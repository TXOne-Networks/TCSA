from tracemalloc import start
from vivisect.impemu.emulator import WorkspaceEmulator, envi

def getFuncRetVal_Symbol(self, callconv):
    rtype, rvalue = callconv.retval_def
    if rtype == envi.CC_REG:
        regName = self.emu.getRealRegisterNameByIdx(rvalue)
        return regName
    #elif rtype == envi.CC_STACK:
    #    pass
    else:
        raise Exception('unknown argument type')
        
def collect_reachDefinition(self, op, emu, starteip):
    # emu.getRealRegisterNameByIdx( list[0].reg ) = "esp"
    # mov dword [esp + 28],666 ... list[0].disp = 28
    # mov dword [esp + 28],666 ... list[0].isReg() = True
    # mov dword [esp + 28],666 ... list[1].isImmed() = True
    # mov dword [esp + 28],666 ... list[1].imm = 666

    # consider that should be 5 cases of using mov in i386:
    # (a.) mov ds:[dest], register       -> We Care!
    # (b.) mov register, ds:[dest]       -> We Care!
    # (c.) mov register, register        -> We Care!
    # (d.) mov ds:[dest], immediate      -> Clear It? so we should remove the reference
    # (e.) mov register,  immediate      -> Clear It? so we should remove the reference
    preExecOp = False
 
    if op.mnem == 'mov' and len(op.getOperands()) > 1:
        arglist = op.getOperands()

        if arglist[0].isReg() and arglist[1].isReg():           # case (c.) - mov ebp, esp
            valueRefFrom = emu.getRealRegisterNameByIdx( arglist[1].reg )
            dataVal     = emu.getOperValue(op, 1)
            valueWriteTo = emu.getRealRegisterNameByIdx( arglist[0].reg )

            if (valueRefFrom, dataVal) in self.defuseList[emu.funcva]:
                dataRef, refType, refCode = self.defuseList[emu.funcva][valueRefFrom, dataVal]
                self.defuseList[emu.funcva][valueWriteTo, dataVal] = (dataRef, refType, starteip)
            else:
                # assert the values is passed from another caller to here callee, and recive it.
                self.defuseList[emu.funcva][valueWriteTo, dataVal] = (valueRefFrom, 'INIT_REF', starteip)
                #raise Exception("Unhandle?")
            
        elif arglist[0].isReg() and arglist[1].isDeref():       # case (b.) - mov eax, ds:[deadbeef]
            
            valueWriteTo = emu.getRealRegisterNameByIdx( arglist[0].reg )
            dataRef = emu.getOperAddr(op, 1)
            dataVal = emu.getOperValue(op, 1)
            self.defuseList[emu.funcva][valueWriteTo, dataVal] = (dataRef, "DATA_REF", starteip)
            '''
            if arglist[0].isReg() and (hasattr(arglist[1], "scale") or arglist[1].isDiscrete()): # lea register, [register + register * n] or lea rcx, ds:[0xdeadbeef]
                if (dataFrom, dataVal) in self.defuseList[emu.funcva]:
                    dataRef, refType, refCode = self.defuseList[emu.funcva][dataFrom, dataVal]
                    self.defuseList[emu.funcva][valueWriteTo, dataVal] = (dataRef, refType, starteip)
                else:
                    self.defuseList[emu.funcva][valueWriteTo, dataVal] = (dataRef, 'INIT_REF', starteip)
        
            elif arglist[0].isReg() and hasattr(arglist[1], "disp") and not hasattr(arglist[1], "scale"):# lea register, [register + offset]
                register = emu.getRealRegisterNameByIdx( arglist[1].reg ) 
                delta = arglist[1].disp
                
                # check that register have DefUse difition?
                if (register, emu.getRegisterByName(register)) in self.defuseList[emu.funcva]:
                    dataRef, refType, refCode = self.defuseList[emu.funcva][register, emu.getRegisterByName(register)]
                    self.defuseList[emu.funcva][dataWriteDest, dataVal] = ((dataRef,  emu.getRegisterByName(register),  delta), 'FORK_REF', starteip )
                # lea register, [dest]
                else: 
                    if (dataFrom, dataVal) in self.defuseList[emu.funcva]:
                        dataRef, refType, refCode = self.defuseList[emu.funcva][dataFrom, dataVal]
                        self.defuseList[emu.funcva][dataWriteDest, dataVal] = (dataRef, refType, starteip)
                    else:
                        self.defuseList[emu.funcva][dataWriteDest, dataVal] = (dataFrom, 'INIT_REF', starteip)
                        #raise Exception("Unhandle?")
            else:
                raise Exception("Unexpected x86 Lea Bheavior.")
            '''

        elif arglist[0].isDeref() and arglist[1].isReg():       # case (a.) - mov/lea dword [esp + 12],ecx
            valueGetFrom = emu.getRealRegisterNameByIdx( arglist[1].reg )
            dataVal = emu.getOperValue(op, 1)
            dataWriteDest = emu.getOperAddr(op, 0)
            if (valueGetFrom, dataVal) in self.defuseList[emu.funcva]:
                dataRef, refType, refCode = self.defuseList[emu.funcva][valueGetFrom, dataVal]
                self.defuseList[emu.funcva][dataWriteDest, dataVal] = (dataRef, refType, starteip)
            else:
                self.defuseList[emu.funcva][dataWriteDest, dataVal] = (valueGetFrom, 'INIT_REF', starteip)
                #raise Exception("Unhandle?")

        elif arglist[0].isDeref() and arglist[1].isImmed():     # case (d.) - mov ds:[dest], immediate 
            pass
        
        elif arglist[0].isReg() and arglist[1].isImmed():       # case (e.) - mov register,  immediate
            #valueWriteTo = emu.getRealRegisterNameByIdx( arglist[0].reg )
            #self.defuseList[emu.funcva] = { (write2where, val) : info for ((write2where, val), info) in self.defuseList[emu.funcva].items() if write2where != valueWriteTo}
            pass
        
        else:
            raise Exception("Unexpected Mov Should be Handled?")

    elif op.mnem == 'lea':
        self.emu.executeOpcode(op)
        preExecOp = True

        arglist = op.getOperands()
        dataFrom = emu.getOperAddr(op, 1)
        dataVal  = emu.getOperAddr(emu.op, 1)    
        dataWriteDest = emu.getRealRegisterNameByIdx( arglist[0].reg ) 

        if arglist[0].isReg() and (hasattr(arglist[1], "scale") or arglist[1].isDiscrete()): # lea register, [register + register * n] or lea rcx, ds:[0xdeadbeef]
            if (dataFrom, dataVal) in self.defuseList[emu.funcva]:
                dataRef, refType, refCode = self.defuseList[emu.funcva][dataFrom, dataVal]
                self.defuseList[emu.funcva][dataWriteDest, dataVal] = (dataRef, refType, starteip)
            else:
                self.defuseList[emu.funcva][dataWriteDest, dataVal] = (dataFrom, 'INIT_REF', starteip)

        elif arglist[0].isReg() and hasattr(arglist[1], "disp") and not hasattr(arglist[1], "scale"):# lea register, [register + offset]
            register = emu.getRealRegisterNameByIdx( arglist[1].reg ) 
            delta = arglist[1].disp
            
            # check that register have DefUse difition?
            if (register, emu.getRegisterByName(register)) in self.defuseList[emu.funcva]:
                dataRef, refType, refCode = self.defuseList[emu.funcva][register, emu.getRegisterByName(register)]
                self.defuseList[emu.funcva][dataWriteDest, dataVal] = ((dataRef,  emu.getRegisterByName(register),  delta), 'FORK_REF', starteip )
            # lea register, [dest]
            else: 
                if (dataFrom, dataVal) in self.defuseList[emu.funcva]:
                    dataRef, refType, refCode = self.defuseList[emu.funcva][dataFrom, dataVal]
                    self.defuseList[emu.funcva][dataWriteDest, dataVal] = (dataRef, refType, starteip)
                else:
                    self.defuseList[emu.funcva][dataWriteDest, dataVal] = (dataFrom, 'INIT_REF', starteip)
                    #raise Exception("Unhandle?")
        else:
            raise Exception("Unexpected x86 Lea Bheavior.")

    # label DefUse references of stack variables 
    elif op.mnem == 'push': # consider that Push is writing data in the top of stack.
        opVal = op.getOperands()[0]
        dataWriteDest = emu.getStackCounter() - opVal.tsize

        if opVal.isReg():   # push register
            valueGetFrom = emu.getRealRegisterNameByIdx( opVal.reg )
            dataVal = emu.getOperValue(op, 0)
            if (valueGetFrom, dataVal) in self.defuseList[emu.funcva]: # check there's source definition of where value from 
                dataRef, refType, refCode = self.defuseList[emu.funcva][valueGetFrom, dataVal]
                self.defuseList[emu.funcva][dataWriteDest, dataVal] = (dataRef, refType, starteip)
            else:
                # assert the values is passed from another caller to here callee, and recive it.
                self.defuseList[emu.funcva][dataWriteDest, dataVal] = (valueGetFrom, 'INIT_REF', starteip)
                #raise Exception("Unhandle?")

        elif opVal.isDeref(): # push ds:[0xdeadbeef]
            value, dataRef = emu.getOperValue(op, 0), emu.getOperAddr(op, 0)
            self.defuseList[emu.funcva][dataWriteDest, value] = (dataRef, 'DATA_REF', starteip)

        elif opVal.isImmed(): # push 72h - no source here the stack data? drop it.
            pass
        else:
            raise Exception("Unexcepted Push Should be Handled?")   
        
    # TODO: consider that register value got modified, should record the change. 
    elif op.mnem == 'add': 
        arglist = op.getOperands()
        if arglist[0].isReg(): # add register, whatever
            refreshValueFrom = emu.getRealRegisterNameByIdx( arglist[0].reg ) 
            dataVal, delta = emu.getOperValue(op, 0), emu.getOperValue(op, 1)

            if (refreshValueFrom, dataVal) in self.defuseList[emu.funcva]:    
                dataRef, refType, refCode = self.defuseList[emu.funcva][refreshValueFrom, dataVal]
                if refType == "CALL_RET":
                    self.defuseList[emu.funcva][refreshValueFrom, dataVal] = (f"{dataRef}() + {delta}", refType, starteip)
                elif refType == "DATA_REF":
                    self.defuseList[emu.funcva][refreshValueFrom, dataVal + delta] = (dataRef + delta, refType, starteip)
                elif refType == "INIT_VAL":
                    raise Exception("Unhandled?")
                    self.defuseList[emu.funcva][refreshValueFrom, dataVal + delta] = (dataRef + delta, "DATA_REF", starteip)
            else:
                self.defuseList[emu.funcva][refreshValueFrom, dataVal + delta] = (refreshValueFrom, 'INIT_REF', starteip)
                #raise Exception("Unhandle?")


    
    # Execute the opcode
    if not preExecOp: self.emu.executeOpcode(op)
    return


#or op.mnem == 'sub'
# emu.getRegisterByName("esp")


