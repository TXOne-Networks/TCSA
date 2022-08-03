###
### emulate the target functions from it parent and pass the context to the target functions
###
import contextlib
from collections import namedtuple
from envi import Emulator
import envi
import viv_utils
import viv_utils.emulator_drivers
import sys
import os
from typing import List, Tuple
from dataclasses import dataclass
import IPython


MEGABYTE = 1024*1024
STACK_MEM_NAME = "[stack]"
MAX_MAPS_SIZE = 1024 * 1024 * 100  # 100MB max memory allocated in an emulator instance

###
### from flare-floss/floss/api_hooks.py
###

class ApiMonitor(viv_utils.emulator_drivers.Monitor):
    """
    The ApiMonitor observes emulation and cleans up API function returns.
    """

    def __init__(self, vw, function_index):
        viv_utils.emulator_drivers.Monitor.__init__(self, vw)
        self.function_index = function_index

    def apicall(self, emu, op, pc, api, argv):
        # overridden from Monitor
        # print("0x%x %s %s %s", pc, op, api, argv)
        return

    def prehook(self, emu, op, startpc):
        # overridden from Monitor
        # helpful for debugging decoders, but super verbose!
        # print("0x%x %s", startpc, op)
        return

    def posthook(self, emu, op, endpc):
        # overridden from Monitor
        if op.mnem == "ret":
            try:
                self._check_return(emu, op)
            except Exception as e:
                print(str(e))

    def _check_return(self, emu, op):
        """
        Ensure that the target of the return is within the allowed set of functions.
        Do nothing, if return address is valid. If return address is invalid:
        _fix_return modifies program counter and stack pointer if a valid return address is found
        on the stack or raises an Exception if no valid return address is found.
        """
        function_start = self.function_index[op.va]
        return_addresses = self._get_return_vas(emu, function_start)

        if op.opers:
            # adjust stack in case of `ret imm16` instruction
            emu.setStackCounter(emu.getStackCounter() - op.opers[0].imm)

        return_address = self.getStackValue(emu, -4)
        if return_address not in return_addresses:
            print(
                "Return address 0x%08X is invalid, expected one of: %s",
                return_address,
                ", ".join(map(hex, return_addresses)),
            )
            self._fix_return(emu, return_address, return_addresses)
            # TODO return, handle Exception
        else:
            print("Return address 0x%08X is valid, returning", return_address)
            # TODO return?

    def _get_return_vas(self, emu, function_start):
        """
        Get the list of valid addresses to which a function should return.
        """
        return_vas = []
        callers = self._vw.getCallers(function_start)
        for caller in callers:
            call_op = emu.parseOpcode(caller)
            return_va = call_op.va + call_op.size
            return_vas.append(return_va)
        return return_vas

    def _fix_return(self, emu, return_address, return_addresses):
        """
        Find a valid return address from return_addresses on the stack. Adjust the stack accordingly
        or raise an Exception if no valid address is found within the search boundaries.
        Modify program counter and stack pointer, so the emulator does not return to a garbage address.
        """
        self.dumpStack(emu)
        NUM_ADDRESSES = 4
        pointer_size = emu.getPointerSize()
        STACK_SEARCH_WINDOW = pointer_size * NUM_ADDRESSES
        esp = emu.getStackCounter()
        for offset in range(0, STACK_SEARCH_WINDOW, pointer_size):
            ret_va_candidate = self.getStackValue(emu, offset)
            if ret_va_candidate in return_addresses:
                emu.setProgramCounter(ret_va_candidate)
                emu.setStackCounter(esp + offset + pointer_size)
                # print("Returning to 0x%08X, adjusted stack:", ret_va_candidate)
                self.dumpStack(emu)
                return

        self.dumpStack(emu)
        raise Exception("No valid return address found...")

    def dumpStack(self, emu):
        """
        Convenience debugging routine for showing
         state current state of the stack.
        """
        esp = emu.getStackCounter()
        stack_str = ""
        for i in range(16, -16, -4):
            if i == 0:
                sp = "<= SP"
            else:
                sp = "%02x" % (-i)
            stack_str = "%s\n0x%08x - 0x%08x %s" % (stack_str, (esp - i), self.getStackValue(emu, -i), sp)
        # print(stack_str)

    # TODO unused, removeme?
    def dumpState(self, emu):
        self.i("eip: 0x%x", emu.getRegisterByName("eip"))
        self.i("esp: 0x%x", emu.getRegisterByName("esp"))
        self.i("eax: 0x%x", emu.getRegisterByName("eax"))
        self.i("ebx: 0x%x", emu.getRegisterByName("ebx"))
        self.i("ecx: 0x%x", emu.getRegisterByName("ecx"))
        self.i("edx: 0x%x", emu.getRegisterByName("edx"))

        self.dumpStack(emu)


def pointerSize(emu):
    """
    Convenience method whose name might be more readable
     than fetching emu.imem_psize.
    Returns the size of a pointer in bytes for the given emulator.
    :rtype: int
    """
    return emu.imem_psize


def popStack(emu):
    """
    Remove the element at the top of the stack.
    :rtype: int
    """
    v = emu.readMemoryFormat(emu.getStackCounter(), "<P")[0]
    emu.setStackCounter(emu.getStackCounter() + pointerSize(emu))
    return v


class GetProcessHeapHook(viv_utils.emulator_drivers.Hook):
    """
    Hook and handle calls to GetProcessHeap, returning 0.
    """

    def hook(self, callname, emu, callconv, api, argv):
        if callname == "kernel32.GetProcessHeap":
            # nop
            callconv.execCallReturn(emu, 42, len(argv))
            return True
        raise viv_utils.emulator_drivers.UnsupportedFunction()


def round(i, size):
    """
    Round `i` to the nearest greater-or-equal-to multiple of `size`.
    :type i: int
    :type size: int
    :rtype: int
    """
    if i % size == 0:
        return i
    return i + (size - (i % size))


class RtlAllocateHeapHook(viv_utils.emulator_drivers.Hook):
    """
    Hook calls to RtlAllocateHeap, allocate memory in a "heap"
     section, and return pointers to this memory.
    The base heap address is 0x96960000.
    The max allocation size is 10 MB.
    """

    def __init__(self, *args, **kwargs):
        super(RtlAllocateHeapHook, self).__init__(*args, **kwargs)
        self._heap_addr = 0x96960000

    MAX_ALLOCATION_SIZE = 10 * 1024 * 1024

    def _allocate_mem(self, emu, size):
        size = round(size, 0x1000)
        if size > self.MAX_ALLOCATION_SIZE:
            size = self.MAX_ALLOCATION_SIZE
        va = self._heap_addr
        print("RtlAllocateHeap: mapping %s bytes at %s", hex(size), hex(va))
        emu.addMemoryMap(va, envi.memory.MM_RWX, "[heap allocation]", b"\x00" * (size + 4))
        emu.writeMemory(va, b"\x00" * size)
        self._heap_addr += size
        return va

    def hook(self, callname, driver, callconv, api, argv):
        # works for kernel32.HeapAlloc
        if callname == "ntdll.RtlAllocateHeap":
            emu = driver
            hheap, flags, size = argv
            va = self._allocate_mem(emu, size)
            callconv.execCallReturn(emu, va, len(argv))
            return True
        raise viv_utils.emulator_drivers.UnsupportedFunction()


class AllocateHeap(RtlAllocateHeapHook):
    """
    Hook calls to AllocateHeap and handle them like calls to RtlAllocateHeapHook.
    """

    def __init__(self, *args, **kwargs):
        super(AllocateHeap, self).__init__(*args, **kwargs)

    def hook(self, callname, driver, callconv, api, argv):
        if (
            callname == "kernel32.LocalAlloc"
            or callname == "kernel32.GlobalAlloc"
            or callname == "kernel32.VirtualAlloc"
        ):
            size = argv[1]
        elif callname == "kernel32.VirtualAllocEx":
            size = argv[2]
        else:
            raise viv_utils.emulator_drivers.UnsupportedFunction()
        va = self._allocate_mem(driver, size)
        callconv.execCallReturn(driver, va, len(argv))
        return True


class MallocHeap(RtlAllocateHeapHook):
    """
    Hook calls to malloc and handle them like calls to RtlAllocateHeapHook.
    """

    def __init__(self, *args, **kwargs):
        super(MallocHeap, self).__init__(*args, **kwargs)

    def hook(self, callname, driver, callconv, api, argv):
        if callname == "msvcrt.malloc" or callname == "msvcrt.calloc":
            size = argv[0]
            va = self._allocate_mem(driver, size)
            callconv.execCallReturn(driver, va, len(argv))
            return True
        elif callname == "_calloc_base":
            size = argv[0]
            count = argv[1]
            va = self._allocate_mem(driver, size * count)
            callconv.execCallReturn(driver, va, 2)  # TODO len(argv)?
            return True
        raise viv_utils.emulator_drivers.UnsupportedFunction()


class MemcpyHook(viv_utils.emulator_drivers.Hook):
    """
    Hook and handle calls to memcpy and memmove.
    """

    MAX_COPY_SIZE = 1024 * 1024 * 32  # don't attempt to copy more than 32MB, or something is wrong

    def __init__(self, *args, **kwargs):
        super(MemcpyHook, self).__init__(*args, **kwargs)

    def hook(self, callname, driver, callconv, api, argv):
        if callname == "msvcrt.memcpy" or callname == "msvcrt.memmove":
            emu = driver
            dst, src, count = argv
            if count > self.MAX_COPY_SIZE:
                self.d("unusually large memcpy, truncating to 32MB: 0x%x", count)
                count = self.MAX_COPY_SIZE
            data = emu.readMemory(src, count)
            emu.writeMemory(dst, data)
            callconv.execCallReturn(emu, 0x0, len(argv))
            return True
        raise viv_utils.emulator_drivers.UnsupportedFunction()


def readStringAtRva(emu, rva, maxsize=None):
    """
    Borrowed from vivisect/PE/__init__.py
    :param emu: emulator
    :param rva: virtual address of string
    :param maxsize: maxsize of string
    :return: the read string
    """
    ret = bytearray()
    while True:
        if maxsize and maxsize <= len(ret):
            break
        x = emu.readMemory(rva, 1)
        if x == b"\x00" or x is None:
            break
        ret += x
        rva += 1
    return bytes(ret)


class StrlenHook(viv_utils.emulator_drivers.Hook):
    """
    Hook and handle calls to strlen
    """

    def __init__(self, *args, **kwargs):
        super(StrlenHook, self).__init__(*args, **kwargs)

    def hook(self, callname, driver, callconv, api, argv):
        if callname and callname.lower() in ["msvcrt.strlen", "kernel32.lstrlena"]:
            emu = driver
            string_va = argv[0]
            s = readStringAtRva(emu, string_va, 256)
            callconv.execCallReturn(emu, len(s), len(argv))
            return True
        raise viv_utils.emulator_drivers.UnsupportedFunction()


class StrnlenHook(viv_utils.emulator_drivers.Hook):
    """
    Hook and handle calls to strnlen.
    """

    MAX_COPY_SIZE = 1024 * 1024 * 32

    def __init__(self, *args, **kwargs):
        super(StrnlenHook, self).__init__(*args, **kwargs)

    def hook(self, callname, driver, callconv, api, argv):
        if callname == "msvcrt.strnlen":
            emu = driver
            string_va, maxlen = argv
            if maxlen > self.MAX_COPY_SIZE:
                self.d("unusually large strnlen, truncating to 32MB: 0x%x", maxlen)
                maxlen = self.MAX_COPY_SIZE
            s = readStringAtRva(emu, string_va, maxsize=maxlen)
            slen = s.index(b"\x00")
            callconv.execCallReturn(emu, slen, len(argv))
            return True

        raise viv_utils.emulator_drivers.UnsupportedFunction()


class StrncmpHook(viv_utils.emulator_drivers.Hook):
    """
    Hook and handle calls to strncmp.
    """

    MAX_COPY_SIZE = 1024 * 1024 * 32

    def __init__(self, *args, **kwargs):
        super(StrncmpHook, self).__init__(*args, **kwargs)

    def hook(self, callname, driver, callconv, api, argv):
        if callname == "msvcrt.strncmp":
            emu = driver
            s1va, s2va, num = argv
            if num > self.MAX_COPY_SIZE:
                self.d("unusually large strnlen, truncating to 32MB: 0x%x", num)
                num = self.MAX_COPY_SIZE

            s1 = readStringAtRva(emu, s1va, maxsize=num)
            s2 = readStringAtRva(emu, s2va, maxsize=num)

            s1 = s1.partition(b"\x00")[0]
            s2 = s2.partition(b"\x00")[0]

            def cmp(a, b):
                return (a > b) - (a < b)

            result = cmp(s1, s2)

            callconv.execCallReturn(emu, result, len(argv))
            return True

        raise viv_utils.emulator_drivers.UnsupportedFunction()


class MemchrHook(viv_utils.emulator_drivers.Hook):
    """
    Hook and handle calls to memchr
    """

    def __init__(self, *args, **kwargs):
        super(MemchrHook, self).__init__(*args, **kwargs)

    def hook(self, callname, driver, callconv, api, argv):
        if callname == "msvcrt.memchr":
            emu = driver
            ptr, value, num = argv
            value = bytes([value])
            memory = emu.readMemory(ptr, num)
            try:
                idx = memory.index(value)
                callconv.execCallReturn(emu, ptr + idx, len(argv))
            except ValueError:  # substring not found
                callconv.execCallReturn(emu, 0, len(argv))
            return True
        raise viv_utils.emulator_drivers.UnsupportedFunction()


class ExitProcessHook(viv_utils.emulator_drivers.Hook):
    """
    Hook calls to ExitProcess and stop emulation when these are hit.
    """

    def __init__(self, *args, **kwargs):
        super(ExitProcessHook, self).__init__(*args, **kwargs)

    def hook(self, callname, driver, callconv, api, argv):
        if callname == "kernel32.ExitProcess":
            raise viv_utils.emulator_drivers.StopEmulation()


class CriticalSectionHooks(viv_utils.emulator_drivers.Hook):
    """
    Hook calls to:
      - InitializeCriticalSection
    """

    def hook(self, callname, emu, callconv, api, argv):
        if callname == "kernel32.InitializeCriticalSection":
            (hsection,) = argv
            emu.writeMemory(hsection, "csec")
            callconv.execCallReturn(emu, 0, len(argv))
            return True


DEFAULT_HOOKS = [
    GetProcessHeapHook(),
    RtlAllocateHeapHook(),
    AllocateHeap(),
    MallocHeap(),
    ExitProcessHook(),
    MemcpyHook(),
    StrlenHook(),
    MemchrHook(),
    StrnlenHook(),
    StrncmpHook(),
    CriticalSectionHooks(),
]


@contextlib.contextmanager
def defaultHooks(driver):
    """
    Install and remove the default set of hooks to handle common functions.
    intended usage:
        with defaultHooks(driver):
            driver.runFunction()
            ...
    """
    try:
        for hook in DEFAULT_HOOKS:
            driver.add_hook(hook)
        yield
    finally:
        for hook in DEFAULT_HOOKS:
            driver.remove_hook(hook)

###
### from flare-floss/floss/function_arguments_getter.py
###


def make_emulator(vw) -> Emulator:
    """
    create an emulator using consistent settings.
    """
    emu = vw.getEmulator(logwrite=True, taintbyte=b"\xFE")
    remove_stack_memory(emu)
    emu.initStackMemory(stacksize=int(0.5 * MEGABYTE))
    emu.setStackCounter(emu.getStackCounter() - int(0.25 * MEGABYTE))
    # do not short circuit rep prefix
    try:
        emu.setEmuOpt("i386:repmax", 256)  # 0 == no limit on rep prefix
    except Exception:
        # TODO remove once vivisect#465 is included in release
        emu.setEmuOpt("i386:reponce", False)
    return emu


def remove_stack_memory(emu: Emulator):
    # TODO this is a hack while vivisect's initStackMemory() has a bug (see issue #27)
    # TODO does this bug still exist?
    memory_snap = emu.getMemorySnap()
    for i in range((len(memory_snap) - 1), -1, -1):
        (_, _, info, _) = memory_snap[i]
        if info[3] == STACK_MEM_NAME:
            del memory_snap[i]
            emu.setMemorySnap(memory_snap)
            emu.stack_map_base = None
            return
    raise ValueError("`STACK_MEM_NAME` not in memory map")

FunctionContext = namedtuple("FunctionContext", ["emu_snap", "return_address", "decoded_at_va"])

class CallMonitor(viv_utils.emulator_drivers.Monitor):
    """collect call arguments to a target function during emulation"""

    def __init__(self, vivisect_workspace, target_fva):
        """:param target_fva: address of function whose arguments to monitor"""
        viv_utils.emulator_drivers.Monitor.__init__(self, vivisect_workspace)
        self.target_function_va = target_fva
        self.function_contexts = []

    def apicall(self, emu, op, pc, api, argv):
        return_address = self.getStackValue(emu, 0)
        if pc == self.target_function_va:
            self.function_contexts.append(FunctionContext(emu.getEmuSnap(), return_address, op.va))

    def get_contexts(self):
        return self.function_contexts

    def prehook(self, emu, op, starteip):
        return


@contextlib.contextmanager
def installed_monitor(driver, monitor):
    try:
        driver.add_monitor(monitor)
        yield
    finally:
        driver.remove_monitor(monitor)


class FunctionArgumentGetter(viv_utils.LoggingObject):
    def __init__(self, vivisect_workspace):
        viv_utils.LoggingObject.__init__(self)
        self.vivisect_workspace = vivisect_workspace
        self.emu = make_emulator(vivisect_workspace)
        self.driver = viv_utils.emulator_drivers.FunctionRunnerEmulatorDriver(self.emu)
        self.index = viv_utils.InstructionFunctionIndex(vivisect_workspace)
        self.emu.hooks['msvcrt.sprintf'] = msvcrt_sprintf
        
    def get_all_function_contexts(self, function_va, max_hits):
        # print("Getting function context for function at 0x%08X...", function_va)

        all_contexts = []
        for caller_va in self.get_caller_vas(function_va):
            function_context = self.get_contexts_via_monitor(caller_va, function_va, max_hits)
            all_contexts.extend(function_context)

        # print("Got %d function contexts for function at 0x%08X.", len(all_contexts), function_va)
        return all_contexts

    def get_caller_vas(self, function_va):
        # optimization: avoid re-processing the same function repeatedly
        caller_function_vas = set([])
        for caller_va in self.vivisect_workspace.getCallers(function_va):
            # print("    caller: %s" % hex(caller_va))

            try:
                op = self.vivisect_workspace.parseOpcode(caller_va)
            except Exception as e:
                print("      not a call instruction: failed to decode instruction: %s", e.message)
                continue

            if not (op.iflags & envi.IF_CALL):
                # print("      not a call instruction: %s", op)
                continue

            try:
                # the address of the function that contains this instruction
                caller_function_va = self.index[caller_va]
            except KeyError:
                # there's a pointer outside a function, or
                # maybe two functions share the same basic block.
                # this is a limitation of viv_utils.FunctionIndex
                print("unknown caller function: 0x%x", caller_va)
                continue

            # print("      function: %s", hex(caller_function_va))
            caller_function_vas.add(caller_function_va)
        return caller_function_vas

    def get_contexts_via_monitor(self, fva, target_fva, max_hits):
        """
        run the given function while collecting arguments to a target function
        """
        try:
            _ = self.index[fva]
        except KeyError:
            print("    unknown function")
            return []

        # print("    emulating: %s, watching %s" % (hex(self.index[fva]), hex(target_fva)))
        monitor = CallMonitor(self.vivisect_workspace, target_fva)
        with installed_monitor(self.driver, monitor):
            with defaultHooks(self.driver):
                self.driver.runFunction(self.index[fva], maxhit=max_hits, maxrep=0x1000, func_only=True)
        contexts = monitor.get_contexts()

        # print("      results:")
        # for c in contexts:
        #     print("        <context>")

        return contexts


def get_function_contexts(vw, fva, max_hits):
    return FunctionArgumentGetter(vw).get_all_function_contexts(fva, max_hits)



###
### from flare-floss/floss/decoding_manager.py
###

# type aliases for envi.memory map
MemoryMapDescriptor = Tuple[
    # va
    int,
    # size
    int,
    # perms
    int,
    # name
    str,
]

# type aliases for envi.memory map
MemoryMap = Tuple[
    # start
    int,
    # end
    int,
    # descriptor
    MemoryMapDescriptor,
    # content
    bytes,
]

# type aliases for envi.memory map
Memory = List[MemoryMap]

@dataclass
class Snapshot:
    """
    A snapshot of the state of the CPU and memory.
    Attributes:
        memory: a snapshot of the memory contents
        sp: the stack counter
        pc: the instruction pointer
    """

    memory: Memory
    sp: int
    pc: int


def get_map_size(emu):
    size = 0
    for mapva, mapsize, mperm, mfname in emu.getMemoryMaps():
        mapsize += size
    return mapsize


def make_snapshot(emu: Emulator) -> Snapshot:
    """
    Create a snapshot of the current CPU and memory.
    """
    if get_map_size(emu) > MAX_MAPS_SIZE:
        print("emulator mapped too much memory: 0x%x", get_map_size(emu))
        raise Exception("MapsTooLargeError")
    return Snapshot(emu.getMemorySnap(), emu.getStackCounter(), emu.getProgramCounter())

def emulate_function(
    emu: Emulator, function_index, fva: int, return_address: int, max_instruction_count: int):
    """
    Emulate a function and collect snapshots at each interesting place.
    These interesting places include calls to imported API functions
     and the final state of the emulator.
    Emulation continues until the return address is hit, or
     the given max_instruction_count is hit.
    Some library functions are shimmed, such as memory allocation routines.
    This helps "normal" routines emulate correct using standard library function.
    These include:
      - GetProcessHeap
      - RtlAllocateHeap
      - AllocateHeap
      - malloc
    :type function_index: viv_utils.FunctionIndex
    :param fva: The start address of the function to emulate.
    :param return_address: The expected return address of the function.
     Emulation stops here.
    :param max_instruction_count: The max number of instructions to emulate.
     This helps avoid unexpected infinite loops.
    """
    try:
        pre_snap = make_snapshot(emu)
    except:
        print("initial snapshot mapped too much memory, can't extract strings")
        return

    # delta_collector = DeltaCollectorHook(pre_snap)

    try:
        # print("Emulating function at 0x%08X", fva)
        driver = viv_utils.emulator_drivers.DebuggerEmulatorDriver(emu)
        monitor = ApiMonitor(emu.vw, function_index)
        driver.add_monitor(monitor)
        # driver.add_hook(delta_collector)

        with defaultHooks(driver):
            driver.runToVa(return_address, max_instruction_count)

    except:
        print(0)
    # print("Ended emulation at 0x%08X", emu.getProgramCounter())

def CallerSimulate(vw):
    MAX_INS_COUNT, MAX_HIT = 20000, 1
    function_index = viv_utils.InstructionFunctionIndex(vw)
    fva = 0x0040153A

    # collect context from caller
    for ctx in get_function_contexts(vw, fva, MAX_HIT): 
        print("="*0x30)
        emu = make_emulator(vw)
        emu.setEmuSnap(ctx.emu_snap)
        print("Emulating function at 0x%08X called at 0x%08X, return address: 0x%08X" % (fva, ctx.decoded_at_va, ctx.return_address))
        emulate_function(emu, function_index, fva, ctx.return_address, MAX_INS_COUNT)
