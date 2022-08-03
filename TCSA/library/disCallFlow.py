class BasicBlock():
    def __init__(self, vw, va, size, fva):
        self.vw = vw
        self.va = va
        self.size = size
        self.fva = fva

    def instructions(self):
        """
        from envi/__init__.py:class Opcode
        391         opcode   - An architecture specific numerical value for the opcode
        392         mnem     - A humon readable mnemonic for the opcode
        393         prefixes - a bitmask of architecture specific instruction prefixes
        394         size     - The size of the opcode in bytes
        395         operands - A list of Operand objects for this opcode
        396         iflags   - A list of Envi (architecture independant) instruction flags (see IF_FOO)
        397         va       - The virtual address the instruction lives at (used for PC relative im mediates etc...)
        """
        ret = []
        va = self.va
        while va < self.va + self.size:
            try:
                o = self.vw.parseOpcode(va)
            except Exception as e:
                self.d("Failed to disassemble: %s: %s", hex(va), e)
                break
            ret.append(o)
            va += len(o)
        return ret