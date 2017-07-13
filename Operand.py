from capstone import *
from capstone.x86 import *

# Alias lookup for casting registers. 
# For example: eax -> al
regsSize = [
    [ ['rax', 'eax', 'ax', 'al', 'ah'], {1:'al', 2:'ax', 4:'eax', 8:'rbx'} ],
    [ ['rbx', 'ebx', 'bx', 'bl', 'bh'], {1:'bl', 2:'bx', 4:'ebx', 8:'rbx'} ],
    [ ['rcx', 'ecx', 'cx', 'cl', 'ch'], {1:'cl', 2:'cx', 4:'ecx', 8:'rcx'} ],
    [ ['rdx', 'edx', 'dx', 'dl', 'dh'], {1:'dl', 2:'dx', 4:'edx', 8:'rdx'} ]
]

dataTypes = {
    1 : 'uint8_t',
    2 : 'uint16_t',
    4 : 'uint32_t',
    8 : 'uint64_t'
}

class Operand:
    def __init__(self, type, value, size):
        self.type = type
        self.value = value
        self.sizeBytes = size
        self.sizeBits = size * 8

    def getAsMemoryRef(self, size = 0):
        if size != 0:
            dataType = dataTypes[size]
        else:
            dataType = dataTypes[self.sizeBytes]

        # Type other than MEM, so this will propably not compile
        if self.type != X86_OP_MEM:
            return "_no_no_no_"

        return 'MEMORY(%s, %s)' % (dataType, self.value)

    def getAsRegImm(self, size = 0):
        if not size:
            size = self.sizeBytes
        for r in regsSize:
            if self.value in r[0]:
                return r[1][size]

        # Propably imm
        return self.value

    def getValue(self, size = 0):
        if self.type == X86_OP_MEM:
            return self.getAsMemoryRef(size)
        elif self.type == X86_OP_IMM or self.type == X86_OP_REG:
            return self.getAsRegImm(size)

        raise '!!!'

