from capstone import *
from capstone.x86 import *
from Instructions import *

''' Basic code, we will be generating instructions
    inside func(char*)
'''

codeC = '''
#include "environment.h"

void func() {
%s}\n
int main() {
}
''' 

''' Just load bytes in desired range '''
def loadCode(filename, start, stop):
    f = open(filename, 'rb')
    code = f.read()
    return code[start:stop]



class CodeGenerator:
    def __init__(self, name, start, stop):
        self.code = loadCode(name, start, stop)
        self.cCode = ''

        # Instruction lookup
        self.cinstr = {
            'mov' : mov,
            'sub' : sub,
            'add' : add,
            'inc' : inc,
            'cmp' : cmp,
            'jne' : jne
        }
    
        self.jumps = [
            'jmp', 'je', 'jne', 'jz', 'jnz'
        ]
        
        self.jumpPlaces = {}

        # Init capstone
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True
        self.instructions = [x for x in self.cs.disasm(self.code, 0)]
    
        self.checkJumps()

        # go go go
        self.generate()

    ''' Just fill C template '''
    def getAsC(self):
        return codeC % self.cCode

    def checkJumps(self):
        for instr in self.instructions:
            if instr.mnemonic in self.jumps:
                addr = int(instr.operands[0].imm)
                found = False
                for _instr in self.instructions:
                    if _instr.address == addr:
                        found = True
                        self.jumpPlaces[addr] = True
                        break
                if not found:
                    print("Jump to nonexisting place...\nQuitting...")
                    exit(0)

    ''' Go over each instruction in range, nothing special '''
    def generate(self):
        for inst in self.instructions:

            if inst.address in self.jumpPlaces:
                self.emit('_%x:' % (inst.address), indent=0)

            # Operands is list of ops, 0, 1, 2 (may more) ops
            ops = [x for x in inst.operands]
            args = [self.buildArg(inst, x) for x in ops]

            # get C implementation
            if inst.mnemonic not in self.cinstr:
                print("Instruction not found...\nQuitting...")
                exit(0)

            c = self.cinstr[ inst.mnemonic ](*args, inst)
           
            # Emit to C pattern
            self.emit(c)

            print('%x: %s %s -> %s' % (inst.address, inst.mnemonic, inst.op_str, c) )


    ''' Return type of operand (register, memory, immediate)
        and 'value' in C
    '''
    def buildArg(self, instr, operand):
        type = operand.type

        if type == X86_OP_REG:
            return (type, 'regs.' + instr.reg_name(operand.reg))

        if type == X86_OP_MEM:
            baseReg = instr.reg_name(operand.mem.base)
            displacement = operand.mem.disp
            index, scale = (operand.mem.index, operand.mem.scale) 
            out = 'regs.' + baseReg
            if index:
                out += '+' + 'regs.' + instr.reg_name(index) + '*' + str(scale)
            if displacement:
                out += '+' + str(displacement)
            return (type, out)

        if type == X86_OP_IMM:
            return (type, str(operand.imm))
        
        raise "????"

    ''' Spaces FTW '''    
    def emit(self, data, macros = '', indent = 1):
        self.cCode += '    ' * indent
        self.cCode += data + ';'
        if(len(macros)):
            self.cCode += macros + ';'
        self.cCode += '\n'



