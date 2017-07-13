from capstone import *
from capstone.x86 import *


from Instructions import *

# Basic code..

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
    def __init__(self, name, start, stop, flags):
        self.code = loadCode(name, start, stop)
        self.cCode = ''

        # Instruction lookup
        self.cinstr = {
            'mov' : mov,
            'movzx' : movzx,
            'movsx' : movzx,
            'cdqe' : cdqe,
            'sub' : sub,
            'add' : add,
            'inc' : inc,
            'dec' : dec,
            'cmp' : cmp,
            'jmp' : jmp,
            'jne' : jne,
            'je'  : je,
            'jnb' : jnb,
            'jb'  : jb,
            'jbe' : jbe
        }

        self.jumps = ['jmp', 'je', 'jne', 'jz', 'jnz', 'jnb', 'jb', 'jbe']
        self.usedFlags = flags

        # Init capstone
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True
        self.instructions = [x for x in self.cs.disasm(self.code, 0)]
    
        self.jumpPlaces = {}
        self.checkJumps()

        # go go go
        self.generate()

    ''' Just fill C template '''
    def getAsC(self):
        return codeC % self.cCode

    ''' Every jump must have place to jump,
        here we check, that every jump has place,
        if code is self-modyifing or jumps in middle of instruction
        then this method will fail
    '''
    def checkJumps(self):
        for instr in self.instructions:

            # Is it jump?
            if instr.mnemonic in self.jumps:

                # Yes, so get address
                addr = int(instr.operands[0].imm)
                found = False

                # Check existence of target instruction
                for _instr in self.instructions:
                    if _instr.address == addr:
                        found = True
                        self.jumpPlaces[addr] = True
                        break

                if not found:
                    print("Jump to nonexisting instr (Or jump in instr middle)...\nQuitting...")
                    exit(0)

    ''' Go over each instruction in range '''
    def generate(self):
        for inst in self.instructions:

            # If we will jump to this instruction
            # Add label for goto
            if inst.address in self.jumpPlaces:
                self.emit('_%x:' % (inst.address), indent=0)

            # Operands is list of ops, 0, 1, 2 (may more) ops
            ops = [x for x in inst.operands]
            args = [self.buildOperand(inst, x) for x in ops]

            #print('%x: %s %s -> %s' % (inst.address, inst.mnemonic, inst.op_str, '') )

            # check is available
            if inst.mnemonic not in self.cinstr:
                print("Instruction not found...\nQuitting...")
                exit(0)

            # process instruction
            self.cinstr[ inst.mnemonic ](*args, inst, self)

    ''' 
        Create Operand
    '''
    def buildOperand(self, instr, operand):
        type = operand.type

        # eg. regs.eax
        if type == X86_OP_REG:
            return Operand(type, instr.reg_name(operand.reg), operand.size)

        # eg. rax + rbx * 1 - 0x13
        if type == X86_OP_MEM:
            baseReg = instr.reg_name(operand.mem.base)
            displacement = operand.mem.disp
            index, scale = (operand.mem.index, operand.mem.scale) 
            out = baseReg

            if index:
                out += '+' + instr.reg_name(index) + '*' + str(scale)

            if displacement:
                if displacement < 0: out += '-'
                if displacement > 0: out += '+'
                out += str(abs(displacement))

            return Operand(type, out, operand.size)

        # eg. 0x10
        if type == X86_OP_IMM:
            return Operand(type, str(operand.imm), operand.size)
        
        raise "Unknown type..."

    ''' Spaces FTW '''    
    def emit(self, data, flags = '', actions = '', comment = '', indent = 1):
        self.cCode += '    ' * indent
        self.cCode += data + '; '

        # Append comment 
        if len(comment):
            self.cCode += '// ' + comment + '\n'
    
        # Check is flag used, and append
        if len(flags):
            for (id, flag) in flags:
                if id in self.usedFlags:
                    self.cCode += ('    ' * indent) + '  ' + flag + ';\n'
        
        # Add actions, executed after setting flags
        if len(actions):
            for action in actions:
                self.cCode += ('    ' * indent) + '    ' + action + ';\n'

        if len(comment) == 0 and len(flags) == 0:
            self.cCode += '\n'



