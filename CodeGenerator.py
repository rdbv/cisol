from capstone import *
from capstone.x86 import *

''' Basic code, we will be generating instructions
    inside func(char*)
'''

codeC = '''
#include <stdint.h>
#define MEMORY_SIZE 1024

uint8_t of = 0, sf = 0, zf = 0, af = 0, pf = 0, cf = 0;
uint8_t  tmp8   = 0;
uint16_t tmp16  = 0;
uint32_t tmp32  = 0;
uint64_t tmp64  = 0;

#define MEMORY_SET(T, O, V) *((T*)&stack[O]) = V
#define MEMORY_GET(T, O) (*((T*)&stack[O]))

uint8_t memory[MEMORY_SIZE] = {0};

struct {
    union {
        uint64_t regs64[17];
        struct {
            uint64_t rax, rbx, rcx,
                     rdx, rsi, rdi,
                     r8,  r9,  r10,
                     r11, r12, r13,
                     r14, r15, rip,
                     rbp, rsp;
        };
        uint32_t regs32[17];
        struct {
            uint32_t eax,  ebx,  ecx,
                     edx,  esi,  edi,
                     r8d,  r9d,  r10d,
                     r11d, r12d, r13d,
                     r14d, r15d, eip,
                     ebp, esp;
        };
        uint16_t regs16[17];
        struct {
            uint16_t ax, bx, cx,
                     dx, si, di,
                     r8w, r9w, r10w,
                     r11w, r12w, r13w,
                     r14w, r15w, ip,
                     bp, sp;
        };
        uint8_t regs8[34];
        /* rNx/bpl/eg. don't exist, but must (i think so.. xD) be here for padding */
        struct {
            uint8_t al, ah, bl, bh, cl, ch,
                    dl, dh, sil, sih, dil, dih,
                    r8b, r8x, r9b, r9x, r10b, r10x,
                    r11b, r11x, r12b, r12x, r13b, r13x,
                    r14b, r14x, r15b, r15x, ipl, iph,
                    bpl, bph, spl, sph;
        };
    };
} regs;

#define STEP(n) regs.rip += n;

void func(char* stack) {
%s}\n
int main() {
}
''' 

''' Just load bytes in desired range '''
def loadCode(filename, start, stop):
    f = open(filename, 'rb')
    code = f.read()
    return code[start:stop]


dataTypes = {
    1 : 'uint8_t',
    2 : 'uint16_t',
    4 : 'uint32_t',
    8 : 'uint64_t'
}

''' Instructions C impl. '''
def mov(l, r, inst):
    if l[0] == X86_OP_MEM:
        # mem, <reg/imm>
        return 'MEMORY_SET(%s, %s, %s)' % (dataTypes[inst.operands[0].size], l, r)

    if l[0] == X86_OP_REG:
        # reg, <mem/imm>
        if r[0] == X86_OP_IMM:
            return '%s = %s' % (l[1], r[1])
        if r[0] == X86_OP_MEM:
            return '%s = MEMORY_GET(%s, %s)' % (l[1], dataTypes[inst.operands[0].size], r[1])

    return '???'

def cmp(l, r, inst):
    pass

class CodeGenerator:
    def __init__(self, name, start, stop):
        self.code = loadCode(name, start, stop)
        self.cCode = ''

        # Instruction lookup
        self.cinstr = {
            'mov' : mov,
            'cmp' : cmp
        }

        # Init capstone
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True
        self.instructions = [x for x in self.cs.disasm(self.code, 0)]

        # go go go
        self.generate()

    ''' Just fill C template '''
    def getAsC(self):
        return codeC % self.cCode

    ''' Go over each instruction in range, nothing special '''
    def generate(self):
        for inst in self.instructions:

            # Operands is list of ops, 0, 1, 2 (may more) ops
            ops = [x for x in inst.operands]
            args = [self.buildArg(inst, x) for x in ops]

            # get C implementation
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
            # Apply simple displacement [<reg> +- <displacement>]
            # Should be also variants like [<reg> + n*<reg> +- <displacement>]
            # But this is only POC code
            baseReg = instr.reg_name(operand.mem.base)
            displacement = operand.mem.disp
            out = 'regs.' + baseReg
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



