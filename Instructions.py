from capstone import *
from capstone.x86 import *

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
        return 'MEMORY_SET(%s, %s, %s)' % (dataTypes[inst.operands[0].size], l[1], r[1])

    if l[0] == X86_OP_REG:
        # reg, <reg/mem/imm>
        if r[0] == X86_OP_IMM or r[0] == X86_OP_REG:
            return '%s = %s' % (l[1], r[1])
        # reg, mem
        if r[0] == X86_OP_MEM:
            return '%s = MEMORY_GET(%s, %s)' % (l[1], dataTypes[inst.operands[0].size], r[1])

    return '_not_compile_'

def sub(l, r, inst):
    size = dataTypes[inst.operands[0].size]
    sizeB = inst.operands[0].size * 8

    # mem, <reg, imm>
    if l[0] == X86_OP_MEM:
        return 'TMP%s(MEMORY_GET(%s, %s), -, %s)' % (sizeB, size, l[1], r[1]) \
            +  '     zf =  !tmp%s;\n' % (sizeB) \
            +  '     cf =  MEMORY_GET(%s, %s) < %s;\n' % (size, l[1], r[1]) \
            +  '     MEMORY_GET(%s, %s) = tmp%d;' % (size, l[1], sizeB)

    # reg, <reg/imm/mem>
    if l[0] == X86_OP_REG:
        # reg, <imm/reg>
        if r[0] == X86_OP_IMM or r[0] == X86_OP_REG:
            return 'TMP%s(%s, -, %s);\n' % (sizeB, l[1], r[1]) \
                 + '     zf = !tmp%s;\n' % (sizeB) \
                 + '     cf = %s < %s;\n' % (l[1], r[1])\
                 + '     %s = %s;' % (l[1],'tmp%d' % (sizeB) ) 
        # reg, mem
        if r[0] == X86_OP_MEM:
            return 'TMP%s(%s, -, MEMORY_GET(%s, %s));\n' % (sizeB, l[1], size, r[1]) \
                +  '     zf = !tmp%s\n' % (sizeB) \
                +  '     cf = %s < MEMORY_GET(%s, %s);\n' % (l[1], size, r[1]) \
                +  '     %s = %s' % (l[1], 'tmp%d' % (sizeB) )

    return '_not_compile_'

def add(l, r, inst):
    size = dataTypes[inst.operands[0].size]
    sizeB = inst.operands[0].size * 8

    # mem, <reg, imm>
    if l[0] == X86_OP_MEM:
        return 'TMP%s(MEMORY_GET(%s, %s), +, %s)' % (sizeB, size, l[1], r[1]) \
            +  '     zf =  !tmp%s;\n' % (sizeB) \
            +  '     cf =  tmp%s < MEMORY_GET(%s, %s);\n' % (sizeB, size, l[1]) \
            +  '     MEMORY_GET(%s, %s) = tmp%d;' % (size, l[1], sizeB)

    # reg, <reg/imm/mem>
    if l[0] == X86_OP_REG:
        # reg, <imm/reg>
        if r[0] == X86_OP_IMM or r[0] == X86_OP_REG:
            return 'TMP%s(%s, +, %s);\n' % (sizeB, l[1], r[1]) \
                 + '     zf = !tmp%s;\n' % (sizeB) \
                 + '     cf = tmp%s < %s;\n' % (sizeB, l[1])\
                 + '     %s = %s;' % (l[1],'tmp%d' % (sizeB) ) 
        # reg, mem
        if r[0] == X86_OP_MEM:
            return 'TMP%s(%s, +, MEMORY_GET(%s, %s));\n' % (sizeB, l[1], size, r[1]) \
                +  '     zf = !tmp%s;\n' % (sizeB) \
                +  '     cf = tmp%s < %s;\n' % (sizeB, l[1]) \
                +  '     %s = %s' % (l[1], 'tmp%d' % (sizeB) )

    return '_not_compile_'

def inc(l, inst):
    size = dataTypes[inst.operands[0].size]
    sizeB = inst.operands[0].size * 8

    if l[0] == X86_OP_MEM:
        return 'TMP%s(MEMORY_GET(%s, %s), +, 1)' % (sizeB, size, l[1])

    if l[0] == X86_OP_REG:
        return '%s += 1' % (l[1])
    
    return '_not_compile_'

def dec(l, inst):
    size = dataTypes[inst.operands[0].size]
    sizeB = inst.operands[0].size * 8

    if l[0] == X86_OP_MEM:
        return 'TMP%s(MEMORY_GET(%s, %s), -, 1)' % (sizeB, size, l[1])

    if l[0] == X86_OP_REG:
        return '%s -= 1' % (l[1])
    
    return '_not_compile_'

def cmp(l, r, inst):
    size = dataTypes[inst.operands[0].size]
    sizeB = inst.operands[0].size * 8

    # mem, <reg, imm>
    if l[0] == X86_OP_MEM:
        return 'TMP%s(MEMORY_GET(%s, %s), -, %s)' % (sizeB, size, l[1], r[1]) \
            +  '     zf =  !tmp%s;\n' % (sizeB) \
            +  '     cf =  MEMORY_GET(%s, %s) < %s;' % (size, l[1], r[1]) 

    # reg, <reg/imm/mem>
    if l[0] == X86_OP_REG:
        # reg, <imm/reg>
        if r[0] == X86_OP_IMM or r[0] == X86_OP_REG:
            return 'TMP%s(%s, -, %s);\n' % (sizeB, l[1], r[1]) \
                 + '     zf = !tmp%s;\n' % (sizeB) \
                 + '     cf = %s < %s;' % (l[1], r[1])
        # reg, mem
        if r[0] == X86_OP_MEM:
            return 'TMP%s(%s, -, MEMORY_GET(%s, %s));\n' % (sizeB, l[1], size, r[1]) \
                +  '     zf = !tmp%s\n' % (sizeB) \
                +  '     cf = %s < MEMORY_GET(%s, %s);' % (l[1], size, r[1]) 

    return '_not_compile_'

def jne(l, inst):
    return 'if(!zf) goto _%x;' % (int(l[1]))
