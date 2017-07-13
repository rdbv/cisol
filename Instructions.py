from capstone import *
from capstone.x86 import *
from Operand import *

# Overflow flag mask
ofMask = {
    1 : 0x80,
    2 : 0x8000,
    4 : 0x80000000,
    8 : 0x8000000000000000
}

''' 
    Instructions in C implementation
'''

def mov(left, right, inst, cg):
    cg.emit('%s = %s' % (left.getValue(), right.getValue()) ,
            comment = (inst.mnemonic + ' ' + inst.op_str))

def movzx(left, right, inst, cg):
    cg.emit('%s = 0, %s = %s' % (left.getValue(8), left.getValue(), right.getValue()),
            comment = (inst.mnemonic + ' ' + inst.op_str))

def sub(left, right, inst, cg, isCmp = False):
    sizeBits, sizeBytes = (left.sizeBits, left.sizeBytes)
    lVal, rVal = (left.getValue(), right.getValue())
    
    if isCmp:
        actions = []
    else:
        actions = ['%s = tmp%s' % (lVal, sizeBits)]

    cg.emit('TMP%s(%s, -, %s)' % (sizeBits, lVal, rVal),
            flags = [
                ['c', 'SET_CF_SUB(%s, %s)' % (lVal, rVal)],
                ['z', 'SET_ZF(%s)' % (sizeBits)],
                ['a', 'SET_AF_0(%s, %s)' % (left.getValue(1), right.getValue(1))],
                ['o', 'SET_OF_SUB(%s, %s, %s, %s)' % (lVal, rVal, sizeBits, hex(ofMask[sizeBytes]) )]
            ],
            actions = actions,
            comment = (inst.mnemonic + ' ' + inst.op_str));


def add(left, right, inst, cg):
    sizeBits, sizeBytes = (left.sizeBits, left.sizeBytes)
    lVal, rVal = (left.getValue(), right.getValue())

    cg.emit('TMP%s(%s, +, %s)' % (sizeBits, lVal, rVal),
            flags = [
                ['c', 'SET_CF_ADD(%s, %s)' % (sizeBits, lVal)],
                ['z', 'SET_ZF(%s)' % (sizeBits)],
                ['a', 'SET_AF_0(%s, %s)' % (left.getValue(1), right.getValue(1))],
                ['o', 'SET_OF_ADD(%s, %s, %s, %s)' % (lVal, rVal, sizeBits, hex(ofMask[sizeBytes]) )]
            ],
            actions = [
                '%s = tmp%s' % (lVal, sizeBits)
            ],
            comment = (inst.mnemonic + ' ' + inst.op_str))


def inc(left, inst, cg):
    sizeBits, sizeBytes = (left.sizeBits, left.sizeBytes)
    lVal, rVal = left.getValue(), '1'
    
    cg.emit('TMP%s(%s, +, %s)' % (sizeBits, lVal, rVal),
            flags = [
                ['z', 'SET_ZF(%s)' % (sizeBits)],
                ['a', 'SET_AF_INC(%s)' % (sizeBits)],
                ['o', 'SET_OF_INC_DEC_NEG(%s, %s)' % (sizeBits, hex(ofMask[sizeBytes]) )],
            ],
            actions = [
                '%s = tmp%s' % (lVal, sizeBits)
            ],
            comment = (inst.mnemonic + ' ' + inst.op_str))


def dec(left, inst, cg):
    sizeBits, sizeBytes = (left.sizeBits, left.sizeBytes)
    lVal, rVal = left.getValue(), '1'
    
    cg.emit('TMP%s(%s, -, %s)' % (sizeBits, lVal, rVal),
            flags = [
                ['z', 'SET_ZF(%s)' % (sizeBits)],
                ['a', 'SET_AF_DEC(%s)' % (sizeBits)],
                ['o', 'SET_OF_INC_DEC_NEG(%s, %s)' % (sizeBits, hex(ofMask[sizeBytes]-1) )],
            ],
            actions = [
                '%s = tmp%s' % (lVal, sizeBits)
            ],
            comment = (inst.mnemonic + ' ' + inst.op_str))


def cdqe(inst, cg):
    cg.emit('// cdqe not implemented yet')

def xor(left, right, inst, cg):
    pass

def cmp(left, right, inst, cg):
    # cmp is sub without setting value
    sub(left, right, inst, cg, True)

def jmp(op, inst, cg):
    cg.emit('goto _%x' % (int(op.value)),
            comment = (inst.mnemonic + ' ' + inst.op_str));

def jne(op, inst, cg):
    cg.emit('if(!zf)\n        goto _%x' % (int(op.value)),
            comment = (inst.mnemonic + ' ' + inst.op_str));

def je(op, inst, cg):
    cg.emit('if(zf)\n         goto _%x' % (int(op.value)),
            comment = (inst.mnemonic + ' ' + inst.op_str));

def jb(op, inst, cg):
    cg.emit('if(cf)\n         goto _%x;' % (int(op.value)),
            comment = (inst.mnemonic + ' ' + inst.op_str));

def jbe(op, inst, cg):
    cg.emit('if(cf == 1 || zf == 1)\n      goto _%x' % (int(op.value)),
            comment = (inst.mnemonic + ' ' + inst.op_str));

def jnb(op, inst, cg):
    cg.emit('if(!cf)\n        goto _%x;' % (int(op.value)),
            comment = (inst.mnemonic + ' ' + inst.op_str));
