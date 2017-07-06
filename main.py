from CodeGenerator import *

cg = CodeGenerator('bin/main', 0x80, 0x80 + 10)

cCode = cg.getAsC()

out = open('out.c', 'wb')
out.write(bytes(cCode, encoding='ascii'))


