from CodeGenerator import *
from os import system

cg = CodeGenerator('bin/main', 0x80, 0x9f + 3)

cCode = cg.getAsC()

out = open('out.c', 'wb')
out.write(bytes(cCode, encoding='ascii'))
out.close()

system("gcc out.c -o out")




